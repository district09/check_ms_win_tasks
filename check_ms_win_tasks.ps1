###################################################################################################
# Script name:   	check_ms_win_tasks.ps1
# Version:			2.14.3.23b
# Created on:    	01/02/2014																			
# Author:        	D'Haese Willem
# Purpose:       	Checks Microsoft Windows scheduled tasks excluding defined folders and defined 
#					task patterns, returning state of tasks with name, author, exit code and 
#					performance data to Nagios.
# On Github:		https://github.com/willemdh/check_ms_win_tasks.ps1
# To do:			
#  	- Add switches to change returned values and output
#  	- Add array parameter with exit codes that should be excluded
#	- Make parameters non mandatory
#	- Test remote execution
# History:       	
#	03/02/2014 => Add array as argument with excluded folders
#	15/02/2014 => Add array as argument with excluded task patterns
#	03/03/2014 => Added perfdata and edited output
#	09/03/2014 => Added running tasks information and perfdata
#	22/03/2014 => Resolved a bug with output treated as perfdata
#	23/03/2014 => Created repository on Github and updated documentation
# How to:
#	1) Put the script in the NSCP scripts folder
#	2) In the nsclient.ini configuration file, define the script like this:
#		check_ms_win_tasks=cmd /c echo scripts\check_ms_win_tasks.ps1 $ARG1$ $ARG2$ $ARG3$; exit 
#		$LastExitCode | powershell.exe -command -
#	3) Make a command in Nagios like this:
#		check_ms_win_tasks => $USER1$/check_nrpe -H $HOSTADDRESS$ -p 5666 -t 60 -c 
#		check_ms_win_tasks -a $ARG1$ $ARG2$ $ARG3$
#	4) Configure your service in Nagios:
#		- Make use of the above created command
#		- Parameter 1 should be 'localhost' (did not test with remoting)
#		- Parameter 2 should be an array of folders to exclude, example 'Microsoft, Backup'
#		- Parameter 3 should be an array of task patterns to exclude, example 'Jeff,"Copy Test"'
#		- All single quotes need to be included (In Nagios XI)
#		- Array values with spaces need double quotes (see above example)
#		- All three parameters are mandatory for now, use " " if you don't want exclusions
# Help:
#	This script works perfectly in our environment on Windows 2008 and Windows 2008 R2 servers. If
#	you do happen to find an issue, let me know on Github. The script is highly adaptable if you 
#	want different output etc. I've been asked a few times to make it multilingual, as obviously
#	this script will only work on English Windows 2008 or higher servers, but as I do not have 
#	non-English servers at my disposal, I'm not going to implement any other languages..
# Copyright:
#	This program is free software: you can redistribute it and/or modify it under the terms of the
# 	GNU General Public License as published by the Free Software Foundation, either version 3 of 
#   the License, or (at your option) any later version.
#   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
#	without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
# 	See the GNU General Public License for more details.You should have received a copy of the GNU
#   General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
###################################################################################################


param(
	[Parameter(Mandatory=$true)][string]$ComputerName = "localhost",
    [Parameter(Mandatory=$true)]$ExclFolders = @(),
	[Parameter(Mandatory=$true)]$ExclTasks = @(),
	[switch]$RootFolder
)
 
#region Functions
function Get-AllTaskSubFolders {
    [cmdletbinding()]
    param (
       $FolderRef = $Schedule.getfolder("\")
    )
    if ($RootFolder) {
        $FolderRef
    } else {
        $FolderRef	     
        if(($folders = $folderRef.getfolders(1)).count -ge 1) {
            foreach ($folder in $folders) {
				if ($ExclFolders -notcontains $folder.Name) {     
                	if(($folder.getfolders(1).count -ge 1)) {
                    	Get-AllTaskSubFolders -FolderRef $folder
                	}
					else {
						$folder
					}
				}
            }
        }
    }
}

function Check-Array ([string]$str, [string[]]$patterns) {
    foreach($pattern in $patterns) { if($str -match $pattern) { return $true; } }
    return $false;
}

#endregion Functions

if ($PSVersionTable) {$Host.Runspace.ThreadOptions = 'ReuseThread'}
 
$status = 3;
 
try {
	$schedule = new-object -com("Schedule.Service") 
} catch {
	Write-Host "Schedule.Service COM Object not found, this script requires this object"
	exit $status
	return
}
 

$Schedule.connect($ComputerName) 
$AllFolders = @()
$AllFolders = Get-AllTaskSubFolders
$TaskOk = 0
$TaskNotOk = 0
$TaskRunning = 0
$BadTasks = @()
$GoodTasks = @()
$RunningTasks = @()


foreach ($Folder in $AllFolders) {		
		    if (($Tasks = $Folder.GetTasks(0))) {
		        $Tasks | Foreach-Object {$ObjTask = New-Object -TypeName PSCustomObject -Property @{
			            'Name' = $_.name
		                'Path' = $_.path
		                'State' = $_.state
		                'Enabled' = $_.enabled
		                'LastRunTime' = $_.lastruntime
		                'LastTaskResult' = $_.lasttaskresult
		                'NumberOfMissedRuns' = $_.numberofmissedruns
		                'NextRunTime' = $_.nextruntime
		                'Author' =  ([xml]$_.xml).Task.RegistrationInfo.Author
		                'UserId' = ([xml]$_.xml).Task.Principals.Principal.UserID
		                'Description' = ([xml]$_.xml).Task.RegistrationInfo.Description
						'Cmd' = ([xml]$_.xml).Task.Actions.Exec.Command 
						'Params' = ([xml]$_.xml).Task.Actions.Exec.Arguments
		            }
				if ($ObjTask.LastTaskResult -eq "0") {
					if(!(Check-Array $ObjTask.Name $ExclTasks)){
						$GoodTasks += $ObjTask
						$TaskOk += 1
						}
					}
				elseif ($ObjTask.LastTaskResult -eq "0x00041301") {
					if(!(Check-Array $ObjTask.Name $ExclTasks)){
						$RunningTasks += $ObjTask
						$TaskRunning += 1
						}
					}
				else {
					if(!(Check-Array $ObjTask.Name $ExclTasks)){
						$BadTasks += $ObjTask
						$TaskNotOk += 1
						}
					}
				}
		    }	
} 
$TotalTasks = $TaskOk + $TaskNotOk + $TaskRunning
if ($TaskNotOk -gt "0") {
	Write-Host "$TaskNotOk / $TotalTasks tasks failed! Check tasks: "
	foreach ($BadTask in $BadTasks) {
		Write-Host "Task $($BadTask.Name) by $($BadTask.Author)failed with exitcode $($BadTask.lasttaskresult)"
	}
	foreach ($RunningTask in $RunningTasks) {
		Write-Host "Task $($RunningTask.Name) by $($RunningTask.Author), exitcode $($RunningTask.lasttaskresult) is still running!"
	}
	Write-Host " | 'Total Tasks'=$TotalTasks, 'OK Tasks'=$TaskOk, 'Failed Tasks'=$TaskNotOk, 'Running Tasks'=$TaskRunning"
	$status = 2
}	
else {
	Write-Host "All $TotalTasks tasks ran succesfully!"
	foreach ($RunningTask in $RunningTasks) {
		Write-Host "Task $($RunningTask.Name) by $($RunningTask.Author), exitcode $($RunningTask.lasttaskresult) is still running!"
	}
	Write-Host " | 'Total Tasks'=$TotalTasks, 'OK Tasks'=$TaskOk, 'Failed Tasks'=$TaskNotOk, 'Running Tasks'=$TaskRunning"
	$status = 0
}
exit $status