# Script name:  check_ms_win_tasks.ps1
# Version:      v5.16.161118
# Created on:   01/02/2014
# Author:       Willem D'Haese
# Purpose:      Checks Microsoft Windows enabled scheduled tasks excluding defined folders and task patterns, returning state of tasks
#               with name, author, exit code and performance data to Nagios.
# On Github:    https://github.com/willemdh/check_ms_win_tasks
# On OutsideIT: https://outsideit.net/check-ms-win-tasks
# Recent History:
#   12/02/16 => Added Write-Log
#   11/06/16 => Added hidden parameter, set to 1 to include hidden tasks
#   14/06/16 => Improved spacing and structure
#   28/07/16 => GuestName bugfixe and better IF and EF regex
#   18/11/16 => Add funcionality to alert on disabled tasks, fix perfdata format and add 'Disabled Tasks' to perfdata (Aaron Gorka)
# Copyright:
#   This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published
#   by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. This program is distributed 
#   in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 
#   PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU General Public 
#   License along with this program.  If not, see <http://www.gnu.org/licenses/>.

#Requires –Version 2.0

$DebugPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'

$Struct = New-Object PSObject -Property @{
    Hostname = [string]'localhost';
    ExclFolders = [string[]]@();
    InclFolders = [string[]]@();
    ExclTasks = [string[]]@();
    InclTasks = [string[]]@();
    FolderRef = [string]'';
    AllValidFolders = [string[]]@();
    ExitCode = [int]3;
    Hidden = [int]0;
    TasksOk = [int]0;
    TasksNotOk = [int]0;
    TasksRunning = [int]0;
    TasksTotal = [int]0;
    TasksDisabled = [int]0;
    AlertOnDisabled = [bool]$False;
    OutputString = [string]'Unknown: Error processing, no data returned.'
}

#region Functions
Function Write-Log {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)][string]$Log,
        [parameter(Mandatory=$true)][ValidateSet('Debug', 'Info', 'Warning', 'Error', 'Unknown')][string]$Severity,
        [parameter(Mandatory=$true)][string]$Message
    )
    $Now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss,fff'
    # $LocalScriptName = split-path $MyInvocation.PSCommandPath -Leaf
    $LocalScriptName = Split-Path $myInvocation.ScriptName -Leaf
    if ($Log -eq 'Undefined') {
        Write-Debug "${Now}: ${LocalScriptName}: Info: LogServer is undefined."
    }
    elseif ($Log -eq 'Verbose') {
        Write-Verbose "${Now}: ${LocalScriptName}: ${Severity}: $Message"
    }
    elseif ($Log -eq 'Debug') {
        Write-Debug "${Now}: ${LocalScriptName}: ${Severity}: $Message"
    }
    elseif ($Log -eq 'Output') {
        Write-Host "${Now}: ${LocalScriptName}: ${Severity}: $Message"
    }
    elseif ($Log -match '^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])(?::(?<port>\d+))$' -or $Log -match "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$") {
        $IpOrHost = $log.Split(':')[0]
        $Port = $log.Split(':')[1]
        if  ($IpOrHost -match '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$') {
            $Ip = $IpOrHost
        }
        else {
            $Ip = [System.Net.Dns]::GetHostAddresses($IpOrHost)[0].IPAddressToString
        }
        Try {
            $LocalHostname = ([System.Net.Dns]::GetHostByName((hostname.exe)).HostName).tolower()
            $JsonObject = (New-Object PSObject | 
                Add-Member -PassThru NoteProperty logsource $LocalHostname | 
                Add-Member -PassThru NoteProperty hostname $LocalHostname | 
                Add-Member -PassThru NoteProperty scriptname $LocalScriptName | 
                Add-Member -PassThru NoteProperty logtime $Now | 
                Add-Member -PassThru NoteProperty severity_label $Severity | 
                Add-Member -PassThru NoteProperty message $Message ) 
            if ($psversiontable.psversion.major -ge 3) {
                $JsonString = $JsonObject | ConvertTo-Json
                $JsonString = $JsonString -replace "`n",' ' -replace "`r",' '
            }
            else {
                $JsonString = $JsonObject | ConvertTo-Json2
            }               
            $Socket = New-Object System.Net.Sockets.TCPClient($Ip,$Port) 
            $Stream = $Socket.GetStream() 
            $Writer = New-Object System.IO.StreamWriter($Stream)
            $Writer.WriteLine($JsonString)
            $Writer.Flush()
            $Stream.Close()
            $Socket.Close()
        }
        catch {
            Write-Host "${Now}: ${LocalScriptName}: Error: Something went wrong while trying to send message to Logstash server `"$Log`"."
        }
        Write-Verbose "${Now}: ${LocalScriptName}: ${Severity}: Ip: $Ip Port: $Port JsonString: $JsonString"
    }
    elseif ($Log -match '^((([a-zA-Z]:)|(\\{2}\w+)|(\\{2}(?:(?:25[0-5]|2[0-4]\d|[01]\d\d|\d?\d)(?(?=\.?\d)\.)){4}))(\\(\w[\w ]*))*)') {
        if (Test-Path -Path $Log -pathType container){
            Write-Host "${Now}: ${LocalScriptName}: Error: Passed Path is a directory. Please provide a file."
            exit 1
        }
        elseif (!(Test-Path -Path $Log)) {
            try {
                New-Item -Path $Log -Type file -Force | Out-null	
            } 
            catch { 
                $Now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss,fff'
                Write-Host "${Now}: ${LocalScriptName}: Error: Write-Log was unable to find or create the path `"$Log`". Please debug.."
                exit 1
            }
        }
        try {
            "${Now}: ${LocalScriptName}: ${Severity}: $Message" | Out-File -filepath $Log -Append   
        }
        catch {
            Write-Host "${Now}: ${LocalScriptName}: Error: Something went wrong while writing to file `"$Log`". It might be locked."
        }
    }
}
Function Initialize-Args {
    Param ( 
        [Parameter(Mandatory=$True)]$Args
    )
    Try {
        For ( $i = 0; $i -lt $Args.count; $i++ ) { 
            $CurrentArg = $Args[$i].ToString()
            If ($i -lt $Args.Count-1) {
                $Value = $Args[$i+1];
                If ($Value.Count -ge 2) {
                    ForEach ($Item in $Value) {
                        Test-Strings $Item | Out-Null
                    }
                }
                Else {
                    $Value = $Args[$i+1];
                    Test-Strings $Value | Out-Null
                }
            } 
            Else {
                $Value = ''
            }
            Switch -regex -casesensitive ($CurrentArg) {
                "^(-H|--Hostname)$" {
                    If ($value -match '^[a-zA-Z.]+') {
                        If ($Value -ne ([System.Net.Dns]::GetHostByName((hostname.exe)).HostName).tolower() -and $Value -ne 'localhost') {
                            & ping.exe -n 1 $Value | out-null
                            If($? -eq $true) {
                                $Struct.Hostname = $Value
                                $i++
                            }
                            Else {
                                Throw "Ping to $Value failed! Please provide valid reachable hostname."
                            }
                        }
                        Else {
                            $Struct.Hostname = $Value
                            $i++
                        }
                    }
                    Else {
                        throw "Hostname `"$value`" does not meet regex requirements."
                    }
                }
                "^(-EF|--ExclFolders)$" {
                    If ($Value.Count -ge 2) {
                        ForEach ($Item in $Value) {
                            If ($Item -match '^[a-zA-Z0-9\\.]+') {
                                $Struct.ExclFolders += $Item
                            }
                            Else {
                                Throw "ExclFolders `"$value`" does not meet regex requirements."
                            }
                        }
                    }
                    Else {
                        If ($Value -match '^[a-zA-Z0-9\\.]+') {
                            $Struct.ExclFolders = $Value 
                        }
                        Else {
                            Throw "ExclFolders `"$value`" does not meet regex requirements."
                        }
                    }
                    $i++
                }
                "^(-IF|--InclFolders)$" {
                    If ($Value.Count -ge 2) {
                        ForEach ($Item in $Value) {
                            If ($Item -match '^[a-zA-Z0-9\\.]+') {
                                $Struct.InclFolders += $Item
                            }
                            Else {
                                Throw "InclFolders `"$value`" does not meet regex requirements."
                            }
                        }
                    }
                    Else {
                        If ($Value -match '^[a-zA-Z0-9\\.]+') {
                            $Struct.InclFolders = $Value 
                        }
                        Else {
                            Throw "InclFolders `"$value`" does not meet regex requirements."
                        }
                    }
                    $i++
                }
                "^(-ET|--ExclTasks)$" {
                    If ($Value.Count -ge 2) {
                        ForEach ($Item in $Value) {
                            If ($Item -match '^[a-zA-Z0-9.]+') {
                                $Struct.ExclTasks += $Item
                            }
                            Else {
                                Throw "ExclTasks `"$value`" does not meet regex requirements."
                            }
                        }
                    }
                    Else {
                        If ($Value -match '^[a-zA-Z0-9.]+') {
                            $Struct.ExclTasks = $Value 
                        }
                        Else {
                            Throw "ExclTasks `"$value`" does not meet regex requirements."
                        }
                    }
                    $i++
                }
                "^(-IT|--IncllTasks)$" {
                    If ($Value.Count -ge 2) {
                        ForEach ($Item in $Value) {
                            If ($Item -match '^[a-zA-Z0-9.]+') {
                                $Struct.InclTasks += $Item
                            }
                            Else {
                                Throw "InclTasks `"$value`" does not meet regex requirements."
                            }
                        }
                    }
                    Else {
                        If ($Value -match '^[a-zA-Z0-9.]+') {
                            $Struct.InclTasks = $Value 
                        }
                        Else {
                            Throw "InclTasks `"$value`" does not meet regex requirements."
                        }
                    }
                    $i++
                }
                "^(-Hid|--Hidden)$" {
                    If ($value -match "^[0-1]{1}$") {
                        $Struct.hidden = $Value
                    }
                    Else {
                        Throw "Method `"$value`" does not meet regex requirements."
                    }
                    $i++
                }
                "^(-w|--Warning)$" {
                    If (($value -match "^[\d]+$") -and ([int]$value -lt 100)) {
                        $Struct.WarningTreshold = $value
                    } 
                    Else {
                        Throw "Warning treshold should be numeric and less than 100. Value given is $value."
                    }
                    $i++
                }
                "^(-c|--Critical)$" {
                    If (($value -match "^[\d]+$") -and ([int]$value -lt 100)) {
                        $Struct.CriticalTreshold = $value
                    } 
                    Else {
                        Throw "Critical treshold should be numeric and less than 100. Value given is $value."
                    }
                    $i++
                 }
                "^(-h|--Help)$" {
                    Write-Help
                }
                "^(-a|--AlertOnDisabled)$" {
                    $Struct.AlertOnDisabled = $True
                }
                default {
                    throw "Illegal arguments detected: $_"
                 }
            }
        }
    } 
    Catch {
        Write-Host "CRITICAL: Argument: $CurrentArg Value: $Value Error: $_"
        Exit 2
    }
}
Function Test-Strings {
    Param ( [Parameter(Mandatory=$True)][string]$String )
    $BadChars=@("``", '|', ';', "`n")
    $BadChars | ForEach-Object {
        If ( $String.Contains("$_") ) {
            Write-Host "Error: String `"$String`" contains illegal characters."
            Exit $Struct.ExitCode
        }
    }
    Return $true
} 
Function Get-AllTaskSubFolders {
    If ($Struct.ExclFolders){
        If(!(Compare-Array $Struct.FolderRef.Name $Struct.ExclFolders)){
            $Struct.AllValidFolders+=$Struct.FolderRef	         
        }
    }
    Else {
        $Struct.AllValidFolders+=$Struct.FolderRef
    }
    If(($folders = $Struct.FolderRef.getfolders(1)).count -ge 1) {
        ForEach ($folder in $folders) {
            If ($Struct.ExclFolders -notcontains $folder.Name) {   
                If(($folder.getfolders(1).count -ge 1)) {
                    $Struct.FolderRef=$folder
                    Get-AllTaskSubFolders
                }
                Else {
                    $Struct.AllValidFolders+=$folder
                }
            }
        }
        Return
    }
}
Function Find-InclFolders {
    $TempValidFolders = $Struct.AllValidFolders
    $Struct.AllValidFolders = @()
    ForEach ($folder in $TempValidFolders) {
        If (Compare-Array $Folder.Name $Struct.InclFolders){
            $Struct.AllValidFolders += $Folder	
        }
    }
}
Function Compare-Array  {
    Param(
        [System.String]$str,
        [System.String[]]$patterns
         )
    ForEach($pattern in $patterns) { 
        If($str -match $pattern) {
            Return $true; 
        } 
    }
    Return $false;
}
Function Write-Help {
    Write-Host @"
check_ms_win_tasks.ps1: This script is designed to check Windows 2008 or higher scheduled tasks and alert in case tasks
    failed in Nagios style output.
Arguments:
    -H   | --Hostname        => Optional hostname of remote system, default is localhost, not yet tested on remote host.
    -EF  | --ExclFolders     => Name of folders to exclude from monitoring.
    -IF  | --InclFolders     => Name of folders to include in monitoring.
    -ET  | --ExclTasks       => Name of task patterns to exclude from monitoring.
    -IT  | --InclTasks       => Name of task patterns to include in monitoring.
    -Hid | --Hidden          => Switch to determine if hidden tasks need to be excluded.
    -a   | --AlertOnDisabled => If any tasks are disabled, throw a CRITICAL alert.
    -w   | --Warning         => Threshold for warning alert. (not yet implemented)
    -c   | --Critical        => Threshold for critical alert. (not yet implemented)
    -h   | --Help            => Print this help output.
"@
    Exit $Struct.ExitCode;
} 
Function Search-Tasks { 
    Try {
        $schedule = New-Object -com('Schedule.Service') 
    } 
    Catch {
        Write-Host "Error: Schedule.Service COM Object not found on $($Struct.Hostname), which is required by this script."
        Exit 2
    } 
    $Schedule.connect($Struct.Hostname) 
    $Struct.FolderRef = $Schedule.getfolder('\')
    Get-AllTaskSubFolders
    If ($Struct.InclFolders){
        Find-InclFolders
    }
    $BadTasks = @()
    $GoodTasks = @()
    $RunningTasks = @()
    $DisabledTasks = @()
    $OutputString = ''
    ForEach ($Folder in $Struct.AllValidFolders) {
        If (($Tasks = $Folder.GetTasks($Struct.Hidden))) {
            $Tasks | Foreach-Object { 
                $ObjTask = New-Object -TypeName PSCustomObject -Property @{
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
                If ( $ObjTask.LastTaskResult -eq '0'-or $ObjTask.LastTaskResult -eq '0x00041325' -and $ObjTask.Enabled ) {
                    If ( ! $Struct.InclTasks ) {
                        If ( ! ( Compare-Array $ObjTask.Name $Struct.ExclTasks ) ) {
                            $GoodTasks += $ObjTask
                            $Struct.TasksOk += 1
                        }
                    }
                    Else {
                        If ( Compare-Array $ObjTask.Name $Struct.InclTasks ) {
                            $GoodTasks += $ObjTask
                            $Struct.TasksOk += 1
                        }
                    }
                }
                ElseIf ( $ObjTask.LastTaskResult -eq '0x00041301' -and $ObjTask.Enabled ) {
                    If ( ! $Struct.InclTasks ) {
                        If ( ! ( Compare-Array $ObjTask.Name $Struct.ExclTasks ) ) {
                            $RunningTasks += $ObjTask
                            $Struct.TasksRunning += 1
                        }
                    }
                    Else {
                        If ( Compare-Array $ObjTask.Name $Struct.InclTasks ) {
                            $RunningTasks += $ObjTask
                            $Struct.TasksRunning += 1
                        }
                    }
                }
                ElseIf ( $ObjTask.Enabled ) {
                    If ( ! $Struct.InclTasks ) {
                        If ( ! ( Compare-Array $ObjTask.Name $Struct.ExclTasks ) ) {
                            $BadTasks += $ObjTask
                            $Struct.TasksNotOk += 1
                        }
                    }
                    Else {
                        If ( Compare-Array $ObjTask.Name $Struct.InclTasks ) {
                            $BadTasks += $ObjTask
                            $Struct.TasksNotOk += 1
                        }
                    }
                }
                Else {
                    If ( ! $Struct.InclTasks ) {
                        If ( ! ( Compare-Array $ObjTask.Name $Struct.ExclTasks ) ) {
                            $DisabledTasks += $ObjTask
                            $Struct.TasksDisabled += 1
                        }
                    }
                    Else {
                        If ( Compare-Array $ObjTask.Name $Struct.InclTasks ) {
                            $DisabledTasks += $ObjTask
                            $Struct.TasksDisabled += 1
                        }
                    }
                }
            }
        }
    } 
    $Struct.TasksTotal = $Struct.TasksOk + $Struct.TasksNotOk + $Struct.TasksRunning
    If ( $Struct.TasksNotOk -gt '0' ) {
        $OutputString += "$($Struct.TasksNotOk) / $($Struct.TasksTotal) tasks failed! "
        ForEach ($BadTask in $BadTasks) {
            $OutputString += "{Taskname: `"$($BadTask.Name)`" (Author: $($BadTask.Author))(Exitcode: $($BadTask.lasttaskresult))(Last runtime: $($BadTask.lastruntime))} "
        }
        If ( $Struct.TasksRunning -gt '0' ) {
            $OutputString += "$($Struct.TasksRunning) / $($Struct.TasksTotal) tasks still running! "
            ForEach ( $RunningTask in $RunningTasks ) {
                $OutputString += "{Taskname: `"$($RunningTask.Name)`" (Author: $($RunningTask.Author))(Exitcode: $($RunningTask.lasttaskresult))(Last runtime: $($RunningTask.lastruntime))} "
            }
        }
        If (( $Struct.AlertOnDisabled -eq $True ) -and ( $Struct.TasksDisabled -gt 0 )) {
            $OutputString += "$($Struct.TasksDisabled) / $($Struct.TasksTotal) tasks disabled! "
            ForEach ( $DisabledTask in $DisabledTasks ) {
                $OutputString += "{Taskname: `"$($DisabledTask.Name)`" (Author: $($DisabledTask.Author))(Last runtime: $($DisabledTask.lastruntime))} "
            }
        }
        $OutputString +=  " | 'Total Tasks'=$($Struct.TasksTotal) 'OK Tasks'=$($Struct.TasksOk);;;0;$($Struct.TasksTotal) 'Failed Tasks'=$($Struct.TasksNotOk);;;0;$($Struct.TasksTotal) 'Running Tasks'=$($Struct.TasksRunning);;;0;$($Struct.TasksTotal) 'Disabled Tasks'=$($Struct.TasksDisabled);;;0;$($Struct.TasksTotal)"
        $Struct.ExitCode = 2
    }
    Elseif (( $Struct.AlertOnDisabled -eq $True ) -and ( $Struct.TasksDisabled -gt 0 )) {
        $OutputString += "$($Struct.TasksDisabled) / $($Struct.TasksTotal) tasks disabled! "
        ForEach ( $DisabledTask in $DisabledTasks ) {
            $OutputString += "{Taskname: `"$($DisabledTask.Name)`" (Author: $($DisabledTask.Author))(Last runtime: $($DisabledTask.lastruntime))} "
        }
        $OutputString +=  " | 'Total Tasks'=$($Struct.TasksTotal) 'OK Tasks'=$($Struct.TasksOk);;;0;$($Struct.TasksTotal) 'Failed Tasks'=$($Struct.TasksNotOk);;;0;$($Struct.TasksTotal) 'Running Tasks'=$($Struct.TasksRunning);;;0;$($Struct.TasksTotal) 'Disabled Tasks'=$($Struct.TasksDisabled);;;0;$($Struct.TasksTotal)"
        $Struct.ExitCode = 2
    }
    Else {
        $OutputString +=  "$($Struct.TasksOk) / $($Struct.TasksTotal) tasks ran succesfully. "
        If ($Struct.TasksRunning -gt '0') {
            $OutputString += "$($Struct.TasksRunning) / $($Struct.TasksTotal) tasks still running! "
            ForEach ($RunningTask in $RunningTasks) {
                $OutputString += "{Taskname: `"$($RunningTask.Name)`" (Author: $($RunningTask.Author))(Exitcode: $($RunningTask.lasttaskresult))(Last runtime: $($RunningTask.lastruntime))} "
            }
        }
        $OutputString +=  " | 'Total Tasks'=$($Struct.TasksTotal) 'OK Tasks'=$($Struct.TasksOk);;;0;$($Struct.TasksTotal) 'Failed Tasks'=$($Struct.TasksNotOk);;;0;$($Struct.TasksTotal) 'Running Tasks'=$($Struct.TasksRunning);;;0;$($Struct.TasksTotal) 'Disabled Tasks'=$($Struct.TasksDisabled);;;0;$($Struct.TasksTotal)"
        $Struct.ExitCode = 0
    }
    Write-Host "$outputString"
    Exit $Struct.ExitCode
}
#endregion Functions

#region Main
If ( $Args ) {
    If ( ! ( $Args[0].ToString()).StartsWith("$") ) {
        If ( $Args.count -ge 1 ) {
            Initialize-Args $Args
        }
    }
    Else {
        Write-Host "CRITICAL: Seems like something is wrong with your parameters: Args: $Args."
        Exit 2
    }
}
Search-Tasks
Write-Host 'UNKNOWN: Script exited in an abnormal way. Please debug...'
Exit $Struct.ExitCode
#endregion Main