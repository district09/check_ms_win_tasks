# Script name:  check_ms_win_tasks.ps1
# Version:      v7.04.190321
# Created on:   01/02/2014
# Author:       Willem D'Haese
# Purpose:      Checks Microsoft Windows enabled scheduled tasks excluding defined folders and task patterns, returning state of tasks
#               with name, author, exit code and performance data to Nagios.
# On Github:    https://github.com/willemdh/check_ms_win_tasks
# On OutsideIT: https://outsideit.net/check-ms-win-tasks
# Copyright:
#   This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published
#   by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. This program is distributed 
#   in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 
#   PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU General Public 
#   License along with this program.  If not, see <http://www.gnu.org/licenses/>.

#Requires -Version 2.0

$DebugPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'

$Struct = New-Object -TypeName PSObject -Property @{
  Hostname = [string]'localhost'
  ExclFolders = [string[]]@()
  InclFolders = [string[]]@()
  ExclTasks = [string[]]@()
  InclTasks = [string[]]@()
  ExclAuthors = [string[]]@()
  InclAuthors = [string[]]@()
  FolderRef = [string]''
  AllValidFolders = [string[]]@()
  ExitCode = [int]3
  Hidden = [int]0
  TasksOk = [int]0
  TasksNotOk = [int]0
  TasksRunning = [int]0
  TasksTotal = [int]0
  TasksDisabled = [int]0
  BadTasks = [object[]]@()
  RunningTasks = [object[]]@()
  DisabledTasks = [object[]]@()
  AlertOnDisabled = [bool]$False
  FullPath = [bool]$False
  OutputString = [string]'Unknown: Error processing, no data returned.'
  WarningTreshold =  [int]0
  CriticalTreshold = [int]0
  LastExec = [bool]$false                    
}

#region Functions
Function Write-Log {
  Param (
    [parameter(Mandatory=$True,HelpMessage='Log output')][string]$Log,
    [parameter(Mandatory=$True,HelpMessage='Log severity')][ValidateSet('Debug', 'Info', 'Warning', 'Error', 'Unknown')][string]$Severity,
    [parameter(Mandatory=$True,HelpMessage='Log message')][string]$Message
  )
  $Now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss,fff'
  $LocalScriptName = Split-Path -Path $myInvocation.ScriptName -Leaf
  If ( $Log -eq 'Verbose' ) {
    Write-Verbose -Message ('{0}: {1}: {2}: {3}' -f $Now, $LocalScriptName, $Severity, $Message)
  }
  ElseIf ( $Log -eq 'Debug' ) {
    Write-Debug -Message ('{0}: {1}: {2}: {3}' -f $Now, $LocalScriptName, $Severity, $Message)
  }
  ElseIf ( $Log -eq 'Output' ) {
    Write-Host ('{0}: {1}: {2}: {3}' -f $Now, $LocalScriptName, $Severity, $Message)
  }
  ElseIf ( $Log -match '^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])(?::(?<port>\d+))$' -or $Log -match '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$' ) {
    $IpOrHost = $log.Split(':')[0]
    $Port = $log.Split(':')[1]
    If ( $IpOrHost -match '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$' ) {
      $Ip = $IpOrHost
    }
    Else {
      $Ip = [Net.Dns]::GetHostAddresses($IpOrHost)[0].IPAddressToString
    }
    Try {
      $LocalHostname = ([Net.Dns]::GetHostByName((& "$env:windir\system32\hostname.exe")).HostName).tolower()
      $JsonObject = (New-Object -TypeName PSObject | 
        Add-Member -PassThru -NotePropertyName NoteProperty -NotePropertyValue logsource -InputObject $LocalHostname | 
        Add-Member -PassThru -NotePropertyName NoteProperty -NotePropertyValue hostname -InputObject $LocalHostname | 
        Add-Member -PassThru -NotePropertyName NoteProperty -NotePropertyValue scriptname -InputObject $LocalScriptName | 
        Add-Member -PassThru -NotePropertyName NoteProperty -NotePropertyValue logtime -InputObject $Now | 
        Add-Member -PassThru -NotePropertyName NoteProperty -NotePropertyValue severity_label -InputObject $Severity | 
        Add-Member -PassThru -NotePropertyName NoteProperty -NotePropertyValue message -InputObject $Message ) 
      If ( $psversiontable.psversion.major -ge 3 ) {
        $JsonString = $JsonObject | ConvertTo-Json
        $JsonString = $JsonString -replace "`n",' ' -replace "`r",' '
      }
      Else {
        $JsonString = $JsonObject | ConvertTo-Json2
      }               
      $Socket = New-Object -TypeName System.Net.Sockets.TCPClient -ArgumentList ($Ip,$Port) 
      $Stream = $Socket.GetStream() 
      $Writer = New-Object -TypeName System.IO.StreamWriter -ArgumentList ($Stream)
      $Writer.WriteLine($JsonString)
      $Writer.Flush()
      $Stream.Close()
      $Socket.Close()
    }
    Catch {
      Write-Host ("{0}: {1}: Error: Something went wrong while trying to send message to logserver `"{2}`"." -f $Now, $LocalScriptName, $Log)
    }
    Write-Verbose -Message ('{0}: {1}: {2}: Ip: {3} Port: {4} JsonString: {5}' -f $Now, $LocalScriptName, $Severity, $Ip, $Port, $JsonString)
  }
  ElseIf ($Log -match '^((([a-zA-Z]:)|(\\{2}\w+)|(\\{2}(?:(?:25[0-5]|2[0-4]\d|[01]\d\d|\d?\d)(?(?=\.?\d)\.)){4}))(\\(\w[\w ]*))*)') {
    If (Test-Path -Path $Log -pathType container){
      Write-Host ('{0}: {1}: Error: Passed Path is a directory. Please provide a file.' -f $Now, $LocalScriptName)
      Exit 1
    }
    ElseIf (!(Test-Path -Path $Log)) {
      Try {
        $Null = New-Item -Path $Log -ItemType file -Force	
      } 
      Catch { 
        $Now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss,fff'
        Write-Host ("{0}: {1}: Error: Write-Log was unable to find or create the path `"{2}`". Please debug.." -f $Now, $LocalScriptName, $Log)
        exit 1
      }
    }
    Try {
      ('{0}: {1}: {2}: {3}' -f $Now, $LocalScriptName, $Severity, $Message) | Out-File -filepath $Log -Append   
    }
    Catch {
      Write-Host ("{0}: {1}: Error: Something went wrong while writing to file `"{2}`". It might be locked." -f $Now, $LocalScriptName, $Log)
    }
  }
}

Function Initialize-Args {
  Param ( 
    [Parameter(Mandatory=$True,HelpMessage='Argument list')]$Args
  )
  Try {
    For ( $i = 0; $i -lt $Args.count; $i++ ) { 
      $CurrentArg = $Args[$i].ToString()
      If ($i -lt $Args.Count-1) {
        $Value = $Args[$i+1];
        If ($Value.Count -ge 2) {
          ForEach ($Item in $Value) {
            $Null = Test-Strings -String $Item
          }
        }
        Else {
          $Value = $Args[$i+1];
          $Null = Test-Strings -String $Value
        }
      } 
      Else {
        $Value = ''
      }
      Switch -regex -casesensitive ($CurrentArg) {
        '^(-H|--Hostname)$' {
          If ($value -match '^[a-zA-Z.]+') {
            If ($Value -ne ([Net.Dns]::GetHostByName((& "$env:windir\system32\hostname.exe")).HostName).tolower() -and $Value -ne 'localhost') {
              $Null = & "$env:windir\system32\ping.exe" -n 1 $Value
              If($? -eq $true) {
                $Struct.Hostname = $Value
                $i++
              }
              Else {
                Throw ('Ping to {0} failed! Please provide valid reachable hostname.' -f $Value)
              }
            }
            Else {
              $Struct.Hostname = $Value
              $i++
            }
          }
          Else {
            Throw ("Hostname `"{0}`" does not meet regex requirements." -f $value)
          }
        }
        '^(-EF|--ExclFolders)$' {
          If ($Value.Count -ge 2) {
            ForEach ($Item in $Value) {
              If ($Item -match '^[a-zA-Z0-9\\.]+') {
                $Struct.ExclFolders += $Item
              }
              Else {
                Throw ("ExclFolders `"{0}`" does not meet regex requirements." -f $Value)
              }
            }
          }
          Else {
            If ($Value -match '^[a-zA-Z0-9\\.]+') {
              $Struct.ExclFolders = $Value 
            }
            Else {
              Throw ("ExclFolders `"{0}`" does not meet regex requirements." -f $value)
            }
          }
          $i++
        }
        '^(-IF|--InclFolders)$' {
          If ($Value.Count -ge 2) {
            ForEach ($Item in $Value) {
              If ($Item -match '^[a-zA-Z0-9\\.]+') {
                $Struct.InclFolders += $Item
              }
              Else {
                Throw ("InclFolders `"{0}`" does not meet regex requirements." -f $value)
              }
            }
          }
          Else {
            If ($Value -match '^[a-zA-Z0-9\\.]+') {
              $Struct.InclFolders = $Value 
            }
            Else {
              Throw ("InclFolders `"{0}`" does not meet regex requirements." -f $value)
            }
          }
          $i++
        }
        '^(-ET|--ExclTasks)$' {
          If ($Value.Count -ge 2) {
            ForEach ($Item in $Value) {
              If ($Item -match '^[a-zA-Z0-9.]+') {
                $Struct.ExclTasks += $Item
              }
              Else {
                Throw ("ExclTasks `"{0}`" does not meet regex requirements." -f $value)
              }
            }
          }
          Else {
            If ($Value -match '^[a-zA-Z0-9.]+') {
              $Struct.ExclTasks = $Value 
            }
            Else {
              Throw ("ExclTasks `"{0}`" does not meet regex requirements." -f $value)
            }
          }
          $i++
        }
        '^(-IT|--IncllTasks)$' {
          If ($Value.Count -ge 2) {
            ForEach ($Item in $Value) {
              If ($Item -match '^[a-zA-Z0-9.]+') {
                $Struct.InclTasks += $Item
              }
              Else {
                Throw ("InclTasks `"{0}`" does not meet regex requirements." -f $value)
              }
            }
          }
          Else {
            If ($Value -match '^[a-zA-Z0-9.]+') {
              $Struct.InclTasks = $Value 
            }
            Else {
              Throw ("InclTasks `"{0}`" does not meet regex requirements." -f $value)
            }
          }
          $i++
        }
        '^(-EA|--ExclAuthors)$' {
          If ($Value.Count -ge 2) {
            ForEach ($Item in $Value) {
                $Struct.ExclAuthors += $Item
            }
          }
          Else {
            $Struct.ExclAuthors = $Value 
          }
          $i++
        }
        '^(-IA|--InclAuthors)$' {
          If ($Value.Count -ge 2) {
            ForEach ($Item in $Value) {
              $Struct.InclAuthors += $Item
            }
          }
          Else {
            $Struct.InclAuthors = $Value 
          }
          $i++
        }
        '^(-Hid|--Hidden)$' {
          If ($value -match '^[0-1]{1}$') {
            $Struct.hidden = $Value
          }
          Else {
            Throw ("Method `"{0}`" does not meet regex requirements." -f $value)
          }
          $i++
        }
        '^(-w|--Warning)$' {
          If (($value -match '^[\d]+$') -and ([int]$value -lt 100)) {
            $Struct.WarningTreshold = $value
          } 
          Else {
            Throw ('Warning treshold should be numeric and less than 100. Value given is {0}.' -f $value)
          }
          $i++
        }
        '^(-c|--Critical)$' {
          If (($value -match '^[\d]+$') -and ([int]$value -lt 100)) {
            $Struct.CriticalTreshold = $value
          } 
          Else {
            Throw ('Critical treshold should be numeric and less than 100. Value given is {0}.' -f $value)
          }
          $i++
        }
        '^(-AD|--AlertOnDisabled)$' {
          $Struct.AlertOnDisabled = $True
        }
        '^(-FP|--FullPath)$' {
          $Struct.FullPath = $True
        }
        '^(-h|--Help)$' {
          Write-Help
        }
        '^(-LE|--LastExec)$' {
          $Struct.LastExec = $True
        }
        default {
          Throw ('Illegal arguments detected: {0}' -f $_)
        }
      }
    }
  } 
  Catch {
    Write-Host ('CRITICAL: Argument: {0} Value: {1} Error: {2}' -f $CurrentArg, $Value, $_)
    Exit 2
  }
}

Function Test-Strings {
  Param ( [Parameter(Mandatory=$True,HelpMessage='String to check')][string]$String )
  $BadChars = @("``", '|', ';', "`n")
  $BadChars | ForEach-Object {
    If ( $String.Contains(('{0}' -f $_)) ) {
      Write-Host ("Error: String `"{0}`" contains illegal characters." -f $String)
      Exit $Struct.ExitCode
    }
  }
  Return $true
}

Function Get-AllTaskSubFolders {
  If ($Struct.ExclFolders){
    If ( ! ( Compare-Array -Str $Struct.FolderRef.Name -Patterns $Struct.ExclFolders ) ) {
      $Struct.AllValidFolders+=$Struct.FolderRef	         
    }
  }
  Else {
    $Struct.AllValidFolders+=$Struct.FolderRef
  }
  If ( ( $folders = $Struct.FolderRef.getfolders(1)).count -ge 1) {
    ForEach ( $folder in $folders ) {
      If ( $Struct.ExclFolders -notcontains $folder.Name ) {
        If ( ( $folder.getfolders(1).count -ge 1 ) ) {
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
    If (Compare-Array -Str $Folder.Name -Patterns $Struct.InclFolders){
      $Struct.AllValidFolders += $Folder	
    }
  }
}

Function Compare-Array  {
  Param(
    [Parameter(Mandatory=$True,HelpMessage='String to search')][string]$Str,
    [Parameter(Mandatory=$True,HelpMessage='Array to search')][AllowEmptyCollection()][String[]]$Patterns
  )
  ForEach ( $Pattern in $Patterns ) { 
    If ( $Str -Match $Pattern ) {
      Return $True
    } 
  }
  Return $False
}

Function Write-Help {
  Write-Host @'
check_ms_win_tasks.ps1: This script is designed to check Windows 2008 or higher scheduled tasks and alert in case tasks
  failed in Nagios style output.
Arguments:
  -H   | --Hostname        => Optional hostname of remote system, default is localhost, not yet tested on remote host.
  -EF  | --ExclFolders     => Name of folders to exclude from monitoring.
  -IF  | --InclFolders     => Name of folders to include in monitoring.
  -ET  | --ExclTasks       => Name of task patterns to exclude from monitoring.
  -IT  | --InclTasks       => Name of task patterns to include in monitoring.
  -EA  | --ExclAuthors     => Name of task author patterns to exclude from monitoring.
  -IA  | --InclAuthors      => Name of task author patterns to include in monitoring.
  -Hid | --Hidden          => Switch to determine if hidden tasks need to be excluded.
  -a   | --AlertOnDisabled => If any tasks are disabled, throw a CRITICAL alert.
  -FP  | --FullPath        => Displays full path in plugin output
  -w   | --Warning         => Threshold for warning alert. (not yet implemented)
  -c   | --Critical        => Threshold for critical alert. (not yet implemented)
  -h   | --Help            => Print this help output.
  -LE  | --LastExec        => check if last execution is >warn or >critical in hours                                                                            
'@
  Exit $Struct.ExitCode
} 
Function Search-Tasks { 
  Try {
    $schedule = New-Object -ComObject('Schedule.Service') 
  } 
  Catch {
    Write-Host ('Error: Schedule.Service COM Object not found on {0}, which is required by this script.' -f $Struct.Hostname)
    Exit 2
  } 
  $Schedule.connect($Struct.Hostname) 
  $Struct.FolderRef = $Schedule.getfolder('\')
  Get-AllTaskSubFolders
  If ($Struct.InclFolders){
    Find-InclFolders
  }
  $OutputString = ''
  ForEach ($Folder in $Struct.AllValidFolders) {
    If (($Tasks = $Folder.GetTasks($Struct.Hidden))) {
      foreach ($Author in $Struct.ExclAuthors) {
        $Tasks = $Tasks | ? {([xml]($_.xml)).Task.RegistrationInfo.Author -notlike $Author}
      }
      if ($Struct.InclAuthors) {
        $NewTasks = @()
        foreach ($Author in $Struct.InclAuthors) {
          $newTasks += $Tasks | ? {([xml]($_.xml)).Task.RegistrationInfo.Author -like $Author}
        }
        $Tasks = $NewTasks | Select -Unique
      }
      $Tasks | Select-TaskInfo
    }
  } 
  $Struct.TasksTotal = $Struct.TasksOk + $Struct.TasksNotOk + $Struct.TasksRunning
  If ( $Struct.TasksNotOk -gt '0' ) {
    $OutputString += ('{0} / {1} tasks failed! ' -f $Struct.TasksNotOk, $Struct.TasksTotal)
    ForEach ($BadTask in $Struct.BadTasks) {
      If ( $Struct.FullPath -eq $False ) {
              $OutputString += ("{{Taskname: `"{0}`" (Author: {1})(Exitcode: {2})(Last runtime: {3})}} " -f $BadTask.Name, $BadTask.Author, $BadTask.lasttaskresult, $BadTask.lastruntime)
      }
      Else {
        $OutputString += ("{{Taskname: `"{0}`" (Author: {1})(Exitcode: {2})(Last runtime: {3})}} " -f $BadTask.Path, $BadTask.Author, $BadTask.lasttaskresult, $BadTask.lastruntime)
      }
    }
    If ( $Struct.TasksRunning -gt '0' ) {
      $OutputString += ('{0} / {1} tasks still running! ' -f $Struct.TasksRunning, $Struct.TasksTotal)
      ForEach ( $RunningTask in $Struct.RunningTasks ) {
        If ( $Struct.FullPath -eq $False ) {
          $OutputString += ("{{Taskname: `"{0}`" (Author: {1})(Exitcode: {2})(Last runtime: {3})}} " -f $RunningTask.Name, $RunningTask.Author, $RunningTask.lasttaskresult, $RunningTask.lastruntime)
        }
        Else {
          $OutputString += ("{{Taskname: `"{0}`" (Author: {1})(Exitcode: {2})(Last runtime: {3})}} " -f $RunningTask.Path, $RunningTask.Author, $RunningTask.lasttaskresult, $RunningTask.lastruntime)
        }
      }
    }
    If (( $Struct.AlertOnDisabled -eq $True ) -and ( $Struct.TasksDisabled -gt 0 )) {
      $OutputString += ('{0} / {1} tasks disabled! ' -f $Struct.TasksDisabled, $Struct.TasksTotal)
      ForEach ( $DisabledTask in $Struct.DisabledTasks ) {
        If ( $Struct.FullPath -eq $False ) {
          $OutputString += ("{{Taskname: `"{0}`" (Author: {1}))(Last runtime: {2})}} " -f $DisabledTask.Name, $DisabledTask.Author, $DisabledTask.lastruntime)
        }
        Else {
          $OutputString += ("{{Taskname: `"{0}`" (Author: {1})(Last runtime: {2})}} " -f $DisabledTask.Path, $DisabledTask.Author, $DisabledTask.lastruntime)
        }
      }
    }
    $OutputString +=  " | 'Total Tasks'=$($Struct.TasksTotal) 'OK Tasks'=$($Struct.TasksOk);;;0;$($Struct.TasksTotal) 'Failed Tasks'=$($Struct.TasksNotOk);;1;0;$($Struct.TasksTotal) 'Running Tasks'=$($Struct.TasksRunning);;;0;$($Struct.TasksTotal) 'Disabled Tasks'=$($Struct.TasksDisabled);;;0;$($Struct.TasksTotal)"
    $Struct.ExitCode = 2
  }
  Elseif (( $Struct.AlertOnDisabled -eq $True ) -and ( $Struct.TasksDisabled -gt 0 )) {
    $OutputString += ('{0} / {1} tasks disabled! ' -f $Struct.TasksDisabled, $Struct.TasksTotal)
    ForEach ( $DisabledTask in $Struct.DisabledTasks ) {
      If ( $Struct.FullPath -eq $False ) {
        $OutputString += ("{{Taskname: `"{0}`" (Author: {1}))(Last runtime: {2})}} " -f $DisabledTask.Name, $DisabledTask.Author, $RunningTask.lastruntime)
      }
      Else {
        $OutputString += ("{{Taskname: `"{0}`" (Author: {1})(Last runtime: {2})}} " -f $DisabledTask.Path, $DisabledTask.Author, $DisabledTask.lastruntime)
      }
    }
    $OutputString +=  " | 'Total Tasks'=$($Struct.TasksTotal) 'OK Tasks'=$($Struct.TasksOk);;;0;$($Struct.TasksTotal) 'Failed Tasks'=$($Struct.TasksNotOk);;1;0;$($Struct.TasksTotal) 'Running Tasks'=$($Struct.TasksRunning);;;0;$($Struct.TasksTotal) 'Disabled Tasks'=$($Struct.TasksDisabled);;;0;$($Struct.TasksTotal)"
    $Struct.ExitCode = 2
  }
  Else {
    $OutputString +=  ('{0} / {1} tasks ran successfully. ' -f $Struct.TasksOk, $Struct.TasksTotal)
    If ($Struct.TasksRunning -gt '0') {
      $OutputString += ('{0} / {1} tasks still running! ' -f $Struct.TasksRunning, $Struct.TasksTotal)
      ForEach ($RunningTask in $Struct.RunningTasks) {
        If ( $Struct.FullPath -eq $False ) {
          $OutputString += ("{{Taskname: `"{0}`" (Author: {1})(Exitcode: {2})(Last runtime: {3})}} " -f $RunningTask.Name, $RunningTask.Author, $RunningTask.lasttaskresult, $RunningTask.lastruntime)
        }
        Else {
          $OutputString += ("{{Taskname: `"{0}`" (Author: {1})(Exitcode: {2})(Last runtime: {3})}} " -f $RunningTask.Path, $RunningTask.Author, $RunningTask.lasttaskresult, $RunningTask.lastruntime)
        }
      }
    }
    $OutputString +=  " | 'Total Tasks'=$($Struct.TasksTotal) 'OK Tasks'=$($Struct.TasksOk);;;0;$($Struct.TasksTotal) 'Failed Tasks'=$($Struct.TasksNotOk);;1;0;$($Struct.TasksTotal) 'Running Tasks'=$($Struct.TasksRunning);;;0;$($Struct.TasksTotal) 'Disabled Tasks'=$($Struct.TasksDisabled);;;0;$($Struct.TasksTotal)"
    $Struct.ExitCode = 0
  }
  Write-Host ('{0}' -f $outputString)
  Exit $Struct.ExitCode
}

Function Select-TaskInfo {
  Param (
    [Parameter(Mandatory=$True,ValueFromPipeline=$True,HelpMessage='Task to process')]$InputObject
  )
  Process {
    $ObjTask = New-Object -TypeName PSCustomObject -Property @{
      'Name' = $InputObject.name
      'Path' = $InputObject.path
      'State' = $InputObject.state
      'Enabled' = $InputObject.enabled
      'LastRunTime' = $InputObject.lastruntime
      'LastTaskResult' = $InputObject.lasttaskresult
      'NumberOfMissedRuns' = $InputObject.numberofmissedruns
      'NextRunTime' = $InputObject.nextruntime
      'Author' =  ([xml]$InputObject.xml).Task.RegistrationInfo.Author
      'UserId' = ([xml]$InputObject.xml).Task.Principals.Principal.UserID
      'Description' = ([xml]$InputObject.xml).Task.RegistrationInfo.Description
      'Cmd' = ([xml]$InputObject.xml).Task.Actions.Exec.Command 
      'Params' = ([xml]$InputObject.xml).Task.Actions.Exec.Arguments
    }
    #setting up things to handle last execution for now checking unit is hour
    If ($Struct.LastExec -eq $true) {	
      $lastExecWarn = (get-date).addHours(-$Struct.WarningTreshold)
      $lastExecCrit = (get-date).addHours(-$Struct.CriticalTreshold)
    }
    #emit warning if last task execution too old
    If ( $ObjTask.LastRunTime -lt $lastExecWarn) {
      If ($ObjTask.LastRunTime -lt $lastExecCrit) {
        #write-host 'Task ' + $ObjTask.name + ' : CRITICAL'
      }
      Else {
        #write-host 'Task ' + $ObjTask.name + ' : WARNING'
      }
      If ( ! $Struct.InclTasks ) {
        If ( ! ( Compare-Array -Str $ObjTask.Name -Patterns $Struct.ExclTasks ) ) {
          $Struct.BadTasks += $ObjTask
          $Struct.TasksNotOk += 1
        }
      }
      Else {
        If ( Compare-Array -Str $ObjTask.Name -Patterns $Struct.InclTasks ) {
          $Struct.BadTasks += $ObjTask
          $Struct.TasksNotOk += 1
        }
      }
    }
    ElseIf ( $ObjTask.LastTaskResult -eq '0'-or $ObjTask.LastTaskResult -eq '0x00041325' -or $ObjTask.LastTaskResult -eq '0x00041306' -or $ObjTask.LastRunTime -lt (get-date 2000-01-01) -and $ObjTask.Enabled ) {
# 0x00041325 => The Task Scheduler service has asked the task to run
# 0x00041306 => The last run of the task was terminated by the user
      If ( ! $Struct.InclTasks ) {
        If ( ! ( Compare-Array -Str $ObjTask.Name -Patterns $Struct.ExclTasks ) ) {
          $Struct.TasksOk += 1
        }
      }
      Else {
        If ( Compare-Array -Str $ObjTask.Name -Patterns $Struct.InclTasks ) {
          $Struct.TasksOk += 1
        }
      }
    }
    ElseIf ( $ObjTask.LastTaskResult -eq '0x8004131F'-or $ObjTask.LastTaskResult -eq '0x00041301' -and $ObjTask.Enabled ) {
# 0x00041301 => The task is currently running
# 0x8004131F => An instance of this task is already running.
      If ( ! $Struct.InclTasks ) {
        If ( ! ( Compare-Array -Str $ObjTask.Name -Patterns $Struct.ExclTasks ) ) {
          $Struct.RunningTasks += $ObjTask
          $Struct.TasksRunning += 1
        }
      }
      Else {
        If ( Compare-Array -Str $ObjTask.Name -Patterns $Struct.InclTasks ) {
          $Struct.RunningTasks += $ObjTask
          $Struct.TasksRunning += 1
        }
      }
    }
    ElseIf ( $ObjTask.Enabled ) {
      If ( ! $Struct.InclTasks ) {
        If ( ! ( Compare-Array -Str $ObjTask.Name -Patterns $Struct.ExclTasks ) ) {
          $Struct.BadTasks += $ObjTask
          $Struct.TasksNotOk += 1
        }
      }
      Else {
        If ( Compare-Array -Str $ObjTask.Name -Patterns $Struct.InclTasks ) {
          $Struct.BadTasks += $ObjTask
          $Struct.TasksNotOk += 1
        }
      }
    }
    Else {
      If ( ! $Struct.InclTasks ) {
        If ( ! ( Compare-Array -Str $ObjTask.Name -Patterns $Struct.ExclTasks ) ) {
          $Struct.DisabledTasks += $ObjTask
          $Struct.TasksDisabled += 1
        }
      }
      Else {
        If ( Compare-Array -Str $ObjTask.Name -Patterns $Struct.InclTasks ) {
          $Struct.DisabledTasks += $ObjTask
          $Struct.TasksDisabled += 1
        }
      }
    }
  }
}
#endregion Functions

#region Main
If ( $Args ) {
  If ( ! ( $Args[0].ToString()).StartsWith('$') ) {
    If ( $Args.count -ge 1 ) {
      Initialize-Args -Args $Args
    }
  }
  Else {
    Write-Host ('CRITICAL: Seems like something is wrong with your parameters: Args: {0}.' -f $Args)
    Exit 2
  }
}
Search-Tasks
Write-Host 'UNKNOWN: Script exited in an abnormal way. Please debug...'
Exit $Struct.ExitCode
#endregion Main
