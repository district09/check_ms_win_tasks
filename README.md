# Nagios plugin to check Microsoft Windows 2008 or higher scheduled tasks

### Idea

Checks Microsoft Windows scheduled tasks excluding defined folders and defined task patterns, returning state of  
tasks with name, author, exit code and performance data to Nagios.

### Status

Production ready. After using this plugin for almost a year now, I can confirm it is working as expected on Windows  
2008 and Windows 2008 R2.

### How To

1) Put the script in the NSCP scripts folder  
2) In the nsclient.ini configuration file, define the script like this:  
	check_ms_win_tasks=cmd /c echo scripts\check_ms_win_tasks.ps1 $ARG1$ $ARG2$ $ARG3$; exit $LastExitCode | powershell.exe -command -  
3) Make a command in Nagios like this:  
	check_ms_win_tasks => $USER1$/check_nrpe -H $HOSTADDRESS$ -p 5666 -t 60 -c check_ms_win_tasks -a $ARG1$ $ARG2$ $ARG3$  
4) Configure your service in Nagios:  
	- Make use of the above created command  
	- Parameter 1 should be 'localhost' (did not test with remoting)  
	- Parameter 2 should be an array of folders to exclude, example 'Microsoft, Backup'  
	- Parameter 3 should be an array of task patterns to exclude, example 'Jeff,"Copy Test"'  
	- All single quotes need to be included (In Nagios XI)  
	- Array values with spaces need double quotes (see above example)  
	- Parameters are no longer mandatory. If not used, default values in TaskStruct will be used.  

### Help

This script works perfect in our environment on Windows 2008 and Windows 2008 R2 servers for more than a year now.   
If you do happen to find a bug, please create an issue on GitHub. Please include console's output and reproduction   
step in your bug report.The script is highly adaptable if you want different output etc. I've been asked a few times  
to make it multilingual, as obviously this script will only work on English Windows 2008 or higher servers, but as   
I do not have non-English servers at my disposal, I'm not going to implement any other languages.  

### On Nagios Exchange

http://exchange.nagios.org/directory/Plugins/Operating-Systems/Windows/NRPE/Check-Windows-2008-or-Higher-Scheduled-Tasks/details

### History

03/02/2014 => Add array as argument with excluded folders  
15/02/2014 => Add array as argument with excluded task patterns  
03/03/2014 => Added perfdata and edited output  
09/03/2014 => Added running tasks information and perfdata  
22/03/2014 => Resolved a bug with output treated as perfdata  
23/03/2014 => Created repository on Github and updated documentation  
11/04/2014 => New output format with outputstring to be able to see failed tasks in service history  
11/04/2014 => Added [int] to prevent decimal numbers  
24/04/2014 => Used ' -> ' to split failed and running tasks  
05/05/2014 => Test script fro better handling and checking of parameters, does not work yet...  
18/08/2014 => Made parameters non mandatory, working with TaskStruct object  
20/08/2014 => Solved bugs with -h or --help not displaying help and cleaned up some code  
08/09/2014 => Cleaned code and updated documentation  

### Copyright:
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public  
License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later  
version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the  
implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more  
details at <http://www.gnu.org/licenses/>.
