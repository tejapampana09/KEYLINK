# KeyLink Companion Task Scheduler Authoritative Registration Script
# Registers the KeyLinkCompanion task to run at user logon with full interactive permissions.

$TaskName = "KeyLinkCompanion"
$PythonExe = "C:\Users\ss\AppData\Local\Programs\Python\Python310\python.exe"
$ScriptPath = "C:\Users\ss\Desktop\project college\keylink\windows\companion\companion.py"
$WorkDir = "C:\Users\ss\Desktop\project college\keylink\windows\companion"
$Username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

Write-Host "Registering Task Scheduler Task '$TaskName' for user '$Username'..."

# Unregister existing task if present
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

# Trigger: At user logon with 30-second delay for Windows Bluetooth Stack initialization
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $Username
$Trigger.Delay = "PT30S"

# Action: Launch Python with --autostart
$Action = New-ScheduledTaskAction -Execute $PythonExe -Argument """$ScriptPath"" --autostart" -WorkingDirectory $WorkDir

# Settings: Allow on demand, restart on failure, run only when user is logged on
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 0) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

# Register the Scheduled Task
Register-ScheduledTask -TaskName $TaskName -Trigger $Trigger -Action $Action -Settings $Settings -User $Username

Write-Host "Task '$TaskName' successfully registered!"
