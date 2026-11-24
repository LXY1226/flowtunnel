$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $PSCommandPath + '"'
    $process = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden -PassThru -Wait
    exit $process.ExitCode
}
$hash = [Security.Cryptography.SHA256]::Create()
try { $suffix = ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($projectRoot.ToLowerInvariant())))).Replace('-','').Substring(0,12) } finally { $hash.Dispose() }
$taskName = 'FlowTunnel-LocalTest-' + $suffix
$resultsPath = Join-Path $projectRoot 'test-results\local-cpp'
$arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + (Join-Path $PSScriptRoot 'test-local.ps1') + '" -Exe "' + (Join-Path $projectRoot 'bin\flowtunnel.exe') + '" -Results "' + $resultsPath + '"'
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $arguments -WorkingDirectory $projectRoot
$principal = New-ScheduledTaskPrincipal -UserId $identity.User.Value -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Description 'Run this FlowTunnel workspace local WinDivert test on demand.' -Force | Out-Null
$scheduler = New-Object -ComObject Schedule.Service
$scheduler.Connect()
$registered = $scheduler.GetFolder('\').GetTask($taskName)
$registered.SetSecurityDescriptor('D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFXSD;;;' + $identity.User.Value + ')',0)
$statePath = Join-Path $projectRoot 'test-results\authorization'
New-Item -ItemType Directory -Path $statePath -Force | Out-Null
@{ task_name=$taskName; user_sid=$identity.User.Value; project=$projectRoot; results=$resultsPath; automatic_triggers=$false } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $statePath 'task.json') -Encoding utf8
Write-Output "Registered $taskName"
Start-ScheduledTask -TaskName $taskName
