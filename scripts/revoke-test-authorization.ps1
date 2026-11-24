$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$state = Get-Content -LiteralPath (Join-Path $projectRoot 'test-results\authorization\task.json') -Raw | ConvertFrom-Json
if ($state.project -ne $projectRoot) { throw 'Authorization belongs to another workspace' }
$lifetimeTaskName=$state.task_name.Replace('LocalTest','UdpLifetime')
if (Get-ScheduledTask -TaskName $lifetimeTaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $lifetimeTaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $lifetimeTaskName -Confirm:$false
}
$serverTaskName=$state.task_name.Replace('LocalTest','Server31828')
$serverTask=Get-ScheduledTask -TaskName $serverTaskName -ErrorAction SilentlyContinue
if ($serverTask) {
    if ($serverTask.State -eq 'Running') { & (Join-Path $PSScriptRoot 'server-control.ps1') -Action Stop }
    Unregister-ScheduledTask -TaskName $serverTaskName -Confirm:$false
}
Stop-ScheduledTask -TaskName $state.task_name -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $state.task_name -Confirm:$false
Write-Output "Removed $($state.task_name)"
