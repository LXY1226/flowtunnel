param([Parameter(Mandatory=$true)][ValidateSet('Start','Stop','Probe','Lifetime')][string]$Action)
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
$profileRoot=Join-Path $projectRoot 'test-results\server-31828'
$authorization=Get-Content -LiteralPath (Join-Path $projectRoot 'test-results\authorization\task.json') -Raw | ConvertFrom-Json
$taskName=$authorization.task_name.Replace('LocalTest','Server31828')
$readyPath=Join-Path $profileRoot 'ready.json'
if ($Action -eq 'Start') {
    $existing=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existing -and $existing.State -eq 'Running') { Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json; return }
    $arguments='-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "'+(Join-Path $PSScriptRoot 'server-31828.ps1')+'"'
    $taskAction=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $arguments -WorkingDirectory $projectRoot
    $principal=New-ScheduledTaskPrincipal -UserId $authorization.user_sid -LogonType Interactive -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $taskAction -Principal $principal -Settings $settings -Description 'Run the FlowTunnel test server on TCP 31828 until stopped.' -Force | Out-Null
    $scheduler=New-Object -ComObject Schedule.Service
    $scheduler.Connect()
    $scheduler.GetFolder('\').GetTask($taskName).SetSecurityDescriptor('D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFXSD;;;'+$authorization.user_sid+')',0)
    $started=Get-Date
    Start-ScheduledTask -TaskName $taskName
    $deadline=$started.AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        if ((Test-Path -LiteralPath $readyPath) -and (Get-Item -LiteralPath $readyPath).LastWriteTime -ge $started) {
            $ready=Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json
            if (-not $ready.success) { throw $ready.error }
            $ready
            return
        }
        Start-Sleep -Milliseconds 200
    }
    throw 'Server did not report ready within 30 seconds'
}
if ($Action -eq 'Stop') {
    (Get-Date).ToString('o') | Set-Content -LiteralPath (Join-Path $profileRoot 'stop.request') -Encoding ascii
    $deadline=(Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline) {
        if ((Get-ScheduledTask -TaskName $taskName).State -ne 'Running') { @{stopped=$true;task=$taskName};return }
        Start-Sleep -Milliseconds 200
    }
    throw 'Server did not stop gracefully'
}
if ($Action -eq 'Probe') {
    & python -u (Join-Path $projectRoot 'tests\probe-running-server.py') --exe (Join-Path $projectRoot 'bin\flowtunnel.exe') --profile $profileRoot | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Running-server probe failed' }
    Get-Content -LiteralPath (Join-Path $profileRoot 'local-probe.json') -Raw | ConvertFrom-Json
}
if ($Action -eq 'Lifetime') {
    $lifetimeTaskName=$authorization.task_name.Replace('LocalTest','UdpLifetime')
    $existing=Get-ScheduledTask -TaskName $lifetimeTaskName -ErrorAction SilentlyContinue
    if ($existing -and $existing.State -eq 'Running') { throw 'The UDP lifetime test is already running' }
    . (Join-Path $PSScriptRoot 'client-process.ps1')
    $clients=@(Get-FlowTunnelClientProcess)
    try {
        if ($clients.Count) { throw "Stop the existing local client before testing: $($clients.Id -join ', ')" }
    } finally {
        foreach ($client in $clients) { $client.Process.Dispose() }
    }
    $resultRoot=Join-Path $projectRoot 'test-results\udp-lifetime'
    New-Item -ItemType Directory -Path $resultRoot -Force | Out-Null
    $arguments='-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "'+(Join-Path $PSScriptRoot 'test-udp-lifetime.ps1')+'"'
    $taskAction=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $arguments -WorkingDirectory $projectRoot
    $principal=New-ScheduledTaskPrincipal -UserId $authorization.user_sid -LogonType Interactive -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 20) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $lifetimeTaskName -Action $taskAction -Principal $principal -Settings $settings -Description 'Run the fixed FlowTunnel UDP lifetime regression test on demand.' -Force | Out-Null
    $scheduler=New-Object -ComObject Schedule.Service
    $scheduler.Connect()
    $scheduler.GetFolder('\').GetTask($lifetimeTaskName).SetSecurityDescriptor('D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFXSD;;;'+$authorization.user_sid+')',0)
    $started=Get-Date
    Start-ScheduledTask -TaskName $lifetimeTaskName
    $progressPath=Join-Path $resultRoot 'progress.json'
    $deadline=$started.AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        if ((Test-Path -LiteralPath $progressPath) -and (Get-Item -LiteralPath $progressPath).LastWriteTime -ge $started) {
            @{task=$lifetimeTaskName;results=$resultRoot;execution_limit_minutes=20;progress=(Get-Content -LiteralPath $progressPath -Raw | ConvertFrom-Json)}
            return
        }
        Start-Sleep -Milliseconds 200
    }
    throw 'UDP lifetime test did not report progress within 30 seconds'
}
