$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
$profileRoot=Join-Path $projectRoot 'test-results\server-31828'
$exe=Join-Path $projectRoot 'bin\flowtunnel.exe'
$config=Join-Path $profileRoot 'server.toml'
$readyPath=Join-Path $profileRoot 'ready.json'
$stopPath=Join-Path $profileRoot 'stop.request'
$authorization=Get-Content -LiteralPath (Join-Path $projectRoot 'test-results\authorization\task.json') -Raw | ConvertFrom-Json
$ruleName=$authorization.task_name.Replace('LocalTest','Inbound31828')
$processes=@()
$started=Get-Date
$createdRule=$false
try {
    & $exe check $config
    if ($LASTEXITCODE -ne 0) { throw 'Server configuration is invalid' }
    if (-not (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name $ruleName -DisplayName 'FlowTunnel TCP 31828 test server' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 31828 -Program $exe -Profile Any | Out-Null
        $createdRule=$true
    }
    $fixtureArgs='-u "'+(Join-Path $projectRoot 'tests\server_fixture.py')+'"'
    $fixture=Start-Process -FilePath (Get-Command python).Source -ArgumentList $fixtureArgs -WorkingDirectory $projectRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $profileRoot 'fixture.log') -RedirectStandardError (Join-Path $profileRoot 'fixture.err.log') -PassThru
    $processes+=$fixture
    $server=Start-Process -FilePath $exe -ArgumentList @('run',('"'+$config+'"')) -WorkingDirectory (Split-Path -Parent $exe) -WindowStyle Hidden -RedirectStandardOutput (Join-Path $profileRoot 'server.log') -RedirectStandardError (Join-Path $profileRoot 'server.err.log') -PassThru
    $processes+=$server
    $deadline=(Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
        if ($server.HasExited -or $fixture.HasExited) { throw 'Server or fixture exited before ready; inspect logs' }
        $serverLog=Get-Content -LiteralPath (Join-Path $profileRoot 'server.log') -Raw -ErrorAction SilentlyContinue
        $fixtureLog=Get-Content -LiteralPath (Join-Path $profileRoot 'fixture.log') -Raw -ErrorAction SilentlyContinue
        if ($serverLog -match 'server ready' -and $fixtureLog -match 'fixture ready') { break }
        Start-Sleep -Milliseconds 200
    }
    if ($serverLog -notmatch 'server ready' -or $fixtureLog -notmatch 'fixture ready') { throw 'Server startup timeout' }
    @{success=$true;listen='0.0.0.0:31828';core_pid=$server.Id;fixture_pid=$fixture.Id;http_port=18082;udp_port=18083;tcp_echo_port=18084;started=$started.ToString('o');firewall_rule=$ruleName} | ConvertTo-Json | Set-Content -LiteralPath $readyPath -Encoding utf8
    while (-not $server.HasExited -and -not $fixture.HasExited) {
        if ((Test-Path -LiteralPath $stopPath) -and (Get-Item -LiteralPath $stopPath).LastWriteTime -ge $started) { break }
        Start-Sleep -Milliseconds 300
    }
} catch {
    @{success=$false;error=$_.Exception.Message} | ConvertTo-Json | Set-Content -LiteralPath $readyPath -Encoding utf8
    throw
} finally {
    if ($server -and -not $server.HasExited) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class FlowTunnelShutdown {
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern IntPtr OpenEvent(uint access,bool inherit,string name);
    [DllImport("kernel32.dll")] public static extern bool SetEvent(IntPtr handle);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
}
'@
        $eventHandle=[FlowTunnelShutdown]::OpenEvent(2,$false,('Local\FlowTunnel.Stop.'+$server.Id))
        if ($eventHandle -ne [IntPtr]::Zero) { [FlowTunnelShutdown]::SetEvent($eventHandle) | Out-Null;[FlowTunnelShutdown]::CloseHandle($eventHandle) | Out-Null;$server.WaitForExit(5000) | Out-Null }
    }
    foreach ($process in $processes) { if (-not $process.HasExited) { $process.Kill();$process.WaitForExit(5000) | Out-Null } }
    if ($createdRule) { Remove-NetFirewallRule -Name $ruleName }
}
