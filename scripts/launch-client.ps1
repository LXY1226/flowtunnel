$ErrorActionPreference = 'Stop'
$clientRoot = $PSScriptRoot
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '"'
    Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $arguments -Verb RunAs -WorkingDirectory $clientRoot -WindowStyle Normal -Wait
    exit
}
. (Join-Path $clientRoot 'client-process.ps1')
$exe = [IO.Path]::GetFullPath((Join-Path $clientRoot 'flowtunnel.exe'))
$config = [IO.Path]::GetFullPath((Join-Path $clientRoot 'client.toml'))
& $exe check $config
if ($LASTEXITCODE -ne 0) { throw 'Client configuration is invalid' }
if ((Get-Content -LiteralPath $config -Raw -Encoding UTF8) -notmatch '(?m)^[ \t]*mode[ \t]*=[ \t]*"client"[ \t]*(?:#[^\r\n]*)?\r?$') { throw 'Client launcher requires mode = "client"' }

$mutex = [Threading.Mutex]::new($false, 'Global\FlowTunnel.Client.Startup')
$held = $false
$clients = @()
$child = $null
$ruleName = $null
$ruleCreated = $false
try {
    try { $null = $mutex.WaitOne(); $held = $true }
    catch [Threading.AbandonedMutexException] { $held = $true }
    $clients = @(Get-FlowTunnelClientProcess)
    if ($clients.Count) {
        Write-Host 'A FlowTunnel client is already running:'
        $clients | Select-Object Id, ExecutablePath, ConfigPath | Format-Table -AutoSize | Out-Host
        $answer = Read-Host 'Stop the listed client(s) and start this version? [y/N]'
        if ($answer -cne 'y' -and $answer -cne 'Y') { return }
        foreach ($client in $clients) { Stop-FlowTunnelClientProcess -Client $client }
    }
    $rules = @(Get-NetFirewallRule -Name 'FlowTunnel-VirtualPeer-Client*' -ErrorAction SilentlyContinue)
    Remove-FlowTunnelClientFirewallRules -Rules $rules -Clients $clients
    $ruleName = 'FlowTunnel-VirtualPeer-Client-' + [Guid]::NewGuid().ToString('N')
    New-NetFirewallRule -Name $ruleName -DisplayName 'FlowTunnel virtual peer client' -Direction Inbound -Action Allow -Protocol TCP -RemoteAddress 10.200.0.1 -Program $exe -Profile Any | Out-Null
    $ruleCreated = $true
    $child = Start-Process -FilePath $exe -ArgumentList ('run "' + $config + '"') -WorkingDirectory $clientRoot -NoNewWindow -PassThru
    $null = $child.Handle
    $mutex.ReleaseMutex()
    $held = $false
    $child.WaitForExit()
    if ($child.ExitCode -ne 0) { Write-Warning "Client exited with code $($child.ExitCode)" }
} finally {
    if ($held) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
    foreach ($client in $clients) { $client.Process.Dispose() }
    if ($ruleCreated) { Remove-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue }
    if ($child) { $child.Dispose() }
}
Read-Host 'Client stopped. Press Enter to close'
