param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [Parameter(Mandatory = $true)][string]$ClientConfig,
    [Parameter(Mandatory = $true)][int]$BaselineClientId,
    [Parameter(Mandatory = $true)][int]$ServerId,
    [Parameter(Mandatory = $true)][string]$Results
)

$ErrorActionPreference = 'Stop'
$Exe = (Resolve-Path -LiteralPath $Exe).Path
$ClientConfig = (Resolve-Path -LiteralPath $ClientConfig).Path
$Results = [IO.Path]::GetFullPath($Results)
New-Item -ItemType Directory -Path $Results -Force | Out-Null
$testIdentity = [Guid]::NewGuid().ToString('N')
$testDirectory = Join-Path $Results ('launcher-' + $testIdentity)
$staleProgram = Join-Path $testDirectory 'flowtunnel.exe'
$staleRuleName = 'FlowTunnel-VirtualPeer-Client-Test-' + $testIdentity + '-Stale'
$liveRuleName = 'FlowTunnel-VirtualPeer-Client-Test-' + $testIdentity + '-Live'
$stdoutPath = Join-Path $Results 'launcher-child.stdout.log'
$stderrPath = Join-Path $Results 'launcher-child.stderr.log'
$resultPath = Join-Path $Results 'client-launcher-result.json'
$ownedRuleNames = [Collections.Generic.List[string]]::new()
$snapshots = [Collections.Generic.List[object]]::new()
$testProcess = $null
$testClient = $null
$result = [ordered]@{
    success = $false
    baseline_client_id = $BaselineClientId
    server_id = $ServerId
    test_client_id = $null
    cases = @()
    cleanup = @()
}

function Assert-FtTest([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Get-FtTestClients {
    $clients = @(Get-FlowTunnelClientProcess)
    foreach ($client in $clients) { $snapshots.Add($client) }
    return $clients
}

function Add-FtTestRule([string]$Name, [string]$Program) {
    Assert-FtTest (@(Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue).Count -eq 0) 'Test firewall rule name already exists'
    $ownedRuleNames.Add($Name)
    New-NetFirewallRule -Name $Name -DisplayName $Name -Direction Inbound -Action Allow -Protocol TCP `
        -RemoteAddress 10.200.0.1 -Program $Program -Profile Any | Out-Null
    return Get-NetFirewallRule -Name $Name
}

function Assert-FtBaselineAlive {
    $baseline = Get-Process -Id $BaselineClientId -ErrorAction Stop
    $server = Get-Process -Id $ServerId -ErrorAction Stop
    try {
        Assert-FtTest (-not $baseline.HasExited) 'Baseline client exited during launcher helper test'
        Assert-FtTest (-not $server.HasExited) 'E2E server exited during launcher helper test'
    } finally {
        $baseline.Dispose()
        $server.Dispose()
    }
}

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $administrator = [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Assert-FtTest $administrator 'Administrator privileges are required for the real firewall test'
    . (Join-Path $PSScriptRoot '..\scripts\client-process.ps1')
    $clients = @(Get-FtTestClients)
    $baseline = @($clients | Where-Object { $_.Id -eq $BaselineClientId })
    Assert-FtTest ($baseline.Count -eq 1) 'CIM helper did not identify exactly one baseline client'
    Assert-FtTest (@($clients | Where-Object { $_.Id -eq $ServerId }).Count -eq 0) 'CIM helper incorrectly identified the server as a client'
    Assert-FtTest ([string]::Equals($baseline[0].ExecutablePath, $Exe, [StringComparison]::OrdinalIgnoreCase)) 'Baseline executable path does not match'
    Assert-FtTest ([string]::Equals($baseline[0].ConfigPath, $ClientConfig, [StringComparison]::OrdinalIgnoreCase)) 'Baseline configuration path does not match'
    Assert-FtTest ($null -ne $baseline[0].CreationDate -and $null -ne $baseline[0].Process) 'CIM helper did not return process identity and held process handle'
    Assert-FtBaselineAlive
    $result.cases += @{ name = 'baseline_identity_and_server_exclusion'; passed = $true }

    New-Item -ItemType Directory -Path $testDirectory | Out-Null
    Copy-Item -LiteralPath $Exe -Destination $staleProgram
    $staleRule = Add-FtTestRule $staleRuleName $staleProgram
    Remove-FlowTunnelClientFirewallRules -Rules @($staleRule) -Clients $clients
    Assert-FtTest (@(Get-NetFirewallRule -Name $staleRuleName -ErrorAction SilentlyContinue).Count -eq 0) 'Firewall rule for a stopped executable path was retained'
    $result.cases += @{ name = 'stale_rule_removed'; passed = $true }

    $liveRule = Add-FtTestRule $liveRuleName $Exe
    Remove-FlowTunnelClientFirewallRules -Rules @($liveRule) -Clients $clients
    Assert-FtTest (@(Get-NetFirewallRule -Name $liveRuleName -ErrorAction SilentlyContinue).Count -eq 1) 'Firewall rule for a live client executable was removed'
    $result.cases += @{ name = 'live_client_rule_preserved'; passed = $true }

    $arguments = 'run "' + $ClientConfig + '"'
    $testProcess = Start-Process -FilePath $Exe -ArgumentList $arguments -WorkingDirectory (Split-Path -Parent $Exe) `
        -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    $null = $testProcess.Handle
    $result.test_client_id = $testProcess.Id
    Assert-FtTest ($testProcess.Id -ne $BaselineClientId -and $testProcess.Id -ne $ServerId) 'Temporary process identity collided with a baseline process'
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    $ready = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        $testProcess.Refresh()
        if ($testProcess.HasExited) { throw 'Temporary client exited before ready' }
        if (Test-Path -LiteralPath $stdoutPath) {
            $output = Get-Content -LiteralPath $stdoutPath -Raw -ErrorAction SilentlyContinue
            if ($output -match 'client ready') { $ready = $true; break }
        }
        Start-Sleep -Milliseconds 50
    }
    Assert-FtTest $ready 'Temporary client did not report ready'
    $temporary = @(Get-FtTestClients | Where-Object { $_.Id -eq $testProcess.Id })
    Assert-FtTest ($temporary.Count -eq 1) 'CIM helper did not identify the dedicated test client'
    $testClient = $temporary[0]
    Stop-FlowTunnelClientProcess -Client $testClient
    Assert-FtTest ($testProcess.WaitForExit(5000)) 'Dedicated test client did not exit'
    Assert-FtTest ($testProcess.ExitCode -eq 0) 'Dedicated test client did not stop gracefully through its named event'
    Assert-FtBaselineAlive
    $result.cases += @{ name = 'dedicated_client_named_stop'; passed = $true; exit_code = $testProcess.ExitCode }
    $result.success = $true
} catch {
    $result.error = $_.Exception.Message
} finally {
    if ($null -ne $testProcess) {
        try {
            $testProcess.Refresh()
            if (-not $testProcess.HasExited) {
                $testProcess.Kill()
                Assert-FtTest ($testProcess.WaitForExit(5000)) 'Dedicated test client remained alive during cleanup'
                $result.success = $false
                $result.cleanup += @{ name = 'dedicated_client'; method = 'kill'; id = $testProcess.Id }
            } else {
                $result.cleanup += @{ name = 'dedicated_client'; method = 'already_exited'; id = $testProcess.Id; exit_code = $testProcess.ExitCode }
            }
        } catch {
            $result.success = $false
            $result.cleanup += @{ name = 'dedicated_client'; error = $_.Exception.Message }
        } finally {
            $testProcess.Dispose()
        }
    }
    foreach ($name in $ownedRuleNames) {
        try {
            $rule = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
            if ($null -ne $rule) { $rule | Remove-NetFirewallRule }
            Assert-FtTest (@(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue).Count -eq 0) 'Owned test firewall rule remained after cleanup'
        } catch {
            $result.success = $false
            $result.cleanup += @{ name = 'test_firewall_rule'; rule = $name; error = $_.Exception.Message }
        }
    }
    try {
        $resolvedDirectory = [IO.Path]::GetFullPath($testDirectory)
        $resultsPrefix = $Results.TrimEnd('\') + '\'
        Assert-FtTest ($resolvedDirectory.StartsWith($resultsPrefix, [StringComparison]::OrdinalIgnoreCase)) 'Test cleanup path escaped results directory'
        if (Test-Path -LiteralPath $staleProgram) { Remove-Item -LiteralPath $staleProgram -Force }
        if (Test-Path -LiteralPath $testDirectory) { Remove-Item -LiteralPath $testDirectory -Force }
        Assert-FtBaselineAlive
    } catch {
        $result.success = $false
        $result.cleanup += @{ name = 'temporary_executable_or_baseline'; error = $_.Exception.Message }
    }
    foreach ($snapshot in $snapshots) {
        if ($null -ne $snapshot.Process) { $snapshot.Process.Dispose() }
    }
    $encoded = $result | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText($resultPath, $encoded + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    Write-Output $encoded
}

if ($result.success) { exit 0 }
exit 1
