param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [Parameter(Mandatory = $true)][string]$Results,
    [int]$BaselineServerId = 36572
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator privileges are required for the real Windows service test'
}
if (-not [IO.Path]::IsPathRooted($Exe) -or -not [IO.Path]::IsPathRooted($Results)) {
    throw 'Executable and results paths must be absolute'
}
$Exe = (Resolve-Path -LiteralPath $Exe).Path
$Results = [IO.Path]::GetFullPath($Results)
$workspace = Split-Path -Parent $PSScriptRoot
$resultsRoot = [IO.Path]::GetFullPath((Join-Path $workspace 'test-results')).TrimEnd('\') + '\'
if (-not $Results.StartsWith($resultsRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Results must be a dedicated directory inside this workspace test-results'
}
New-Item -ItemType Directory -Path $Results -Force | Out-Null
$testIdentity = [Guid]::NewGuid().ToString('N')
$serviceName = 'FlowTunnel-ServiceTest-' + $testIdentity
$ruleName = 'FlowTunnel-Service-' + $serviceName
$testDirectory = Join-Path $Results ('service fixture ' + $testIdentity)
New-Item -ItemType Directory -Path $testDirectory | Out-Null
$configPath = Join-Path $testDirectory 'server configuration.toml'
$clientConfigPath = Join-Path $testDirectory 'client configuration.toml'
$clientServiceName = $serviceName + '-Client'
$clientRuleName = 'FlowTunnel-Service-' + $clientServiceName
$logDirectory = (Join-Path $testDirectory 'service logs') + '\'
$installScript = Join-Path $workspace 'scripts\install-service.ps1'
$removeScript = Join-Path $workspace 'scripts\remove-service.ps1'
$baseline = $null
$ownProcess = $null
$configCreated = $false
$result = [ordered]@{ success = $false; service_name = $serviceName; firewall_rule = $ruleName; baseline_server_id = $BaselineServerId; cases = @(); cleanup = @() }

function Assert-ServiceTest([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Get-TestService {
    return Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop
}

function Get-TestRule {
    try { return Get-NetFirewallRule -Name $ruleName -ErrorAction Stop }
    catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound) { return $null }
        throw
    }
}

function Assert-BaselineRunning {
    $baseline.Refresh()
    Assert-ServiceTest (-not $baseline.HasExited) 'The protected baseline server exited during the test'
}

function Wait-TestService([ServiceProcess.ServiceControllerStatus]$Status) {
    $controller = Get-Service -Name $serviceName -ErrorAction Stop
    try { $controller.WaitForStatus($Status, [TimeSpan]::FromSeconds(30)) }
    finally { $controller.Dispose() }
}

function Assert-TestListener([int]$Port) {
    $probe = [Net.Sockets.TcpClient]::new()
    try {
        $connected = $probe.ConnectAsync('127.0.0.1', $Port)
        Assert-ServiceTest ($connected.Wait(5000)) 'The service TCP listener did not accept a loopback connection'
        $null = $connected.GetAwaiter().GetResult()
        Assert-ServiceTest $probe.Connected 'The service did not expose its configured TCP listener'
    } finally { $probe.Dispose() }
}

try {
    $baseline = [Diagnostics.Process]::GetProcessById($BaselineServerId)
    $null = $baseline.Handle
    Assert-BaselineRunning
    Assert-ServiceTest ($null -eq (Get-TestService)) 'The generated service name already exists'
    Assert-ServiceTest ($null -eq (Get-TestRule)) 'The generated firewall rule already exists'
    $reservation = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try {
        $reservation.Start()
        $port = ([Net.IPEndPoint]$reservation.LocalEndpoint).Port
    } finally { $reservation.Stop() }
    $keyOutput = @(& $Exe genkey 2>&1)
    Assert-ServiceTest ($LASTEXITCODE -eq 0) 'Native key generation failed'
    $key = ($keyOutput -join '').Trim()
    $decoded = [Convert]::FromBase64String($key)
    Assert-ServiceTest ($decoded.Length -eq 32) 'Native key generation did not return 32 bytes'
    $config = "mode = `"server`"`nlisten = `"127.0.0.1:$port`"`nkey = `"$key`"`n"
    [IO.File]::WriteAllText($configPath, $config, [Text.UTF8Encoding]::new($false))
    $configCreated = $true
    $key = $null
    $keyOutput = $null
    $decoded = $null
    $config = $null
    $null = & $installScript -Name $serviceName -ExecutablePath $Exe -ConfigPath $configPath -LogDirectory $logDirectory
    Wait-TestService ([ServiceProcess.ServiceControllerStatus]::Running)
    $installed = Get-TestService
    Assert-ServiceTest ($installed.StartMode -eq 'Auto' -and $installed.State -eq 'Running') 'Service startup mode or state is incorrect'
    Assert-ServiceTest ($installed.StartName -eq 'LocalSystem') 'The service does not run as LocalSystem'
    Assert-ServiceTest ($installed.Description -ceq 'FlowTunnel native tunnel service') 'The service ownership marker is incorrect'
    Assert-TestListener $port
    Assert-ServiceTest ((Test-Path -LiteralPath (Join-Path $logDirectory 'stdout.log')) -and (Test-Path -LiteralPath (Join-Path $logDirectory 'stderr.log'))) 'Native service log files were not created'
    Assert-ServiceTest ($null -ne (Get-TestRule)) 'The owned firewall rule is missing'
    $result.cases += @{ name = 'automatic_native_service_running'; passed = $true; process_id = [int]$installed.ProcessId; port = $port }

    . (Join-Path $workspace 'scripts\client-process.ps1')
    $clients = @(Get-FlowTunnelClientProcess)
    try {
        Assert-ServiceTest (@($clients | Where-Object { $_.Id -eq [int]$installed.ProcessId }).Count -eq 0) 'The client helper misidentified the server service as a client'
        Assert-ServiceTest (@($clients | Where-Object { $_.Id -eq $BaselineServerId }).Count -eq 0) 'The client helper misidentified the baseline server as a client'
    } finally {
        foreach ($client in $clients) { $client.Process.Dispose() }
    }
    $result.cases += @{ name = 'server_service_excluded_from_clients'; passed = $true }
    Assert-BaselineRunning

    $ownProcess = [Diagnostics.Process]::GetProcessById([int]$installed.ProcessId)
    $null = $ownProcess.Handle
    Stop-Service -Name $serviceName -ErrorAction Stop
    Wait-TestService ([ServiceProcess.ServiceControllerStatus]::Stopped)
    Assert-ServiceTest ($ownProcess.WaitForExit(10000)) 'The service process remained alive after SCM stop'
    Assert-ServiceTest ($ownProcess.ExitCode -eq 0) 'The service process did not stop cleanly'
    $ownProcess.Dispose()
    $ownProcess = $null
    Start-Service -Name $serviceName -ErrorAction Stop
    Wait-TestService ([ServiceProcess.ServiceControllerStatus]::Running)
    $restarted = Get-TestService
    Assert-ServiceTest ($restarted.State -eq 'Running' -and $restarted.StartMode -eq 'Auto') 'The service did not restart in automatic mode'
    Assert-TestListener $port
    Assert-BaselineRunning
    $result.cases += @{ name = 'service_stop_and_restart'; passed = $true; process_id = [int]$restarted.ProcessId }

    $clientConfiguration = (Get-Content -LiteralPath $configPath -Raw).Replace('mode = "server"', 'mode = "client"').Replace('listen = ', 'endpoint = ')
    [IO.File]::WriteAllText($clientConfigPath, $clientConfiguration, [Text.UTF8Encoding]::new($false))
    $clientConfiguration = $null
    $null = & $installScript -Name $clientServiceName -ExecutablePath $Exe -ConfigPath $clientConfigPath -LogDirectory (Join-Path $testDirectory 'client logs')
    $clientService = Get-CimInstance -ClassName Win32_Service -Filter "Name='$clientServiceName'" -ErrorAction Stop
    Assert-ServiceTest ($clientService.State -eq 'Running' -and $clientService.StartMode -eq 'Auto') 'Client service did not start in automatic mode'
    $clients = @(Get-FlowTunnelClientProcess)
    try {
        $clientIdentity = @($clients | Where-Object { $_.Id -eq [int]$clientService.ProcessId })
        Assert-ServiceTest ($clientIdentity.Count -eq 1 -and $clientIdentity[0].ServiceName -eq $clientServiceName) 'Client service identity was not recognized'
        $duplicateName = $serviceName + '-Duplicate'
        $refused = $false
        try { $null = & $installScript -Name $duplicateName -ExecutablePath $Exe -ConfigPath $clientConfigPath }
        catch { $refused = $_.Exception.Message -like 'Stop the existing client before installing*' }
        Assert-ServiceTest $refused 'Installing a second client was not refused before creating a service'
        Assert-ServiceTest ($null -eq (Get-CimInstance Win32_Service -Filter "Name='$duplicateName'")) 'Duplicate client service was created'
        Stop-FlowTunnelClientProcess -Client $clientIdentity[0]
        Assert-ServiceTest $clientIdentity[0].Process.HasExited 'Client service did not stop via SCM'
        Assert-ServiceTest ($clientIdentity[0].Process.ExitCode -eq 0) 'Client service did not stop cleanly'
    } finally {
        foreach ($client in $clients) { $client.Process.Dispose() }
    }
    Start-Service -Name $clientServiceName -ErrorAction Stop
    $null = & $removeScript -Name $clientServiceName
    Assert-ServiceTest ($null -eq (Get-CimInstance Win32_Service -Filter "Name='$clientServiceName'")) 'Client service remains after removal'
    Assert-ServiceTest ($null -eq (Get-NetFirewallRule -Name $clientRuleName -ErrorAction SilentlyContinue)) 'Client service rule remains after removal'
    $result.cases += @{ name = 'automatic_client_service_identity_duplicate_refusal_and_scm_stop'; passed = $true }

    $null = & $removeScript -Name $serviceName
    Assert-ServiceTest ($null -eq (Get-TestService)) 'The service remains after removal'
    Assert-ServiceTest ($null -eq (Get-TestRule)) 'The owned firewall rule remains after removal'
    Assert-ServiceTest ((Test-Path -LiteralPath $configPath) -and (Test-Path -LiteralPath $logDirectory)) 'Removal deleted configuration or logs'
    Assert-BaselineRunning
    $result.cases += @{ name = 'owned_service_and_rule_removed_files_preserved'; passed = $true }
    $result.success = $true
} catch {
    $result.error = $_.Exception.Message
} finally {
    if ($ownProcess) { $ownProcess.Dispose() }
    try {
        if (Get-CimInstance Win32_Service -Filter "Name='$clientServiceName'" -ErrorAction Stop) {
            $null = & $removeScript -Name $clientServiceName
        }
        if (Test-Path -LiteralPath $clientConfigPath) { Remove-Item -LiteralPath $clientConfigPath -Force }
        if ($null -ne (Get-TestService)) {
            $null = & $removeScript -Name $serviceName
        }
        Assert-ServiceTest ($null -eq (Get-TestService)) 'The test service remained after cleanup'
        Assert-ServiceTest ($null -eq (Get-TestRule)) 'The test firewall rule remained after cleanup'
        $result.cleanup += @{ name = 'test_service_and_rule'; removed = $true }
        if ($configCreated -and (Test-Path -LiteralPath $configPath)) {
            $resolvedConfig = (Resolve-Path -LiteralPath $configPath).Path
            $resolvedDirectory = [IO.Path]::GetFullPath($testDirectory).TrimEnd('\') + '\'
            Assert-ServiceTest ($resolvedConfig.StartsWith($resolvedDirectory, [StringComparison]::OrdinalIgnoreCase)) 'The temporary key path escaped the test directory'
            Remove-Item -LiteralPath $resolvedConfig -Force
        }
    } catch {
        $result.success = $false
        $result.cleanup += @{ name = 'test_service_rule_or_key'; error = $_.Exception.Message; configuration_preserved = (Test-Path -LiteralPath $configPath) }
    }
    if ($baseline) {
        try { Assert-BaselineRunning }
        catch { $result.success = $false; $result.cleanup += @{ name = 'baseline_server'; error = $_.Exception.Message } }
        finally { $baseline.Dispose() }
    }
    $encoded = $result | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText((Join-Path $Results 'result.json'), $encoded + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $Results 'exit-code.txt'), $(if ($result.success) { '0' } else { '1' }), [Text.UTF8Encoding]::new($false))
    Write-Output $encoded
}

if ($result.success) { exit 0 }
exit 1
