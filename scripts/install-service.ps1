param(
    [string]$Name = 'FlowTunnel',
    [string]$ExecutablePath = (Join-Path $PSScriptRoot 'flowtunnel.exe'),
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'server.toml'),
    [string]$LogDirectory
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run install-service.ps1 from an Administrator PowerShell session'
}
if ($Name.Length -gt 256 -or $Name -cnotmatch '^FlowTunnel[-_.A-Za-z0-9]*$') {
    throw 'Service name must start with FlowTunnel and contain only letters, digits, hyphens, underscores, or periods'
}
foreach ($path in @($ExecutablePath, $ConfigPath)) {
    if (-not [IO.Path]::IsPathRooted($path) -or $path.Contains('"')) { throw 'Executable and configuration paths must be absolute and contain no quote characters' }
}
$ExecutablePath = (Resolve-Path -LiteralPath $ExecutablePath).Path
$ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path
if (-not (Test-Path -LiteralPath $ExecutablePath -PathType Leaf) -or -not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw 'Executable and configuration must be files'
}
if (-not $LogDirectory) { $LogDirectory = Join-Path (Split-Path -Parent $ConfigPath) ('logs\' + $Name) }
if (-not [IO.Path]::IsPathRooted($LogDirectory) -or $LogDirectory.Contains('"')) { throw 'Log directory must be an absolute path without quote characters' }
$LogDirectory = [IO.Path]::GetFullPath($LogDirectory)
$marker = 'FlowTunnel native tunnel service'
$ruleName = 'FlowTunnel-Service-' + $Name
if (Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction Stop) { throw "Service $Name already exists" }
if (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue) { throw "Firewall rule $ruleName already exists" }
$checkOutput = & $ExecutablePath check $ConfigPath 2>&1
if ($LASTEXITCODE -ne 0) { throw 'Native configuration validation failed; no service was installed' }
try { $metadata = ($checkOutput | Out-String).Trim() | ConvertFrom-Json -ErrorAction Stop }
catch { throw 'Native check did not return its configuration metadata JSON' }
if ($metadata.mode -cnotin @('server', 'client') -or $null -eq $metadata.port -or
    $metadata.port -is [bool] -or [double]$metadata.port -ne [int]$metadata.port -or
    [int]$metadata.port -lt 1 -or [int]$metadata.port -gt 65535) {
    throw 'Native check returned invalid service mode or TCP port'
}

function Quote-FlowTunnelServiceArgument([string]$Value) {
    if ($Value.Contains('"')) { throw 'Service arguments cannot contain quote characters' }
    return '"' + [regex]::Replace($Value, '(\\+)$', '$1$1') + '"'
}

$binaryPath = (Quote-FlowTunnelServiceArgument $ExecutablePath) + ' service ' +
    (Quote-FlowTunnelServiceArgument $Name) + ' ' + (Quote-FlowTunnelServiceArgument $ConfigPath) + ' ' +
    (Quote-FlowTunnelServiceArgument $LogDirectory)
$startupMutex = $null
$startupHeld = $false
try {
if ($metadata.mode -ceq 'client') {
    $startupMutex = [Threading.Mutex]::new($false, 'Global\FlowTunnel.Client.Startup')
    try { $null = $startupMutex.WaitOne(); $startupHeld = $true }
    catch [Threading.AbandonedMutexException] { $startupHeld = $true }
    . (Join-Path $PSScriptRoot 'client-process.ps1')
    $clients = @(Get-FlowTunnelClientProcess)
    try {
        if ($clients.Count) { throw "Stop the existing client before installing this service: $($clients.Id -join ', ')" }
    } finally {
        foreach ($client in $clients) { $client.Process.Dispose() }
    }
}
$createdService = $false
$createdRule = $false
try {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    $controller = New-Service -Name $Name -BinaryPathName $binaryPath -DisplayName $Name `
        -Description $marker -StartupType Automatic
    $createdService = $true
    $controller.Dispose()
    $firewall = @{ Name = $ruleName; DisplayName = $ruleName; Description = $marker;
                   Direction = 'Inbound'; Action = 'Allow'; Protocol = 'TCP'; Program = $ExecutablePath; Profile = 'Any' }
    if ($metadata.mode -ceq 'server') { $firewall.LocalPort = [int]$metadata.port }
    else { $firewall.RemoteAddress = '10.200.0.1' }
    New-NetFirewallRule @firewall | Out-Null
    $createdRule = $true
    $controller = Get-Service -Name $Name -ErrorAction Stop
    try {
        Start-Service -InputObject $controller -ErrorAction Stop
        $controller.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
    } finally {
        $controller.Dispose()
    }
    Write-Output "Installed $Name with Automatic startup. Logs: $LogDirectory"
} catch {
    $failure = $_
    $rollbackErrors = [Collections.Generic.List[string]]::new()
    if ($createdService) {
        $controller = $null
        $process = $null
        try {
            $installed = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
            if ($installed) {
                if ($installed.Description -cne $marker -or -not [string]::Equals($installed.PathName, $binaryPath, [StringComparison]::OrdinalIgnoreCase)) {
                    throw 'Created service identity changed; rollback refused'
                }
                if ([int]$installed.ProcessId -gt 0) {
                    $process = [Diagnostics.Process]::GetProcessById([int]$installed.ProcessId)
                    $null = $process.Handle
                    if (-not $process.HasExited -and -not [string]::Equals($process.MainModule.FileName, $ExecutablePath, [StringComparison]::OrdinalIgnoreCase)) {
                        throw 'Created service process identity changed; rollback refused'
                    }
                }
                $controller = Get-Service -Name $Name -ErrorAction Stop
                if ($controller.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
                    Stop-Service -InputObject $controller -ErrorAction Stop
                    $controller.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
                }
                if ($process -and -not $process.WaitForExit(30000)) { throw 'Created service process did not exit during rollback' }
                $controller.Dispose()
                $controller = $null
                & "$env:SystemRoot\System32\sc.exe" delete $Name | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'DeleteService failed during installation rollback' }
                $deleteDeadline = [DateTime]::UtcNow.AddSeconds(10)
                while (Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction Stop) {
                    if ([DateTime]::UtcNow -ge $deleteDeadline) { throw 'Created service is still marked for deletion' }
                    Start-Sleep -Milliseconds 100
                }
            }
        } catch { $rollbackErrors.Add($_.Exception.Message) }
        finally {
            if ($controller) { $controller.Dispose() }
            if ($process) { $process.Dispose() }
        }
    }
    if ($createdRule) {
        try {
            foreach ($rule in @(Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)) {
                $filters = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
                if ($rule.Description -cne $marker -or $filters.Count -ne 1 -or
                    -not [string]::Equals($filters[0].Program, $ExecutablePath, [StringComparison]::OrdinalIgnoreCase)) {
                    throw 'Created firewall rule identity changed; rollback refused'
                }
                Remove-NetFirewallRule -Name $ruleName -ErrorAction Stop
            }
        }
        catch { $rollbackErrors.Add($_.Exception.Message) }
    }
    if ($rollbackErrors.Count) { throw "Installation failed: $($failure.Exception.Message). Rollback failed: $($rollbackErrors -join '; ')" }
    throw $failure
}
} finally {
    if ($startupHeld) { $startupMutex.ReleaseMutex() }
    if ($startupMutex) { $startupMutex.Dispose() }
}
