function Get-FlowTunnelClientProcess {
    $clients = [Collections.Generic.List[object]]::new()
    $unknown = [Collections.Generic.List[int]]::new()
    foreach ($candidate in @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'flowtunnel.exe'" -ErrorAction Stop)) {
        $process = $null
        $retained = $false
        try {
            $process = [Diagnostics.Process]::GetProcessById([int]$candidate.ProcessId)
            $null = $process.Handle
            if ($process.HasExited) { continue }
            # Read command metadata after opening the handle so a reused PID cannot change the target.
            $current = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($process.Id)" -ErrorAction Stop
            if (-not $current -or $process.HasExited) { continue }
            if (-not [string]::Equals($current.Name, 'flowtunnel.exe', [StringComparison]::OrdinalIgnoreCase)) { continue }
            if (-not $current.ExecutablePath -or -not [string]::Equals($process.MainModule.FileName, $current.ExecutablePath, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Executable identity is unavailable'
            }
            $command = [string]$current.CommandLine
            if ($command -match '^\s*(?:"[^"]+"|\S+)\s+(?:genkey|check)\b') { continue }
            $run = [regex]::Match($command, '^\s*(?:"[^"]+"|\S+)\s+(?:run|"run")\s+(?:"(?<config>[^"]+)"|(?<config>\S+))\s*$')
            if (-not $run.Success) { throw 'Run configuration is unavailable' }
            $configPath = $run.Groups['config'].Value
            if (-not [IO.Path]::IsPathRooted($configPath)) { throw 'Run configuration path is not absolute' }
            $configPath = [IO.Path]::GetFullPath($configPath)
            $config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 -ErrorAction Stop
            $mode = [regex]::Matches($config, '(?m)^[ \t]*mode[ \t]*=[ \t]*"(?<mode>client|server)"[ \t]*(?:#[^\r\n]*)?\r?$')
            if ($mode.Count -ne 1 -or $config -match '(?m)^[ \t]*\[') { throw 'Run mode is ambiguous' }
            if ($mode[0].Groups['mode'].Value -ceq 'server') { continue }
            if ($process.HasExited) { continue }
            $clients.Add([pscustomobject]@{
                Id = $process.Id
                ExecutablePath = [string]$current.ExecutablePath
                ConfigPath = $configPath
                CreationDate = $current.CreationDate
                Process = $process
            })
            $retained = $true
        } catch {
            if ($process) {
                try { if ($process.HasExited) { continue } } catch {}
            }
            $unknown.Add([int]$candidate.ProcessId)
        } finally {
            if ($process -and -not $retained) { $process.Dispose() }
        }
    }
    if ($unknown.Count) {
        foreach ($client in $clients) { $client.Process.Dispose() }
        throw "Cannot determine the mode of FlowTunnel process PID(s) $($unknown -join ', '). Check their command and configuration manually before starting another client."
    }
    return $clients.ToArray()
}

function Stop-FlowTunnelClientProcess {
    param([Parameter(Mandatory)] [object]$Client)
    $process = $Client.Process
    if (-not $process -or $process.Id -ne $Client.Id) { throw 'Client process handle is unavailable' }
    if ($process.HasExited) { return }
    if (-not [string]::Equals($process.MainModule.FileName, $Client.ExecutablePath, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Client process identity does not match PID $($Client.Id)"
    }
    $event = $null
    try {
        $event = [Threading.EventWaitHandle]::OpenExisting("Local\FlowTunnel.Stop.$($Client.Id)")
        $null = $event.Set()
    } catch [Threading.WaitHandleCannotBeOpenedException], [UnauthorizedAccessException] {
    } finally {
        if ($event) { $event.Dispose() }
    }
    if ($process.WaitForExit(5000)) { return }
    if ($process.HasExited) { return }
    try {
        if (-not [string]::Equals($process.MainModule.FileName, $Client.ExecutablePath, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Client process identity does not match PID $($Client.Id)"
        }
        $process.Kill()
    } catch {
        if ($process.HasExited) { return }
        throw
    }
    if (-not $process.WaitForExit(5000)) { throw "Client PID $($Client.Id) did not exit after stopping" }
}

function Remove-FlowTunnelClientFirewallRules {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]]$Rules,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]]$Clients
    )
    $livePaths = @($Clients | Where-Object { -not $_.Process.HasExited } | ForEach-Object { $_.ExecutablePath })
    foreach ($rule in $Rules) {
        $preserve = $false
        if ($livePaths.Count) {
            foreach ($filter in @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)) {
                foreach ($path in $livePaths) {
                    if ([string]::Equals($filter.Program, $path, [StringComparison]::OrdinalIgnoreCase)) { $preserve = $true }
                }
            }
        }
        if (-not $preserve) {
            try { Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop }
            catch { if ($_.CategoryInfo.Category -ne [Management.Automation.ErrorCategory]::ObjectNotFound) { throw } }
        }
    }
}
