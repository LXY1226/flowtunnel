param([string]$Name = 'FlowTunnel')

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run remove-service.ps1 from an Administrator PowerShell session'
}
if ($Name.Length -gt 256 -or $Name -cnotmatch '^FlowTunnel[-_.A-Za-z0-9]*$') {
    throw 'Service name must start with FlowTunnel and contain only letters, digits, hyphens, underscores, or periods'
}
$marker = 'FlowTunnel native tunnel service'
$ruleName = 'FlowTunnel-Service-' + $Name
$installed = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
$rules = @(Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)
if (-not $installed) {
    if ($rules.Count) { throw 'Service is absent but a firewall rule remains; its ownership cannot be verified' }
    Write-Output "Service $Name is not installed"
    return
}

function ConvertFrom-FlowTunnelServiceCommandLine([string]$CommandLine) {
    if (-not ('FlowTunnelServiceCommandLine' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class FlowTunnelServiceCommandLine {
    [DllImport("shell32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern IntPtr CommandLineToArgvW(string commandLine, out int count);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
    public static string[] Parse(string commandLine) {
        int count;
        IntPtr memory = CommandLineToArgvW(commandLine, out count);
        if (memory == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            var arguments = new string[count];
            for (int i=0; i<count; ++i)
                arguments[i] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(memory, i*IntPtr.Size));
            return arguments;
        } finally { LocalFree(memory); }
    }
}
'@
    }
    return [FlowTunnelServiceCommandLine]::Parse($CommandLine)
}

$arguments = @(ConvertFrom-FlowTunnelServiceCommandLine $installed.PathName)
if ($installed.Description -cne $marker -or $arguments.Count -ne 5 -or $arguments[1] -cne 'service' -or
    -not [string]::Equals($arguments[2], $Name, [StringComparison]::OrdinalIgnoreCase) -or
    -not [IO.Path]::IsPathRooted($arguments[0]) -or -not [IO.Path]::IsPathRooted($arguments[3]) -or
    -not [IO.Path]::IsPathRooted($arguments[4])) {
    throw 'Service description or native command identity does not belong to this installer'
}
if ($rules.Count -gt 1) { throw 'Owned firewall rule identity is ambiguous' }
foreach ($rule in $rules) {
    $filters = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
    if ($rule.Description -cne $marker -or $filters.Count -ne 1 -or
        -not [string]::Equals($filters[0].Program, $arguments[0], [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Firewall rule identity does not belong to this installed service'
    }
}
$controller = $null
$process = $null
try {
    $controller = Get-Service -Name $Name -ErrorAction Stop
    if ([int]$installed.ProcessId -gt 0) {
        $process = [Diagnostics.Process]::GetProcessById([int]$installed.ProcessId)
        $null = $process.Handle
        if (-not $process.HasExited -and -not [string]::Equals($process.MainModule.FileName, $arguments[0], [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Running service executable identity changed; removal refused'
        }
    }
    if ($controller.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
        Stop-Service -InputObject $controller -ErrorAction Stop
        $controller.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
    }
    if ($process -and -not $process.WaitForExit(30000)) { throw 'Service process did not exit after SCM stop' }
} finally {
    if ($controller) { $controller.Dispose() }
    if ($process) { $process.Dispose() }
}
& "$env:SystemRoot\System32\sc.exe" delete $Name | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'DeleteService failed' }
$deadline = [DateTime]::UtcNow.AddSeconds(10)
while (Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction Stop) {
    if ([DateTime]::UtcNow -ge $deadline) { throw 'Service is still marked for deletion; close other service handles' }
    Start-Sleep -Milliseconds 100
}
if ($rules.Count) { Remove-NetFirewallRule -Name $ruleName -ErrorAction Stop }
Write-Output "Removed $Name. Configuration and logs were retained."
