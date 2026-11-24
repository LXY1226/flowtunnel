param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^(v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?|dev-[0-9a-f]{40})$')]
    [string]$Version
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$outputRoot = Join-Path $projectRoot 'dist'
$packageName = 'flowtunnel-' + $Version + '-windows-x64'
$stageRoot = Join-Path $outputRoot $packageName
if (Test-Path -LiteralPath $stageRoot) { throw "Package staging directory already exists: $stageRoot" }
New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null

foreach ($name in @('flowtunnel.exe', 'WinDivert.dll', 'WinDivert64.sys')) {
    Copy-Item -LiteralPath (Join-Path $projectRoot ('bin\' + $name)) -Destination $stageRoot
}
foreach ($name in @('launch-client.ps1', 'client-process.ps1')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $stageRoot
}
foreach ($name in @('client.example.toml', 'server.example.toml')) {
    Copy-Item -LiteralPath (Join-Path $projectRoot $name) -Destination $stageRoot
}

$licenseRoot = Join-Path $stageRoot 'LICENSES'
New-Item -ItemType Directory -Path $licenseRoot | Out-Null
Copy-Item -LiteralPath (Join-Path $projectRoot 'third_party\WinDivert-2.2.2-A\LICENSE') -Destination (Join-Path $licenseRoot 'WinDivert.txt')
Copy-Item -LiteralPath (Join-Path $projectRoot 'third_party\asio-asio-1-36-0\asio\LICENSE_1_0.txt') -Destination (Join-Path $licenseRoot 'Asio.txt')
Copy-Item -LiteralPath (Join-Path $projectRoot 'third_party\asio-asio-1-36-0\asio\COPYING') -Destination (Join-Path $licenseRoot 'Asio-COPYING.txt')
Copy-Item -LiteralPath (Join-Path $projectRoot 'third_party\tomlplusplus-3.4.0\LICENSE') -Destination (Join-Path $licenseRoot 'tomlplusplus.txt')

@'
@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0launch-client.ps1"
'@ | Set-Content -LiteralPath (Join-Path $stageRoot 'run-client.cmd') -Encoding ascii

@"
FlowTunnel $Version - Windows x64

Client setup:
1. Run .\flowtunnel.exe genkey and share the same key with the server.
2. Copy client.example.toml to client.toml; set endpoint and key.
3. Run run-client.cmd and approve Windows UAC. Keep the console open.
4. Access the server's TCP/UDP services through 10.200.0.1:<target-port>.
5. Stop the client with Ctrl+C in its console.

Server setup:
1. Copy server.example.toml to server.toml; set listen and the shared key.
2. In an Administrator PowerShell, run .\flowtunnel.exe run .\server.toml.
3. Allow the configured inbound TCP port in Windows Firewall and forward it
   through the router if needed. The target services must listen on loopback
   or all IPv4 addresses. No public UDP port is required.

Both roles use the same executable. Windows x64 and Administrator privileges
are required for WinDivert. MSVC runtime libraries are linked statically.
Third-party licenses are included in LICENSES.

This prototype supports client-initiated IPv4 TCP and UDP only. Its custom
handshake and Fake TCP transport have not undergone a third-party audit.
Source, configuration and protocol details:
https://github.com/LXY1226/flowtunnel
"@ | Set-Content -LiteralPath (Join-Path $stageRoot 'README.txt') -Encoding utf8

$commit = & git -C $projectRoot rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Could not identify the source commit' }
@("version=$Version", "commit=$commit") | Set-Content -LiteralPath (Join-Path $stageRoot 'BUILD.txt') -Encoding ascii

$archivePath = Join-Path $outputRoot ($packageName + '.zip')
Compress-Archive -Path (Join-Path $stageRoot '*') -DestinationPath $archivePath -Force
$hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $packageName.zip" | Set-Content -LiteralPath ($archivePath + '.sha256') -Encoding ascii
Get-Item -LiteralPath $archivePath,($archivePath + '.sha256') | Select-Object FullName,Length
