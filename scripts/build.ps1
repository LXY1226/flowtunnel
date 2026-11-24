param([switch]$SkipTests)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$dependencyRoot = Join-Path $projectRoot 'third_party'
$outputRoot = Join-Path $projectRoot 'bin'
New-Item -ItemType Directory -Path $dependencyRoot,$outputRoot -Force | Out-Null
$dependencies = @(
    @{ name='asio-1.36.0'; folder='asio-asio-1-36-0'; url='https://codeload.github.com/chriskohlhoff/asio/zip/refs/tags/asio-1-36-0'; sha256='BCC4E7143352E4556D22CBFD0F072F352BFA87BD6F454FE8D7B1D55CDC8F8695' },
    @{ name='tomlplusplus-3.4.0'; folder='tomlplusplus-3.4.0'; url='https://codeload.github.com/marzer/tomlplusplus/zip/refs/tags/v3.4.0'; sha256='AD2A4CD786E25305D802E7490EA65A2531195E5834BF6B4FA5A323421FD81F9B' },
    @{ name='WinDivert-2.2.2-A'; folder='WinDivert-2.2.2-A'; url='https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip'; sha256='63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15' }
)
foreach ($dependency in $dependencies) {
    $archivePath = Join-Path $dependencyRoot ($dependency.name + '.zip')
    if (-not (Test-Path -LiteralPath $archivePath)) { Invoke-WebRequest $dependency.url -OutFile $archivePath }
    if ($dependency.sha256 -and (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash -ne $dependency.sha256) { throw "Dependency checksum mismatch: $($dependency.name)" }
    if (-not (Test-Path -LiteralPath (Join-Path $dependencyRoot $dependency.folder))) { Expand-Archive -LiteralPath $archivePath -DestinationPath $dependencyRoot }
}
$releaseRoot = Join-Path $dependencyRoot 'WinDivert-2.2.2-A'
$driverPath = Join-Path $releaseRoot 'x64\WinDivert64.sys'
$signature = Get-AuthenticodeSignature -LiteralPath $driverPath
if ($signature.Status -ne 'Valid') { throw "WinDivert driver signature is invalid: $($signature.Status)" }
& cmake -S $projectRoot -B (Join-Path $projectRoot 'build') -G 'Visual Studio 18 2026' -A x64
if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed' }
& cmake --build (Join-Path $projectRoot 'build') --config Release --parallel
if ($LASTEXITCODE -ne 0) { throw 'C++ build failed' }
if (-not $SkipTests) {
    & ctest --test-dir (Join-Path $projectRoot 'build') -C Release --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw 'Native tests failed' }
}
foreach ($sourcePath in @((Join-Path $releaseRoot 'x64\WinDivert.dll'),$driverPath)) {
    $destinationPath = Join-Path $outputRoot (Split-Path -Leaf $sourcePath)
    if ((Test-Path -LiteralPath $destinationPath) -and (Get-FileHash -LiteralPath $sourcePath).Hash -eq (Get-FileHash -LiteralPath $destinationPath).Hash) { continue }
    Copy-Item -LiteralPath $sourcePath -Destination $destinationPath -Force
}
foreach ($name in 'LICENSE','WINDIVERTLICENSE') {
    $sourcePath = Join-Path $releaseRoot $name
    if (Test-Path -LiteralPath $sourcePath) { Copy-Item -LiteralPath $sourcePath -Destination $outputRoot -Force }
}
Write-Output "Built $(Join-Path $outputRoot 'flowtunnel.exe')"
