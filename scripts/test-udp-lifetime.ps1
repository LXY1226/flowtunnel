$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
$resultRoot=Join-Path $projectRoot 'test-results\udp-lifetime'
New-Item -ItemType Directory -Path $resultRoot -Force | Out-Null
try {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The UDP lifetime test requires Administrator privileges for WinDivert'
    }
    & python -u (Join-Path $projectRoot 'tests\udp_lifetime.py') --exe (Join-Path $projectRoot 'bin\flowtunnel.exe') --profile (Join-Path $projectRoot 'test-results\server-31828') --results $resultRoot 1> (Join-Path $resultRoot 'output.log') 2> (Join-Path $resultRoot 'error.log')
    $testExitCode=$LASTEXITCODE
    Set-Content -LiteralPath (Join-Path $resultRoot 'exit-code.txt') -Value $testExitCode -Encoding ascii
    exit $testExitCode
} catch {
    @{success=$false;error=$_.Exception.Message} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $resultRoot 'result.json') -Encoding utf8
    Set-Content -LiteralPath (Join-Path $resultRoot 'exit-code.txt') -Value 1 -Encoding ascii
    throw
}
