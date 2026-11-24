param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [Parameter(Mandatory = $true)][string]$Results
)

$ErrorActionPreference = 'Stop'
$testScript = Join-Path $PSScriptRoot '..\tests\local_e2e.py'
New-Item -ItemType Directory -Path $Results -Force | Out-Null
$exitCodePath = Join-Path $Results 'exit-code.txt'
$projectRoot = Split-Path -Parent $PSScriptRoot
$requestPath = Join-Path $projectRoot 'test-results\authorization\operation.request.json'
if (Test-Path -LiteralPath $requestPath) {
    $request = Get-Content -LiteralPath $requestPath -Raw | ConvertFrom-Json
    $requestId = [Guid]::ParseExact($request.id,'D').ToString()
    Move-Item -LiteralPath $requestPath -Destination (Join-Path (Split-Path -Parent $requestPath) ('operation-' + $requestId + '.json'))
    $response = @{ id=$requestId; action=$request.action; success=$false }
    try {
        $response.result = & (Join-Path $PSScriptRoot 'server-control-admin.ps1') -Action $request.action
        $response.success = $true
    } catch { $response.error=$_.Exception.Message }
    $response | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path (Split-Path -Parent $requestPath) 'operation.response.json') -Encoding utf8
    if ($response.success) { exit 0 } else { exit 1 }
}
try {
    & python -u $testScript --exe $Exe --results $Results
    $testExitCode = $LASTEXITCODE
    Set-Content -LiteralPath $exitCodePath -Value $testExitCode -Encoding ascii
    exit $testExitCode
} catch {
    Set-Content -LiteralPath $exitCodePath -Value 1 -Encoding ascii
    Write-Error $_
    exit 1
}
