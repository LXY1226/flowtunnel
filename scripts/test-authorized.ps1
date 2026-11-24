$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$state = Get-Content -LiteralPath (Join-Path $projectRoot 'test-results\authorization\task.json') -Raw | ConvertFrom-Json
if ($state.project -ne $projectRoot) { throw 'Authorization belongs to another workspace' }
$started = Get-Date
Start-ScheduledTask -TaskName $state.task_name
$exitPath = Join-Path $state.results 'exit-code.txt'
$deadline = $started.AddMinutes(5)
while ((Get-Date) -lt $deadline) {
    if ((Test-Path -LiteralPath $exitPath) -and (Get-Item -LiteralPath $exitPath).LastWriteTime -ge $started) {
        Get-Content -LiteralPath (Join-Path $state.results 'result.json')
        exit [int](Get-Content -LiteralPath $exitPath -Raw)
    }
    Start-Sleep -Milliseconds 200
}
throw 'Authorized local test did not complete within five minutes'
