param([Parameter(Mandatory=$true)][ValidateSet('Start','Stop','Probe','Lifetime')][string]$Action)
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
$authorizationRoot=Join-Path $projectRoot 'test-results\authorization'
$state=Get-Content -LiteralPath (Join-Path $authorizationRoot 'task.json') -Raw | ConvertFrom-Json
if ($state.project -ne $projectRoot) { throw 'Authorization belongs to another workspace' }
if ((Get-ScheduledTask -TaskName $state.task_name).State -eq 'Running') { throw 'Another authorized operation is running' }
$requestId=[Guid]::NewGuid().ToString()
@{id=$requestId;action=$Action} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $authorizationRoot 'operation.request.json') -Encoding utf8
Start-ScheduledTask -TaskName $state.task_name
$responsePath=Join-Path $authorizationRoot 'operation.response.json'
$deadline=(Get-Date).AddMinutes(2)
while ((Get-Date) -lt $deadline) {
    if (Test-Path -LiteralPath $responsePath) {
        $response=Get-Content -LiteralPath $responsePath -Raw | ConvertFrom-Json
        if ($response.id -eq $requestId) {
            if (-not $response.success) { throw $response.error }
            $response.result | ConvertTo-Json -Depth 8
            exit 0
        }
    }
    Start-Sleep -Milliseconds 200
}
throw 'Authorized server operation timed out'
