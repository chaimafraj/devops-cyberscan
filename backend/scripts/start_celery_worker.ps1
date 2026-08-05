param(
    [string]$PythonExecutable = 'python',
    [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR')]
    [string]$LogLevel = 'INFO'
)

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Set-Location -LiteralPath $projectRoot

$pythonCommand = Get-Command $PythonExecutable -ErrorAction Stop
Write-Host "CyberScan Celery worker"
Write-Host "Python : $($pythonCommand.Source)"
Write-Host "Projet : $projectRoot"
Write-Host "Pool   : solo (Windows)"
Write-Host ''

& $pythonCommand.Source -m celery -A backend worker --loglevel=$LogLevel --pool=solo --concurrency=1 --hostname='cyberscan-worker@%h'
exit $LASTEXITCODE