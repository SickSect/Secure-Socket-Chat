# Usage: .\run-local.ps1 server|client
# If scripts are blocked: powershell -ExecutionPolicy Bypass -File .\run-local.ps1 server
param([Parameter(Mandatory = $true)][ValidateSet('server', 'client')][string]$Target)

Set-Location $PSScriptRoot

# Pick .env from app/ first, then repo root
$envFile = @('app\.env', '.env') | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($envFile) {
    Write-Host ">> loading $envFile"
    Get-Content $envFile -Encoding UTF8 | ForEach-Object {
        $line = $_.Replace([string][char]0xFEFF, '').Trim()
        if ($line -and -not $line.StartsWith('#') -and $line.Contains('=')) {
            $k, $v = $line.Split('=', 2)
            [Environment]::SetEnvironmentVariable($k.Trim(), $v.Trim(), 'Process')
        }
    }
} else {
    Write-Host '>> WARNING: no .env found, using defaults from application.yml'
}

switch ($Target) {
    'server' { & .\gradlew.bat bootRun }
    'client' { & .\gradlew.bat runClient --console=plain }
}
