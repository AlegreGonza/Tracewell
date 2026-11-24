<#
.SYNOPSIS
  Verificacion completa: ruff, bandit, pip-audit, pytest y, si hay frontend/, lint, tests, build y audit.
.DESCRIPTION
  Corta en el primer fallo salvo con -Seguir. -Linux repite el backend en Docker (python:3.12-slim).
  Ver docs/pruebas.md.
.EXAMPLE
  .\verificar.ps1 -Seguir
  .\verificar.ps1 -Linux -Imagen python:3.13-slim
#>
param(
    [switch]$Seguir,
    [switch]$Linux,
    [switch]$SinFrontend,
    [switch]$SinRed,
    [string]$Imagen = "python:3.12-slim"
)
$ErrorActionPreference = "Continue"
Set-Location $PSScriptRoot

if ($Linux) {
    Write-Host "=== Linux en Docker ($Imagen)"
    docker run --rm -v "${PSScriptRoot}:/src:ro" $Imagen bash /src/scripts/verificar_linux.sh
    exit $LASTEXITCODE
}

$py = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }
if ($env:TRACEWELL_PYTHON) { $py = $env:TRACEWELL_PYTHON }  # p. ej. otro venv con requirements-dev.lock
$script:fallos = @()
$script:total = 0

function Invoke-Paso {
    param([string]$Nombre, [scriptblock]$Bloque)
    $script:total++
    Write-Host "`n=== $Nombre"
    $t0 = Get-Date
    & $Bloque
    $seg = [int]((Get-Date) - $t0).TotalSeconds
    if ($LASTEXITCODE -eq 0) { Write-Host "OK: $Nombre ($seg s)"; return }
    Write-Host "FALLO: $Nombre"
    $script:fallos += $Nombre
    if (-not $Seguir) {
        Write-Host "Se corta en el primer fallo (use -Seguir para continuar)."
        exit 1
    }
}

Invoke-Paso "ruff" { & $py -m ruff check backend main.py }
Invoke-Paso "bandit" { & $py -m bandit -r backend main.py -ll -c pyproject.toml -q 2>$null }
if (-not $SinRed) { Invoke-Paso "pip-audit" { & $py -m pip_audit --require-hashes -r requirements.lock } }
Invoke-Paso "pytest" { & $py -m pytest -q -p no:cacheprovider }

if (-not $SinFrontend -and (Test-Path "frontend\package.json")) {
    $pm = if (Test-Path "frontend\pnpm-lock.yaml") { "pnpm" } else { "npm" }
    Write-Host "`nFrontend con $pm"
    Push-Location frontend
    try {
        if (-not (Test-Path "node_modules")) {
            if ($pm -eq "pnpm") { Invoke-Paso "frontend: instalar" { pnpm install --frozen-lockfile } }
            else { Invoke-Paso "frontend: instalar" { npm ci } }
        }
        Invoke-Paso "frontend: lint" { & $pm run lint }
        Invoke-Paso "frontend: tests" { & $pm run test }
        Invoke-Paso "frontend: build" { & $pm run build }
        if (-not $SinRed) { Invoke-Paso "frontend: audit" { & $pm audit --audit-level=high } }
    } finally { Pop-Location }
}

Write-Host "`nPasos: $($script:total), con fallo: $($script:fallos.Count)"
if ($script:fallos.Count -gt 0) { $script:fallos | ForEach-Object { Write-Host " - $_" }; exit 1 }
