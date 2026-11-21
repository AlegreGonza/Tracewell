<#
.SYNOPSIS
    Abre Tracewell (usa el entorno creado por instalar.ps1).
.EXAMPLE
    .\iniciar.ps1                    # ventana de escritorio
    .\iniciar.ps1 --serve-only       # en el navegador, en http://127.0.0.1:<puerto>
    .\iniciar.ps1 --self-test        # autoprueba (ventana oculta)
#>
param([Parameter(ValueFromRemainingArguments = $true)]$Rest)

$py = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
    Write-Host "Todavía no está instalado. Ejecutá primero:  .\instalar.ps1" -ForegroundColor Yellow
    exit 1
}
& $py (Join-Path $PSScriptRoot "main.py") @Rest
exit $LASTEXITCODE
