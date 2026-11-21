<#
.SYNOPSIS
    Instala todo lo que Tracewell necesita y verifica que abra. Windows 10/11.

.DESCRIPTION
    Detecta lo que falta y lo instala con winget (previa confirmación):
      Python 3.11+, Node.js (solo si falta frontend\dist), WebView2.
    Crea el entorno virtual .venv, instala las dependencias de requirements.txt
    y corre la autoprueba de la ventana. Se puede ejecutar varias veces: lo que
    ya está listo se omite.
    NO instala Npcap (captura en vivo): su licencia no permite instalarlo en
    silencio ni redistribuirlo; el script solo indica cómo hacerlo.
    NO cambia la política de ejecución ni ningún ajuste del sistema.

.PARAMETER Check
    Solo informa qué falta. No instala ni descarga nada.
.PARAMETER Yes
    No pregunta: acepta las instalaciones con winget.
.PARAMETER Dev
    Instala también las dependencias de desarrollo (pytest, etc.).
.PARAMETER SkipTest
    No corre la autoprueba final de la ventana.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\instalar.ps1
#>
[CmdletBinding()]
param(
    [switch]$Check,
    [switch]$Yes,
    [switch]$Dev,
    [switch]$SkipTest
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$script:Missing = New-Object System.Collections.Generic.List[string]

# ------------------------------------------------------------------ mensajes
function Write-Step($text) { Write-Host ""; Write-Host "== $text" -ForegroundColor Cyan }
function Write-Ok($text)   { Write-Host "  [OK]    $text" -ForegroundColor Green }
function Write-Warn2($text){ Write-Host "  [AVISO] $text" -ForegroundColor Yellow }
function Write-Bad($text)  { Write-Host "  [FALTA] $text" -ForegroundColor Red }

function Confirm-Action($question) {
    if ($Check) { return $false }
    if ($Yes) { return $true }
    $answer = Read-Host "  $question [s/N]"
    return ($answer -match '^(s|si|sí|y|yes)$')
}

# ------------------------------------------------------------------- winget
function Update-SessionPath {
    # Solo la sesión actual: así el programa recién instalado se encuentra sin reiniciar.
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $user = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = "$machine;$user"
}

function Install-WithWinget($id, $name) {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Warn2 "winget no está disponible. Instalá $name a mano y volvé a ejecutar este script."
        return $false
    }
    Write-Host "  Instalando $name con winget (id: $id, origen: winget)..."
    & winget install --id $id --exact --source winget --silent --accept-package-agreements --accept-source-agreements
    Update-SessionPath
    return ($LASTEXITCODE -eq 0)
}

# ------------------------------------------------------------------- Python
function Test-PythonCandidate($cmd, $extra) {
    try {
        $out = & $cmd @extra -c "import sys; print(sys.executable); print(sys.version_info[0]*100+sys.version_info[1])" 2>$null
        if ($LASTEXITCODE -ne 0 -or @($out).Count -lt 2) { return $null }
        if ([int]$out[1] -ge 311) { return [string]$out[0] }
    } catch { }   # p. ej. el alias vacío de Microsoft Store: se descarta
    return $null
}

function Find-Python {
    # Se prefiere 3.12/3.13 (versiones con las que se probó Tracewell) antes que "la más nueva".
    $candidates = @(
        @{ cmd = "py"; extra = @("-3.12") },
        @{ cmd = "py"; extra = @("-3.13") },
        @{ cmd = "py"; extra = @("-3.11") },
        @{ cmd = "py"; extra = @("-3") },
        @{ cmd = "python"; extra = @() },
        @{ cmd = "python3"; extra = @() }
    )
    foreach ($c in $candidates) {
        if (Get-Command $c.cmd -ErrorAction SilentlyContinue) {
            $found = Test-PythonCandidate $c.cmd $c.extra
            if ($found) { return $found }
        }
    }
    return $null
}

function Step-Python {
    Write-Step "1. Python 3.11 o superior"
    $py = Find-Python
    if ($py) { Write-Ok "Encontrado: $py"; return $py }
    Write-Bad "No se encontró Python 3.11+."
    if (Confirm-Action "¿Instalar Python 3.12 con winget?") {
        if (Install-WithWinget "Python.Python.3.12" "Python 3.12") { $py = Find-Python }
        if ($py) { Write-Ok "Instalado: $py"; return $py }
        Write-Warn2 "Python se instaló pero esta terminal no lo ve. Cerrá y abrí PowerShell y volvé a ejecutar."
    }
    $script:Missing.Add("Python 3.11+ (https://www.python.org/downloads/)")
    return $null
}

# -------------------------------------------------------- entorno y paquetes
function Step-Venv($py) {
    Write-Step "2. Entorno virtual (.venv)"
    $venvPy = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
    if (Test-Path $venvPy) { Write-Ok ".venv ya existe"; return $venvPy }
    if ($Check) { $script:Missing.Add("entorno virtual .venv"); Write-Bad ".venv no existe"; return $null }
    Write-Host "  Creando .venv..."
    & $py -m venv .venv
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $venvPy)) { throw "No se pudo crear el entorno virtual." }
    Write-Ok ".venv creado"
    return $venvPy
}

function Test-Dependencies($venvPy) {
    # En PowerShell 5.1 el stderr de un programa externo se vuelve error fatal con "Stop":
    # acá el import FALLA a propósito en un .venv recién creado, así que se relaja localmente.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $venvPy -c "import dpkt, yaml, fastapi, uvicorn, scapy, webview, psutil" 2>$null | Out-Null
        return ($LASTEXITCODE -eq 0)
    } finally {
        $ErrorActionPreference = $previous
    }
}

function Step-Packages($venvPy) {
    Write-Step "3. Paquetes de Python"
    if ($Dev) { $reqs = "requirements-dev.txt" } else { $reqs = "requirements.txt" }
    if (-not (Test-Path $reqs)) {
        throw "Falta $reqs. El zip 'solo para usar' no trae las dependencias de desarrollo ni los tests: usá el repositorio completo."
    }
    if (-not $Dev -and (Test-Dependencies $venvPy)) { Write-Ok "Dependencias ya instaladas"; return }
    if ($Check) { $script:Missing.Add("paquetes de Python ($reqs)"); Write-Bad "Faltan paquetes de Python"; return }
    Write-Host "  Instalando $reqs desde PyPI (puede tardar un minuto)..."
    & $venvPy -m pip install --disable-pip-version-check -r $reqs
    if ($LASTEXITCODE -ne 0) { throw "pip no pudo instalar las dependencias." }
    Write-Ok "Paquetes instalados"
}

# ----------------------------------------------------------------- interfaz
function Step-Frontend {
    Write-Step "4. Interfaz web (frontend\dist)"
    if (Test-Path "frontend\dist\index.html") { Write-Ok "La interfaz ya está compilada"; return }
    Write-Bad "Falta frontend\dist (la interfaz compilada)."
    if ($Check) { $script:Missing.Add("interfaz compilada (frontend\dist)"); return }
    if (-not (Test-Path "frontend\package.json")) {
        $script:Missing.Add("frontend\dist (este paquete no trae el código de la interfaz: volvé a descargar el zip completo)"); return
    }
    if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
        if (-not (Confirm-Action "Para compilarla hace falta Node.js. ¿Instalarlo con winget?")) {
            $script:Missing.Add("Node.js (https://nodejs.org) para compilar la interfaz"); return
        }
        if (-not (Install-WithWinget "OpenJS.NodeJS.LTS" "Node.js LTS") -or -not (Get-Command npm -ErrorAction SilentlyContinue)) {
            Write-Warn2 "Node.js no quedó disponible en esta terminal. Cerrá y abrí PowerShell y volvé a ejecutar."
            $script:Missing.Add("Node.js (https://nodejs.org) para compilar la interfaz"); return
        }
    }
    Push-Location "frontend"
    try {
        & npm install
        if ($LASTEXITCODE -ne 0) { throw "npm install falló." }
        & npm run build
        if ($LASTEXITCODE -ne 0) { throw "npm run build falló." }
    } finally { Pop-Location }
    Write-Ok "Interfaz compilada"
}

# ------------------------------------------------------------------ WebView2
function Test-WebView2 {
    $guid = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
    $keys = @(
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$guid",
        "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$guid",
        "HKCU:\Software\Microsoft\EdgeUpdate\Clients\$guid"
    )
    foreach ($k in $keys) {
        $item = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        if ($item -and $item.pv) { return $true }
    }
    return $false
}

function Step-WebView2 {
    Write-Step "5. WebView2 (la ventana de escritorio)"
    if (Test-WebView2) { Write-Ok "WebView2 instalado"; return }
    Write-Bad "No se detectó WebView2."
    if (Confirm-Action "¿Instalar el runtime de WebView2 con winget?") {
        if ((Install-WithWinget "Microsoft.EdgeWebView2Runtime" "WebView2 Runtime") -and (Test-WebView2)) {
            Write-Ok "WebView2 instalado"; return
        }
    }
    Write-Warn2 "Sin WebView2 usá el modo navegador: .\iniciar.ps1 --serve-only"
    $script:Missing.Add("WebView2 (opcional: solo para la ventana; https://developer.microsoft.com/microsoft-edge/webview2/)")
}

# --------------------------------------------------------------------- Npcap
function Step-Npcap {
    Write-Step "6. Npcap (solo para captura en vivo)"
    if ((Test-Path "$env:SystemRoot\System32\Npcap") -or (Get-Service -Name npcap -ErrorAction SilentlyContinue)) {
        Write-Ok "Npcap instalado"; return
    }
    Write-Warn2 "Npcap no está instalado. Analizar archivos .pcap funciona igual; solo la captura en vivo lo necesita."
    Write-Host "         Instalalo vos desde https://npcap.com (su licencia no permite que este script lo instale)."
}

# ------------------------------------------------------------------ autoprueba
function Step-SelfTest($venvPy) {
    Write-Step "7. Autoprueba de la ventana"
    if ($SkipTest -or $Check) { Write-Host "  Omitida."; return }
    Write-Host "  Abriendo la ventana oculta para comprobar que todo carga..."
    & $venvPy main.py --self-test
    if ($LASTEXITCODE -eq 0) { Write-Ok "Tracewell abre y funciona." }
    else { Write-Warn2 "La autoprueba falló. Probá el modo navegador: .\iniciar.ps1 --serve-only" }
}

# ----------------------------------------------------------------------- main
Write-Host "Tracewell - instalador" -ForegroundColor White
if ($Check) { Write-Host "(modo -Check: solo informa, no instala nada)" }

$python = Step-Python
$venvPython = $null
if ($python) {
    $venvPython = Step-Venv $python
    if ($venvPython) { Step-Packages $venvPython }
}
Step-Frontend
Step-WebView2
Step-Npcap
if ($venvPython -and -not $Check -and $script:Missing.Count -eq 0) { Step-SelfTest $venvPython }

Write-Host ""
if ($script:Missing.Count -gt 0) {
    Write-Host "Falta para terminar:" -ForegroundColor Yellow
    foreach ($m in $script:Missing) { Write-Host "  - $m" }
    exit 1
}
if ($Check) { Write-Host "Todo está listo. Para abrir Tracewell: .\iniciar.ps1" -ForegroundColor Green; exit 0 }
Write-Host "Listo. Para abrir Tracewell:  .\iniciar.ps1" -ForegroundColor Green
Write-Host "Modo navegador:               .\iniciar.ps1 --serve-only"
exit 0
