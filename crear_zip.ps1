<#
.SYNOPSIS
    Arma el .zip "solo para usar" de Tracewell: sin tests, sin código fuente de la
    interfaz y sin archivos generados (.venv, __pycache__, node_modules).

.DESCRIPTION
    Copia a una carpeta temporal únicamente lo necesario para EJECUTAR la app,
    lo comprime en release\tracewell-<versión>.zip y calcula su SHA-256.
    No modifica el proyecto. La carpeta temporal se borra al terminar.
    Requiere que frontend\dist esté compilada (si falta, avisa cómo hacerlo).

.PARAMETER OutDir
    Carpeta de salida (por defecto: release\ dentro del proyecto).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\crear_zip.ps1
#>
[CmdletBinding()]
param([string]$OutDir = "release")

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

# Lo que va en el zip: archivos sueltos y carpetas (de las carpetas se omiten tests y basura).
$Files = @(
    "main.py", "pyproject.toml", "requirements.txt", "README.md",
    "instalar.ps1", "instalar.sh", "iniciar.ps1", "iniciar.sh",
    "samples\demo.pcap"
)
$Dirs = @("backend", "rules", "docs", "frontend\dist")
$SkipDirNames = @("tests", "__pycache__", ".pytest_cache", ".mypy_cache", "node_modules", ".venv")
$SkipExtensions = @(".pyc", ".pyo")

function Get-Version {
    $line = Select-String -Path "pyproject.toml" -Pattern '^\s*version\s*=\s*"([^"]+)"' | Select-Object -First 1
    if (-not $line) { throw "No se encontró la versión en pyproject.toml." }
    return $line.Matches[0].Groups[1].Value
}

function Test-Skipped($fullPath, $root) {
    $relative = $fullPath.Substring($root.Length).TrimStart("\", "/")
    foreach ($part in ($relative -split "[\\/]")) { if ($SkipDirNames -contains $part) { return $true } }
    return ($SkipExtensions -contains [IO.Path]::GetExtension($fullPath).ToLower())
}

function Copy-Project($stage) {
    foreach ($f in $Files) {
        if (-not (Test-Path $f)) { throw "Falta $f (necesario para el zip)." }
        $dest = Join-Path $stage $f
        New-Item -ItemType Directory -Force (Split-Path $dest) | Out-Null
        Copy-Item $f $dest
    }
    $root = (Get-Location).Path
    foreach ($d in $Dirs) {
        if (-not (Test-Path $d)) { throw "Falta la carpeta $d." }
        Get-ChildItem $d -Recurse -File | ForEach-Object {
            if (Test-Skipped $_.FullName $root) { return }
            $dest = Join-Path $stage ($_.FullName.Substring($root.Length).TrimStart("\", "/"))
            New-Item -ItemType Directory -Force (Split-Path $dest) | Out-Null
            Copy-Item $_.FullName $dest
        }
    }
}

function New-ZipFromFolder($stage, $zipPath, $topFolder) {
    # Se arma con .NET y rutas con "/" : Compress-Archive de PowerShell 5.1 escribe "\"
    # y el zip no se descomprime bien en Linux/macOS.
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    $zip = [IO.Compression.ZipFile]::Open($zipPath, [IO.Compression.ZipArchiveMode]::Create)
    try {
        Get-ChildItem $stage -Recurse -File | ForEach-Object {
            $name = $topFolder + "/" + ($_.FullName.Substring($stage.Length).TrimStart("\", "/") -replace "\\", "/")
            [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $_.FullName, $name, [IO.Compression.CompressionLevel]::Optimal)
        }
    } finally { $zip.Dispose() }
}

# ----------------------------------------------------------------------- main
if (-not (Test-Path "frontend\dist\index.html")) {
    Write-Host "Falta frontend\dist (la interfaz compilada). Compilala primero:" -ForegroundColor Yellow
    Write-Host "  cd frontend; npm install; npm run build"
    exit 1
}
$version = Get-Version
$topFolder = "tracewell-$version"
$stage = Join-Path ([IO.Path]::GetTempPath()) ("tracewell_zip_" + [Guid]::NewGuid().ToString("N"))
try {
    New-Item -ItemType Directory $stage | Out-Null
    Copy-Project $stage
    New-Item -ItemType Directory -Force $OutDir | Out-Null
    $zipPath = Join-Path (Resolve-Path $OutDir).Path "$topFolder.zip"
    New-ZipFromFolder $stage $zipPath $topFolder
} finally {
    if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
}
$hash = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLower()
Set-Content -Path "$zipPath.sha256" -Value "$hash  $topFolder.zip" -Encoding ASCII
$size = [math]::Round((Get-Item $zipPath).Length / 1KB)
Write-Host "Listo: $zipPath ($size KB)" -ForegroundColor Green
Write-Host "SHA-256: $hash"
Write-Host "Quien lo use: descomprime, entra a la carpeta y ejecuta .\instalar.ps1 (Windows) o bash instalar.sh (Linux/macOS)."
