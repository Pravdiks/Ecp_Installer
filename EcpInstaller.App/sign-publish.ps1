# Сборка и подпись EcpInstaller.exe
# 1) Сборка: dotnet publish в ./publish
# 2) Подпись: если заданы CERT_PFX и CERT_PASSWORD — подписываем exe (signtool или PowerShell)

$ErrorActionPreference = "Stop"
$projectDir = $PSScriptRoot
$publishDir = Join-Path $projectDir "publish"
$exePath = Join-Path $publishDir "EcpInstaller.exe"

# Публикация
Push-Location $projectDir
try {
    dotnet publish -c Release -r win-x64 --self-contained true `
        -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:EnableCompressionInSingleFile=true `
        -o $publishDir
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally { Pop-Location }

# Подпись своим сертификатом (опционально)
$pfx = $env:CERT_PFX
$pwd = $env:CERT_PASSWORD
if ($pfx -and $pwd -and (Test-Path $pfx) -and (Test-Path $exePath)) {
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($pfx, $pwd)
    $sig = Set-AuthenticodeSignature -FilePath $exePath -Certificate $cert -HashAlgorithm SHA256
    Write-Host "Подпись: $($sig.Status)" -ForegroundColor Cyan
} else {
    Write-Host "CERT_PFX и CERT_PASSWORD не заданы — exe не подписан сторонним сертификатом." -ForegroundColor Yellow
}

Write-Host "Готово: $exePath" -ForegroundColor Green
