#Requires -Version 5.1
<#
.SYNOPSIS
    Generates a local development TLS keystore and client truststore.

.DESCRIPTION
    Creates:
      certs/server-keystore.p12  - server private key + certificate (PKCS#12)
      certs/server.crt           - exported public certificate
      certs/client-truststore.p12 - truststore containing the server certificate

    The certificate is valid for localhost and 127.0.0.1. This is for local
    development only; use a real CA in production.

.PARAMETER Password
    Password for both the keystore and the truststore. Default: changeit.

.PARAMETER OutDir
    Output directory. Default: the directory containing this script.
#>
param(
    [string]$Password = "changeit",
    [string]$OutDir = $PSScriptRoot
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Password)) {
    throw "Password must not be empty."
}
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path (Get-Location) "certs"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$keytool = "keytool"
if ($env:JAVA_HOME) {
    $candidate = Join-Path $env:JAVA_HOME "bin\keytool.exe"
    if (Test-Path $candidate) {
        $keytool = $candidate
    }
}

$keyStore = Join-Path $OutDir "server-keystore.p12"
$certFile = Join-Path $OutDir "server.crt"
$trustStore = Join-Path $OutDir "client-truststore.p12"

foreach ($file in @($keyStore, $certFile, $trustStore)) {
    if (Test-Path $file) {
        Remove-Item -Force $file
    }
}

Write-Host ">> Generating server key pair and certificate..."
& $keytool -genkeypair `
    -alias server `
    -keyalg RSA `
    -keysize 2048 `
    -validity 825 `
    -dname "CN=localhost, OU=Development, O=Secure-Chat, L=Local, C=US" `
    -ext "SAN=dns:localhost,ip:127.0.0.1" `
    -storetype PKCS12 `
    -keystore $keyStore `
    -storepass $Password `
    -keypass $Password

if ($LASTEXITCODE -ne 0) {
    throw "keytool -genkeypair failed with exit code $LASTEXITCODE"
}

Write-Host ">> Exporting public certificate..."
& $keytool -exportcert `
    -alias server `
    -keystore $keyStore `
    -storepass $Password `
    -rfc `
    -file $certFile

if ($LASTEXITCODE -ne 0) {
    throw "keytool -exportcert failed with exit code $LASTEXITCODE"
}

Write-Host ">> Creating client truststore..."
& $keytool -importcert `
    -noprompt `
    -alias secure-chat-server `
    -file $certFile `
    -storetype PKCS12 `
    -keystore $trustStore `
    -storepass $Password

if ($LASTEXITCODE -ne 0) {
    throw "keytool -importcert failed with exit code $LASTEXITCODE"
}

Write-Host ""
Write-Host "Done. Set these values in .env:"
Write-Host "  TLS_KEYSTORE=certs/server-keystore.p12"
Write-Host "  TLS_KEYSTORE_PASSWORD=$Password"
Write-Host "  TLS_KEY_PASSWORD=$Password"
Write-Host "  TLS_TRUSTSTORE=certs/client-truststore.p12"
Write-Host "  TLS_TRUSTSTORE_PASSWORD=$Password"
