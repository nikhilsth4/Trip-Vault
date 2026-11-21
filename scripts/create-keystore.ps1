<#
.SYNOPSIS
  Creates the PKCS12 keystore that Spring Boot's embedded Tomcat uses to serve HTTPS.

.DESCRIPTION
  Uses the JDK's keytool to generate an RSA key pair plus a self-signed X.509 certificate.
  The certificate's Subject Alternative Names (SAN) cover localhost, this computer's name and
  its IPv4 addresses, so the app can be reached over HTTPS from other machines on the network.

  Outputs (all in ./keystore, which is git-ignored so secrets never reach source control):
    securedb.p12                  - keystore holding the private key + certificate
    securedb.cer                  - public certificate only (import it as "trusted" on client machines)
    keystore-secret.properties    - the keystore password, read by Spring Boot at startup

  For production, replace the self-signed certificate with one issued by your company's CA
  or a public CA (e.g. Let's Encrypt); the Spring Boot configuration stays the same.

.EXAMPLE
  .\scripts\create-keystore.ps1
  .\scripts\create-keystore.ps1 -ExtraSan "dns:securedb.corp.local"
#>
param(
    [string]$Alias        = "securedb",
    [int]   $ValidityDays = 365,
    [string]$ExtraSan     = "",       # optional extra SAN entries, comma separated
    [switch]$Force                     # overwrite an existing keystore
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$outDir      = Join-Path $projectRoot "keystore"
$keystore    = Join-Path $outDir "$Alias.p12"
$certFile    = Join-Path $outDir "$Alias.cer"
$secretFile  = Join-Path $outDir "keystore-secret.properties"

# --- 1. Locate keytool (ships with every JDK) -------------------------------------------------
$keytool = if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME "bin\keytool.exe" } else { "keytool" }
if (-not (Get-Command $keytool -ErrorAction SilentlyContinue)) {
    throw "keytool not found. Set JAVA_HOME to your JDK (e.g. C:\Users\<you>\.jdks\ms-21.0.7)."
}

if ((Test-Path $keystore) -and -not $Force) {
    throw "Keystore already exists at $keystore. Re-run with -Force to replace it."
}
New-Item -ItemType Directory -Force $outDir | Out-Null
if (Test-Path $keystore) { Remove-Item $keystore -Force }

# --- 2. Generate a strong random keystore password (never hard-coded in source) ----------------
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$password = [Convert]::ToBase64String($bytes) -replace '[+/=]', ''

# --- 3. Build the Subject Alternative Name list (browsers validate SAN, not CN) ----------------
$san = @("dns:localhost", "ip:127.0.0.1", "dns:$($env:COMPUTERNAME.ToLower())")
Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
    ForEach-Object { $san += "ip:$($_.IPAddress)" }
if ($ExtraSan) { $san += $ExtraSan.Split(",") | ForEach-Object { $_.Trim() } }
$sanExt = "SAN=" + ($san -join ",")

# --- 4. Generate key pair + self-signed certificate into a PKCS12 keystore --------------------
#   -keyalg RSA -keysize 3072 : NIST-recommended strength beyond 2030
#   -sigalg SHA256withRSA     : modern signature algorithm (no SHA-1)
#   -storetype PKCS12         : industry-standard format (JKS is legacy)
#   -ext KeyUsage/EKU         : restrict the certificate to TLS server authentication
& $keytool -genkeypair `
    -alias $Alias `
    -keyalg RSA -keysize 3072 -sigalg SHA256withRSA `
    -validity $ValidityDays `
    -storetype PKCS12 -keystore $keystore `
    -storepass $password `
    -dname "CN=localhost, OU=IT Security, O=Cumberlands Secure Coding, L=Williamsburg, ST=KY, C=US" `
    -ext $sanExt `
    -ext "KeyUsage=digitalSignature,keyEncipherment" `
    -ext "ExtendedKeyUsage=serverAuth"
if ($LASTEXITCODE -ne 0) { throw "keytool -genkeypair failed" }

# --- 5. Export the public certificate (safe to share; clients import it to trust the server) ---
& $keytool -exportcert -alias $Alias -keystore $keystore -storepass $password -rfc -file $certFile
if ($LASTEXITCODE -ne 0) { throw "keytool -exportcert failed" }

# --- 6. Store the password for Spring Boot (git-ignored file, read via spring.config.import) ---
"KEYSTORE_PASSWORD=$password" | Out-File -FilePath $secretFile -Encoding ascii -NoNewline

Write-Host ""
Write-Host "Keystore created:   $keystore"
Write-Host "Certificate:        $certFile"
Write-Host "Password file:      $secretFile  (keep private, never commit)"
Write-Host "SAN entries:        $($san -join ', ')"
Write-Host ""
Write-Host "Optional - trust the certificate on this machine (removes the browser warning):"
Write-Host "  Import-Certificate -FilePath `"$certFile`" -CertStoreLocation Cert:\CurrentUser\Root"
