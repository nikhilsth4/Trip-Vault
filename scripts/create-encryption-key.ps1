<#
.SYNOPSIS
  Generates the AES-256 key TripVault uses to encrypt passport numbers in the database.

.DESCRIPTION
  Creates 32 cryptographically random bytes, Base64-encodes them, and writes
  ./keystore/tripvault-key.properties  (git-ignored)  as  TRIPVAULT_KEY=<key>.
  Spring Boot loads that file at startup (spring.config.import). Alternatively set the
  TRIPVAULT_KEY environment variable, which takes precedence.

  IMPORTANT: if you replace the key, passports already stored with the old key can no longer
  be decrypted. In production keep the key in a secrets manager (e.g. Vault, AWS KMS, Azure
  Key Vault), separate from the database and its backups.

.EXAMPLE
  .\scripts\create-encryption-key.ps1
#>
param([switch]$Force)

$ErrorActionPreference = "Stop"
$outDir  = Join-Path (Split-Path -Parent $PSScriptRoot) "keystore"
$keyFile = Join-Path $outDir "tripvault-key.properties"

if ((Test-Path $keyFile) -and -not $Force) {
    throw "Key already exists at $keyFile. Re-run with -Force to replace it (existing encrypted data becomes unreadable)."
}
New-Item -ItemType Directory -Force $outDir | Out-Null

$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
"TRIPVAULT_KEY=$([Convert]::ToBase64String($bytes))" | Out-File -FilePath $keyFile -Encoding ascii -NoNewline

Write-Host "AES-256 key written to $keyFile (keep private, never commit)"
