# descifrar_token.ps1 — Reconstruye token.pickle desde token_cifrado.txt (en la VDI).
# No instala nada: usa el PowerShell que ya viene en Windows.
# Uso, en la carpeta del AppEmail.exe:
#   powershell -ExecutionPolicy Bypass -File descifrar_token.ps1
$ErrorActionPreference = 'Stop'
$ITERS = 200000

$in = Join-Path $PWD 'token_cifrado.txt'
if (-not (Test-Path $in)) { throw "No encuentro token_cifrado.txt en esta carpeta." }

$blob = [Convert]::FromBase64String(((Get-Content $in -Raw).Trim()))
if ($blob.Length -le 64) { throw "Archivo cifrado invalido." }

$salt = [byte[]]($blob[0..15])
$iv   = [byte[]]($blob[16..31])
$mac  = [byte[]]($blob[32..63])
$ct   = [byte[]]($blob[64..($blob.Length - 1)])

$sec = Read-Host 'Contrasena' -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
$pw = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

$kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($pw, $salt, $ITERS, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
$dk = $kdf.GetBytes(64)
$kEnc = [byte[]]($dk[0..31])
$kMac = [byte[]]($dk[32..63])

$ivct = New-Object byte[] ($iv.Length + $ct.Length)
[Array]::Copy($iv, 0, $ivct, 0, $iv.Length)
[Array]::Copy($ct, 0, $ivct, $iv.Length, $ct.Length)
$hmac = New-Object System.Security.Cryptography.HMACSHA256(,$kMac)
$calc = $hmac.ComputeHash($ivct)
if ([Convert]::ToBase64String($calc) -ne [Convert]::ToBase64String($mac)) {
    throw "Contrasena incorrecta (o archivo corrupto). No se escribio nada."
}

$aes = [System.Security.Cryptography.Aes]::Create()
$aes.KeySize = 256; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'
$aes.Key = $kEnc; $aes.IV = $iv
$dec = $aes.CreateDecryptor()
$plain = $dec.TransformFinalBlock($ct, 0, $ct.Length)

[IO.File]::WriteAllBytes((Join-Path $PWD 'token.pickle'), $plain)
Write-Host "OK: token.pickle restaurado. Ya puedes abrir AppEmail.exe." -ForegroundColor Green
