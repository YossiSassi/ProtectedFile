<# 
ProtectedFile Module - Protect/Unprotect any file (PE files, .ps1, etc.) by compressing & Encrypting content using AES 256 & gzip, and a cipher base64. uses random salt, KDF -> key+IV, and prepends salt to ciphertext.
Can be used for simple privacy stuff, as well as to avoid issues with CD&R payload entry or the occasional flagging by random EPP (AV/EDR).

Main functions: ConvertTo-ProtectedFile, ConvertFrom-ProtectedFile
Inner functions: Protect-String, Unprotect-String

Module Version: 1.0
Comments: yossis@protonmail.com (#Yossi_Sassi, 1nTh35h311)
Special thanks to Eldar Azan for his feedback!
#>

## Inner functions ##
# Protect-String function v1.0
# Get plain-text string, convert string to bytes, compress, encrypt w/AES 256 and return encrypted Base64
function Protect-String {
    param(
        [Parameter(Mandatory=$true)][string]$PlainText,
        [Parameter(Mandatory=$true)][string]$Passphrase
    )

    # 1. Convert string to bytes
    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText);

    # 2. Compress with GZip
    $ms = New-Object System.IO.MemoryStream;
    $gzip = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress);
    $gzip.Write($plainBytes, 0, $plainBytes.Length);
    $gzip.Close();
    $compressedBytes = $ms.ToArray();
    $ms.Close();

    # 3. Encryption: random salt, KDF -> key+IV, prepend salt to ciphertext
    $saltLength = 16;

    # generate random salt
    $salt = New-Object byte[] $saltLength;
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt);

    # derive key+IV
    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Passphrase, $salt, 10000);
    $aes = [System.Security.Cryptography.Aes]::Create();
    $aes.Key = $kdf.GetBytes(32);
    $aes.IV  = $kdf.GetBytes(16);

    # encrypt
    $enc = $aes.CreateEncryptor();
    $encBytes = $enc.TransformFinalBlock($compressedBytes, 0, $compressedBytes.Length);

    # allocate destination array (salt length + ciphertext length)
    $out = New-Object byte[] ($salt.Length + $encBytes.Length);

    # copy salt
    [Array]::Copy($salt, 0, $out, 0, $salt.Length);

    # copy ciphertext
    [Array]::Copy($encBytes, 0, $out, $salt.Length, $encBytes.Length);
    # base64 output (ready to store/transmit)
    $encBytes = [Convert]::ToBase64String($out);

    # 4. cleanup
    $enc.Dispose();
    $aes.Dispose();
    $kdf.Dispose();

    # 5. Output Encrypted Base64
    return $encBytes
}

# UnProtect-String function v1.0
# Get ciper base64 string, decode to bytes, decrypt bytes, de-compress string and return plain-text
function Unprotect-String {
    param(
        [Parameter(Mandatory=$true)][string]$CipherBase64,
        [Parameter(Mandatory=$true)][string]$Passphrase
    )

    # 1. Base64 decode
    $inBytes = [Convert]::FromBase64String($CipherBase64);

    # 2. Decrypt
    $saltLength = 16;
    $salt = $inBytes[0..($saltLength-1)];
    $cipherBytes = $inBytes[$saltLength..($inBytes.Length-1)];

    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Passphrase, $salt, 10000);
    $aes = [System.Security.Cryptography.Aes]::Create();
    $aes.Key = $kdf.GetBytes(32);
    $aes.IV  = $kdf.GetBytes(16);

    $dec = $aes.CreateDecryptor();
    $CompressedBytes = $dec.TransformFinalBlock($cipherBytes, 0, $cipherBytes.Length);

    # Ensure the password was typed correctly, and no error occured during un-protect process
    if (!$?)
        {
            Write-Warning "[!] An error occured while trying to unprotect the file - MAKE SURE YOU'VE TYPED THE RIGHT PASSPHRASE!`n$($Error[0].Exception.Message)";
            break
    }

    # 3. Cleanup
    $dec.Dispose();
    $aes.Dispose();
    $kdf.Dispose();

    # 4. Decompress GZip
    $ms = New-Object System.IO.MemoryStream;
    $ms.Write($compressedBytes, 0, $compressedBytes.Length);
    $ms.Position = 0;
    $gzip = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress);
    $outMs = New-Object System.IO.MemoryStream;
    $gzip.CopyTo($outMs);
    $gzip.Close();
    $ms.Close();

    $plainBytes = $outMs.ToArray();
    $outMs.Close();

    return [System.Text.Encoding]::UTF8.GetString($plainBytes)
}

## Main functions ##
# ConvertTo-ProtectedFile v1.0
# Protect input file and save it to output path (optional: copy protected string to clipboard)
function ConvertTo-ProtectedFile {
<#
.SYNOPSIS
Protect the input file and save it to output path (optional: copy protected string to clipboard).

.DESCRIPTION
ProtectedFile Module - Protect/Unprotect any file (PE files, .ps1, etc.) by compressing & Encrypting content using AES 256 & gzip, and a cipher base64. uses random salt, KDF -> key+IV, and prepends salt to ciphertext.
Can be used for simple privacy stuff, as well as to avoid issues with CD&R payload entry or the occasional flagging by random EPP (AV/EDR).

Module Version: 1.0
Comments: yossis@protonmail.com (#Yossi_Sassi, 1nTh35h311)

Main functions: ConvertTo-ProtectedFile, ConvertFrom-ProtectedFile
Inner functions: Protect-String, Unprotect-String

Inner functions:
Protect-String - Gets plain-text string, convert string to bytes, compress, encrypt w/AES 256 and return encrypted Base64
UnProtect-String - Gets ciper base64 string, decode to bytes, decrypt bytes, de-compress string and return plain-text

.PARAMETER InputFile
Full path to the file you want to compress & encrypt. e.g. c:\temp\sourcefile.exe

.PARAMETER ProtectedOutputfile
Full path to the resulted encrypted file. e.g. c:\temp\out.txt

.EXAMPLE
ConvertTo-ProtectedFile -InputFile 'C:\temp\myfile.exe' -ProtectedOutputFile 'c:\temp\ProtectedFile.txt'

Converts the PE file into a compressed/encrypted Base64 text file.

.EXAMPLE
ConvertTo-ProtectedFile -InputFile 'C:\temp\Myfile.txt' -ProtectedOutputFile 'c:\temp\ProtectedFile.whatever' -CopyProtectedStringToClipboard

Converts the text file into a compressed/encrypted file, and also copies the AES-encrypted/compressed Base64 string into the clipboard.

.NOTES
#yossi_sassi, 1nTh35h311
#>
[cmdletbinding()]
    param (
        [parameter(mandatory=$true)]
        [string]$InputFile,
        [parameter(mandatory=$true)]
        [string]$ProtectedOutputFile,
        [switch]$CopyProtectedStringToClipboard
    )

    # Step 1 - get payload from file -> exe, ps1, etc.
    if (!(Test-Path $InputFile))
        {
            Write-Warning "[!] Cannot find input file";
            break
    }

    # Get passphrase securely from the prompt
    function Get-SecurePasswordForEncryption {
    param(
        [SecureString]$Passphrase
    )

    if (-not $Password) {
        $Passphrase = Read-Host "Enter Passphrase for Encryption" -AsSecureString
    }

    return $Passphrase
    }

    # Get the DPAPI encrypted passphrase from the user
    $PassToEncrypt = Get-SecurePasswordForEncryption;

    # Get file bytes & encode to base64
    $B = [io.file]::ReadAllBytes($InputFile);
    $b64 = [convert]::ToBase64String($B);

    # Protect file content with gzip+encryption
    $ProtectedString  = Protect-String -PlainText $b64 -Passphrase $([Runtime.InteropServices.Marshal]::PtrToStringUni([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PassToEncrypt)))

    # save protected string to output file
    if ($?) {
        $ProtectedString | Out-File $ProtectedOutputFile -Encoding ascii
    }
    else
        {
        Write-Warning "An error occured while trying to protect the string.`n$($Error[0].Exception.Message)"
        break
    }

    if ($?) {
        Write-Host "Protected string saved to $ProtectedOutputFile." -ForegroundColor Cyan
    }
    else
        {
        Write-Warning "An error occured while trying to save the protected string to $($ProtectedOutputFile):`n$($Error[0].Exception.Message)"
    }

    # if specified, copy protected string to clip board
    if ($CopyProtectedStringToClipboard) {
            $ProtectedString | clip;
            Write-Host "[x] Successfully copied protected string to clipboard." -ForegroundColor Magenta    
        }
}

# ConvertFrom-ProtectedFile v1.0
# UnProtect input file and save it to output path
function ConvertFrom-ProtectedFile {
<#
.SYNOPSIS
UnProtect the input file and save it to output path.

.DESCRIPTION
ProtectedFile Module - Protect/Unprotect any file (PE files, .ps1, etc.) by compressing & Encrypting content using AES 256 & gzip, and a cipher base64. uses random salt, KDF -> key+IV, and prepends salt to ciphertext.
Can be used for simple privacy stuff, as well as to avoid issues with CD&R payload entry or the occasional flagging by random EPP (AV/EDR).

Module Version: 1.0
Comments: yossis@protonmail.com (#Yossi_Sassi, 1nTh35h311)

Main functions: ConvertTo-ProtectedFile, ConvertFrom-ProtectedFile
Inner functions: Protect-String, Unprotect-String

Inner functions:
Protect-String - Gets plain-text string, convert string to bytes, compress, encrypt w/AES 256 and return encrypted Base64
UnProtect-String - Gets ciper base64 string, decode to bytes, decrypt bytes, de-compress string and return plain-text

.PARAMETER ProtectedInputfile
Full path to the encrypted file, which was converted using ConvertTo-ProtectedFile function from this module. e.g. c:\temp\MyEncryptedFile.txt

.PARAMETER Outputfile
Full path to the file you want to de-compress & decrypt back. e.g. c:\temp\myDecryptedResult.exe

.EXAMPLE
ConvertFrom-ProtectedFile -ProtectedInputFile C:\temp\Enc.txt -OutputFile C:\temp\Myfile.exe

Converts the Base64 result file (originally produced using the ConvertTo-ProtectedFile function) into the original file (in this case, an exe).

.NOTES
#yossi_sassi, 1nTh35h311
#>
[cmdletbinding()]
    param (
        [parameter(mandatory=$true)]
        [string]$ProtectedInputFile,
        [parameter(mandatory=$true)]
        [string]$OutputFile
    )

    function Get-SecurePasswordForDecryption {
    param(
        [SecureString]$Passphrase
    )

    if (-not $Password) {
        $Passphrase = Read-Host "Enter Passphrase for Decryption" -AsSecureString
    }

    return $Passphrase
    }

    # Get the DPAPI encrypted passphrase from the user
    $PassToDecrypt = Get-SecurePasswordForDecryption;

    # Decrypt & de-compress payload
    $Encoded = Get-Content $ProtectedInputFile -Encoding Ascii;
    $decoded  = Unprotect-String -CipherBase64 $encoded -Passphrase $([Runtime.InteropServices.Marshal]::PtrToStringUni([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PassToDecrypt)));
    
    $B = [convert]::FromBase64String($decoded);
    [IO.File]::WriteAllBytes($OutputFile,$B)

    if ($?)
        {
            Write-Host "[x] Successfully saved unprotected file to $OutputFile." -ForegroundColor Green
        }
    else
        {
            Write-Warning "An error occured while trying to save unprotected file.`n$($Error[0].Exception.Message)"
        }
}