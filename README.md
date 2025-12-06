# ProtectedFile
Protect/Unprotect any file (PE files, .ps1, etc.) by compressing &amp; Encrypting content using AES 256 &amp; gzip, and a cipher base64. uses random salt, KDF -> key+IV, and prepends salt to ciphertext. Can be used for simple privacy stuff, as well as to avoid issues with CD&amp;R payload entry or the occasional flagging by random EPP (AV/EDR)
