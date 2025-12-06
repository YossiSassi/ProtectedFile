## ProtectedFile PowerShell Module

ProtectedFile.psm1 is a lightweight PowerShell module designed to simplify Protecting/Unprotecting any file (PE files, .ps1, etc.) by compressing & Encrypting content using AES 256 & gzip, and a cipher base64.<Br>Uses random salt, KDF -> key+IV, and prepends salt to ciphertext.<br>
Can be used for simple privacy stuff, as well as to avoid issues with CD&R payload entry or the occasional flagging by random EPP (AV/EDR).
<br>

The protected file also keeps low entropy (or medium, if originally packed/compressed), unlike "un-protected really-Encrypted file". See the screenshot for Entropy comparison:
<br><br>
![Sample results](/screenshots/screenshot_lowentropy.png) <br><br>
<br>

🚀 Features

* Protect / Unprotect any file

* Drop protected file on disk without worrying of EPPs flagging the file, until it's safe (inside a Sandbox, maybe?)

* Protect/Unprotect functions (Two main ones + 2 inner functions) contained in a single .psm1 module

* No external dependencies required
<br>
📦 Installation<br><br>
Clone the repository

```
git clone https://github.com/YossiSassi/ProtectedFile
```

Import the module
```
Import-Module .\ProtectedFile\ProtectedFile.psm1
```

Or install globally:
```
Copy-Item .\ProtectedFile.psm1 "$env:USERPROFILE\Documents\PowerShell\Modules\ProtectedFile\"
Import-Module ProtectedFile
```
<br>
🔧 Usage Examples
<br><br>

Converts the PE file into a compressed/encrypted cipher-Base64 text file:
```
ConvertTo-ProtectedFile -InputFile 'C:\temp\myfile.exe' -ProtectedOutputFile 'c:\temp\ProtectedFile.txt'
```

Converts the text file into a compressed/encrypted file, and also copies the AES-encrypted/compressed Base64 string into the clipboard:
```
ConvertTo-ProtectedFile -InputFile 'C:\temp\Myfile.txt' -ProtectedOutputFile 'c:\temp\ProtectedFile.whatever' -CopyProtectedStringToClipboard
```

Converts the Base64 result file (originally produced using the ConvertTo-ProtectedFile function) into the original file (in this case, an exe):
```
ConvertFrom-ProtectedFile -ProtectedInputFile C:\temp\Enc.txt -OutputFile C:\temp\Myfile.exe
```
<br>
💬 Comments, Questions, 'The Big Lebowski' quotes etc.
<br>
<p> ... are Welcome!</p>
<br>
🙌 Thanks
<br>
Special thanks to Eldar Azan for his feedback!
