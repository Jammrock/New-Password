# New-Password
Creates a cryptographically sound password using the RNGCryptoServiceProvider in Windows.

# Load the function locally
```PowerShell
iwr https://raw.githubusercontent.com/Jammrock/New-Password/main/New-Password.ps1 | iex
```

# Add a loader function to your PowerShell profile

Open the PowerShell profile in a text editor.

```powershell
# If you have VS Code installed
code $PROFILE

# If you do it old school
notepad $PROFILE
```

Add this line to the profile and save.

```powershell
function Load-Password { iwr https://raw.githubusercontent.com/Jammrock/New-Password/main/New-Password.ps1 -SslProtocol Tls12 | iex; iex "function Global:New-Password {$((Get-Command New-Password).ScriptBlock)}" }
```

When you want to download and use New-Password.

```powershell
Load-Password
New-Password
```
