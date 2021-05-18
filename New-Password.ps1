
# FUNCTION  : New-Password
# PURPOSE   : Generates a cryptographically strong secure password.

function New-Password
{
    # how many characters are in the secure key
    [CmdletBinding()]
    param( 
        [int]$length = 16
    )

    Write-Verbose "New-Password: Starting."
    # create the set of characters that will be used for the secure key
    Write-Verbose "New-Password: Generating base characters for SecureKey."

    if ($length -lt 8)
    {
        return (Write-Error "The password must be at least 8 characters long." -EA Stop)
    }

    $lowerCaseLetters = [UInt32][char]"a"..[UInt32][char]"z"
    $domain = $lowerCaseLetters

    $upperCaseLetters = [UInt32][char]"A"..[UInt32][char]"Z"
    $domain += $upperCaseLetters

    $numbers = [UInt32][char]"0"..[UInt32][char]"9"
    $domain += $numbers

    $symbols = [UInt32[]]('!#$%()*+,-./'.ToCharArray())
    $symbols += 58..64  # ':;<=>?@'
    $symbols += 91..96   # '[\]^_`'
    $symbols += 123..126    # '{|}~'
    $domain += $symbols

    Write-Verbose "New-Password: Running calculations."
    $numberOfPossiblePasswords = [BigInt]::Pow($domain.Length, $Length)
    $bitsOfEntropy = [Math]::Log($numberOfPossiblePasswords)/[Math]::Log(2.0)

    if ($bitsOfEntropy -eq [double]::PositiveInfinity)
    {
        Write-Verbose "New-Password: Length is too long."
        return
    }

    $bitsToGenerate = [UInt32]([Math]::Ceiling($bitsOfEntropy))
    $bytesToGenerate = ($bitsToGenerate + 7) -shr 3

    # bias is bounded by number of extra bytes generated. +1 byte yields a bound of 1/256.
    $largest_value_allowed = [BigInt]::Pow(256, $bytesToGenerate) - [BigInt]::ModPow(256, $bytesToGenerate, $numberOfPossiblePasswords)

    Write-Verbose "New-Password: Generating the key."
    $randomBytes = New-Object byte[] $bytesToGenerate
    $random = New-Object Security.Cryptography.RNGCryptoServiceProvider

    do
    {
        $passwordRequirementsMet = $true

        do
        {
            $random.GetBytes($randomBytes)

            # add an extra 0 at the end (the most significant byte) to guarantee that we treat this as a positive number
            $randomBytesPositive = [byte[]]($randomBytes + [byte]0)

            # now, get the integer value of this array of random bytes
            $randomValue = [BigInt]$randomBytesPositive

            if ($Verbose)
            {
                if ($randomValue -gt $largest_value_allowed)
                {
                    Write-Verbose ("Getting a new number because:`n    {0}`n    {1}`n" -f $randomValue.ToString("N0"), $largest_value_allowed.ToString("N0"))
                }
            }

        } while ($randomValue -gt $largest_value_allowed);

        # now, generate the password
        $password = New-Object Text.StringBuilder

        $lowerCaseCharactersPresent = $false
        $upperCaseCharactersPresent = $false
        $numberCharactersPresent = $false
        $symbolCharactersPresent = $false

        for ($i=0 ; $i -lt $Length ; $i++)
        {
            $index = $randomValue % ($domain.Length)
            $character = $domain[$index]

            if ($lowerCaseLetters -contains $character)
            { 
                Write-Verbose "Lower case: $([char]$character)"
                $lowerCaseCharactersPresent = $true
            }
            
            if ($upperCaseLetters -contains $character)
            { 
                Write-Verbose "Upper case: $([char]$character)"
                $upperCaseCharactersPresent = $true
            }
            
            if ($numbers -contains $character)
            { 
                Write-Verbose "Numer: $([char]$character)"
                $numberCharactersPresent = $true
            }

            if ($symbols -contains $character)
            { 
                Write-Verbose "Symbol: $([char]$character)"
                $symbolCharactersPresent = $true
            }

            $randomValue = $randomValue / $domain.Length

            $null = $password.Append([char]$character)
        }

        if ( (-not $lowerCaseCharactersPresent) -or (-not $upperCaseCharactersPresent) -or (-NOT $numberCharactersPresent) -or (-NOT $symbolCharactersPresent) )
        {
            if ($Verbose) { Write-Verbose "Trying again because something is missing." }
            $passwordRequirementsMet = $false
        }
        else
        {
            Write-Verbose ("Left over value`: {0}" -f $randomValue.ToString("N0"))
            $crackTime = ([double]$numberOfPossiblePasswords / (1000000000.0 * 60.0 * 60.0 * 24.0 * 365.24))
            Write-Verbose ("Your password has {0} bits of entropy, and there are {1} possible passwords." -f $bitsOfEntropy, $numberOfPossiblePasswords.ToString("N0"))
            Write-Verbose ("It would take {0} years to brute-force crack (at 1 attempt per nanosecond)." -f $crackTime.ToString("N"))
        }
    } while (-not $passwordRequirementsMet)

    $random = $null

    Write-Verbose "New-Password: Work complete!"
    return $password.ToString()
} #end New-Password
