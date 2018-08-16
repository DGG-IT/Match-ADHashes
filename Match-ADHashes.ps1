function Match-ADHashes {

<#
.NAME
    Match-ADHashes

.SYNOPSIS
    Matches AD NTLM Hashes against other list of hashes

.DESCRIPTION
    Builds a hashmap of AD NTLM hashes/usernames and iterates through a second list of hashes checking for the existence of each entry in the AD NTLM hashmap
        -Outputs results as object including username, hash, and frequency in database
        -Frequency is included in output to provide additional context on the password. A high frequency (> 5) may indicate password is commonly used and not necessarily linked to specific user's password re-use.

.PARAMETER ADNTHashes
    File Path to 'Hashcat' formatted .txt file (username:hash)

.PARAMETER HashDictionary
    File Path to 'Troy Hunt Pwned Passwords' formatted .txt file (HASH:frequencycount)

.PARAMETER Verbose
    Provide run-time of function in Verbose output

.EXAMPLE
    $results = Match-ADHashes -ADNTHashes C:\temp\adnthashes.txt -HashDictionary -C:\temp\Hashlist.txt 

.OUTPUTS
    Array of HashTables with properties "User", "Frequency", "Hash"

.NOTES
    If you are seeing results for User truncated as {user1, user2, user3...} consider modifying the Preference variable $FormatEnumerationLimit (set to -1 for unlimited)
    
    =INSPIRATION / SOURCES / RELATED WORK
        -DSInternal Project https://www.dsinternals.com
        -Checkpot Project https://github.com/ryhanson/checkpot/

    =FUTURE WORK
        -Performance Testing, optimization
        -Other Languages (golang?)

.LINK
    https://github.com/DGG-IT/Match-ADHashes/

#>

    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo] $ADNTHashes,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo] $HashDictionary
    )
    #>

    process {
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        #Declare and fill new hashtable with ADNThashes. Converts to upper case to 
        $htADNTHashes = @{} 
        Import-Csv -Delimiter ":" -Path $ADNTHashes -Header "User","Hash" | % {$htADNTHashes[$_.Hash.toUpper()] += @($_.User)}

        #Create empty output object
        $mrMatchedResults = @()
       
        #Create Filestream reader 
        $fsHashDictionary = New-Object IO.Filestream $HashDictionary,'Open','Read','Read'
        $frHashDictionary = New-Object System.IO.StreamReader($fsHashDictionary) 

        #Iterate through HashDictionary checking each hash against ADNTHashes
        while (($lineHashDictionary = $frHashDictionary.ReadLine()) -ne $null) {
            if($htADNTHashes.ContainsKey($lineHashDictionary.Split(":")[0].ToUpper())) {
                $foFoundObject = [PSCustomObject]@{
                    User = $htADNTHashes[$lineHashDictionary.Split(":")[0].ToUpper()]
                    Frequency = $lineHashDictionary.Split(":")[1]
                    Hash = $linehashDictionary.Split(":")[0].ToUpper()
                }
                $mrMatchedResults += $foFoundObject               
            }
        }
        $stopwatch.Stop()
        Write-Verbose "Function Match-ADHashes completed in $($stopwatch.Elapsed.TotalSeconds) Seconds"
    }
    
    end {
        $mrMatchedResults
    }
}
