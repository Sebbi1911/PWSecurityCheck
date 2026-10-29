<#
.SYNOPSIS
    Checks Active Directory accounts for compromised passwords in Online or Offline mode.
    Supports matching NTLM hashes and plaintext passwords against leak lists.

.DESCRIPTION
    This script compares the NTLM hashes of Active Directory accounts with external leak lists to identify compromised credentials.

    It supports two main operating modes:
    - 'Online': Connects to a live Domain Controller to read hashes in real time.
    - 'Offline': Works with a backup of the Active Directory database (ntds.dit) and the corresponding SYSTEM hive.

    There are also two check types:
    - 'Hashes': Compares AD NTLM hashes directly against a sorted hash file using a binary search. This is very fast.
    - 'Plaintext': Checks plaintext passwords from a leak list. Optionally, their single-edit variants (substitution, insertion, deletion) are also checked against the AD hashes.

    The script uses the DSInternals module to read AD hashes and writes a CSV report with all matches at the end.

.PARAMETER Mode
    Specifies the operating mode: "Online" or "Offline".
    - Online: Checks hashes directly against a live Domain Controller.
    - Offline: Checks hashes from an offline database (backup of ntds.dit and SYSTEM hive).

.PARAMETER DomainController
    The name or IP address of the Domain Controller. Only required in "Online" mode. Defaults to "localhost".

.PARAMETER SystemHive
    The path to the SYSTEM hive file. Only required in "Offline" mode.

.PARAMETER BackupFile
    The path to the Active Directory database backup file (e.g. ntds.dit). Only required in "Offline" mode.

.PARAMETER HashFile
    The path to a sorted file of NTLM hashes (32 hexadecimal characters per line). At least one of -HashFile or -PlainFile must be provided.

.PARAMETER PlainFile
    The path to a leak file containing plaintext passwords. At least one of -HashFile or -PlainFile must be provided.

.PARAMETER DisableVariantChecks
    Disables the check of single-edit variants of the passwords (substitution, insertion, deletion) during the plaintext check.

.EXAMPLE
    .\PWSecurityCheck.ps1 -Mode Online -HashFile C:\leaks\hashes_sorted.txt -PlainFile C:\leaks\passwords.txt

    Checks both a sorted hash list and a plaintext list against the local DC in Online mode.

.EXAMPLE
    .\PWSecurityCheck.ps1 -Mode Offline -SystemHive C:\Backup\SYSTEM -BackupFile C:\Backup\ntds.dit -HashFile C:\leaks\hashes_sorted.txt

    Checks an AD backup database against a sorted hash list only, in Offline mode.

.EXAMPLE
    .\PWSecurityCheck.ps1 -Mode Online -DomainController dc01.corp.local -PlainFile C:\leaks\passwords.txt -DisableVariantChecks

    Checks only a plaintext list against a remote DC in Online mode, without the computationally expensive variant check.

.NOTES
    Requirements:
    - PowerShell 5.1 or later
    - The DSInternals PowerShell module. Copy the DSInternals folder to C:\Program Files\WindowsPowerShell\Modules
    - Permissions: Online mode requires directory replication rights (e.g. Domain Admins). Offline mode requires read access to the backup files.

    Report:
    - All matches are saved to a CSV file in the folder C:\Temp.

    Exit codes:
    - 0: No matches found.
    - 1: Matches were found.

    Attribution:
    - The MD4 implementation (NTLM hashing) is adapted from Rosetta Code (https://rosettacode.org/wiki/MD4#C#).
    - AD hashes are read using DSInternals by Michael Grafnetter (https://github.com/MichaelGrafnetter/DSInternals).
#>

#region Configuration
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Online", "Offline")]
    [string]$Mode,   # Online or Offline mode

    [Parameter(Mandatory = $false)]
    [string]$DomainController = "localhost",   # Online mode only

    [Parameter(Mandatory = $false)]
    [string]$SystemHive,         # Offline mode only (path to the SYSTEM hive file)

    [Parameter(Mandatory = $false)]
    [string]$BackupFile,         # Offline mode only (AD database backup)

    [Parameter(Mandatory = $false)]
    [string]$HashFile,   # Path to the sorted hash file (32-char hex per line)

    [Parameter(Mandatory = $false)]
    [string]$PlainFile,  # Path to the plaintext leak file
	
	[Parameter(Mandatory = $false)]
	[switch]$DisableVariantChecks

    
)

if (-not $HashFile -and -not $PlainFile) {
    Write-Error "Bitte mindestens einen Parameter angeben: -HashFile <Pfad> und/oder -PlainFile <Pfad>"
    exit 2
}
if ($HashFile -and -not (Test-Path $HashFile)) {
    Write-Error "Hash-Datei '$HashFile' nicht gefunden."
    exit 2
}
if ($PlainFile -and -not (Test-Path $PlainFile)) {
    Write-Error "Plain-Datei '$PlainFile' nicht gefunden."
    exit 2
}
if ($DisableVariantChecks.IsPresent -and -not $PlainFile) {
	Write-Host "[?] Der -DisableVariantChecks Parameter wird ohne -PlainFile nicht genutzt. Skript läuft we"
}
if ($Mode -eq "Online") {
    if ($DomainController -eq "localhost") {
        Write-Host "[?] Default Wert `"localhost`" für -DomainController wird verwendet."
    }
    if ($BackupFile -or $SystemHive) {
        Write-Host "[?] Im Online-Modus wird kein -BackupFile oder -SystemHive benötigt."
    }
}
if ($Mode -eq "Offline") {
    if (-not ($SystemHive -and $BackupFile)) {
        Write-Error "Im Offline-Modus müssen -SystemHive und -BackupFile angegeben werden."
        exit 2
    }
}

#region Stopwatch
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
#endregion

$ReportFolder = "C:\Temp"
$MaxVariantSubstitutionsPerPassword = 50000  # Safety limit to prevent uncontrolled variant generation
$VariantCharset = @(
    'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    '0','1','2','3','4','5','6','7','8','9','!','@','#','%','^','&','*','(',')','_','+','=','-','[',']','{',
    '}','\','|',';',':',"'",'"',',','.','<','>','/','?'
)
$EnableVariantChecks = -not $DisableVariantChecks    # true = generate single-edit variants (slower)
#endregion

#region Preparation & helper functions
# Load DSInternals
try {
    Import-Module DSInternals -ErrorAction Stop
} catch {
    Write-Error "DSInternals Modul konnte nicht geladen werden. Bitte DSInternals installieren. Abbruch."
    exit 2
}

# C#-based MD4 hash function for NTLM (UTF-16LE)
# Source: MD4 C# implementation from Rosetta Code (https://rosettacode.org/wiki/MD4#C#), slightly modified.
# Rosetta Code content is available under the GNU Free Documentation License 1.2
# (https://www.gnu.org/licenses/fdl-1.2.html).
Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
public static class Md4
{
    public static string Md4Hash(this string input)
    {
        // get padded uints from bytes
        List<byte> bytes = Encoding.Unicode.GetBytes(input).ToList();
        uint bitCount = (uint)(bytes.Count) * 8;
        bytes.Add(128);
        while (bytes.Count % 64 != 56) bytes.Add(0);
        var uints = new List<uint>();
        for (int i = 0; i + 3 < bytes.Count; i += 4)
            uints.Add(bytes[i] | (uint)bytes[i + 1] << 8 | (uint)bytes[i + 2] << 16 | (uint)bytes[i + 3] << 24);
        uints.Add(bitCount);
        uints.Add(0);

        // run rounds
        uint a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
        Func<uint, uint, uint> rol = (x, y) => x << (int)y | x >> 32 - (int)y;
        for (int q = 0; q + 15 < uints.Count; q += 16)
        {
            var chunk = uints.GetRange(q, 16);
            uint aa = a, bb = b, cc = c, dd = d;
            Action<Func<uint, uint, uint, uint>, uint[]> round = (f, y) =>
            {
                foreach (uint i in new[] { y[0], y[1], y[2], y[3] })
                {
                    a = rol(a + f(b, c, d) + chunk[(int)(i + y[4])] + y[12], y[8]);
                    d = rol(d + f(a, b, c) + chunk[(int)(i + y[5])] + y[12], y[9]);
                    c = rol(c + f(d, a, b) + chunk[(int)(i + y[6])] + y[12], y[10]);
                    b = rol(b + f(c, d, a) + chunk[(int)(i + y[7])] + y[12], y[11]);
                }
            };
            round((x, y, z) => (x & y) | (~x & z), new uint[] { 0, 4, 8, 12, 0, 1, 2, 3, 3, 7, 11, 19, 0 });
            round((x, y, z) => (x & y) | (x & z) | (y & z), new uint[] { 0, 1, 2, 3, 0, 4, 8, 12, 3, 5, 9, 13, 0x5a827999 });
            round((x, y, z) => x ^ y ^ z, new uint[] { 0, 2, 1, 3, 0, 8, 4, 12, 3, 9, 11, 15, 0x6ed9eba1 });
            a += aa; b += bb; c += cc; d += dd;
        }

        // return hex encoded string
        byte[] outBytes = new[] { a, b, c, d }.SelectMany(BitConverter.GetBytes).ToArray();
        return BitConverter.ToString(outBytes).Replace("-", "").ToLower();
    }
}
"@ -Language CSharp

Add-Type -TypeDefinition 'using System.Collections.Concurrent; public static class PwCheckResults { public static ConcurrentBag<object> Results = new ConcurrentBag<object>(); }' -Language CSharp

function Get-NTLMHashHex([string]$password) {
    return [Md4]::Md4Hash($password)
}

# Helper: generates simple single-edit variants (substitution, insertion, deletion)
Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;

public static class Variants {
    public static HashSet<string> GetVariantsOneEdit(string pwd, int maxVariants, char[] charset) {
        var variants = new HashSet<string>(StringComparer.Ordinal);
        int len = pwd.Length;

        // Substitution
        for (int i = 0; i < len; i++) {
            foreach (char c in charset) {
                if (pwd[i] != c) {
                    string v = pwd.Substring(0, i) + c + pwd.Substring(i + 1);
                    variants.Add(v);
                    if (variants.Count >= maxVariants) return variants;
                }
            }
        }

        // Insertion
        for (int i = 0; i <= len; i++) {
            foreach (char c in charset) {
                string v = pwd.Substring(0, i) + c + pwd.Substring(i);
                variants.Add(v);
                if (variants.Count >= maxVariants) return variants;
            }
        }

        // Deletion
        if (len > 0) {
            for (int i = 0; i < len; i++) {
                string v = pwd.Substring(0, i) + pwd.Substring(i + 1);
                variants.Add(v);
                if (variants.Count >= maxVariants) return variants;
            }
        }

        return variants;
    }
}
"@
#endregion

#region Retrieve AD hashes
if ($Mode -eq "Online") {
    Write-Host "[*] AD-Hashes mittels DSInternals abrufen (Online-Modus)..."

    try {
        # Get-ADReplAccount returns, among other things, the NT hash as byte[] in the 'NTHash' or 'PasswordHashes' property
        $adAccounts = Get-ADReplAccount -All -DomainController $DomainController -ErrorAction Stop
    } catch {
        Write-Error "Get-ADReplAccount fehlgeschlagen: $_.Exception.Message"
        exit 3
    }
}
elseif ($Mode -eq "Offline") {
    Write-Host "[*] AD-Hashes aus System Hive oder Backup-Datei laden (Offline-Modus)..."

    try {
        $bootkey = Get-BootKey -SystemHiveFilePath $SystemHive
        $adAccounts = Get-ADDBAccount -All -BootKey $bootkey -DatabasePath $BackupFile -ErrorAction Stop
    } catch {
        Write-Error "Offline-Analyse mit System Hive fehlgeschlagen: $_.Exception.Message"
        exit 3
    }
}
# Normalize entries: SamAccountName, SID, NT hash (lowercase hex)
$adHashMap = @{}   # NTLM hash (hex) => list of accounts
foreach ($acc in $adAccounts) {
    # DSInternals may return the NT hash as byte[] in .NTHash or .PasswordHashes.NTHash
    $hex = $null
    if ($acc -and $acc.NTHash) {
        $b = $acc.NTHash
        if ($b -is [byte[]]) {
            $hex = ([System.BitConverter]::ToString($b)).Replace('-','').ToLowerInvariant()
        } elseif ($b -is [string]) {
            $hex = $b.ToLowerInvariant()
        }
    } elseif ($acc.PasswordHashes -and $acc.PasswordHashes.NTHash) {
        $b = $acc.PasswordHashes.NTHash
        if ($b -is [byte[]]) {
            $hex = ([System.BitConverter]::ToString($b)).Replace('-','').ToLowerInvariant()
        } elseif ($b -is [string]) {
            $hex = $b.ToLowerInvariant()
        }
    }
    if ($hex) {
        if (-not $adHashMap.ContainsKey($hex)) { $adHashMap[$hex] = @() }
        $adHashMap[$hex] += @{
            SamAccountName = $acc.SamAccountName
            DistinguishedName = $acc.DistinguishedName
            SID = $acc.SID
        }
    }
}

Write-Host ("[*] AD-Hashes geladen: {0} unique NTLM-Hashes" -f $adHashMap.Count)
#endregion

#region Process leak list & comparisons (streaming + unified progress bar)

# Binary search in a sorted file (for hash mode)
function BinarySearch-HashInFile {
    param(
        [string]$filePath,
        [string]$targetHash
    )

    $lineLength = 34  # 16 byte NTLM Hash + "\r\n"
    $fileSize = (Get-Item $filePath).Length
    $totalLines = [int64]($fileSize / $lineLength)

    $fs = [System.IO.File]::Open($filePath, 'Open', 'Read', 'Read')
    $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8)
    
    try {
        $low = 0
        $high = $totalLines - 1

        #Write-Host "==========================================="
        #Write-Host "DEBUG: TargetHash = $targetHash"

        while ($low -le $high) {
            $mid = [int64](($low + $high) / 2)
            $offset = $mid * $lineLength

            $sr.DiscardBufferedData()
            $fs.Seek($offset, [System.IO.SeekOrigin]::Begin) | Out-Null
            $line = $sr.ReadLine()

            #Write-Host "------------------------------------------"
            #Write-Host "DEBUG: mid = $mid, offset = $offset, low = $low, high = $high"
            #Write-Host "DEBUG: line = $line"

            if ($null -eq $line) { break }
            $entry = $line.Trim().ToLowerInvariant()

            if ($entry -eq $targetHash) {
                return $true
            } elseif ($entry -lt $targetHash) {
                $low = $mid + 1
            } else {
                $high = $mid - 1
            }
        }

        return $false
    } finally {
        $sr.Close()
        $fs.Close()
    }
}


$resultRows = @()

function Add-Result([string]$Type, [string]$Source, [string]$MatchedHash, [string]$AccountInfo, [string]$Notes) {
    $script:resultRows += [PSCustomObject]@{
        Timestamp   = (Get-Date).ToString("s")
        Type        = $Type
        Source      = $Source
        MatchedHash = $MatchedHash
        Account     = $AccountInfo
        Notes       = $Notes
    }
}

function Process-Hashes {
    param([string]$leakedHashFile)

    Write-Host "[*] Modus: Hashes – vergleiche AD-Hashes gegen Leaked-Datei mittels Binärsuche..."

    foreach ($adHash in $adHashMap.Keys) {
        $found = BinarySearch-HashInFile -filePath $leakedHashFile -targetHash $adHash
        if ($found) {
            $accounts = ($adHashMap[$adHash] | ForEach-Object { "$($_.SamAccountName) ($($_.SID))" }) -join ";"
            Add-Result -Type "ADHashInLeak" -Source $adHash -MatchedHash $adHash -AccountInfo $accounts -Notes "AD-Hash in Leaked-Datei gefunden"
            Write-Host ("[!] Treffer: AD-Hash {0} -> {1}" -f $adHash, $accounts)
        }
    }
}

function Process-Plaintext {
    param(
        [string]$leakedPlainFile,
        [int]$BatchSize = 10
    )

    # Clear old results so they do not accumulate
    [PwCheckResults]::Results = [System.Collections.Concurrent.ConcurrentBag[object]]::new()

    Write-Host "[*] Modus: Plaintext – streame Leak-Datei, prüfe Hashes & Varianten (BatchSize=$BatchSize)..."

    # Open file (streaming)
    $fs = [System.IO.File]::Open($leakedPlainFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8)
    $totalBytes = $fs.Length
    if ($totalBytes -eq 0) {
        Write-Error "Leaked-Datei ist leer. Abbruch."
        $sr.Close(); $fs.Close()
        return
    }

    $lineCount = 0
    $lastPercent = -1

    # Batch collector
    $batch = @()

    while (-not $sr.EndOfStream -or ($sr.EndOfStream -and $batch.Count -gt 0)) {
        $line = $sr.ReadLine()
        $lineCount++
        if (-not $line) { continue }
        $entry = $line.Trim(" `t`r`n")
        if ($entry -eq "") { continue }

        $batch += $entry

        # Progress (byte-based)
        $pos = $fs.Position
        $percent = [int](($pos / $totalBytes) * 100)
        if ($percent -ne $lastPercent) {
            $lastPercent = $percent
            Write-Progress -Id 1 -Activity "Leaked-Passwörter prüfen (gesamt)" -Status "Fortschritt: $percent% ($lineCount Zeilen)" -PercentComplete $percent
        }

        # When the batch is full, process it
        if ($batch.Count -ge $BatchSize -or $sr.EndOfStream) {
            # serialize adHashMap only once; pass the serialized value to the script
            $adSerialized = [System.Management.Automation.PSSerializer]::Serialize($adHashMap)

            $localBatch = $batch  # capture the current batch
            $batch = @()          # reset the collector

            foreach ($plain in $localBatch) {
                # 1) Check the original password (uses the global C# type Md4)
                try {
                    $nt = [Md4]::Md4Hash($plain)
                } catch {
                    # Fallback: in case the Md4 type is not loaded (should not happen)
                    $nt = (Get-NTLMHashHex $plain)
                }

                if ($adHashMap.ContainsKey($nt)) {
                    $accounts = ($adHashMap[$nt] | ForEach-Object { "$($_.SamAccountName) ($($_.SID))" }) -join ";"
                    $result = [PSCustomObject]@{
                        Timestamp   = (Get-Date).ToString("s")
                        Type        = "LeakedPlainMatch"
                        Source      = $plain
                        MatchedHash = $nt
                        Account     = $accounts
                        Notes       = "Klartext-PW Hash stimmt exakt überein"
                    }
                    [PwCheckResults]::Results.Add($result)
                }

                # 2) Check variants
                if ($EnableVariantChecks) {
                    $variants = [Variants]::GetVariantsOneEdit($plain, $MaxVariantSubstitutionsPerPassword, $VariantCharset)
                    foreach ($v in $variants) {
                        $vhash = [Md4]::Md4Hash($v)
                        if ($adHashMap.ContainsKey($vhash)) {
                            $accounts = ($adHashMap[$vhash] | ForEach-Object { "$($_.SamAccountName) ($($_.SID))" }) -join ";"
                            $result = [PSCustomObject]@{
                                Timestamp   = (Get-Date).ToString("s")
                                Type        = "LeakedVariantMatch"
                                Source      = $plain
                                MatchedHash = $vhash
                                Account     = $accounts
                                Notes       = "Variante '$v' stimmt (1-Änderung)"
                            }
                            [PwCheckResults]::Results.Add($result)
                        }
                    }
                }
            }
        }
    }

    # Move results from the ConcurrentBag into the result list (once)
    foreach ($r in [PwCheckResults]::Results) {
        $script:resultRows += $r
    }

    # Cleanup
    $sr.Close()
    $fs.Close()

    Write-Progress -Id 1 -Activity "Leaked-Passwörter prüfen (gesamt)" -Completed
    Write-Host ("[*] Klartextprüfung abgeschlossen. Zeilen gelesen: {0}" -f $lineCount)
}
#endregion
 
#region Dispatcher: select processing based on parameters
if ($HashFile -and (Test-Path $HashFile)) {
    Process-Hashes -leakedHashFile $HashFile
}
if ($PlainFile -and (Test-Path $PlainFile)) {
    Process-Plaintext -leakedPlainFile $PlainFile
}
#endregion
    
#region Write report
$timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$reportFile = Join-Path $ReportFolder ("AD_PwHashCheck_Report_$timestamp.csv")
$resultRows | Export-Csv -Path $reportFile -NoTypeInformation -Encoding UTF8
Write-Host "[*] Report geschrieben: $reportFile"
#endregion

#region Stop timer and print runtime
$stopwatch.Stop()
Write-Host "[*] Gesamtzeit Laufzeit: $($stopwatch.Elapsed.ToString())"
#endregion

# Exit code: 0 = OK (no matches), 1 = matches found
if ($resultRows.Count -gt 0) {
    Write-Host "[!] Es wurden Treffer gefunden. Bitte Report prüfen."
    exit 1
} else {
    Write-Host "[*] Keine Treffer gefunden."
    exit 0
}
