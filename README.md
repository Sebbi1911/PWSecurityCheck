# PWSecurityCheck

This PowerShell script audits Active Directory accounts for compromised passwords using external leak lists. It compares AD password hashes against hash or plaintext files to identify potential matches.

---

## Overview

The script supports two main operating modes and two types of checks:

**Operating Modes:**
- **`Online`**: Connects to a live Domain Controller to read hashes in real-time.
- **`Offline`**: Works with a backup of the Active Directory database (`ntds.dit`) and its corresponding SYSTEM hive, requiring no network connection to the AD.

**Check Types:**
- **Hashes**: Directly compares AD NTLM hashes against a **sorted** hash file using a high-performance binary search.
- **Plaintext**: Checks plaintext passwords from a leak list. Optionally, it can also test their single-edit distance variants (substitution, insertion, deletion) against AD hashes.

The script utilizes the [DSInternals PowerShell module](https://github.com/MichaelGrafnetter/DSInternals) to extract AD hashes and generates a CSV report listing all detected matches.

---

## Prerequisites

- PowerShell (preferably version 5.1 or later)
- The [DSInternals PowerShell module](https://github.com/MichaelGrafnetter/DSInternals) must be installed:
  ```powershell
  Install-Module DSInternals -Scope CurrentUser
  ```
  For systems without internet access, download the module on another machine with `Save-Module DSInternals -Path .\modules` and copy the `DSInternals` folder to `C:\Program Files\WindowsPowerShell\Modules` on the target machine.
  The last tested version of DSInternal was 6.1.1, which can be specified with the `-RequiredVersion 6.1.1` parameter. Newer versions (e.g. 7.x) are expected to work but have not been verified.
- **Permissions:**
  - **Online Mode**: Rights to replicate directory changes (e.g., membership in "Domain Admins" or delegated permissions for `Get-ADReplAccount`).
  - **Offline Mode**: Read access to an AD database backup (`ntds.dit`) and the associated SYSTEM hive file.
- A **sorted** hash file (one 32-character NTLM hash per line) and/or a plaintext password leak file as input.
  - The hash file must use **Windows line endings (CRLF)**. The binary search assumes a fixed line length of 34 bytes (32 hex characters + CRLF); files with Unix line endings (LF) will not work. `Strip_NTLM.ps1` writes CRLF when run on Windows.

---

## Usage

Run the script with the appropriate parameters for the desired mode.

### Online Mode

Checks against a live Domain Controller.

```powershell
# Check hashes and plaintext passwords against the local DC
.\PWSecurityCheck.ps1 -Mode Online -HashFile <PathToSortedHashFile> -PlainFile <PathToPlaintextFile>

# Check only plaintext passwords against a remote DC, without variant checks
.\PWSecurityCheck.ps1 -Mode Online -DomainController "dc01.corp.local" -PlainFile <PathToPlaintextFile> -DisableVariantChecks
```

### Offline Mode

Checks against a backup of the AD database.

```powershell
# Check hashes from an AD backup
.\PWSecurityCheck.ps1 -Mode Offline -SystemHive "C:\Backup\SYSTEM" -BackupFile "C:\Backup\ntds.dit" -HashFile <PathToSortedHashFile>

# Check plaintext passwords and their variants against an AD backup
.\PWSecurityCheck.ps1 -Mode Offline -SystemHive "C:\Backup\SYSTEM" -BackupFile "C:\Backup\ntds.dit" -PlainFile <PathToPlaintextFile>
```

### Parameters

| Parameter | Description | Required |
|---|---|---|
| `-Mode` | Specifies the operating mode: `Online` (against a live DC) or `Offline` (against backup files). | Yes |
| `-DomainController` | Name or IP address of the Domain Controller. Relevant in `Online` mode only. Defaults to `localhost`. | No |
| `-SystemHive` | Path to the SYSTEM hive file. | Yes (in `Offline` mode only) |
| `-BackupFile` | Path to the Active Directory database backup (e.g., `ntds.dit`). | Yes (in `Offline` mode only) |
| `-HashFile` | Path to a **sorted** file of NTLM hashes (32 hex characters per line). | No (but at least one of `-HashFile` or `-PlainFile` must be provided) |
| `-PlainFile` | Path to a leak file containing plaintext passwords. | No (but at least one of `-HashFile` or `-PlainFile` must be provided) |
| `-DisableVariantChecks` | Disables the single-edit variant check for plaintext passwords. | No |

---

## How It Works

1.  Based on the `-Mode` parameter, the script loads AD account data either directly from a Domain Controller (`Online`) or from an offline backup (`Offline`).
2.  The NTLM hashes of the AD are normalized and stored in a hash table for fast lookups.
3.  **Hash Mode**: The script performs a binary search on the sorted hash file to find matches with the AD hashes.
4.  **Plaintext Mode**: Each password from the leak file is hashed and compared against the AD hashes.
    -   If not disabled, single-edit distance variants (substitution, insertion, deletion) are also generated, hashed, and compared.
5.  All matches are saved in a CSV report file located at `C:\Temp\AD_PwHashCheck_Report_<timestamp>.csv`.
6.  The total runtime is displayed.
7.  The script exits with one of the following codes:
    -   `0` if no matches were found.
    -   `1` if matches were found.

---

## Sample Output

```
[*] Retrieving AD hashes using DSInternals (Online Mode)...
[*] Loaded 1234 unique NTLM hashes
[*] Mode: Hashes – comparing AD hashes against leaked file with binary search...
[!] Match found: AD hash d41d8cd98f00b204e9800998ecf8427e -> user1 (S-1-5-21-...)
[*] Report written: C:\Temp\AD_PwHashCheck_Report_20240601_123455.csv
[*] Total runtime: 00:00:15.2436725
[!] Matches found! Please review the report.
```

---

## Notes

- In `Online` mode, the script can connect to any Domain Controller (defaults to `localhost`). In `Offline` mode, it operates entirely without a network connection.
- Variant checking (with `-PlainFile`) is enabled by default. It can significantly increase runtime.
- The maximum number of variants generated per password can be adjusted via the `$MaxVariantSubstitutionsPerPassword` variable (default: 50,000) to prevent uncontrolled generation.

---

## Acknowledgements

- **MD4 implementation:** The C# MD4 hash function used to compute NTLM hashes from plaintext passwords is adapted (slightly modified) from the [MD4 implementation on Rosetta Code](https://rosettacode.org/wiki/MD4#C#). Rosetta Code content is available under the [GNU Free Documentation License 1.2](https://www.gnu.org/licenses/fdl-1.2.html).
- **DSInternals:** AD hashes are read using the [DSInternals PowerShell module](https://github.com/MichaelGrafnetter/DSInternals) by Michael Grafnetter. DSInternals is a separate project and is not included in this repository.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Contact

For questions or improvements, please open an issue.

## Disclaimer

This tool is intended for authorized security assessments only. It is provided as-is, without warranty of any kind; use it at your own risk.