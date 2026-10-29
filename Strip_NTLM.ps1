param (
    [Parameter(Mandatory = $true)]
    [string]$InputFile,

    [Parameter(Mandatory = $false)]
    [string]$OutputFile = "$InputFile`_cleaned.txt"
)

if (-not (Test-Path $InputFile)) {
    Write-Error "Datei '$InputFile' nicht gefunden."
    exit 1
}

# Datei-Größe für Fortschrittsermittlung
$inputFileSize = (Get-Item $InputFile).Length
$bytesRead = 0

# StreamReader und StreamWriter verwenden
$reader = [System.IO.StreamReader]::new($InputFile)
$writer = [System.IO.StreamWriter]::new($OutputFile, $false)

# Fortschrittsbalken-Setup
$progressActivity = "Verarbeite NTLM-Hash-Datei"
$progressId = 1
$lastPercent = -1

try {
    while (-not $reader.EndOfStream) {
        $line = $reader.ReadLine()
        $bytesRead += ([System.Text.Encoding]::UTF8.GetByteCount($line) + 2)  # +2 für CRLF

        # Nur NTLM-Hash behalten (Teil vor dem ersten ':')
        $hash = $line.Split(':')[0].Trim()
        if ($hash -ne '') {
            $writer.WriteLine($hash)
        }

        # Fortschrittsanzeige (nur bei neuem Prozentstand updaten)
        $percent = [math]::Round(($bytesRead / $inputFileSize) * 100)
        if ($percent -ne $lastPercent) {
            Write-Progress -Activity $progressActivity -Status "$percent% abgeschlossen" -PercentComplete $percent -Id $progressId
            $lastPercent = $percent
        }
    }
}
finally {
    $reader.Close()
    $writer.Close()
    Write-Progress -Activity $progressActivity -Completed -Id $progressId
    Write-Host "Fertig. Ergebnis gespeichert in '$OutputFile'"
}
