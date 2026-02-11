#Requires -Version 5.1
<#
.SYNOPSIS
    Monash BuildForge – Bare Metal Init (WinRE / PS 5.1 compatible)

.DESCRIPTION
    Fully automated bare-metal Windows provisioning script.
    Handles disk partitioning, OS image download + apply, driver injection,
    and UEFI boot initialisation – all from WinPE/WinRE.

    Steps:
        1. Disk selection & GPT partitioning (ESP → MSR → Windows → Recovery)
        2. OS catalog lookup + ESD download (with hash verification)
        3. Image apply via DISM
        4. SoftPaq driver download, extraction & offline injection
        5. UEFI boot initialisation via bcdboot

    Requires: WinPE/WinRE with DISM tools, bcdboot; network for catalog/ESD.
    WARNING:  Destructive to the target disk.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Windows 11')]
    [string] $OperatingSystem = 'Windows 11',

    [ValidateSet('24H2', '25H2', '26H2')]
    [string] $ReleaseId = '25H2',

    [ValidateSet('amd64', 'arm64')]
    [string] $Architecture = 'amd64',

    [ValidateSet('en-us')]
    [string] $LanguageCode = 'en-us',

    [ValidateSet('Volume')]
    [string] $License = 'Volume',

    [int] $ImageIndex = 6,

    # Paths (now optional, will default to Windows volume:\BuildOSD)
    [string] $OsDownloadDir = '',

    # Target disk
    [int] $TargetDiskNumber = -1,

    # Drivers
    [string] $DriverSoftPaqUrl = 'https://ftp.hp.com/pub/softpaq/sp160001-160500/sp160195.exe',

    # Skip flags
    [switch] $SkipPartitioning,
    [switch] $SkipApplyImage,
    [switch] $SkipDrivers,
    [switch] $SkipBootInit,

    # Boot
    [string] $BcdBootExtraArgs = '',

    # OS Catalog
    [string] $CatalogUri = 'https://raw.githubusercontent.com/OSDeploy/OSD/refs/heads/master/cache/os-catalogs/build-operatingsystems.xml'
)

$ErrorActionPreference = 'Stop'

$script:CurrentStep = 0
$script:TotalSteps  = 6

function Start-Step {
    param([string] $Description)
    $script:CurrentStep++
    Write-Divider
    Write-Host (" STEP {0} of {1}  –  {2}" -f $script:CurrentStep, $script:TotalSteps, $Description) -ForegroundColor Cyan
    Write-Divider
    Write-Log -Message "=== STEP $($script:CurrentStep): $Description ===" -Level STEP
}

function Get-TempRoot {
    if ($env:TEMP -and (Test-Path -LiteralPath $env:TEMP)) { return $env:TEMP }
    return 'X:\'
}

$script:LogPath = Join-Path (Get-TempRoot) ("BuildForge_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
try {
    $logDir = Split-Path -Path $script:LogPath -Parent
    if (-not (Test-Path -LiteralPath $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    New-Item -ItemType File -Path $script:LogPath -Force | Out-Null
} catch { }

function Write-Log {
    param(
        [Parameter(Mandatory)][string] $Message,
        [ValidateSet('INFO', 'STEP', 'WARN', 'ERROR', 'SUCCESS')]
        [string] $Level = 'INFO'
    )
    $line = "[{0:HH:mm:ss}] [{1,-7}] {2}" -f (Get-Date), $Level, $Message
    try { Add-Content -Path $script:LogPath -Value $line -ErrorAction SilentlyContinue } catch { }
}

function Write-Info {
    param([string] $Message)
    Write-Host "  [INFO]    $Message" -ForegroundColor Gray
    Write-Log   -Message $Message -Level INFO
}

function Write-Warn {
    param([string] $Message)
    Write-Host "  [WARN]    $Message" -ForegroundColor Yellow
    Write-Log   -Message $Message -Level WARN
}

function Write-Fail {
    param([string] $Message)
    Write-Host "  [ERROR]   $Message" -ForegroundColor Red
    Write-Log   -Message $Message -Level ERROR
}

function Write-Ok {
    param([string] $Message)
    Write-Host "  [OK]      $Message" -ForegroundColor Green
    Write-Log   -Message $Message -Level SUCCESS
}

function Write-Divider {
    Write-Host ("─" * 72) -ForegroundColor DarkGray
}

function Show-Banner {
    $banner = @"
            ███╗   ███╗ ██████╗ ███╗   ██╗ █████╗ ███████╗██╗  ██╗                
            ████╗ ████║██╔═══██╗████╗  ██║██╔══██╗██╔════╝██║  ██║                
            ██╔████╔██║██║   ██║██╔██╗ ██║███████║███████╗███████║                
            ██║╚██╔╝██║██║   ██║██║╚██╗██║██╔══██║╚════██║██╔══██║                
            ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║  ██║███████║██║  ██║                
            ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝                
                                                                                  
██████╗ ██╗   ██╗██╗██╗     ██████╗     ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
██╔══██╗██║   ██║██║██║     ██╔══██╗    ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
██████╔╝██║   ██║██║██║     ██║  ██║    █████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
██╔══██╗██║   ██║██║██║     ██║  ██║    ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  
██████╔╝╚██████╔╝██║███████╗██████╔╝    ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
╚═════╝  ╚═════╝ ╚═╝╚══════╝╚═════╝     ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
"@
    $banner -split "`r?`n" | ForEach-Object {
        Write-Host $_ -ForegroundColor Cyan
    }
}

function Show-CompletionSummary {
    param([System.Collections.IDictionary] $Results)
    Write-Host ""
    Write-Divider
    Write-Host "  BUILD COMPLETE" -ForegroundColor Green
    Write-Divider
    foreach ($key in $Results.Keys) {
        Write-Host ("  {0,-30} {1}" -f "${key}:", $Results[$key]) -ForegroundColor White
    }
    Write-Divider
    Write-Host ("  Log saved to: {0}" -f $script:LogPath) -ForegroundColor DarkCyan
    Write-Host ""
}

function Get-SystemInfo {
    $osCaption = 'Unknown / WinRE'
    try { $osCaption = (Get-CimInstance Win32_OperatingSystem).Caption } catch { }
    [pscustomobject]@{
        PSVersion = $PSVersionTable.PSVersion
        OSCaption = $osCaption
    }
}

function Enable-Tls12 {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    } catch { }
}

function Resolve-CurlPath {
    $candidates = @(
        (Join-Path $env:WINDIR 'System32\curl.exe'),
        'curl.exe'
    )
    foreach ($path in $candidates) {
        if (Get-Command $path -ErrorAction SilentlyContinue) {
            return (Get-Command $path).Path
        }
    }
    return $null
}

function Invoke-FileDownload {
    param(
        [Parameter(Mandatory)] [string] $Url,
        [Parameter(Mandatory)] [string] $DestPath,
        [int] $Retries = 2
    )

    Enable-Tls12
    $curl      = Resolve-CurlPath
    $attempts  = $Retries + 1

    for ($try = 1; $try -le $attempts; $try++) {
        Write-Info "Downloading (attempt $try / $attempts): $Url"

        try {
            if ($curl) {
                Write-Info "Using native curl.exe for download..."
                & $curl --fail --location --silent --show-error `
                        --connect-timeout 30 --output $DestPath $Url
                if ($LASTEXITCODE -ne 0) {
                    throw "curl exited with code $LASTEXITCODE."
                }
            } else {
                Write-Info "curl.exe not found – falling back to Invoke-WebRequest..."
                Invoke-WebRequest -Uri $Url -OutFile $DestPath -UseBasicParsing -ErrorAction Stop
            }

            if (-not (Test-Path -LiteralPath $DestPath)) {
                throw "HTTP call succeeded but file is missing on disk. Disk full?"
            }

            Write-Ok "Download complete: $DestPath"
            return $DestPath

        } catch {
            Write-Warn "Attempt $try failed: $($_.Exception.Message)"
            if ($try -lt $attempts) {
                Write-Info "Waiting 3 seconds before retry..."
                Start-Sleep -Seconds 3
            } else {
                throw "All $attempts download attempts failed for '$Url'."
            }
        }
    }
}

function Confirm-FileHash {
    param(
        [Parameter(Mandatory)] [string] $FilePath,
        [string] $ExpectedSha1,
        [string] $ExpectedSha256
    )

    if ($ExpectedSha1) {
        Write-Info "Verifying SHA1 hash..."
        $actual = (Get-FileHash -Algorithm SHA1 -Path $FilePath).Hash.ToLowerInvariant()
        $expect = $ExpectedSha1.ToLowerInvariant().Trim()
        if ($actual -ne $expect) {
            throw "SHA1 mismatch on '$FilePath'.`n  Expected : $expect`n  Got      : $actual"
        }
        Write-Ok "SHA1 verified."
    }

    if ($ExpectedSha256) {
        Write-Info "Verifying SHA256 hash..."
        $actual = (Get-FileHash -Algorithm SHA256 -Path $FilePath).Hash.ToLowerInvariant()
        $expect = $ExpectedSha256.ToLowerInvariant().Trim()
        if ($actual -ne $expect) {
            throw "SHA256 mismatch on '$FilePath'.`n  Expected : $expect`n  Got      : $actual"
        }
        Write-Ok "SHA256 verified."
    }
}

function Get-TargetDisk {
    param([int] $PreferredNumber = -1)

    if ($PreferredNumber -ge 0) {
        Write-Info "Using manually specified disk number: $PreferredNumber"
        $disk = Get-Disk -Number $PreferredNumber -ErrorAction Stop

        if ($disk.BusType -eq 'USB') {
            throw "Disk $PreferredNumber is a USB device – refusing to target it."
        }

        if ($disk.IsOffline) {
            Write-Warn "Disk $PreferredNumber is offline – bringing it online..."
            Set-Disk -Number $disk.Number -IsOffline:$false -ErrorAction Stop
        }
        if ($disk.IsReadOnly) {
            Write-Warn "Disk $PreferredNumber is read-only – clearing that flag..."
            Set-Disk -Number $disk.Number -IsReadOnly:$false -ErrorAction Stop
        }
        return $disk
    }

    Write-Info "No disk number specified – scanning for the best candidate..."
    return Find-BestInternalDisk
}

function Find-BestInternalDisk {
    $candidates = Get-Disk | Where-Object {
        $_.BusType    -ne 'USB'  -and
        -not $_.IsOffline        -and
        -not $_.IsReadOnly       -and
        -not $_.IsBoot           -and
        -not $_.IsSystem
    } | Sort-Object Size -Descending

    if (-not $candidates) {
        Write-Warn "No ready disks found. Attempting to bring offline disks online..."
        Get-Disk | Where-Object { $_.BusType -ne 'USB' -and $_.IsOffline } | ForEach-Object {
            try {
                Set-Disk -Number $_.Number -IsOffline:$false -ErrorAction Stop
                Write-Info "Disk $($_.Number) brought online."
            } catch {
                Write-Warn "Could not bring disk $($_.Number) online: $($_.Exception.Message)"
            }
        }

        $candidates = Get-Disk | Where-Object {
            $_.BusType    -ne 'USB'  -and
            -not $_.IsOffline        -and
            -not $_.IsReadOnly       -and
            -not $_.IsBoot           -and
            -not $_.IsSystem
        } | Sort-Object Size -Descending
    }

    if (-not $candidates) {
        throw "No suitable internal disk found. Ensure at least one non-USB, non-boot disk is attached."
    }

    $chosen = $candidates | Select-Object -First 1
    Write-Info ("Found {0} candidate disk(s). Selected Disk {1} ({2} GB, BusType={3})." -f
        @($candidates).Count, $chosen.Number, [math]::Round($chosen.Size / 1GB, 1), $chosen.BusType)
    return $chosen
}

function Clear-AndInitializeDisk {
    param([Parameter(Mandatory)] [int] $DiskNumber)

    Write-Warn "!!! ALL DATA on Disk $DiskNumber will be permanently erased !!!"
    Set-Disk  -Number $DiskNumber -IsReadOnly:$false -ErrorAction SilentlyContinue | Out-Null
    Set-Disk  -Number $DiskNumber -IsOffline:$false  -ErrorAction SilentlyContinue | Out-Null
    Clear-Disk -Number $DiskNumber -RemoveData -RemoveOEM -Confirm:$false
    Initialize-Disk -Number $DiskNumber -PartitionStyle GPT
    Write-Ok "Disk $DiskNumber cleared and initialised as GPT."
}

function New-EspPartition {
    param([Parameter(Mandatory)] [int] $DiskNumber)

    Write-Info "Creating EFI System Partition (ESP) – 100 MB, FAT32..."
    $esp = New-Partition -DiskNumber $DiskNumber -Size 100MB `
                         -GptType '{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}'
    Format-Volume -Partition $esp -FileSystem FAT32 -NewFileSystemLabel 'System' `
                  -Confirm:$false -Force | Out-Null
    Write-Ok "ESP created."
    return $esp
}

function New-MsrPartition {
    param([Parameter(Mandatory)] [int] $DiskNumber)

    Write-Info "Creating Microsoft Reserved Partition (MSR) – 16 MB..."
    New-Partition -DiskNumber $DiskNumber -Size 16MB `
                  -GptType '{E3C9E316-0B5C-4DB8-817D-F92DF00215AE}' | Out-Null
    Write-Ok "MSR created."
}

function New-WindowsPartition {
    <#
        Creates the Windows partition using all remaining space.
        Assigns drive letter W: (WinPE owns C:).
        Returns the partition object.
    #>
    param([Parameter(Mandatory)] [int] $DiskNumber)

    Write-Info "Creating Windows partition (max available size, NTFS)..."

    $windows = New-Partition -DiskNumber $DiskNumber -UseMaximumSize `
                              -GptType '{EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}' `
                              -AssignDriveLetter

    Write-Info "Assigning Windows partition to W: (C: is reserved by WinPE)..."
    Set-Partition -DiskNumber $windows.DiskNumber `
                  -PartitionNumber $windows.PartitionNumber `
                  -NewDriveLetter W | Out-Null

    Format-Volume -DriveLetter W -FileSystem NTFS -NewFileSystemLabel 'Windows' `
                  -Confirm:$false -Force | Out-Null

    Write-Ok "Windows partition created and mounted as W:."
    return Get-Partition -DiskNumber $DiskNumber -PartitionNumber $windows.PartitionNumber
}

function Resize-WindowsForRecovery {
    param(
        [Parameter(Mandatory)] [int] $DiskNumber,
        [Parameter(Mandatory)] [int] $PartitionNumber,
        [long] $ShrinkByBytes = 750MB
    )

    $part       = Get-Partition -DiskNumber $DiskNumber -PartitionNumber $PartitionNumber
    $supported  = Get-PartitionSupportedSize -DiskNumber $DiskNumber -PartitionNumber $PartitionNumber
    $targetSize = [math]::Max($supported.SizeMin, ($part.Size - $ShrinkByBytes))

    if ($targetSize -ge $part.Size) {
        Write-Warn "Windows partition cannot be shrunk (disk too small?). Recovery will be skipped."
        return $false
    }

    Write-Info ("Shrinking Windows partition by {0} MB..." -f [math]::Round($ShrinkByBytes / 1MB))
    Resize-Partition -DiskNumber $DiskNumber -PartitionNumber $PartitionNumber -Size $targetSize
    Write-Ok "Windows partition resized."
    return $true
}

function New-RecoveryPartition {
    param([Parameter(Mandatory)] [int] $DiskNumber)

    Write-Info "Creating Recovery partition – 750 MB, NTFS..."
    try {
        $recovery = New-Partition -DiskNumber $DiskNumber -UseMaximumSize `
                                  -GptType '{DE94BBA4-06D1-4D40-A16A-BFD50179D6AC}'
        Format-Volume -Partition $recovery -FileSystem NTFS -NewFileSystemLabel 'Recovery' `
                      -Confirm:$false -Force | Out-Null
        Write-Ok "Recovery partition created."
    } catch {
        Write-Warn "Recovery partition creation failed (non-fatal): $($_.Exception.Message)"
    }
}

function Initialize-DiskLayout {
    param([Parameter(Mandatory)] [int] $DiskNumber)

    Write-Info "Laying out Windows 11 UEFI/GPT partition scheme on Disk $DiskNumber..."
    Write-Info "  ESP     – 100 MB  FAT32"
    Write-Info "  MSR     – 16 MB   (unformatted)"
    Write-Info "  Windows – max     NTFS (mounted as W:, shrunk by 750 MB)"
    Write-Info "  Recovery– 750 MB  NTFS"
    Write-Host ""

    Clear-AndInitializeDisk -DiskNumber $DiskNumber
    New-EspPartition        -DiskNumber $DiskNumber | Out-Null
    New-MsrPartition        -DiskNumber $DiskNumber
    $winPart = New-WindowsPartition -DiskNumber $DiskNumber

    $shrunk = Resize-WindowsForRecovery -DiskNumber $DiskNumber -PartitionNumber $winPart.PartitionNumber
    if ($shrunk) {
        New-RecoveryPartition -DiskNumber $DiskNumber
    }

    Write-Ok "Partition layout complete. W: is ready for the OS image."
    return $winPart
}

function Get-OsCatalogFile {
    param([Parameter(Mandatory)] [string] $CatalogUri)

    Enable-Tls12
    Write-Info "Downloading OS catalog from OSD project..."
    $tmpPath = Join-Path ([IO.Path]::GetTempPath()) ("os-catalog_{0}.xml" -f [guid]::NewGuid())

    try {
        Invoke-WebRequest -Uri $CatalogUri -UseBasicParsing -OutFile $tmpPath -ErrorAction Stop
        Write-Ok "Catalog downloaded."
        return $tmpPath
    } catch {
        throw "Failed to download OS catalog from '$CatalogUri': $($_.Exception.Message)"
    }
}

function ConvertFrom-CatalogFile {
    param([Parameter(Mandatory)] [string] $FilePath)

    try {
        $entries = Import-Clixml -Path $FilePath -ErrorAction Stop
        Write-Info "Parsed catalog as CLIXML – $(@($entries).Count) entries loaded."
        return $entries
    } catch {
        Write-Warn "CLIXML parse failed – attempting raw XML fallback..."
    }

    try {
        [xml]$xml    = Get-Content -LiteralPath $FilePath -Raw
        $nodes       = $xml.SelectNodes('//Object')
        $entries     = @()

        if ($nodes -and $nodes.Count -gt 0) {
            foreach ($node in $nodes) {
                $props = @{}
                foreach ($prop in $node.Property) { $props[$prop.Name] = $prop.InnerText }
                $entries += New-Object psobject -Property $props
            }
            Write-Info "Parsed catalog as XML – $($entries.Count) entries loaded."
            return $entries
        }

        throw "Unrecognised XML structure – no <Object> nodes found."
    } catch {
        throw "Unable to parse catalog as CLIXML or XML: $($_.Exception.Message)"
    }
}

function Select-BestCatalogEntry {
    param(
        [Parameter(Mandatory)] [object[]] $Entries,
        [Parameter(Mandatory)] [string]   $OperatingSystem,
        [Parameter(Mandatory)] [string]   $ReleaseId,
        [Parameter(Mandatory)] [string]   $Architecture,
        [Parameter(Mandatory)] [string]   $LanguageCode,
        [Parameter(Mandatory)] [string]   $License
    )

    Write-Info "Filtering catalog for: $OperatingSystem $ReleaseId $Architecture $LanguageCode $License"

    $filtered = $Entries | Where-Object {
        $_.OperatingSystem -eq $OperatingSystem -and
        $_.ReleaseId       -eq $ReleaseId       -and
        $_.Architecture    -eq $Architecture    -and
        $_.LanguageCode    -eq $LanguageCode    -and
        $_.License         -eq $License
    }

    if (-not $filtered) {
        return $null
    }

    Write-Info "$(@($filtered).Count) matching entry/entries found – selecting latest build..."

    $latest = $filtered | Sort-Object -Descending -Property {
        $v = [string]$_.Build
        try { [version]$v } catch { [version]'0.0' }
    } | Select-Object -First 1

    return [pscustomobject]@{
        ESDUrl = $latest.Url
        Sha1   = if ([string]::IsNullOrWhiteSpace([string]$latest.Sha1))   { '' } else { [string]$latest.Sha1 }
        Sha256 = if ([string]::IsNullOrWhiteSpace([string]$latest.Sha256)) { '' } else { [string]$latest.Sha256 }
    }
}

function Resolve-OsCatalogEntry {
    param(
        [string] $CatalogUri,
        [string] $OperatingSystem,
        [string] $ReleaseId,
        [string] $Architecture,
        [string] $LanguageCode,
        [string] $License
    )

    $tmpFile = $null
    try {
        $tmpFile = Get-OsCatalogFile       -CatalogUri $CatalogUri
        $entries = ConvertFrom-CatalogFile -FilePath $tmpFile
        $entry   = Select-BestCatalogEntry -Entries $entries `
                        -OperatingSystem $OperatingSystem -ReleaseId $ReleaseId `
                        -Architecture $Architecture -LanguageCode $LanguageCode `
                        -License $License

        if (-not $entry) {
            throw "No matching OS entry found in catalog."
        }

        Write-Ok "Resolved OS entry from catalog."
        return $entry
    } finally {
        if ($tmpFile -and (Test-Path -LiteralPath $tmpFile)) {
            Remove-Item -LiteralPath $tmpFile -Force -ErrorAction SilentlyContinue
        }
    }
}

function Save-OsImage {
    param(
        [Parameter(Mandatory)] [string] $Url,
        [string] $Sha1Hash,
        [string] $Sha256Hash,
        [Parameter(Mandatory)] [string] $DestinationDir
    )

    if (-not (Test-Path -LiteralPath $DestinationDir)) {
        New-Item -ItemType Directory -Path $DestinationDir -Force | Out-Null
    }

    $fileName = Split-Path -Path $Url -Leaf
    $destPath = Join-Path $DestinationDir $fileName

    Invoke-FileDownload -Url $Url -DestPath $destPath

    if ($Sha1Hash -or $Sha256Hash) {
        Confirm-FileHash -FilePath $destPath -ExpectedSha1 $Sha1Hash -ExpectedSha256 $Sha256Hash
    }

    $bytes = (Get-Item -LiteralPath $destPath).Length

    [pscustomobject]@{
        Path  = $destPath
        Bytes = $bytes
    }
}

function Expand-OsImage {
    param(
        [Parameter(Mandatory)] [string] $ImagePath,
        [Parameter(Mandatory)] [int]    $Index,
        [Parameter(Mandatory)] [string] $Destination
    )

    Write-Info "Applying image index $Index from '$ImagePath' to '$Destination'..."

    $args = @(
        "/Apply-Image",
        "/ImageFile:`"$ImagePath`"",
        "/Index:$Index",
        "/ApplyDir:$Destination"
    )

    $proc = Start-Process -FilePath dism.exe -ArgumentList $args -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -ne 0) {
        throw "DISM apply failed with exit code $($proc.ExitCode)."
    }

    Write-Ok "Image applied successfully."

    [pscustomobject]@{
        ImagePath  = $ImagePath
        ImageIndex = $Index
        ImageName  = "Index $Index"
    }
}

function Install-DriversOffline {
    param(
        [Parameter(Mandatory)] [string] $SoftPaqUrl,
        [Parameter(Mandatory)] [string] $WindowsPath
    )

    Write-Info "Preparing offline driver installation into $WindowsPath..."

    # Normalize Windows path
    $WindowsPath = (Resolve-Path $WindowsPath).ProviderPath
    Write-Info "Resolved Windows path: $WindowsPath"

    # Use OS volume for extraction
    $osVolume = Split-Path $WindowsPath -Qualifier
    $driverDir  = Join-Path $osVolume "BuildOSD\Drivers"
    $softPaqExe = Join-Path $driverDir "SoftPaq.exe"
    $extractDir = Join-Path $driverDir "Extracted"

    New-Item -ItemType Directory -Path $driverDir  -Force | Out-Null
    New-Item -ItemType Directory -Path $extractDir -Force | Out-Null

    Invoke-FileDownload -Url $SoftPaqUrl -DestPath $softPaqExe

    Write-Info "Extracting SoftPaq to $extractDir..."
    & $softPaqExe "/s" "/e" "/f`"$extractDir`""
    if ($LASTEXITCODE -ne 0) {
        throw "SoftPaq extraction failed with exit code $LASTEXITCODE."
    }

    Write-Info "Injecting drivers using Add-WindowsDriver..."
    Add-WindowsDriver -Path $WindowsPath -Driver $extractDir -Recurse -ErrorAction Stop

    Write-Ok "Drivers injected successfully."
    return "Drivers injected from SoftPaq."
}



Show-Banner

$buildResults = @{}

Start-Step "System Information"
$sys = Get-SystemInfo
Write-Info "PowerShell Version : $($sys.PSVersion)"
Write-Info "Host OS            : $($sys.OSCaption)"
Write-Ok   "System info collected."
$buildResults['System'] = "$($sys.OSCaption) / PS $($sys.PSVersion)"

Start-Step "OS Catalog Resolution"
$entry = Resolve-OsCatalogEntry `
            -CatalogUri      $CatalogUri `
            -OperatingSystem $OperatingSystem `
            -ReleaseId       $ReleaseId `
            -Architecture    $Architecture `
            -LanguageCode    $LanguageCode `
            -License         $License

Write-Info "Selected ESD URL: $($entry.ESDUrl)"
$buildResults['Catalog'] = "$OperatingSystem $ReleaseId $Architecture $LanguageCode $License"

Start-Step "Disk Selection & Partitioning"
$disk = Get-TargetDisk -PreferredNumber $TargetDiskNumber
Write-Info "Selected Disk $($disk.Number)"

if ($SkipPartitioning) {
    Write-Warn "Skipping disk partitioning (SkipPartitioning flag set)."
    $winPart = Get-Partition -DiskNumber $disk.Number |
               Where-Object { $_.GptType -eq '{EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}' }
} else {
    $winPart = Initialize-DiskLayout -DiskNumber $disk.Number
}

$WindowsDriveLetter = ($winPart | Get-Volume).DriveLetter + ':'
Write-Ok "Windows partition mounted as $WindowsDriveLetter"
$buildResults['Windows Volume'] = $WindowsDriveLetter

Start-Step "OS Image Download & Verification"

if (-not $OsDownloadDir) {
    $OsDownloadDir = Join-Path $WindowsDriveLetter 'BuildOSD'
}

Write-Info "Using OS download directory: $OsDownloadDir"
New-Item -ItemType Directory -Path $OsDownloadDir -Force | Out-Null

$os = Save-OsImage `
        -Url             $entry.ESDUrl  `
        -Sha1Hash        $entry.Sha1    `
        -Sha256Hash      $entry.Sha256  `
        -DestinationDir  $OsDownloadDir

$buildResults['OS Image'] = "$($os.Path) ($([math]::Round($os.Bytes/1GB,2)) GB)"

Start-Step "Apply OS Image to $WindowsDriveLetter\"

if ($SkipApplyImage) {
    Write-Warn "Skipping image apply (SkipApplyImage flag set)."
} else {
    $apply = Expand-OsImage `
                -ImagePath   $os.Path `
                -Index       $ImageIndex `
                -Destination "$WindowsDriveLetter\"

    $buildResults['Applied Image'] = "$($apply.ImageName) (Index $($apply.ImageIndex))"
}

Start-Step "Driver Injection"

if ($SkipDrivers -or -not $DriverSoftPaqUrl) {
    Write-Warn "Skipping driver injection."
} else {
    $driverResult = Install-DriversOffline `
                        -SoftPaqUrl $DriverSoftPaqUrl `
                        -WindowsPath (Join-Path $WindowsDriveLetter 'Windows')


    $buildResults['Drivers'] = $driverResult
}

Start-Step "UEFI Boot Initialization"

if ($SkipBootInit) {
    Write-Warn "Skipping boot initialization."
} else {
    $esp = Get-Partition -DiskNumber $disk.Number |
           Where-Object { $_.GptType -eq '{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}' }

    $EspDriveLetter = ($esp | Get-Volume).DriveLetter + ':'

    Write-Info "Using ESP at $EspDriveLetter"

    bcdboot "$WindowsDriveLetter\Windows" /s $EspDriveLetter /f UEFI $BcdBootExtraArgs

    Write-Ok "Boot files initialized."
    $buildResults['Boot Init'] = "UEFI boot configured"
}

Show-CompletionSummary -Results $buildResults
