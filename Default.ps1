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

.NOTES
    Source: https://github.com/CMMON112/BetaBareMetal/blob/main/Default.ps1
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    # ── OS Selection ──────────────────────────────────────────────────────────
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

    # WIM/ESD image index to apply
    [int] $ImageIndex = 6,

    # ── Paths ─────────────────────────────────────────────────────────────────
    [string] $OsDownloadDir = 'C:\BuildOSD',

    # ── Target Disk ───────────────────────────────────────────────────────────
    # Leave at -1 to auto-select the largest internal (non-USB, non-boot) disk.
    [int] $TargetDiskNumber = -1,

    # ── Drivers ───────────────────────────────────────────────────────────────
    # HP SoftPaq URL – leave empty to skip driver injection entirely.
    [string] $DriverSoftPaqUrl = 'https://ftp.hp.com/pub/softpaq/sp160001-160500/sp160195.exe',

    # ── Skip Flags ───────────────────────────────────────────────────────────
    [switch] $SkipPartitioning,
    [switch] $SkipApplyImage,
    [switch] $SkipDrivers,
    [switch] $SkipBootInit,

    # ── Boot ──────────────────────────────────────────────────────────────────
    # Extra bcdboot arguments, e.g. '/l en-US'
    [string] $BcdBootExtraArgs = '',

    # ── OS Catalog URI ────────────────────────────────────────────────────────
    [string] $CatalogUri = 'https://raw.githubusercontent.com/OSDeploy/OSD/refs/heads/master/cache/os-catalogs/build-operatingsystems.xml'
)

$ErrorActionPreference = 'Stop'

# ─────────────────────────────────────────────────────────────────────────────
#  STEP TRACKING  –  keeps a global counter so every step prints its number
# ─────────────────────────────────────────────────────────────────────────────

$script:CurrentStep = 0
$script:TotalSteps  = 6   # update this if you add/remove top-level stages

function Start-Step {
    param([string] $Description)
    $script:CurrentStep++
    Write-Divider
    Write-Host (" STEP $($script:CurrentStep) of $($script:TotalSteps)  –  $Description") -ForegroundColor Cyan
    Write-Divider
    Write-Log -Message "=== STEP $($script:CurrentStep): $Description ===" -Level STEP
}


# ─────────────────────────────────────────────────────────────────────────────
#  LOGGING  –  writes timestamped lines to a log file alongside console output
# ─────────────────────────────────────────────────────────────────────────────

function Get-TempRoot {
    if ($env:TEMP -and (Test-Path -LiteralPath $env:TEMP)) { return $env:TEMP }
    return 'X:\'
}

# Resolve log path early so every function can use it
$script:LogPath = Join-Path (Get-TempRoot) ("BuildForge_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
try {
    $logDir = Split-Path -Path $script:LogPath -Parent
    if (-not (Test-Path -LiteralPath $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    New-Item -ItemType File -Path $script:LogPath -Force | Out-Null
} catch { <# silently ignore log init failures so the script can still run #> }

function Write-Log {
    param(
        [Parameter(Mandatory)][string] $Message,
        [ValidateSet('INFO', 'STEP', 'WARN', 'ERROR', 'SUCCESS')]
        [string] $Level = 'INFO'
    )
    $line = "[{0:HH:mm:ss}] [{1,-7}] {2}" -f (Get-Date), $Level, $Message
    try { Add-Content -Path $script:LogPath -Value $line -ErrorAction SilentlyContinue } catch { }
}


# ─────────────────────────────────────────────────────────────────────────────
#  CONSOLE OUTPUT  –  colourful, consistently formatted Write-* helpers
# ─────────────────────────────────────────────────────────────────────────────

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
    Clear-Host

    # Use a here-string for multi-line ASCII text
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

    # Split into lines and output with color
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


# ─────────────────────────────────────────────────────────────────────────────
#  SYSTEM INFO
# ─────────────────────────────────────────────────────────────────────────────

function Get-SystemInfo {
    <#  Returns a quick snapshot of PS version and OS caption.  #>
    $osCaption = 'Unknown / WinRE'
    try { $osCaption = (Get-CimInstance Win32_OperatingSystem).Caption } catch { }

    [pscustomobject]@{
        PSVersion = $PSVersionTable.PSVersion
        OSCaption = $osCaption
    }
}

function Enable-Tls12 {
    <#  Ensures TLS 1.2 is active – required for most modern HTTPS endpoints.  #>
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    } catch { }
}

function Resolve-CurlPath {
    <#
        Prefer the OS-native curl.exe over PowerShell's Invoke-WebRequest.
        Native curl handles large files, redirects and progress far better in WinPE.
    #>
    $candidates = @(
        (Join-Path $env:WINDIR 'System32\curl.exe'),
        'curl.exe'
    )
    foreach ($path in $candidates) {
        if (Get-Command $path -ErrorAction SilentlyContinue) {
            return (Get-Command $path).Path
        }
    }
    return $null   # fall back to Invoke-WebRequest
}


# ─────────────────────────────────────────────────────────────────────────────
#  DOWNLOAD  –  retry-aware file download with optional hash verification
# ─────────────────────────────────────────────────────────────────────────────

function Invoke-FileDownload {
    <#
    .SYNOPSIS
        Downloads a file, retrying up to $Retries times on failure.
    .PARAMETER Url
        Source URL.
    .PARAMETER DestPath
        Full local path where the file should be saved.
    .PARAMETER Retries
        Number of retry attempts (default 2 = 3 total tries).
    #>
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
    <#
    .SYNOPSIS
        Verifies a file's SHA1 and/or SHA256 hash.  Throws on mismatch.
    #>
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


# ─────────────────────────────────────────────────────────────────────────────
#  DISK SELECTION
# ─────────────────────────────────────────────────────────────────────────────

function Get-TargetDisk {
    <#
    .SYNOPSIS
        Returns the disk object to format.  Uses $PreferredNumber if specified;
        otherwise auto-selects the largest suitable internal disk.
    #>
    param([int] $PreferredNumber = -1)

    if ($PreferredNumber -ge 0) {
        Write-Info "Using manually specified disk number: $PreferredNumber"
        $disk = Get-Disk -Number $PreferredNumber -ErrorAction Stop

        if ($disk.BusType -eq 'USB') {
            throw "Disk $PreferredNumber is a USB device – refusing to target it."
        }

        # Bring the disk online and writable if needed
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
    <#
    .SYNOPSIS
        Picks the largest non-USB, non-boot disk.  Brings offline disks online first.
    #>

    # First pass – look for disks already online and ready
    $candidates = Get-Disk | Where-Object {
        $_.BusType    -ne 'USB'  -and
        -not $_.IsOffline        -and
        -not $_.IsReadOnly       -and
        -not $_.IsBoot           -and
        -not $_.IsSystem
    } | Sort-Object Size -Descending

    # Second pass – try bringing offline disks online
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


# ─────────────────────────────────────────────────────────────────────────────
#  PARTITIONING  –  one function per partition keeps things easy to follow
# ─────────────────────────────────────────────────────────────────────────────

function Clear-AndInitializeDisk {
    <#  Wipes all existing data and initialises the disk as GPT.  #>
    param([Parameter(Mandatory)] [int] $DiskNumber)

    Write-Warn "!!! ALL DATA on Disk $DiskNumber will be permanently erased !!!"
    Set-Disk  -Number $DiskNumber -IsReadOnly:$false -ErrorAction SilentlyContinue | Out-Null
    Set-Disk  -Number $DiskNumber -IsOffline:$false  -ErrorAction SilentlyContinue | Out-Null
    Clear-Disk -Number $DiskNumber -RemoveData -RemoveOEM -Confirm:$false
    Initialize-Disk -Number $DiskNumber -PartitionStyle GPT
    Write-Ok "Disk $DiskNumber cleared and initialised as GPT."
}

function New-EspPartition {
    <#  Creates a 100 MB FAT32 EFI System Partition.  #>
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
    <#  Creates a 16 MB Microsoft Reserved Partition (MSR) – unformatted.  #>
    param([Parameter(Mandatory)] [int] $DiskNumber)

    Write-Info "Creating Microsoft Reserved Partition (MSR) – 16 MB..."
    New-Partition -DiskNumber $DiskNumber -Size 16MB `
                  -GptType '{E3C9E316-0B5C-4DB8-817D-F92DF00215AE}' | Out-Null
    Write-Ok "MSR created."
}

function New-WindowsPartition {
    <#
        Creates the Windows partition using all remaining space.
        Assigns drive letter C: (relocating it if something else grabbed it).
        Returns the partition object.
    #>
    param([Parameter(Mandatory)] [int] $DiskNumber)

    Write-Info "Creating Windows partition (max available size, NTFS)..."

    $windows = New-Partition -DiskNumber $DiskNumber -UseMaximumSize `
                              -GptType '{EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}' `
                              -AssignDriveLetter

    # WinPE sometimes steals C: – move it away so we can claim it
    $existing = Get-Partition -DriveLetter C -ErrorAction SilentlyContinue
    if ($existing -and ($existing.PartitionNumber -ne $windows.PartitionNumber)) {
        Write-Warn "C: is occupied by another partition – relocating it..."
        Remove-PartitionAccessPath -DiskNumber $existing.DiskNumber `
                                   -PartitionNumber $existing.PartitionNumber `
                                   -AccessPath 'C:\' -ErrorAction SilentlyContinue
    }

    Format-Volume -Partition $windows -FileSystem NTFS -NewFileSystemLabel 'Windows' `
                  -Confirm:$false -Force | Out-Null
    Set-Partition -DiskNumber $windows.DiskNumber `
                  -PartitionNumber $windows.PartitionNumber `
                  -NewDriveLetter C | Out-Null

    Write-Ok "Windows partition created and mounted as C:."
    return Get-Partition -DiskNumber $DiskNumber -PartitionNumber $windows.PartitionNumber
}

function Resize-WindowsForRecovery {
    <#
        Shrinks the Windows partition by 750 MB to make room for a Recovery partition
        at the physical end of the disk (required for WinRE compatibility).
    #>
    param(
        [Parameter(Mandatory)] [int] $DiskNumber,
        [Parameter(Mandatory)] [int] $PartitionNumber,
        [long] $ShrinkByBytes = 750MB
    )

    $part      = Get-Partition -DiskNumber $DiskNumber -PartitionNumber $PartitionNumber
    $supported = Get-PartitionSupportedSize -DiskNumber $DiskNumber -PartitionNumber $PartitionNumber
    $targetSize = [math]::Max($supported.SizeMin, ($part.Size - $ShrinkByBytes))

    if ($targetSize -ge $part.Size) {
        Write-Warn "Windows partition cannot be shrunk (disk too small?). Recovery will be skipped."
        return $false
    }

    Write-Info ("Shrinking Windows partition by {0} MB to make room for Recovery..." -f [math]::Round($ShrinkByBytes / 1MB))
    Resize-Partition -DiskNumber $DiskNumber -PartitionNumber $PartitionNumber -Size $targetSize
    Write-Ok "Windows partition resized."
    return $true
}

function New-RecoveryPartition {
    <#  Creates a 750 MB WinRE Recovery partition at the end of the disk.  #>
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
    <#
    .SYNOPSIS
        Orchestrates the full Windows 11 GPT layout: ESP → MSR → Windows → Recovery.
    #>
    param([Parameter(Mandatory)] [int] $DiskNumber)

    Write-Info "Laying out Windows 11 UEFI/GPT partition scheme on Disk $DiskNumber..."
    Write-Info "  [1/4]  ESP     –  100 MB  FAT32"
    Write-Info "  [2/4]  MSR     –   16 MB  (unformatted)"
    Write-Info "  [3/4]  Windows –  max     NTFS  (shrunk by 750 MB)"
    Write-Info "  [4/4]  Recovery–  750 MB  NTFS"
    Write-Host ""

    Clear-AndInitializeDisk -DiskNumber $DiskNumber
    New-EspPartition        -DiskNumber $DiskNumber | Out-Null
    New-MsrPartition        -DiskNumber $DiskNumber
    $winPart = New-WindowsPartition -DiskNumber $DiskNumber

    $shrunk = Resize-WindowsForRecovery -DiskNumber $DiskNumber -PartitionNumber $winPart.PartitionNumber
    if ($shrunk) {
        New-RecoveryPartition -DiskNumber $DiskNumber
    }

    Write-Ok "Partition layout complete. C: is ready for the OS image."
}


# ─────────────────────────────────────────────────────────────────────────────
#  OS CATALOG  –  download, parse, filter, return the best matching ESD URL
# ─────────────────────────────────────────────────────────────────────────────

function Get-OsCatalogFile {
    <#  Downloads the OSD catalog XML/CLIXML to a temp file and returns the path.  #>
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
    <#  Parses either CLIXML or OSD-style XML and returns a collection of entries.  #>
    param([Parameter(Mandatory)] [string] $FilePath)

    # Try CLIXML first (the OSD project uses this format)
    try {
        $entries = Import-Clixml -Path $FilePath -ErrorAction Stop
        Write-Info "Parsed catalog as CLIXML – $(@($entries).Count) entries loaded."
        return $entries
    } catch {
        Write-Warn "CLIXML parse failed – attempting raw XML fallback..."
    }

    # Raw XML fallback
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
    <#
    .SYNOPSIS
        Filters the catalog entries and returns the one with the highest build number
        that matches all specified OS criteria.
    #>
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

    # Sort by build number descending, return the newest
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
    <#
    .SYNOPSIS
        Full pipeline: download catalog → parse → filter → return best entry.
    #>
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
        $tmpFile = Get-OsCatalogFile    -CatalogUri $CatalogUri
        $entries = ConvertFrom-CatalogFile -FilePath $tmpFile
        $entry   = Select-BestCatalogEntry -Entries $entries `
                        -OperatingSystem $OperatingSystem -ReleaseId $ReleaseId `
                        -Architecture $Architecture -LanguageCode $LanguageCode `
                        -License $License
        return $entry
    } finally {
        if ($tmpFile -and (Test-Path -LiteralPath $tmpFile)) {
            Remove-Item -LiteralPath $tmpFile -Force -ErrorAction SilentlyContinue
        }
    }
}


# ─────────────────────────────────────────────────────────────────────────────
#  OS IMAGE DOWNLOAD & APPLY
# ─────────────────────────────────────────────────────────────────────────────

function Save-OsImage {
    <#
    .SYNOPSIS
        Downloads the OS ESD/WIM if not already present, then verifies its hash.
    #>
    param(
        [Parameter(Mandatory)] [string] $Url,
        [string] $Sha1Hash,
        [string] $Sha256Hash,
        [Parameter(Mandatory)] [string] $DestinationDir
    )

    Enable-Tls12

    if (-not (Test-Path -LiteralPath $DestinationDir)) {
        Write-Info "Creating download directory: $DestinationDir"
        New-Item -ItemType Directory -Path $DestinationDir -Force | Out-Null
    }

    # Derive filename from the URL
    $cleanUrl  = $Url.Trim() -replace '\s', ''
    $fileName  = [IO.Path]::GetFileName(([Uri]$cleanUrl).LocalPath)
    if ([string]::IsNullOrWhiteSpace($fileName)) {
        throw "Could not determine a filename from URL: $Url"
    }
    $localPath = Join-Path -Path $DestinationDir -ChildPath $fileName

    if (Test-Path -LiteralPath $localPath) {
        Write-Info "OS image already exists locally – skipping download: $localPath"
    } else {
        Write-Info "OS image not found locally – starting download now. This may take a while..."
        Invoke-FileDownload -Url $cleanUrl -DestPath $localPath
    }

    # Verify integrity
    Confirm-FileHash -FilePath $localPath -ExpectedSha1 $Sha1Hash -ExpectedSha256 $Sha256Hash

    $info = Get-Item -LiteralPath $localPath
    Write-Ok ("OS image ready: {0}  ({1:N0} bytes  /  {2:N1} GB)" -f
              $info.Name, $info.Length, ($info.Length / 1GB))

    return [pscustomobject]@{
        Path   = $localPath
        Bytes  = $info.Length
    }
}

function Expand-OsImage {
    <#
    .SYNOPSIS
        Applies a WIM/ESD image index to the specified volume using DISM.
    #>
    param(
        [Parameter(Mandatory)] [string] $ImagePath,
        [Parameter(Mandatory)] [int]    $Index,
        [Parameter(Mandatory)] [string] $Destination
    )

    if (-not (Test-Path -LiteralPath $ImagePath)) {
        throw "Image file not found: $ImagePath"
    }
    if (-not (Test-Path -LiteralPath $Destination)) {
        Write-Info "Creating destination path: $Destination"
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    }

    Write-Info "Querying available image indices in: $ImagePath"
    $images   = Get-WindowsImage -ImagePath $ImagePath
    if (-not $images) { throw "No images found in: $ImagePath" }

    $selected = $images | Where-Object { $_.ImageIndex -eq $Index } | Select-Object -First 1
    if (-not $selected) {
        $available = ($images | Select-Object -ExpandProperty ImageIndex) -join ', '
        throw "Image index $Index not found in the ESD.`n  Available indices: $available"
    }

    Write-Info "Selected image: [$($selected.ImageIndex)] '$($selected.ImageName)'"
    Write-Info "Applying image to $Destination – this will take several minutes..."

    Expand-WindowsImage -ImagePath $ImagePath -Index $selected.ImageIndex `
                        -ApplyPath $Destination -ErrorAction Stop | Out-Null

    Write-Ok "Image applied successfully: '$($selected.ImageName)' → $Destination"
    return [pscustomobject]@{
        ImageName  = $selected.ImageName
        ImageIndex = $selected.ImageIndex
        Destination = $Destination
    }
}


# ─────────────────────────────────────────────────────────────────────────────
#  UEFI BOOT INIT  –  mounts ESP, runs bcdboot, cleans up the temp mount
# ─────────────────────────────────────────────────────────────────────────────

function Find-EspPartition {
    <#  Locates the EFI System Partition on any attached disk.  #>
    Write-Info "Scanning all disks for the EFI System Partition (ESP)..."

    $esp = Get-Partition -ErrorAction SilentlyContinue |
           Where-Object   { $_.GptType -eq '{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}' } |
           Sort-Object Size -Descending |
           Select-Object -First 1

    if (-not $esp) {
        throw "No EFI System Partition found. Was disk partitioning skipped?"
    }

    Write-Ok ("ESP found on Disk {0}, Partition {1} ({2} MB)." -f
              $esp.DiskNumber, $esp.PartitionNumber, [math]::Round($esp.Size / 1MB, 1))
    return $esp
}

function Mount-EspToLetter {
    <#
    .SYNOPSIS
        Assigns a drive letter to the ESP.  Tries $PreferredLetter first,
        then scans for any free letter.  Returns the letter that was assigned.
    #>
    param(
        [Parameter(Mandatory)] [object] $EspPartition,
        [string] $PreferredLetter = 'S'
    )

    # Check if it already has a letter (less common in WinPE)
    try {
        $vol = $EspPartition | Get-Volume -ErrorAction Stop
        if ($vol.DriveLetter) {
            $letter = $vol.DriveLetter.ToString().ToUpper()
            Write-Info "ESP already has drive letter ${letter}: – using it."
            return [pscustomobject]@{ Letter = $letter; AssignedByUs = $false }
        }
    } catch {
        Write-Info "Could not read existing volume info (normal in WinPE)."
    }

    # Find a free letter
    $usedLetters = @(
        Get-Volume -ErrorAction SilentlyContinue |
        Where-Object DriveLetter |
        ForEach-Object { $_.DriveLetter.ToString().ToUpper() }
    )
    $candidate = $PreferredLetter.ToUpper()
    if ($usedLetters -contains $candidate) {
        $candidate = [string]([char[]]'BCDEFGHIJKLMNOPQRSTUVWXYZ' |
                     Where-Object { $usedLetters -notcontains $_.ToString() } |
                     Select-Object -First 1)
    }
    if (-not $candidate) {
        Write-Warn "No free drive letter found – will attempt GUID path fallback."
        return $null
    }

    Write-Info "Assigning drive letter $candidate`: to ESP..."
    try {
        $EspPartition | Set-Partition -NewDriveLetter $candidate -ErrorAction Stop
        Start-Sleep -Milliseconds 800   # give Windows a moment to recognise the mount
        Write-Ok "ESP mounted as ${candidate}:."
        return [pscustomobject]@{ Letter = $candidate; AssignedByUs = $true }
    } catch {
        Write-Warn "Failed to assign letter $candidate`: ($($_.Exception.Message)). Will try GUID path."
        return $null
    }
}

function Remove-EspMount {
    <#  Removes a temporary drive letter from the ESP.  #>
    param(
        [Parameter(Mandatory)] [object] $EspPartition,
        [Parameter(Mandatory)] [string] $Letter
    )
    Write-Info "Removing temporary drive letter $Letter`: from ESP..."
    try {
        $EspPartition | Remove-PartitionAccessPath -AccessPath "${Letter}:\" -ErrorAction Stop
        Write-Ok "Drive letter $Letter`: removed."
    } catch {
        Write-Warn "Could not remove drive letter $Letter`: – $($_.Exception.Message)"
    }
}

function Invoke-BcdBoot {
    <#
    .SYNOPSIS
        Runs bcdboot with the supplied Windows path and ESP target.
    #>
    param(
        [Parameter(Mandatory)] [string] $WindowsPath,
        [Parameter(Mandatory)] [string] $EspTarget,   # e.g. "S:" or a GUID volume path
        [string[]] $ExtraArgs = @()
    )

    $bcdboot = Join-Path $env:SystemRoot 'System32\bcdboot.exe'
    if (-not (Test-Path $bcdboot)) {
        throw "bcdboot.exe not found at: $bcdboot"
    }

    $bcdArgs = @($WindowsPath, '/f', 'UEFI', '/s', $EspTarget) + $ExtraArgs
    Write-Info "Running: bcdboot $($bcdArgs -join ' ')"

    $proc = Start-Process -FilePath $bcdboot -ArgumentList $bcdArgs -NoNewWindow -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        throw "bcdboot failed with exit code $($proc.ExitCode)."
    }
    Write-Ok "bcdboot succeeded."
}

function Initialize-UefiBoot {
    <#
    .SYNOPSIS
        Orchestrates UEFI boot setup: find ESP → mount it → run bcdboot → unmount.
    #>
    param(
        [Parameter(Mandatory)] [string] $WindowsPath,
        [string]   $PreferredEspLetter = 'S',
        [string[]] $BcdBootExtraArgs   = @()
    )

    if (-not (Test-Path (Join-Path $WindowsPath 'System32\config\SYSTEM'))) {
        throw "'$WindowsPath' does not look like a valid Windows installation (missing SYSTEM hive)."
    }

    $esp    = Find-EspPartition
    $mount  = Mount-EspToLetter -EspPartition $esp -PreferredLetter $PreferredEspLetter

    $espTarget = $null
    if ($mount) {
        $espTarget = "$($mount.Letter):"
    } else {
        # GUID path fallback
        $guid = try { ($esp | Get-Volume).UniqueId.TrimEnd('\') } catch { $null }
        if ($guid -and $guid -match '^\\\\\?\\Volume\{') {
            Write-Info "Using volume GUID path as ESP target: $guid"
            $espTarget = $guid
        } else {
            throw "Cannot determine ESP path by letter or GUID – bcdboot cannot proceed."
        }
    }

    try {
        Invoke-BcdBoot -WindowsPath $WindowsPath -EspTarget $espTarget -ExtraArgs $BcdBootExtraArgs

        # Quick sanity check
        if ($mount) {
            $bootFile = Join-Path "${espTarget}" 'EFI\Microsoft\Boot\bootmgfw.efi'
            if (Test-Path $bootFile) {
                Write-Ok "bootmgfw.efi found on ESP – UEFI boot looks good!"
            } else {
                Write-Warn "bootmgfw.efi NOT found at expected path – boot may fail."
            }
        }
    } finally {
        if ($mount -and $mount.AssignedByUs) {
            Remove-EspMount -EspPartition $esp -Letter $mount.Letter
        }
    }
}


# ─────────────────────────────────────────────────────────────────────────────
#  DEVICE INFO
# ─────────────────────────────────────────────────────────────────────────────

function Get-DeviceSkuName {
    <#  Returns a filesystem-safe SKU string for naming the drivers folder.  #>
    $sku = ''
    try { $sku = (Get-CimInstance Win32_ComputerSystem).SystemSKUNumber } catch { }
    if ([string]::IsNullOrWhiteSpace($sku)) {
        try { $sku = (Get-CimInstance Win32_BaseBoard).Product } catch { }
    }
    if ([string]::IsNullOrWhiteSpace($sku)) { $sku = 'UnknownSKU' }

    # Strip characters that are illegal in file/folder names
    $invalid  = [IO.Path]::GetInvalidFileNameChars() -join ''
    $pattern  = '[{0}]' -f [Regex]::Escape($invalid)
    return ($sku -replace $pattern, '_')
}


# ─────────────────────────────────────────────────────────────────────────────
#  DRIVERS  –  download SoftPaq, extract it, inject into offline image
# ─────────────────────────────────────────────────────────────────────────────

function Expand-SoftPaq {
    <#
    .SYNOPSIS
        Silently extracts an HP SoftPaq self-extracting archive to a folder.
    #>
    param(
        [Parameter(Mandatory)] [string] $ExePath,
        [Parameter(Mandatory)] [string] $DestDir,
        [int] $TimeoutSec = 600
    )

    if (-not (Test-Path -LiteralPath $ExePath)) {
        throw "SoftPaq file not found: $ExePath"
    }
    if (-not (Test-Path -LiteralPath $DestDir)) {
        New-Item -ItemType Directory -Path $DestDir -Force | Out-Null
    }

    Write-Info "Extracting SoftPaq to: $DestDir (timeout ${TimeoutSec}s)..."
    $proc = Start-Process -FilePath $ExePath `
                          -ArgumentList @('/e', '/s', '/f', "`"$DestDir`"") `
                          -PassThru -WindowStyle Hidden

    if (-not $proc.WaitForExit($TimeoutSec * 1000)) {
        try { $proc.Kill() } catch { }
        throw "SoftPaq extraction timed out after ${TimeoutSec} seconds."
    }

    if ($proc.ExitCode -ne 0) {
        Write-Warn "Extractor returned exit code $($proc.ExitCode) – checking output anyway..."
    }

    Start-Sleep -Milliseconds 500

    $infCount = @(Get-ChildItem -Path $DestDir -Recurse -Filter '*.inf' -ErrorAction SilentlyContinue).Count
    if ($infCount -gt 0) {
        Write-Ok "Extraction complete – $infCount INF file(s) found."
    } else {
        Write-Warn "Extraction finished but no INF files found. The payload may not contain drivers."
    }
}

function Add-OfflineDrivers {
    <#
    .SYNOPSIS
        Injects all drivers under $DriverRoot into an offline Windows image in one
        DISM session (fast).  Falls back to per-INF on bulk failure to isolate errors.
    .PARAMETER ImagePath
        Path to the root of the mounted offline Windows volume (e.g. C:\).
    .PARAMETER DriverRoot
        Folder that will be searched recursively for .INF driver packages.
    .PARAMETER ForceUnsigned
        Allow unsigned drivers.  Use with caution.
    .EXAMPLE
        Add-OfflineDrivers -ImagePath 'C:\' -DriverRoot 'C:\Drivers\extracted'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string] $ImagePath,
        [Parameter(Mandatory)] [string] $DriverRoot,
        [switch] $ForceUnsigned,
        [string] $ScratchDirectory,
        [string] $LogPath
    )

    if (-not (Test-Path -Path $DriverRoot -PathType Container)) {
        throw "Driver root folder not found: $DriverRoot"
    }
    if (-not (Test-Path -Path $ImagePath  -PathType Container)) {
        throw "Image path not found: $ImagePath"
    }

    Write-Info "Scanning $DriverRoot for driver INF files..."
    $infs = @(Get-ChildItem -Path $DriverRoot -Filter '*.inf' -File -Recurse -ErrorAction SilentlyContinue)
    Write-Info "Found $($infs.Count) INF file(s)."

    if ($infs.Count -eq 0) {
        Write-Warn "No INF files found – nothing to inject."
        return [pscustomobject]@{ DriversFound = 0; Succeeded = 0; Failed = 0 }
    }

    # Build DISM parameters
    $addParams = @{
        Path        = $ImagePath
        Recurse     = $true
        Driver      = $DriverRoot
        ErrorAction = 'Stop'
    }
    if ($ForceUnsigned)                                    { $addParams['ForceUnsigned']    = $true }
    if ($ScratchDirectory -and (Test-Path $ScratchDirectory)) { $addParams['ScratchDirectory'] = $ScratchDirectory }
    if ($LogPath)                                          { $addParams['LogPath']           = $LogPath }

    $succeeded = 0
    $failed    = 0
    $timer     = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Info "Attempting bulk driver injection (single DISM session)..."
    try {
        if ($PSCmdlet.ShouldProcess($ImagePath, "Add-WindowsDriver (bulk)")) {
            Add-WindowsDriver @addParams | Out-Null
            $succeeded = $infs.Count
            Write-Ok "Bulk injection succeeded for $succeeded driver package(s)."
        }
    } catch {
        Write-Warn "Bulk injection failed: $($_.Exception.Message)"
        Write-Info "Falling back to per-INF injection to isolate any problem drivers..."

        foreach ($inf in $infs) {
            try {
                if ($PSCmdlet.ShouldProcess($inf.FullName, "Add-WindowsDriver")) {
                    $single = @{ Path = $ImagePath; Driver = $inf.FullName; ErrorAction = 'Stop' }
                    if ($ForceUnsigned)    { $single['ForceUnsigned']    = $true }
                    if ($ScratchDirectory) { $single['ScratchDirectory'] = $ScratchDirectory }
                    if ($LogPath)          { $single['LogPath']           = $LogPath }
                    Add-WindowsDriver @single | Out-Null
                    $succeeded++
                    Write-Info "  [OK]  $($inf.Name)"
                }
            } catch {
                $failed++
                Write-Warn "  [FAIL] $($inf.Name): $($_.Exception.Message)"
            }
        }
    } finally {
        $timer.Stop()
    }

    Write-Ok ("Driver injection complete – {0} succeeded, {1} failed, elapsed {2}." -f
              $succeeded, $failed, ('{0:c}' -f $timer.Elapsed))

    return [pscustomobject]@{
        DriversFound = $infs.Count
        Succeeded    = $succeeded
        Failed       = $failed
        Elapsed      = ('{0:c}' -f $timer.Elapsed)
    }
}


# =============================================================================
#  MAIN  –  runs each stage in order, respecting skip flags
# =============================================================================

Show-Banner

$sys = Get-SystemInfo
Write-Info "PowerShell : $($sys.PSVersion)"
Write-Info "OS         : $($sys.OSCaption)"
Write-Info "Log file   : $script:LogPath"
Write-Host ""

$buildResults = [ordered]@{}

try {

    # ── STEP 1: Disk Selection & Partitioning ──────────────────────────────

    Start-Step "Disk Selection & Partitioning"

    $disk = Get-TargetDisk -PreferredNumber $TargetDiskNumber
    Write-Info ("Target → Disk {0}  ({1:N1} GB,  BusType={2})" -f
                $disk.Number, ($disk.Size / 1GB), $disk.BusType)
    $buildResults['Target Disk'] = "Disk $($disk.Number) ($([math]::Round($disk.Size/1GB,1)) GB)"

    if ($SkipPartitioning) {
        Write-Warn "Skipping partitioning (SkipPartitioning flag set)."
    } else {
        Initialize-DiskLayout -DiskNumber $disk.Number
        $buildResults['Partitioning'] = 'Complete (ESP + MSR + Windows + Recovery)'
    }


    # ── STEP 2: OS Catalog Lookup ──────────────────────────────────────────

    Start-Step "OS Catalog Lookup"

    Write-Info "Looking up: $OperatingSystem $ReleaseId ($Architecture / $LanguageCode / $License)"
    $entry = Resolve-OsCatalogEntry `
                -CatalogUri       $CatalogUri       `
                -OperatingSystem  $OperatingSystem  `
                -ReleaseId        $ReleaseId        `
                -Architecture     $Architecture     `
                -LanguageCode     $LanguageCode     `
                -License          $License

    if (-not $entry) {
        throw "No catalog entry matched: $OperatingSystem $ReleaseId $Architecture $LanguageCode $License"
    }
    Write-Ok "ESD URL resolved from catalog."
    $buildResults['OS Entry'] = "$OperatingSystem $ReleaseId $Architecture"


    # ── STEP 3: OS Image Download ──────────────────────────────────────────

    Start-Step "OS Image Download & Verification"

    $os = Save-OsImage `
            -Url             $entry.ESDUrl  `
            -Sha1Hash        $entry.Sha1    `
            -Sha256Hash      $entry.Sha256  `
            -DestinationDir  $OsDownloadDir

    $buildResults['OS Image'] = "$($os.Path)  ($([math]::Round($os.Bytes/1GB,2)) GB)"


    # ── STEP 4: Apply OS Image ─────────────────────────────────────────────

    Start-Step "Apply OS Image to C:\"

    if ($SkipApplyImage) {
        Write-Warn "Skipping image apply (SkipApplyImage flag set)."
    } else {
        $apply = Expand-OsImage -ImagePath $os.Path -Index $ImageIndex -Destination 'C:\'
        $buildResults['Applied Image'] = "$($apply.ImageName) (Index $($apply.ImageIndex))"
    }


    # ── STEP 5: Driver Injection ───────────────────────────────────────────

    Start-Step "Driver Download, Extraction & Injection"

    if ($SkipDrivers) {
        Write-Warn "Skipping drivers (SkipDrivers flag set)."
    } elseif (-not $DriverSoftPaqUrl) {
        Write-Info "No DriverSoftPaqUrl provided – skipping driver injection."
    } else {
        $sku        = Get-DeviceSkuName
        $driverRoot = Join-Path 'C:\Drivers' $sku
        if (-not (Test-Path -LiteralPath $driverRoot)) {
            New-Item -ItemType Directory -Path $driverRoot -Force | Out-Null
        }
        Write-Info "Driver folder : $driverRoot"
        Write-Info "Device SKU    : $sku"

        $softPaqName = [IO.Path]::GetFileName(([Uri]$DriverSoftPaqUrl).ToString())
        $softPaqPath = Join-Path $driverRoot $softPaqName

        Write-Info "Downloading SoftPaq: $softPaqName"
        Invoke-FileDownload -Url $DriverSoftPaqUrl -DestPath $softPaqPath | Out-Null

        $extractDir = Join-Path $driverRoot 'extracted'
        Expand-SoftPaq -ExePath $softPaqPath -DestDir $extractDir

        Write-Info "Injecting drivers into offline image at C:\..."
        $driverSummary = Add-OfflineDrivers -ImagePath 'C:\' -DriverRoot $extractDir

        $buildResults['Drivers'] = "Found=$($driverSummary.DriversFound)  OK=$($driverSummary.Succeeded)  Failed=$($driverSummary.Failed)"
    }


    # ── STEP 6: UEFI Boot Initialisation ──────────────────────────────────

    Start-Step "UEFI Boot Initialisation"

    if ($SkipBootInit) {
        Write-Warn "Skipping boot init (SkipBootInit flag set)."
    } else {
        $extraArgs = if ($BcdBootExtraArgs) { $BcdBootExtraArgs -split ' ' } else { @() }
        Initialize-UefiBoot -WindowsPath 'C:\Windows' -BcdBootExtraArgs $extraArgs
        $buildResults['Boot Init'] = 'UEFI boot configured via bcdboot'
    }


    # ── Done ───────────────────────────────────────────────────────────────

    Show-CompletionSummary -Results $buildResults

} catch {
    Write-Host ""
    Write-Fail "BUILD FAILED: $($_.Exception.Message)"
    Write-Host ""
    Write-Host ("  Log: {0}" -f $script:LogPath) -ForegroundColor DarkCyan
    Write-Host ""
    exit 1
}
