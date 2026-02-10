# Monash BuildForge – Bare Metal Init (WinRE / PS 5.1 compatible)
# Refactored: structured modules, unified logging/status, safer partitioning, hardened downloads
# Requires: WinPE/WinRE with DISM tools, bcdboot; network for catalog/ESD
# Note: Destructive to target disk

[CmdletBinding()]
param(
    # --- OS Selection ---
    [ValidateSet('Windows 11')] [string] $OperatingSystem = 'Windows 11',
    [ValidateSet('24H2','25H2','26H2')] [string] $ReleaseId = '25H2',
    [ValidateSet('amd64','arm64')] [string] $Architecture = 'amd64',
    [ValidateSet('en-us')] [string] $LanguageCode = 'en-us',
    [ValidateSet('Volume')] [string] $License = 'Volume',

    # Set which image index to apply from the ESD/WIM
    [int] $ImageIndex = 6,

    # Destination and temporary paths
    [string] $OsDownloadDir = 'C:\BuildOSD',

    # Optional targeting (leave blank to auto-select internal, non-USB)
    [int] $TargetDiskNumber = -1,

    # SoftPaq (HP example) – can be overridden; leave empty to skip
    [string] $DriverSoftPaqUrl = 'https://ftp.hp.com/pub/softpaq/sp160001-160500/sp160195.exe',

    # Steps control
    [switch] $SkipPartitioning,
    [switch] $SkipApplyImage,
    [switch] $SkipDrivers,
    [switch] $SkipBootInit,

    # Extra bcdboot args, e.g. '/l en-US'
    [string] $BcdBootExtraArgs = '',

    # Catalog (CLIXML or XML) – default from OSD project cache
    [string] $CatalogUri = 'https://raw.githubusercontent.com/OSDeploy/OSD/refs/heads/master/cache/os-catalogs/build-operatingsystems.xml'
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# STATUS + LOGGING
# ---------------------------------------------------------------------------

function Get-TempRoot {
    if ($env:TEMP -and (Test-Path -LiteralPath $env:TEMP)) { return $env:TEMP }
    return 'X:\'
}

$script:LogPath = Join-Path (Get-TempRoot) ("BuildForge_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
try {
    $logDir = Split-Path -Path $script:LogPath -Parent
    if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    New-Item -ItemType File -Path $script:LogPath -Force | Out-Null
} catch { }

function Write-Log {
    param(
        [Parameter(Mandatory)][string] $Message,
        [ValidateSet('INFO','STEP','WARN','ERROR','SUCCESS')][string] $Level = 'INFO'
    )
    $ts = Get-Date -Format 'HH:mm:ss'
    $line = "[${ts}] [$Level] $Message"
    try { Add-Content -Path $script:LogPath -Value $line -ErrorAction SilentlyContinue } catch { }
}

function Write-Status {
    param(
        [Parameter(Mandatory)][string] $Message,
        [ValidateSet('INFO','STEP','WARN','ERROR','SUCCESS')][string] $Level = 'INFO'
    )
    $prefix = switch ($Level) {
        'STEP'    { '▶' }
        'INFO'    { '•' }
        'WARN'    { '!' }
        'ERROR'   { '✖' }
        'SUCCESS' { '✔' }
    }
    $color = switch ($Level) {
        'STEP'    { 'Magenta' }
        'INFO'    { 'Gray' }
        'WARN'    { 'Yellow' }
        'ERROR'   { 'Red' }
        'SUCCESS' { 'Green' }
    }
    Write-Host ("{0} {1}" -f $prefix, $Message) -ForegroundColor $color
    Write-Log -Message $Message -Level $Level
}

function Show-Banner {
@"
################################################################################
#███╗   ███╗ ██████╗ ███╗   ██╗ █████╗ ███████╗██╗  ██╗                        #
#████╗ ████║██╔═══██╗████╗  ██║██╔══██╗██╔════╝██║  ██║                        #
#██╔████╔██║██║   ██║██╔██╗ ██║███████║███████╗███████║                        #
#██║╚██╔╝██║██║   ██║██║╚██╗██║██╔══██║╚════██║██╔══██║                        #
#██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║  ██║███████║██║  ██║                        #
#╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝                        #
#                                                                              #
#██████╗ ██╗   ██╗██╗██╗     ██████╗ ███████╗ ██████╗ ██████╗  ██████╗ ███████╗#
#██╔══██╗██║   ██║██║██║     ██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝#
#██████╔╝██║   ██║██║██║     ██║  ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  #
#██╔══██╗██║   ██║██║██║     ██║  ██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  #
#██████╔╝╚██████╔╝██║███████╗██████╔╝██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗#
#╚═════╝  ╚═════╝ ╚═╝╚══════╝╚═════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝#
################################################################################
                    Monash BuildForge – Bare Metal Init
"@ | Write-Host -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# UTILITIES
# ---------------------------------------------------------------------------

function Enable-Tls12 {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
}

function Get-SystemInfo {
    $osCaption = 'Unknown/WinRE'
    try { $osCaption = (Get-CimInstance Win32_OperatingSystem).Caption } catch { }
    [pscustomobject]@{
        PSVersion = $PSVersionTable.PSVersion
        OSCaption = $osCaption
    }
}

function Resolve-Curl {
    # Prefer OS-native curl to avoid IWR performance/redirect issues
    $candidates = @(
        (Join-Path $env:WINDIR 'System32\curl.exe'),
        'curl.exe'
    )
    foreach ($c in $candidates) {
        if (Get-Command $c -ErrorAction SilentlyContinue) { return (Get-Command $c).Path }
    }
    return $null
}

function Download-File {
    param(
        [Parameter(Mandatory)][string] $Url,
        [Parameter(Mandatory)][string] $DestPath,
        [int] $Retries = 2
    )
    Enable-Tls12
    $curl = Resolve-Curl
    for ($i=0; $i -le $Retries; $i++) {
        Write-Status -Level INFO -Message ("Downloading: {0} (attempt {1}/{2})" -f $Url, ($i+1), ($Retries+1))
        try {
            if ($curl) {
                & $curl --fail --location --silent --show-error --connect-timeout 30 --output "$DestPath" "$Url"
                if ($LASTEXITCODE -ne 0) { throw "curl exited with $LASTEXITCODE." }
            } else {
                Invoke-WebRequest -Uri $Url -OutFile $DestPath -UseBasicParsing -ErrorAction Stop
            }
            if (Test-Path -LiteralPath $DestPath) { return $DestPath }
            throw "HTTP OK but file missing on disk."
        } catch {
            if ($i -lt $Retries) {
                Start-Sleep -Seconds 2
            } else {
                throw "Failed to download '$Url' after $($Retries+1) attempts. $($_.Exception.Message)"
            }
        }
    }
}

# ---------------------------------------------------------------------------
# DISK / PARTITIONS (UEFI/GPT, Recovery at end)
# ---------------------------------------------------------------------------

function Get-InternalTargetDisk {
    param([int] $PreferredNumber = -1)

    if ($PreferredNumber -ge 0) {
        $d = Get-Disk -Number $PreferredNumber -ErrorAction Stop
        if ($d.BusType -eq 'USB') { throw "Disk $PreferredNumber is USB; refusing." }
        if ($d.IsOffline) { try { Set-Disk -Number $d.Number -IsOffline:$false -ErrorAction Stop } catch { } }
        if ($d.IsReadOnly) { try { Set-Disk -Number $d.Number -IsReadOnly:$false -ErrorAction Stop } catch { } }
        return $d
    }

    $preferred = Get-Disk | Where-Object {
        $_.BusType -ne 'USB' -and
        -not $_.IsOffline -and
        -not $_.IsReadOnly -and
        -not $_.IsBoot -and
        -not $_.IsSystem
    } | Sort-Object Size -Descending

    if (-not $preferred) {
        foreach ($d in (Get-Disk | Where-Object { $_.BusType -ne 'USB' -and $_.IsOffline })) {
            try { Set-Disk -Number $d.Number -IsOffline:$false -ErrorAction Stop } catch { }
        }
        $preferred = Get-Disk | Where-Object {
            $_.BusType -ne 'USB' -and
            -not $_.IsOffline -and
            -not $_.IsReadOnly -and
            -not $_.IsBoot -and
            -not $_.IsSystem
        } | Sort-Object Size -Descending
    }

    if (-not $preferred) { throw "No suitable internal disk found (non-USB)." }
    return ($preferred | Select-Object -First 1)
}

function Prep-Disk-Win11Layout {
    param([Parameter(Mandatory)][int] $DiskNumber)

    Write-Status -Level STEP -Message "Preparing Disk $DiskNumber for Windows 11 (UEFI/GPT, Recovery at end)"
    # Online & writable
    Set-Disk -Number $DiskNumber -IsReadOnly:$false -ErrorAction SilentlyContinue | Out-Null
    Set-Disk -Number $DiskNumber -IsOffline:$false -ErrorAction SilentlyContinue | Out-Null

    Write-Status -Level WARN -Message "Clearing disk $DiskNumber (ALL DATA WILL BE ERASED)"
    Clear-Disk -Number $DiskNumber -RemoveData -RemoveOEM -Confirm:$false
    Initialize-Disk -Number $DiskNumber -PartitionStyle GPT

    # 1) ESP (FAT32, 100MB)
    $esp = New-Partition -DiskNumber $DiskNumber -Size 100MB `
        -GptType "{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}"
    Format-Volume -Partition $esp -FileSystem FAT32 -NewFileSystemLabel "System" -Confirm:$false -Force

    # 2) MSR (16MB)
    New-Partition -DiskNumber $DiskNumber -Size 16MB `
        -GptType "{E3C9E316-0B5C-4DB8-817D-F92DF00215AE}" | Out-Null

    # 3) Windows partition – take ALL remaining, then shrink by 750MB for Recovery
    $windows = New-Partition -DiskNumber $DiskNumber -UseMaximumSize `
        -GptType "{EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}" -AssignDriveLetter

    # Work around WinRE letter quirks: free up C: if occupied
    try {
        $cPart = Get-Partition -DriveLetter C -ErrorAction SilentlyContinue
        if ($cPart) {
            Remove-PartitionAccessPath -DiskNumber $cPart.DiskNumber `
                -PartitionNumber $cPart.PartitionNumber -AccessPath "C:\" `
                -ErrorAction SilentlyContinue
        }
    } catch { }

    Format-Volume -Partition $windows -FileSystem NTFS -NewFileSystemLabel "Windows" -Confirm:$false -Force
    Set-Partition -DiskNumber $windows.DiskNumber -PartitionNumber $windows.PartitionNumber -NewDriveLetter C | Out-Null

    # Shrink Windows volume by 750MB
    $vol = Get-Volume -DriveLetter C
    $part = Get-Partition -DiskNumber $DiskNumber -PartitionNumber $windows.PartitionNumber
    $supported = Get-PartitionSupportedSize -DiskNumber $DiskNumber -PartitionNumber $part.PartitionNumber
    $shrinkBy = 750MB
    $targetSize = [math]::Max($supported.SizeMin, ($part.Size - $shrinkBy))
    if ($targetSize -lt $part.Size) {
        Write-Status -Level INFO -Message "Shrinking Windows partition by 750MB to create Recovery at end"
        Resize-Partition -DiskNumber $DiskNumber -PartitionNumber $part.PartitionNumber -Size $targetSize
    } else {
        Write-Status -Level WARN -Message "Unable to shrink Windows partition; Recovery will not be created at end."
    }

    # 4) Recovery partition (750MB) at end (if space exists)
    $recovery = $null
    try {
        $recovery = New-Partition -DiskNumber $DiskNumber -UseMaximumSize `
            -GptType "{DE94BBA4-06D1-4D40-A16A-BFD50179D6AC}"
        Format-Volume -Partition $recovery -FileSystem NTFS -NewFileSystemLabel "Recovery" -Confirm:$false -Force
    } catch {
        Write-Status -Level WARN -Message "Recovery partition creation skipped: $($_.Exception.Message)"
    }

    Write-Status -Level SUCCESS -Message "Disk prepared. C: ready; Recovery created at end (if possible)."
}

# ---------------------------------------------------------------------------
# DEVICE / MODEL INFO
# ---------------------------------------------------------------------------

function Get-DeviceSkuName {
    $sku = ''
    try { $sku = (Get-CimInstance Win32_ComputerSystem).SystemSKUNumber } catch { }
    if ([string]::IsNullOrWhiteSpace($sku)) {
        try { $sku = (Get-CimInstance Win32_BaseBoard).Product } catch { }
    }
    if ([string]::IsNullOrWhiteSpace($sku)) { $sku = 'UnknownSKU' }
    $invalid = [IO.Path]::GetInvalidFileNameChars() -join ''
    $pattern = "[{0}]" -f [Regex]::Escape($invalid)
    $sku -replace $pattern, '_'
}

# ---------------------------------------------------------------------------
# OS CATALOG + DOWNLOAD
# ---------------------------------------------------------------------------

function Get-OsCatalogEntry {
    [CmdletBinding()]
    param(
        [Parameter()][string] $CatalogUri,
        [Parameter(Mandatory)][ValidateSet('Windows 11')] [string] $OperatingSystem,
        [Parameter(Mandatory)][ValidateSet('24H2','25H2','26H2')] [string] $ReleaseId,
        [Parameter(Mandatory)][ValidateSet('arm64','amd64')] [string] $Architecture,
        [Parameter(Mandatory)][ValidateSet('en-us')] [string] $LanguageCode,
        [Parameter(Mandatory)][ValidateSet('Volume')] [string] $License
    )

    Enable-Tls12
    Write-Status -Level STEP -Message "Fetching OS catalog"
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("os-catalog_{0}.xml" -f ([guid]::NewGuid()))
    try {
        Invoke-WebRequest -Uri $CatalogUri -UseBasicParsing -OutFile $tmp -ErrorAction Stop
    } catch {
        throw "Failed to download catalog '$CatalogUri'. $($_.Exception.Message)"
    }

    # Try CLIXML first, then raw XML
    $entries = $null
    try {
        $entries = Import-Clixml -Path $tmp -ErrorAction Stop
    } catch {
        try {
            [xml]$xml = Get-Content -LiteralPath $tmp -Raw
            # The OSD catalog often serializes entries under root; normalize to PSCustomObjects
            $entries = @()
            $nodes = $xml.SelectNodes('//Object') # fallback for CLIXML-like; else map common fields
            if ($nodes -and $nodes.Count -gt 0) {
                # Attempt generic projection
                foreach ($n in $nodes) {
                    $props = @{}
                    foreach ($p in $n.Property) { $props[$p.Name] = $p.InnerText }
                    $entries += New-Object psobject -Property $props
                }
            } else {
                # Try a simple schema guess
                $items = $xml.SelectNodes('//*')
                throw "Unsupported XML structure. Update parser for this catalog."
            }
        } catch {
            throw "Unable to parse catalog as CLIXML or XML. $($_.Exception.Message)"
        }
    } finally {
        try { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } catch { }
    }

    if (-not $entries) { throw "Catalog contained no entries." }

    # Normalize field names/dynamic properties for filtering
    $filtered = $entries | Where-Object {
        ($_.OperatingSystem -eq $OperatingSystem) -and
        ($_.ReleaseId -eq $ReleaseId) -and
        ($_.Architecture -eq $Architecture) -and
        ($_.LanguageCode -eq $LanguageCode) -and
        ($_.License -eq $License)
    }

    if (-not $filtered) { return $null }

    function _ToVersion([object]$v) {
        $s = [string]$v
        if ([string]::IsNullOrWhiteSpace($s)) { return [version]'0.0' }
        try { return [version]$s } catch {
            $parts = ($s -split '\.') | ForEach-Object { ($_ -as [int]) }
            if ($parts.Count -lt 2) { $parts += 0 }
            return New-Object System.Version ($parts[0]),($parts[1])
        }
    }

    $latest = $filtered | Sort-Object -Descending -Property @{Expression = { _ToVersion $_.Build } } | Select-Object -First 1

    # Return concise object (PS 5.1-friendly)
    [pscustomobject]@{
        ESDUrl = $latest.Url
        Sha1   = if ([string]::IsNullOrWhiteSpace([string]$latest.Sha1))   { '' } else { [string]$latest.Sha1 }
        Sha256 = if ([string]::IsNullOrWhiteSpace([string]$latest.Sha256)) { '' } else { [string]$latest.Sha256 }
    }
}

function Save-OsFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Url,
        [string] $Sha1Hash,
        [string] $Sha256Hash,
        [Parameter(Mandatory)][string] $Destination
    )

    Enable-Tls12
    if (-not (Test-Path -LiteralPath $Destination)) {
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    }

    $cleanUrl = ($Url.Trim() -replace '\s','')
    $Sha1Hash   = if ($Sha1Hash)   { ($Sha1Hash   -replace '\s','').ToLowerInvariant() } else { $null }
    $Sha256Hash = if ($Sha256Hash) { ($Sha256Hash -replace '\s','').ToLowerInvariant() } else { $null }

    try {
        $uri = [Uri]$cleanUrl
        $fileName = [IO.Path]::GetFileName($uri.LocalPath)
        if ([string]::IsNullOrWhiteSpace($fileName)) { throw "Could not derive filename from URL." }
        $targetPath = Join-Path -Path $Destination -ChildPath $fileName
    } catch {
        throw "Invalid URL '$Url'. $($_.Exception.Message)"
    }

    if (-not (Test-Path -LiteralPath $targetPath)) {
        Write-Status -Level STEP -Message "Downloading OS image"
        $curl = Resolve-Curl
        if ($curl) {
            & $curl --fail --location --silent --show-error --connect-timeout 30 --output $targetPath $cleanUrl
            if ($LASTEXITCODE -ne 0) {
                if (Test-Path -LiteralPath $targetPath) { Remove-Item -LiteralPath $targetPath -Force -ErrorAction SilentlyContinue }
                throw "curl.exe failed with exit code $LASTEXITCODE for '$cleanUrl'."
            }
        } else {
            Invoke-WebRequest -Uri $cleanUrl -UseBasicParsing -OutFile $targetPath -ErrorAction Stop
        }
    } else {
        Write-Status -Level INFO -Message "Using existing OS image: $targetPath"
    }

    if ($Sha1Hash) {
        $actual = (Get-FileHash -Algorithm SHA1 -Path $targetPath).Hash.ToLowerInvariant()
        if ($actual -ne $Sha1Hash) { throw "SHA1 mismatch for '$targetPath'." }
    }
    if ($Sha256Hash) {
        $actual2 = (Get-FileHash -Algorithm SHA256 -Path $targetPath).Hash.ToLowerInvariant()
        if ($actual2 -ne $Sha256Hash) { throw "SHA256 mismatch for '$targetPath'." }
    }

    $fi = Get-Item -LiteralPath $targetPath
    [pscustomobject]@{
        Path           = $targetPath
        Bytes          = $fi.Length
        VerifiedSHA1   = if ($Sha1Hash)   { $Sha1Hash }   else { '' }
        VerifiedSHA256 = if ($Sha256Hash) { $Sha256Hash } else { '' }
        Verified       = $true
    }
}

# ---------------------------------------------------------------------------
# IMAGE APPLY + BOOT INIT
# ---------------------------------------------------------------------------

function Apply-OsImage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $ImagePath,
        [Parameter(Mandatory)][int] $Index,
        [Parameter(Mandatory)][string] $DestinationVolume
    )

    if (-not (Test-Path -LiteralPath $ImagePath)) { throw "Image not found: $ImagePath" }
    if (-not (Test-Path -LiteralPath $DestinationVolume)) {
        New-Item -ItemType Directory -Path $DestinationVolume -Force | Out-Null
    }

    Write-Status -Level STEP -Message "Querying image metadata"
    $images = Get-WindowsImage -ImagePath $ImagePath
    if (-not $images) { throw "No images in: $ImagePath" }
    $selected = $images | Where-Object { $_.ImageIndex -eq $Index } | Select-Object -First 1
    if (-not $selected) {
        $available = ($images | Select-Object -ExpandProperty ImageIndex) -join ', '
        throw "Image index $Index not found. Available indices: $available"
    }

    Write-Status -Level STEP -Message ("Applying image index {0} ({1}) to {2}" -f $selected.ImageIndex, $selected.ImageName, $DestinationVolume)
    Expand-WindowsImage -ImagePath $ImagePath -Index $selected.ImageIndex -ApplyPath $DestinationVolume -ErrorAction Stop | Out-Null

    [pscustomobject]@{
        ImagePath         = $ImagePath
        AppliedImageName  = $selected.ImageName
        AppliedImageIndex = $selected.ImageIndex
        Destination       = $DestinationVolume
    }
}

function Initialize-UefiBootAfterApply {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateScript({ Test-Path $_ -PathType Container })][string] $WindowsPath,
        [string] $PreferredEspLetter = 'S',
        [string] $BcdBootExtraArgs = ''
    )

    $win = (Resolve-Path -LiteralPath $WindowsPath).Path.TrimEnd('\')
    if (-not (Test-Path -LiteralPath (Join-Path $win 'System32'))) {
        throw "WindowsPath '$WindowsPath' doesn't look like a valid Windows directory."
    }

    $bcdboot = Join-Path $env:SystemRoot 'System32\bcdboot.exe'
    if (-not (Test-Path -LiteralPath $bcdboot)) { throw "bcdboot.exe not found at '$bcdboot'." }

    $esp = Get-Partition -ErrorAction Stop |
           Where-Object { $_.GptType -eq '{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}' } |
           Sort-Object -Property Size -Descending | Select-Object -First 1
    if (-not $esp) { throw "EFI System Partition (ESP) not found." }

    $existingLetter = ($esp | Get-Volume -ErrorAction SilentlyContinue).DriveLetter
    $tempLetter = $null
    try {
        $espRoot = if ($existingLetter) { "$existingLetter`:" } else {
            $used = (Get-Volume -ErrorAction SilentlyContinue).DriveLetter | Where-Object { $_ } | ForEach-Object { $_.ToUpper() }
            $letter = if ($used -notcontains $PreferredEspLetter.ToUpper()) { $PreferredEspLetter.ToUpper() }
                      else { (65..90 | ForEach-Object { [char]$_ } | Where-Object { $used -notcontains $_ })[0] }
            if (-not $letter) { throw "No free drive letter available to mount ESP." }
            $esp | Set-Partition -NewDriveLetter $letter -ErrorAction Stop
            $tempLetter = $letter
            "$letter`:"
        }

        Write-Status -Level INFO -Message "Using ESP at $espRoot"
        $args = @("$win", '/f', 'UEFI', '/s', $espRoot)
        if ($BcdBootExtraArgs) { $args += $BcdBootExtraArgs }

        Write-Status -Level STEP -Message "Running: bcdboot $($args -join ' ')"
        & $bcdboot @args
        if ($LASTEXITCODE -ne 0) { throw "bcdboot failed with exit code $LASTEXITCODE." }

        $efiBoot = Join-Path $espRoot 'EFI\Microsoft\Boot\bootmgfw.efi'
        if (-not (Test-Path -LiteralPath $efiBoot)) { throw "Boot files not found at '$efiBoot' after bcdboot." }

        Write-Status -Level SUCCESS -Message "UEFI boot initialized successfully."
    } finally {
        if ($tempLetter) {
            try { $esp | Remove-PartitionAccessPath -AccessPath "$tempLetter`:" -ErrorAction SilentlyContinue } catch { }
        }
    }
}

# ---------------------------------------------------------------------------
# DRIVERS (SoftPaq extraction + offline inject)
# ---------------------------------------------------------------------------

function Extract-SoftPaq {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $ExePath,
        [Parameter(Mandatory)][string] $DestDir,
        [int] $TimeoutSec = 600
    )
    if (-not (Test-Path -LiteralPath $ExePath)) { throw "SoftPaq not found: $ExePath" }
    if (-not (Test-Path -LiteralPath $DestDir)) { New-Item -ItemType Directory -Path $DestDir -Force | Out-Null }

    Write-Status -Level STEP -Message "Extracting SoftPaq to $DestDir"
    $args = @('/e','/s','/f',"`"$DestDir`"")
    $p = Start-Process -FilePath $ExePath -ArgumentList $args -PassThru -WindowStyle Hidden
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill() } catch { }
        throw "Extraction timed out after ${TimeoutSec}s."
    }
    if ($p.ExitCode -ne 0) {
        Write-Status -Level WARN -Message "Extractor returned exit code $($p.ExitCode). Checking output anyway."
    }

    Start-Sleep -Milliseconds 500
    $inf = Get-ChildItem -Path $DestDir -Recurse -Filter *.inf -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($inf) {
        Write-Status -Level SUCCESS -Message "Extraction OK. Found INF: $($inf.FullName)"
    } else {
        Write-Status -Level WARN -Message "No INF found—payload may be nested or non-driver."
    }
}

function Install-OfflineDrivers {
<#
    .SYNOPSIS
        Injects drivers into an offline Windows image (one INF at a time for clarity).
#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param(
        [Parameter(Mandatory)][string] $ImagePath,     # e.g., C:\
        [Parameter(Mandatory)][string] $DriverRoot,
        [switch] $ForceUnsigned
    )
    if (-not (Test-Path -Path $ImagePath -PathType Container)) { throw "ImagePath '$ImagePath' is not a valid folder." }
    if (-not (Test-Path -Path $DriverRoot -PathType Container)) { throw "DriverRoot '$DriverRoot' is not a valid folder." }
    if (-not (Get-Command Add-WindowsDriver -ErrorAction SilentlyContinue)) {
        throw "Add-WindowsDriver not found. Ensure DISM PowerShell module is available."
    }

    Write-Status -Level STEP -Message "Scanning for driver INF files under: $DriverRoot"
    $infs = Get-ChildItem -Path $DriverRoot -Filter *.inf -File -Recurse -ErrorAction SilentlyContinue
    $count = $infs.Count
    Write-Status -Level INFO -Message "Found $count driver INF file(s)."
    if ($count -eq 0) {
        return [pscustomobject]@{ ImagePath=$ImagePath; DriverRoot=$DriverRoot; DriversFound=0; Succeeded=0; Failed=0; Timestamp=(Get-Date) }
    }

    $ok = 0; $fail = 0; $i = 0; $activity = "Injecting drivers to $ImagePath"
    foreach ($inf in $infs) {
        $i++
        Write-Progress -Activity $activity -Status ("[{0}/{1}] {2}" -f $i,$count,$inf.Name) -PercentComplete ([int](($i/$count)*100))
        Write-Host ("[{0}/{1}] {2}" -f $i, $count, $inf.FullName) -ForegroundColor Yellow

        $params = @{ Path=$ImagePath; Driver=$inf.FullName; ErrorAction='Stop' }
        if ($ForceUnsigned) { $params['ForceUnsigned'] = $true }

        try {
            if ($PSCmdlet.ShouldProcess($inf.FullName, "Add-WindowsDriver to '$ImagePath'")) {
                Add-WindowsDriver @params | Out-Host
            }
            Write-Host "   ✔ Success" -ForegroundColor Green
            $ok++
        } catch {
            Write-Warning ("   ✖ Failed: {0}" -f $_.Exception.Message)
            $fail++
        }
    }
    Write-Progress -Activity $activity -Completed -Status "Done"

    [pscustomobject]@{
        ImagePath    = $ImagePath
        DriverRoot   = $DriverRoot
        DriversFound = $count
        Succeeded    = $ok
        Failed       = $fail
        Timestamp    = (Get-Date)
    }
}

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

Show-Banner
$sys = Get-SystemInfo
Write-Status -Level INFO -Message ("PowerShell: {0}, OS: {1}" -f $sys.PSVersion, $sys.OSCaption)
Write-Status -Level INFO -Message "Source: https://github.com/CMMON112/BetaBareMetal/blob/main/Default.ps1"
Write-Host ""

try {
    # 1) Select Disk + Partition
    $disk = Get-InternalTargetDisk -PreferredNumber $TargetDiskNumber
    Write-Status -Level INFO -Message ("Selected Disk {0} ({1} GB) Bus={2}" -f $disk.Number, [math]::Round($disk.Size/1GB), $disk.BusType)
    if (-not $SkipPartitioning) {
        Prep-Disk-Win11Layout -DiskNumber $disk.Number
    } else {
        Write-Status -Level WARN -Message "Skipping partitioning per parameter."
    }

    # 2) Resolve OS ESD (Catalog)
    Write-Status -Level STEP -Message "Resolving OS payload from catalog"
    $entry = Get-OsCatalogEntry -CatalogUri $CatalogUri -OperatingSystem $OperatingSystem -ReleaseId $ReleaseId -Architecture $Architecture -LanguageCode $LanguageCode -License $License
    if (-not $entry) { throw "No catalog entry matched selection: $OperatingSystem $ReleaseId $Architecture $LanguageCode $License" }
    Write-Status -Level INFO -Message "ESD URL resolved."

    # 3) Download OS image
    $os = Save-OsFile -Url $entry.ESDUrl -Sha1Hash $entry.Sha1 -Sha256Hash $entry.Sha256 -Destination $OsDownloadDir
    Write-Status -Level SUCCESS -Message ("OS image ready: {0} ({1} bytes)" -f $os.Path, $os.Bytes)

    # 4) Apply image to C:\
    if (-not $SkipApplyImage) {
        $apply = Apply-OsImage -ImagePath $os.Path -Index $ImageIndex -DestinationVolume 'C:\'
        Write-Status -Level SUCCESS -Message ("Applied: {0} (Index {1})" -f $apply.AppliedImageName, $apply.AppliedImageIndex)
    } else {
        Write-Status -Level WARN -Message "Skipping image apply per parameter."
    }

    # 5) Drivers (optional SoftPaq)
    if (-not $SkipDrivers -and $DriverSoftPaqUrl) {
        $sku = Get-DeviceSkuName
        $driversRoot = Join-Path 'C:\Drivers' $sku
        if (-not (Test-Path -LiteralPath $driversRoot)) { New-Item -ItemType Directory -Path $driversRoot -Force | Out-Null }
        Write-Status -Level INFO -Message "Drivers folder: $driversRoot"

        $spPath = Join-Path $driversRoot ([IO.Path]::GetFileName(([Uri]$DriverSoftPaqUrl).ToString()))
        Download-File -Url $DriverSoftPaqUrl -DestPath $spPath | Out-Null

        $extractDir = Join-Path $driversRoot 'extracted'
        Extract-SoftPaq -ExePath $spPath -DestDir $extractDir

        Write-Status -Level STEP -Message "Injecting offline Drivers"
        $summary = Install-OfflineDrivers -ImagePath "C:\" -DriverRoot $extractDir
        Write-Status -Level INFO -Message ("Drivers: processed={0}, ok={1}, failed={2}" -f $summary.DriversFound, $summary.Succeeded, $summary.Failed)
    } elseif ($SkipDrivers) {
        Write-Status -Level WARN -Message "Skipping driver injection per parameter."
    } else {
        Write-Status -Level INFO -Message "No DriverSoftPaqUrl provided; skipping drivers."
    }

    # 6) Boot initialization
    if (-not $SkipBootInit) {
        Write-Status -Level STEP -Message "Initializing UEFI boot"
        Initialize-UefiBootAfterApply -WindowsPath 'C:\Windows' -BcdBootExtraArgs $BcdBootExtraArgs
    } else {
        Write-Status -Level WARN -Message "Skipping boot initialization per parameter."
    }

    Write-Status -Level SUCCESS -Message "BuildForge init complete."
    Write-Host ""
    Write-Host ("Log: {0}" -f $script:LogPath) -ForegroundColor Cyan
}
catch {
    Write-Status -Level ERROR -Message $_.Exception.Message
    Write-Host ("Log: {0}" -f $script:LogPath) -ForegroundColor Cyan
    exit 1
}
