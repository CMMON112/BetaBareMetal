# Monash BuildForge – Bare Metal Init (WinRE / PS 5.1 compatible)

$ErrorActionPreference = 'Stop'

function Get-TempRoot {
    # WinRE usually has X:\; $env:TEMP may or may not exist/point to a valid path
    if ($env:TEMP -and (Test-Path -LiteralPath $env:TEMP)) { return $env:TEMP }
    return 'X:\'
}

# Precreate a log file (ensure directory exists)
$script:LogPath = Join-Path -Path (Get-TempRoot) -ChildPath ("BuildForge_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
try {
    $logDir = Split-Path -Path $script:LogPath -Parent
    if (-not (Test-Path -LiteralPath $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    New-Item -ItemType File -Path $script:LogPath -Force | Out-Null
} catch {}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
    )
    $line = "[{0:HH:mm:ss}] [{1}] {2}" -f (Get-Date), $Level, $Message
    Write-Host $line
    try {
        Add-Content -Path $script:LogPath -Value $line -ErrorAction SilentlyContinue
    } catch {}
}

function Log {
    param(
        [Parameter(Mandatory=$true)][string]$m,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
    )
    Write-Log -Message $m -Level $Level
}

function Coalesce {
    param(
        [Parameter(Mandatory=$true)][AllowNull()][object]$Value,
        [string]$Fallback = ''
    )
    if ($null -eq $Value) { return $Fallback }
    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace([string]$Value)) { return $Fallback }
        return [string]$Value
    }
    return $Value
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

# Confirm GitHub source (keep as info only)
$ScriptSourceUrl = 'https://github.com/CMMON112/BetaBareMetal/blob/main/Default.ps1'
Show-Banner
Write-Log "This script is being executed from GitHub source:"
Write-Host "  $ScriptSourceUrl" -ForegroundColor Yellow
Write-Host ""

# Environment banner
try {
    $osCaption = (Get-CimInstance Win32_OperatingSystem).Caption
} catch {
    $osCaption = 'Unknown/WinRE'
}
Write-Log ("PowerShell: {0}, OS: {1}" -f $PSVersionTable.PSVersion, $osCaption)

function Enable-Tls12 {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
}

function Download-File {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$DestPath,
        [int]$Retries = 2
    )
    Enable-Tls12
    for ($i=0; $i -le $Retries; $i++) {
        Log ("Downloading: {0} (attempt {1}/{2})" -f $Url, ($i+1), ($Retries+1))
        $curl = "X:\Windows\System32\curl.exe"
        try {
            if ($curl) {
                & curl.exe --fail --location --silent --show-error -o "$DestPath" "$Url"
                if ($LASTEXITCODE -ne 0) { throw "curl download failed with exit code $LASTEXITCODE." }
            } else {
                Invoke-WebRequest -Uri $Url -OutFile $DestPath -UseBasicParsing
            }
            if (Test-Path -LiteralPath $DestPath) { return }
            throw "Download succeeded but file missing on disk."
        } catch {
            if ($i -lt $Retries) {
                Start-Sleep -Seconds 2
            } else {
                throw $_
            }
        }
    }
}

function Get-InternalTargetDisk {
    # Prefer a non-USB, non-removable, online, non-boot/system disk (largest)
    $preferred = Get-Disk | Where-Object {
        $_.BusType -ne 'USB' -and
        $_.IsOffline -eq $false -and
        $_.IsReadOnly -eq $false -and
        $_.IsBoot -eq $false -and
        $_.IsSystem -eq $false
    } | Sort-Object Size -Descending

    if (-not $preferred -or $preferred.Count -eq 0) {
        foreach ($d in (Get-Disk | Where-Object { $_.BusType -ne 'USB' -and $_.IsOffline })) {
            try { Set-Disk -Number $d.Number -IsOffline:$false -ErrorAction Stop } catch {}
        }
        $preferred = Get-Disk | Where-Object {
            $_.BusType -ne 'USB' -and
            $_.IsOffline -eq $false -and
            $_.IsReadOnly -eq $false -and
            $_.IsBoot -eq $false -and
            $_.IsSystem -eq $false
        } | Sort-Object Size -Descending
    }

    if (-not $preferred -or $preferred.Count -eq 0) { throw "No suitable internal disk found (non-USB)." }
    return ($preferred | Select-Object -First 1)
}

function Prep-Disk-Win11Layout {
    param([Parameter(Mandatory=$true)][int]$DiskNumber)

    Log "Preparing Disk $DiskNumber for Windows 11 (UEFI/GPT layout with Recovery at end)"

    # Ensure disk is writable and online
    Set-Disk -Number $DiskNumber -IsReadOnly:$false -ErrorAction SilentlyContinue | Out-Null
    Set-Disk -Number $DiskNumber -IsOffline:$false -ErrorAction SilentlyContinue | Out-Null

    Log "Clearing disk (ALL data will be erased)"
    Clear-Disk -Number $DiskNumber -RemoveData -Confirm:$false -RemoveOEM
    Initialize-Disk -Number $DiskNumber -PartitionStyle GPT

    Log "Creating Windows 11 standard partitions"

    # 1. EFI System Partition (ESP) - 100 MB
    $esp = New-Partition -DiskNumber $DiskNumber -Size 100MB `
        -GptType "{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}"
    Format-Volume -Partition $esp -FileSystem FAT32 -NewFileSystemLabel "System" -Confirm:$false -Force

    # 2. Microsoft Reserved Partition (MSR) - 16 MB
    New-Partition -DiskNumber $DiskNumber -Size 16MB `
        -GptType "{E3C9E316-0B5C-4DB8-817D-F92DF00215AE}" | Out-Null

    # 3. Windows partition (C:) - all space except last 750MB
    $disk = Get-Disk -Number $DiskNumber
    $usable = ($disk | Get-Disk).LargestFreeExtent
    $windowsSize = $usable - 750MB

    $windows = New-Partition -DiskNumber $DiskNumber -Size $windowsSize `
        -GptType "{EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}" -AssignDriveLetter

    # Remove C: from any existing partition (WinRE quirk)
    try {
        $cPart = Get-Partition -DriveLetter C -ErrorAction SilentlyContinue
        if ($cPart) {
            Remove-PartitionAccessPath -DiskNumber $cPart.DiskNumber `
                -PartitionNumber $cPart.PartitionNumber -AccessPath "C:\" `
                -ErrorAction SilentlyContinue
        }
    } catch {}

    # Format Windows partition
    Format-Volume -Partition $windows -FileSystem NTFS -NewFileSystemLabel "Windows" -Confirm:$false -Force
    Set-Partition -DiskNumber $windows.DiskNumber -PartitionNumber $windows.PartitionNumber -NewDriveLetter C | Out-Null

    # 4. Recovery partition (750 MB) - at end of disk
    $recovery = New-Partition -DiskNumber $DiskNumber -UseMaximumSize `
        -GptType "{DE94BBA4-06D1-4D40-A16A-BFD50179D6AC}"
    Format-Volume -Partition $recovery -FileSystem NTFS -NewFileSystemLabel "Recovery" -Confirm:$false -Force

    Log "Disk prepared with Windows 11 layout. C: ready and Recovery at end."
}


function Get-DeviceSkuName {
    # Use SystemSKUNumber; fallback to BaseBoard.Product
    $sku = ''
    try { $sku = (Get-CimInstance Win32_ComputerSystem).SystemSKUNumber } catch {}
    if ([string]::IsNullOrWhiteSpace($sku)) {
        try { $sku = (Get-CimInstance Win32_BaseBoard).Product } catch {}
    }
    if ([string]::IsNullOrWhiteSpace($sku)) { $sku = "UnknownSKU" }
    # Clean for folder name
    $invalid = [IO.Path]::GetInvalidFileNameChars() -join ''
    $sku = ($sku -replace "[{0}]" -f [Regex]::Escape($invalid), '_')
    return $sku
}

function Extract-SoftPaq {
    param(
        [Parameter(Mandatory=$true)][string]$ExePath,
        [Parameter(Mandatory=$true)][string]$DestDir
    )
    if (-not (Test-Path -LiteralPath $ExePath)) { throw "SoftPaq not found: $ExePath" }
    if (-not (Test-Path -LiteralPath $DestDir)) { New-Item -ItemType Directory -Path $DestDir -Force | Out-Null }

    Log "Extracting SoftPaq silently → $DestDir"
    & "$ExePath" /e /s /f "$DestDir"
    $exit1 = $LASTEXITCODE
    if ($exit1 -ne 0) {
        & "$ExePath" -e -s -f "$DestDir"
    }
    # Basic check: look for INF presence
    $inf = Get-ChildItem -Path $DestDir -Recurse -Filter *.inf -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $inf) { Log "Warning: No INF found yet—extraction may have nested folder, continuing." -Level 'WARN' }
}

function Load-Drivers {
    param([Parameter(Mandatory=$true)][string]$Root)

    $infFiles = Get-ChildItem -Path $Root -Recurse -Filter *.inf -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
    $infFiles = @($infFiles)
    if (-not $infFiles -or $infFiles.Count -eq 0) { throw "No .inf files found under $Root." }

    $drvload = Get-Command drvload.exe -ErrorAction SilentlyContinue
    if ($drvload) {
        $ok = 0; $fail = 0
        foreach ($inf in $infFiles) {
            Log "drvload $inf"
            & drvload.exe "$inf"
            if ($LASTEXITCODE -eq 0) { $ok++ } else { $fail++ }
        }
        Log ("drvload results: loaded={0}, failed={1}" -f $ok, $fail)
    } else {
        $pnp = Get-Command pnputil.exe -ErrorAction SilentlyContinue
        if (-not $pnp) { throw "Neither drvload nor pnputil is available to load drivers." }
        Log "pnputil /add-driver ""$Root\*.inf"" /subdirs /install"
        & pnputil.exe /add-driver "$Root\*.inf" /subdirs /install
        # Note: pnputil exit codes vary; we log and continue.
    }
}

function Rescan-Devices {
    Log "Rescanning storage (diskpart)..."
    $dp = Join-Path 'X:\' 'rescan.txt'
    @("rescan","list disk","list volume") | Out-File -FilePath $dp -Encoding ascii -Force
    try { diskpart /s $dp | Out-Null } catch { Log "diskpart rescan failed (continuing)" -Level 'WARN' }

    try { & wpeutil UpdateBootInfo | Out-Null } catch {}
    $pnp = Get-Command pnputil.exe -ErrorAction SilentlyContinue
    if ($pnp) {
        try { & pnputil.exe /scan-devices | Out-Null } catch {}
    }
}
function Get-OsCatalogEntry {
    [CmdletBinding()]
    param(
        # Catalog URL (your provided source)
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $CatalogUri = 'https://raw.githubusercontent.com/OSDeploy/OSD/refs/heads/master/cache/os-catalogs/build-operatingsystems.xml',

        # Constrained inputs as requested
        [Parameter(Mandatory)]
        [ValidateSet('Windows 11')]
        [string] $OperatingSystem,

        [Parameter(Mandatory)]
        [ValidateSet('24H2','25H2','26H2')]
        [string] $ReleaseID,

        [Parameter(Mandatory)]
        [ValidateSet('arm64','amd64')]
        [string] $Architecture,

        [Parameter(Mandatory)]
        [ValidateSet('en-us')]
        [string] $LanguageCode,

        [Parameter(Mandatory)]
        [ValidateSet('Volume')]
        [string] $License
    )

    # --- WinPE networking hardening: enable TLS 1.2 for GitHub raw ---
    try {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch { }

    # --- Helper: normalize Sha1 (Nil -> empty string) ---
    function _Normalize-Sha1([object]$value) {
        if ($null -eq $value) { return '' }
        $s = [string]$value
        if ([string]::IsNullOrWhiteSpace($s)) { return '' }
        return $s
    }

    # --- Helper: safe version conversion for Build like "26200.7623" ---
    function _To-Version([object]$build) {
        $s = [string]$build
        if ([string]::IsNullOrWhiteSpace($s)) {
            return [version]'0.0'
        }
        try {
            # System.Version supports "major.minor[.build[.revision]]" as integers
            return [version]$s
        } catch {
            # Fallback: split on dot and pad/truncate
            $parts = ($s -split '\.') | ForEach-Object { ($_ -as [int]) }
            if ($parts.Count -lt 2) { $parts += 0 }
            return New-Object System.Version ($parts[0]),($parts[1])
        }
    }

    # --- Fetch and load catalog via Import-Clixml (PS 5.1 compatible) ---
    $entries = $null
    $tmp = $null
    try {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("os-catalog_{0}.xml" -f ([guid]::NewGuid().ToString()))
        Invoke-WebRequest -Uri $CatalogUri -UseBasicParsing -OutFile $tmp -ErrorAction Stop
        $entries = Import-Clixml -Path $tmp
    } catch {
        throw "Failed to load catalog from '$CatalogUri'. $_"
    } finally {
        if ($tmp -and (Test-Path $tmp)) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }

    if (-not $entries) {
        throw "Catalog contained no entries."
    }

    # --- Filter: exact, case-insensitive matches ---
    $filtered = $entries | Where-Object {
        ($_.OperatingSystem -eq $OperatingSystem) -and
        ($_.ReleaseId       -eq $ReleaseID) -and
        ($_.Architecture    -eq $Architecture) -and
        ($_.LanguageCode    -eq $LanguageCode) -and
        ($_.License         -eq $License)
    }

    if (-not $filtered) {
        # Nothing matched; return $null to make it easy to test
        return $null
    }

    # --- If multiple, pick the latest by Build ---
    $latest = $filtered |
        Sort-Object -Descending -Property @{ Expression = { _To-Version $_.Build } } |
        Select-Object -First 1

    # --- Project to required fields ---
    [pscustomobject]@{
        ESDUrl = $latest.Url
        Sha1      = _Normalize-Sha1 $latest.Sha1
        Sha256    = $latest.Sha256
    }
}
function Save-OsFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Url,

        [Parameter()]
        [string] $Sha1Hash,

        [Parameter()]
        [string] $Sha256Hash,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Destination
    )

    # Enable TLS 1.2 (common requirement for modern endpoints)
    try {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch { }

    # Normalize inputs: trim and remove accidental whitespace within URL
    $Url = $Url.Trim()
    $cleanUrl = ($Url -replace '\s','')

    $Sha1Hash   = if ($Sha1Hash)   { ($Sha1Hash   -replace '\s','').ToLowerInvariant() } else { $null }
    $Sha256Hash = if ($Sha256Hash) { ($Sha256Hash -replace '\s','').ToLowerInvariant() } else { $null }

    # Ensure destination exists
    if (-not (Test-Path -LiteralPath $Destination)) {
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    }

    # Target path from URL leaf
    try {
        $uri = [Uri]$cleanUrl
        $fileName = [IO.Path]::GetFileName($uri.LocalPath)
        if ([string]::IsNullOrWhiteSpace($fileName)) {
            throw "Could not derive a filename from Url."
        }
        $targetPath = Join-Path -Path $Destination -ChildPath $fileName
    } catch {
        throw "Failed to determine target path from Url '$Url'. $_"
    }

    $downloaded = $false

    # If file does not exist, download; otherwise skip download
    if (-not (Test-Path -LiteralPath $targetPath)) {
        # Prefer curl.exe for performance if available; fallback to Invoke-WebRequest
        $curlPath = Join-Path $env:WINDIR 'System32\curl.exe'
        if (Test-Path -LiteralPath $curlPath) {
            # Build curl arguments safely; handle spaces in paths and URL
            $curlArgs = @(
                '--fail'               # return non-zero on HTTP errors
                '--location'           # follow redirects
                '--silent'             # no progress
                '--show-error'         # but still print errors
                '--connect-timeout', '30'
                '--output', $targetPath
                $cleanUrl
            )

            try {
                # Invoke curl and capture stderr/stdout
                $null = & $curlPath @curlArgs 2>&1 | Out-String
                if ($LASTEXITCODE -ne 0) {
                    # Clean up incomplete file if curl failed and left a stub
                    if (Test-Path -LiteralPath $targetPath) {
                        try { Remove-Item -LiteralPath $targetPath -Force -ErrorAction SilentlyContinue } catch { }
                    }
                    throw "curl.exe download failed with exit code $LASTEXITCODE for '$cleanUrl' -> '$targetPath'."
                }
                $downloaded = $true
            } catch {
                throw "Download failed from '$cleanUrl' to '$targetPath' via curl.exe. $_"
            }
        }
        else {
            try {
                Invoke-WebRequest -Uri $cleanUrl -UseBasicParsing -OutFile $targetPath -ErrorAction Stop
                $downloaded = $true
            } catch {
                throw "Download failed from '$cleanUrl' to '$targetPath'. $_"
            }
        }
    }

    # Hash only if requested
    $actualSha1   = $null
    $actualSha256 = $null

    if ($Sha1Hash) {
        $actualSha1 = (Get-FileHash -Algorithm SHA1 -Path $targetPath -ErrorAction Stop).Hash.ToLowerInvariant()
        if ($actualSha1 -ne $Sha1Hash) {
            throw "SHA1 mismatch for '$targetPath'. Expected: $Sha1Hash  Actual: $actualSha1"
        }
    }

    if ($Sha256Hash) {
        $actualSha256 = (Get-FileHash -Algorithm SHA256 -Path $targetPath -ErrorAction Stop).Hash.ToLowerInvariant()
        if ($actualSha256 -ne $Sha256Hash) {
            throw "SHA256 mismatch for '$targetPath'. Expected: $Sha256Hash  Actual: $actualSha256"
        }
    }

    # Return concise result
    $fi = Get-Item -LiteralPath $targetPath -ErrorAction SilentlyContinue
    [pscustomobject]@{
        Path           = $targetPath
        Bytes          = if ($fi) { $fi.Length } else { $null }
        Downloaded     = $downloaded
        VerifiedSHA1   = if ($Sha1Hash)   { $actualSha1 }   else { '' }
        VerifiedSHA256 = if ($Sha256Hash) { $actualSha256 } else { '' }
        Verified       = @(
                            -not $Sha1Hash   -or ($actualSha1   -eq $Sha1Hash)
                            -not $Sha256Hash -or ($actualSha256 -eq $Sha256Hash)
                          ) -notcontains $false
    }
}
function Apply-OsImage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ImagePath,

        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [string] $DestinationVolume
    )

    # Validate image exists
    if (-not (Test-Path -LiteralPath $ImagePath)) {
        throw "ImagePath not found: $ImagePath"
    }

    # Ensure destination exists
    if (-not (Test-Path -LiteralPath $DestinationVolume)) {
        New-Item -ItemType Directory -Path $DestinationVolume -Force | Out-Null
    }

    # Query available images
    $images = Get-WindowsImage -ImagePath $ImagePath -ErrorAction Stop

    if (-not $images) {
        throw "No images found in: $ImagePath"
    }

    # Find matching image by name (case-insensitive)
    $match = $images | Where-Object {
        $_.ImageName -eq $Name -or
        $_.ImageName.ToLower() -eq $Name.ToLower()
    }

    if (-not $match) {
        $available = ($images.ImageName -join ', ')
        throw "No image named '$Name'. Available images: $available"
    }

    # Pick the highest index if multiple entries match
    $selected = $match | Sort-Object ImageIndex -Descending | Select-Object -First 1
    $index = $selected.ImageIndex

    Write-Host "Applying image index $index ($Name) to $DestinationVolume..."

    # Apply using DISM's Expand-WindowsImage
    Expand-WindowsImage `
        -ImagePath $ImagePath `
        -Index $index `
        -ApplyPath $DestinationVolume `
        -ErrorAction Stop

    return [pscustomobject]@{
        ImagePath         = $ImagePath
        AppliedImageName  = $selected.ImageName
        AppliedImageIndex = $index
        Destination       = $DestinationVolume
    }
}


# ------------------ MAIN ------------------

try {
    Log "Locating internal (non-USB) target disk..."
    $disk = Get-InternalTargetDisk
    Log ("Selected Disk {0} ({1} GB) Bus={2}" -f $disk.Number, [math]::Round($disk.Size/1GB), $disk.BusType)

    Prep-Disk-Win11Layout -DiskNumber $disk.Number
    Log "Done. C: formatted"

    Write-Host "Success. You can proceed with imaging or disk operations." -ForegroundColor Green
} catch {
    Write-Host ("ERROR: {0}" -f $_.Exception.Message) -ForegroundColor Red
    exit 1
}
Log "Looking for Windows image"
$matches = Get-OsCatalogEntry -OperatingSystem 'Windows 11' -ReleaseID '25H2' -Architecture 'amd64' -LanguageCode 'en-us' -License 'Volume'
$matches | Format-List
Write-Host "Success. Starting download" -ForegroundColor Green
$OSESD = Save-OsFile -Url $matches.ESDUrl -Sha1Hash $matches.Sha1 -Sha256Hash $matches.Sha256 -Destination C:\BuildOSD
Expand-WindowsImage -ImagePath $OSESD.Path -Index 6 -ApplyPath "C:\"
$sku = Get-DeviceSkuName
    $driversRoot = Join-Path 'C:\Drivers' $sku
    if (-not (Test-Path -LiteralPath $driversRoot)) { New-Item -ItemType Directory -Path $driversRoot -Force | Out-Null }
    Log "Drivers folder: $driversRoot"

    $url = 'https://ftp.hp.com/pub/softpaq/sp160001-160500/sp160195.exe'
    $dlPath = Join-Path $driversRoot 'sp160195.exe'
    Download-File -Url $url -DestPath $dlPath

    $extractDir = Join-Path $driversRoot 'extracted'
    Extract-SoftPaq -ExePath $dlPath -DestDir $extractDir

    Add-WindowsDriver -Path "C:\" -Driver $extractDir -Recurse

    Log "Done. C: formatted, drivers injected."


