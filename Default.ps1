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

    [ValidateSet('Enterprise', 'Professional')]
    [string] $SKU = 'Enterprise',

    # Driver Catralog
    [string] $DriverCatalogUrl = "https://raw.githubusercontent.com/CMMON112/BetaBareMetal/refs/heads/main/build-driverpackcatalog.xml",

    # OS Catalog
    [string] $OSCatalogUrl  = "https://raw.githubusercontent.com/CMMON112/BetaBareMetal/refs/heads/main/build-oscatalog.xml"
)

$ErrorActionPreference = 'Stop'

# ---- Step tracking (adjust TotalSteps as you build out the workflow) ----
$script:CurrentStep = 0
$script:TotalSteps  = 6

# ---------------------------
# Helpers / Core Infrastructure
# ---------------------------

function Get-TempRoot {
    # Candidate locations
    $xRoot         = 'X:\Windows\Temp\BuildForge'
    $wRootNoWin    = 'W:\BuildForge'
    $wRootWinTemp  = 'W:\Windows\Temp\BuildForge'

    function Ensure-Dir([string]$Path) {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }
    }

    function Move-BuildForgeContents([string]$Source, [string]$Destination) {
        if (-not (Test-Path -LiteralPath $Source)) { return }

        Ensure-Dir $Destination

        # Merge contents from Source into Destination safely (works even if Destination exists)
        $items = Get-ChildItem -LiteralPath $Source -Force -ErrorAction SilentlyContinue
        foreach ($i in $items) {
            $destPath = Join-Path $Destination $i.Name
            try {
                Move-Item -LiteralPath $i.FullName -Destination $destPath -Force -ErrorAction Stop
            } catch {
                # If something is locked or collides, try moving into the destination root.
                Move-Item -LiteralPath $i.FullName -Destination $Destination -Force -ErrorAction SilentlyContinue
            }
        }

        # Remove the (now empty) source folder if possible
        Remove-Item -LiteralPath $Source -Force -Recurse -ErrorAction SilentlyContinue
    }

    $hasX       = Test-Path -LiteralPath 'X:\'
    $hasW       = Test-Path -LiteralPath 'W:\'
    $hasWWin    = Test-Path -LiteralPath 'W:\Windows'

    # 3) If W:\Windows exists, move BuildForge to W:\Windows\Temp\BuildForge
    if ($hasWWin) {
        Ensure-Dir $wRootWinTemp

        # Promote anything previously written elsewhere into the best location
        Move-BuildForgeContents -Source $xRoot      -Destination $wRootWinTemp
        Move-BuildForgeContents -Source $wRootNoWin -Destination $wRootWinTemp

        return $wRootWinTemp
    }

    # 2) If W:\ and X:\ exist but W:\Windows does not,
    #    create and move the contents of X:\Windows\Temp\BuildForge -> W:\BuildForge
    if ($hasW -and $hasX -and -not $hasWWin) {
        Ensure-Dir $wRootNoWin
        Move-BuildForgeContents -Source $xRoot -Destination $wRootNoWin
        return $wRootNoWin
    }

    # 1) If X:\ is available create the BuildForge folder in X:\Windows\Temp
    if ($hasX) {
        Ensure-Dir $xRoot
        return $xRoot
    }

    # No valid temp drive available
    throw "Get-TempRoot: Neither X:\ nor W:\ is available to host BuildForge temp logs."
}


# Core unified output + logging function
function Write-Status {
    param(
        [string] $Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS','STEP')]
        [string] $Level = 'INFO'
    )

    # Ensure temp root is always initialized before logging
    if (-not $script:TempRoot) {
        $script:TempRoot = Get-TempRoot
    }

    # Map log level → console prefix + color
    switch ($Level) {
        'INFO'    { $prefix = 'INFO';    $color = 'Gray' }
        'WARN'    { $prefix = 'WARN';    $color = 'Yellow' }
        'ERROR'   { $prefix = 'ERROR';   $color = 'Red' }
        'SUCCESS' { $prefix = 'OK';      $color = 'Green' }
        'STEP'    { $prefix = 'STEP';    $color = 'Cyan' }
    }

    # Console output
    Write-Host ("  [{0}]    {1}" -f $prefix, $Message) -ForegroundColor $color

    # Ensure log directory exists
    if (-not (Test-Path -LiteralPath $script:TempRoot)) {
        New-Item -ItemType Directory -Path $script:TempRoot -Force | Out-Null
    }

    # Log file path
    $logFile = Join-Path $script:TempRoot 'BuildForce.log'

    # Log entry
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Add-Content -Path $logFile -Value "$timestamp [$Level] $Message"
}

# Convenience wrappers
function Write-Info  { param([string] $Message) Write-Status -Message $Message -Level INFO }
function Write-Warn  { param([string] $Message) Write-Status -Message $Message -Level WARN }
function Write-Fail  { param([string] $Message) Write-Status -Message $Message -Level ERROR }
function Write-Ok    { param([string] $Message) Write-Status -Message $Message -Level SUCCESS }

function Write-Divider {
    # Prevent double-console printing (was happening before when calling Write-Status inside)
    $line = "─" * 72
    Write-Host $line -ForegroundColor DarkGray
    if (-not $script:TempRoot) { $script:TempRoot = Get-TempRoot }
    $logFile = Join-Path $script:TempRoot 'BuildForce.log'
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Add-Content -Path $logFile -Value "$timestamp [INFO] $line"
}

function Start-Step {
    param([string] $Description)
    $script:CurrentStep++
    Write-Divider
    Write-Host (" STEP {0} of {1}  –  {2}" -f $script:CurrentStep, $script:TotalSteps, $Description) -ForegroundColor Cyan
    Write-Divider
    Write-Status -Message "=== STEP $($script:CurrentStep): $Description ===" -Level STEP
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

    # Ensure destination folder exists (curl and IWR both need it)
    $parent = Split-Path -Parent $DestPath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

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

# ---------------------------
# Disk selection helpers
# ---------------------------

function Get-BestOSDisk {
    # Weighting rules for disk types
    $busTypePreference = @{
        'NVMe'    = 1
        'SSD'     = 2
        'SATA'    = 3
        'RAID'    = 4
        'SAS'     = 5
        'ATA'     = 6
        'Unknown' = 10
        'USB'     = 99
        'SD'      = 99
        'MMC'     = 99
    }

    # Get all internal-ish disks
    $disks = Get-Disk | Where-Object {
        $_.BusType -notin @('USB','SD','MMC')
    }

    if (-not $disks) {
        throw "No suitable disks found."
    }

    # Add scoring metadata
    $ranked = $disks | ForEach-Object {
        $busScore = if ($busTypePreference.ContainsKey($_.BusType)) {
            $busTypePreference[$_.BusType]
        } else {
            $busTypePreference['Unknown']
        }

        [PSCustomObject]@{
            DiskNumber = $_.Number
            Size       = $_.Size
            BusType    = $_.BusType
            IsBoot     = $_.IsBoot
            IsSystem   = $_.IsSystem
            BusScore   = $busScore
        }
    }

    # Sort by:
    # 1. Bus type preference (lower is better)
    # 2. Non-boot disks first
    # 3. Non-system disks first
    # 4. Largest size
    $best = $ranked |
        Sort-Object `
            BusScore,
            IsBoot,
            IsSystem,
            @{Expression = 'Size'; Descending = $true} |
        Select-Object -First 1

    return $best.DiskNumber
}

function Find-BestInternalDisk {
    $diskNumber = Get-BestOSDisk
    if ($null -eq $diskNumber) { throw "No suitable internal disk found." }
    return Get-Disk -Number $diskNumber -ErrorAction Stop
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

        return $disk  # ALWAYS return disk object
    }

    Write-Info "No disk number specified – scanning for the best candidate..."
    return Find-BestInternalDisk  # ALWAYS return disk object
}

function New-UEFIPartitionLayout {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [int]$DiskNumber,

        [int]$RecoverySizeMB = 500,
        [int]$EfiSizeMB = 200
    )

    $commands = @(
        "select disk $DiskNumber",
        "clean",
        "convert gpt",

        "create partition efi size=$EfiSizeMB",
        "format quick fs=fat32 label=System",
        "assign letter=S",

        "create partition msr size=16",

        "create partition primary",
        "shrink minimum=$RecoverySizeMB",
        "format quick fs=ntfs label=Windows",
        "assign letter=W",

        "create partition primary",
        "format quick fs=ntfs label=Recovery",
        "assign letter=R",
        'set id="de94bba4-06d1-4d40-a16a-bfd50179d6ac"',
        "gpt attributes=0x8000000000000001",

        "list volume",
        "exit"
    )

    if ($PSCmdlet.ShouldProcess("Disk $DiskNumber", "Apply UEFI/GPT partition layout")) {
        $commands -join "`r`n" | diskpart
    }
}

# ---------------------------
# Catalog Handling
# ---------------------------

function Get-Catalog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $CatalogUrl
    )

    if (-not $script:TempRoot) { $script:TempRoot = Get-TempRoot }

    # Get the URL "leaf" (last path segment) and use it as the local filename
    try {
        $uri  = [Uri]$CatalogUrl
        $leaf = [IO.Path]::GetFileName($uri.AbsolutePath)
    }
    catch {
        # If CatalogUrl isn't a valid URI, fall back to treating it as a path-like string
        $leaf = Split-Path -Path $CatalogUrl -Leaf
    }

    # Fallback if leaf is empty (e.g., URL ends with /)
    if ([string]::IsNullOrWhiteSpace($leaf)) {
        $leaf = "catalog.clixml"
    }

    $localPath = Join-Path $script:TempRoot $leaf

    Write-Info "Downloading OS catalog: $CatalogUrl"
    Invoke-FileDownload -Url $CatalogUrl -DestPath $localPath -Retries 2 | Out-Null

    Write-Info "Importing PowerShell CLIXML catalog: $localPath"
    $catalog = Import-Clixml -Path $localPath
    return $catalog
}

function Resolve-OsCatalogEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Catalog,

        [Parameter(Mandatory)]
        [string] $OperatingSystem,

        [Parameter(Mandatory)]
        [string] $ReleaseId,

        [Parameter(Mandatory)]
        [string] $Architecture,

        [Parameter(Mandatory)]
        [string] $LanguageCode,

        [Parameter(Mandatory)]
        [string] $License


    )

    $entries = $Catalog
    if (-not $entries) {
        throw "Catalog contains no OperatingSystem entries."
    }

    $filtered = $entries | Where-Object {
        $_.OperatingSystem -eq $OperatingSystem -and
        $_.ReleaseId       -eq $ReleaseId       -and
        $_.Architecture    -eq $Architecture    -and
        $_.LanguageCode    -eq $LanguageCode    -and
        $_.License         -eq $License
    }

    if (-not $filtered) {
        throw "No matching OS entry found in catalog for: OS='$OperatingSystem' ReleaseId='$ReleaseId' Arch='$Architecture' Lang='$LanguageCode' License='$License'."
    }

    # If multiple match, pick newest build
    $best = $filtered |
        Sort-Object -Property Build -Descending |
        Select-Object -First 1

    return $best
}

function Get-HardwareIdentity {
    [CmdletBinding()]
    param()

    $bb = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue

    # Some environments spell these differently or leave them empty
    $bbSku     = $bb.SKU
    if ([string]::IsNullOrWhiteSpace($bbSku)) { $bbSku = $bb.SKUNumber }  # occasional variant

    [pscustomobject]@{
        CSManufacturer = $cs.Manufacturer
        CSModel        = $cs.Model

        BBManufacturer = $bb.Manufacturer
        BBModel        = $bb.Model
        BBSKU          = $bbSku
        BBProduct      = $bb.Product
    }
}



function Find-DriverPackMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Hardware,

        [Parameter(Mandatory)]
        [object[]] $DriverCatalog,

        [int] $MinScore = 6
    )

    function Normalize([string]$s) {
        if ([string]::IsNullOrWhiteSpace($s)) { return $null }
        return (($s -replace '\s+', ' ').Trim()).ToUpperInvariant()
    }

    function Get-AnyPropValue {
        param(
            [Parameter(Mandatory)] $Obj,
            [Parameter(Mandatory)] [string[]] $Names
        )
        foreach ($n in $Names) {
            $p = $Obj.PSObject.Properties[$n]
            if ($p) {
                $v = $p.Value
                if (-not [string]::IsNullOrWhiteSpace([string]$v)) { return [string]$v }
            }
        }
        return $null
    }

    $propMap = @{
        CSManufacturer = @('CSManufacturer','ComputerSystemManufacturer','CSMfr','ManufacturerCS')
        CSModel        = @('CSModel','ComputerSystemModel','CSProduct','ModelCS')
        BBManufacturer = @('BBManufacturer','BaseBoardManufacturer','BBMfr','ManufacturerBB')
        BBModel        = @('BBModel','BaseBoardModel','BBBoardModel','ModelBB')
        BBSKU          = @('BBSKU','BB-SKU','BaseBoardSKU','SKUNumber','SKU')
        BBProduct      = @('BBProduct','BaseBoardProduct','BBProd','Product')
        URL            = @('URL','Uri','DownloadUrl','DriverUrl')
        Sha1           = @('Sha1','SHA1','HashSha1','SHA-1')
        Sha256         = @('Sha256','SHA256','HashSha256','SHA-256')
    }

    $hw = [pscustomobject]@{
        CSManufacturer = Normalize $Hardware.CSManufacturer
        CSModel        = Normalize $Hardware.CSModel
        BBManufacturer = Normalize $Hardware.BBManufacturer
        BBModel        = Normalize $Hardware.BBModel
        BBSKU          = Normalize $Hardware.BBSKU
        BBProduct      = Normalize $Hardware.BBProduct
    }

    $weights = @{
        BBProduct      = 6
        BBSKU          = 6
        CSModel        = 4
        BBModel        = 3
        CSManufacturer = 2
        BBManufacturer = 2
    }

    $penalty = 2

    $scored = foreach ($item in $DriverCatalog) {

        $entry = [pscustomobject]@{
            CSManufacturer = Normalize (Get-AnyPropValue $item $propMap.CSManufacturer)
            CSModel        = Normalize (Get-AnyPropValue $item $propMap.CSModel)
            BBManufacturer = Normalize (Get-AnyPropValue $item $propMap.BBManufacturer)
            BBModel        = Normalize (Get-AnyPropValue $item $propMap.BBModel)
            BBSKU          = Normalize (Get-AnyPropValue $item $propMap.BBSKU)
            BBProduct      = Normalize (Get-AnyPropValue $item $propMap.BBProduct)
            URL            = Get-AnyPropValue $item $propMap.URL
            Sha1           = Get-AnyPropValue $item $propMap.Sha1
            Sha256         = Get-AnyPropValue $item $propMap.Sha256
        }

        $score = 0
        $compared = 0
        $exact = 0
        $matchedFields = New-Object System.Collections.Generic.List[string]

        foreach ($k in $weights.Keys) {
            $hv = $hw.$k
            $ev = $entry.$k

            if ($null -ne $hv -and $null -ne $ev) {
                $compared++
                if ($hv -eq $ev) {
                    $exact++
                    $score += $weights[$k]
                    $matchedFields.Add($k)
                } else {
                    $score -= $penalty
                }
            }
        }

        [pscustomobject]@{
            Score         = $score
            Compared      = $compared
            ExactMatches  = $exact
            HasUrl        = [bool](-not [string]::IsNullOrWhiteSpace($entry.URL))
            MatchedFields = $matchedFields -join ','
            Entry         = $item
            EntryView     = $entry
        }
    }

    # If NOTHING was comparable, don’t claim a tie — it’s “no evidence”
    if (($scored | Measure-Object -Property Compared -Maximum).Maximum -eq 0) {
        return [pscustomobject]@{
            Matched    = $false
            Reason     = "No comparable fields (hardware or catalog values are null / not mapped)."
            Hardware   = $Hardware
            Candidates = $scored | Select Score,Compared,ExactMatches,HasUrl,MatchedFields
        }
    }

    # Deterministic best: score, then most exact matches, then most compared fields, then has URL
    $ordered = $scored | Sort-Object Score, ExactMatches, Compared, HasUrl -Descending
    $top = $ordered | Select-Object -First 1

    # See if 2nd place is identical on all tie-break metrics
    $second = $ordered | Select-Object -Skip 1 -First 1
    $isTie = $false
    if ($second) {
        if ($second.Score -eq $top.Score -and
            $second.ExactMatches -eq $top.ExactMatches -and
            $second.Compared -eq $top.Compared -and
            $second.HasUrl -eq $top.HasUrl) {
            $isTie = $true
        }
    }

    if ($top.Score -lt $MinScore) {
        return [pscustomobject]@{
            Matched    = $false
            Reason     = "No match met minimum score ($MinScore). BestScore=$($top.Score)"
            Hardware   = $Hardware
            Candidates = $ordered | Select-Object -First 10 | Select Score,Compared,ExactMatches,HasUrl,MatchedFields,@{n='URL';e={$_.EntryView.URL}}
        }
    }

    if ($isTie) {
        # return all tied-at-top entries
        $ties = $ordered | Where-Object {
            $_.Score -eq $top.Score -and
            $_.ExactMatches -eq $top.ExactMatches -and
            $_.Compared -eq $top.Compared -and
            $_.HasUrl -eq $top.HasUrl
        }

        return [pscustomobject]@{
            Matched    = $false
            Reason     = "Tie after tie-breakers at Score=$($top.Score) Exact=$($top.ExactMatches) Compared=$($top.Compared) HasUrl=$($top.HasUrl)"
            Hardware   = $Hardware
            Candidates = $ties | Select Score,Compared,ExactMatches,HasUrl,MatchedFields,@{n='URL';e={$_.EntryView.URL}}
        }
    }

    # Single winner
    $one = $top.EntryView
    return [pscustomobject]@{
        Matched   = $true
        Score     = $top.Score
        Compared  = $top.Compared
        Exact     = $top.ExactMatches
        Hardware  = $Hardware
        URL       = $one.URL
        Sha1      = $one.Sha1
        Sha256    = $one.Sha256
        MatchInfo = $top.MatchedFields
    }
}



# ---------------------------
# MAIN (fleshed out)
# ---------------------------

# Optional: allow targeting a specific disk
# Add this param up top if you want it configurable:
# [int] $TargetDiskNumber = -1

# Make step count match reality
$script:CurrentStep = 0
$script:TotalSteps  = 14

function Invoke-Native {
    param(
        [Parameter(Mandatory)] [string] $FilePath,
        [string[]] $Arguments = @(),
        [switch] $IgnoreExitCode
    )

    Write-Info "Running: $FilePath $($Arguments -join ' ')"

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $FilePath
    $psi.Arguments              = ($Arguments -join ' ')
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    [void]$p.Start()

    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()

    if ($stdout) { $stdout.TrimEnd() -split "`r?`n" | ForEach-Object { Write-Info $_ } }
    if ($stderr) { $stderr.TrimEnd() -split "`r?`n" | ForEach-Object { Write-Warn $_ } }

    if (-not $IgnoreExitCode -and $p.ExitCode -ne 0) {
        throw "Command failed (exit $($p.ExitCode)): $FilePath $($Arguments -join ' ')"
    }

    return [pscustomobject]@{ ExitCode = $p.ExitCode; StdOut = $stdout; StdErr = $stderr }
}

function Get-EntryValue {
    param(
        [Parameter(Mandatory)] $Obj,
        [Parameter(Mandatory)] [string[]] $Names
    )
    foreach ($n in $Names) {
        $p = $Obj.PSObject.Properties[$n]
        if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) {
            return [string]$p.Value
        }
    }
    return $null
}

function Get-LeafNameFromUrl([string]$Url, [string]$FallbackName) {
    try {
        $u = [Uri]$Url
        $leaf = [IO.Path]::GetFileName($u.AbsolutePath)
        if ([string]::IsNullOrWhiteSpace($leaf)) { return $FallbackName }
        return $leaf
    } catch {
        return $FallbackName
    }
}

try {
    Start-Step "Creating WinRE Temporary Directory"
    $script:TempRoot = Get-TempRoot
    Write-Info "TempRoot: $script:TempRoot"

    Start-Step "Displaying Banner"
    Show-Banner

    Start-Step "Gathering Operating System and PowerShell Environment Information"
    $sys = Get-SystemInfo
    Write-Info "PowerShell: $($sys.PSVersion)"
    Write-Info "OS: $($sys.OSCaption)"

    Start-Step "Download Operating System Catalog"
    $catalog = Get-Catalog -CatalogUrl $OSCatalogUrl

    Start-Step "Selecting Operating System object"
    $osEntry = Resolve-OsCatalogEntry -Catalog $catalog `
        -OperatingSystem $OperatingSystem `
        -ReleaseId $ReleaseId `
        -Architecture $Architecture `
        -LanguageCode $LanguageCode `
        -License $License

    Write-Ok "Selected OS entry:"
    $osEntry | Format-List * | Out-String | ForEach-Object { Write-Info $_.TrimEnd() }

    # Resolve OS download fields (catalog schema tolerant)
    $osUrl     = Get-EntryValue $osEntry @('URL','Url','Uri','DownloadUrl','ESDUrl','WimUrl')
    $osSha1    = Get-EntryValue $osEntry @('Sha1','SHA1','HashSha1','SHA-1')
    $osSha256  = Get-EntryValue $osEntry @('Sha256','SHA256','HashSha256','SHA-256')
    $osIndex   = Get-EntryValue $osEntry @('Index','ImageIndex','WimIndex')
    if (-not $osIndex) { $osIndex = 1 }

    if (-not $osUrl) {
        throw "OS catalog entry did not contain a usable URL field (URL/DownloadUrl/ESDUrl/WimUrl)."
    }

    Start-Step "Download Driver Catalog"
    $driverCatalog = Get-Catalog -CatalogUrl $DriverCatalogUrl

    Start-Step "Gathering Hardware Identity"
    $hw = Get-HardwareIdentity
    Write-Info ("Hardware: CS={0} {1} | BB={2} {3} SKU={4} Prod={5}" -f `
        $hw.CSManufacturer, $hw.CSModel, $hw.BBManufacturer, $hw.BBModel, $hw.BBSKU, $hw.BBProduct)

    Start-Step "Searching for Best Match Driver Package"
    $result = Find-DriverPackMatch -Hardware $hw -DriverCatalog $driverCatalog

    if ($result.Matched) {
        Write-Ok ("Driver match found. Score={0} Exact={1} Compared={2} Fields={3}" -f `
            $result.Score, $result.Exact, $result.Compared, $result.MatchInfo)
        Write-Info "Driver URL: $($result.URL)"
    } else {
        Write-Warn "No single driver match selected: $($result.Reason)"
        if ($result.Candidates) {
            Write-Info "Top candidates (for troubleshooting):"
            $result.Candidates | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Info $_.TrimEnd() }
        }
    }

    Start-Step "Selecting Suitable Local Disk"
    # If you added $TargetDiskNumber param, pass it here:
    # $disk = Get-TargetDisk -PreferredNumber $TargetDiskNumber
    $disk = Get-TargetDisk
    Write-Ok ("Selected disk: #{0} BusType={1} Size={2:N2} GB Boot={3} System={4}" -f `
        $disk.Number, $disk.BusType, ($disk.Size/1GB), $disk.IsBoot, $disk.IsSystem)

    Start-Step "Clearing Disk and Creating Partitions (UEFI/GPT)"
    if ($PSCmdlet.ShouldProcess("Disk $($disk.Number)", "Clean + Apply UEFI partition layout")) {
        New-UEFIPartitionLayout -DiskNumber $disk.Number
        Write-Ok "Partition layout applied. Expect: S: EFI, W: Windows, R: Recovery"
    } else {
        Write-Warn "Skipped disk partitioning due to ShouldProcess (-WhatIf / -Confirm)."
    }

    Start-Step "Downloading Operating System Image (ESD/WIM)"
    $osFileName = Get-LeafNameFromUrl -Url $osUrl -FallbackName "install.esd"
    $osPath     = Join-Path $script:TempRoot $osFileName
    Invoke-FileDownload -Url $osUrl -DestPath $osPath -Retries 2 | Out-Null

    Start-Step "Performing File Hash Check (if catalog provides hashes)"
    Confirm-FileHash -FilePath $osPath -ExpectedSha1 $osSha1 -ExpectedSha256 $osSha256
    Write-Ok "OS image verified (or no hashes provided)."

    Start-Step "Applying Operating System Image to W:\\"
    if ($PSCmdlet.ShouldProcess("W:\\", "Apply Windows image from $osFileName (Index $osIndex)")) {
        # DISM apply-image works for WIM/ESD
        Invoke-Native -FilePath "dism.exe" -Arguments @(
            "/Apply-Image",
            "/ImageFile:$osPath",
            "/Index:$osIndex",
            "/ApplyDir:W:\"
        ) | Out-Null

        Write-Ok "Windows image applied to W:\"
    } else {
        Write-Warn "Skipped apply-image due to ShouldProcess."
    }

    Start-Step "Creating Boot Files (BCDBoot)"
    if ($PSCmdlet.ShouldProcess("S:\\", "Create UEFI boot files from W:\\Windows")) {
        Invoke-Native -FilePath "bcdboot.exe" -Arguments @(
            "W:\Windows",
            "/s", "S:",
            "/f", "UEFI"
        ) | Out-Null
        Write-Ok "Boot files created."
    } else {
        Write-Warn "Skipped BCDBoot due to ShouldProcess."
    }

    Start-Step "Configuring WinRE on Recovery Partition (Offline)"
    if ($PSCmdlet.ShouldProcess("R:\\", "Copy WinRE + register offline with ReAgentC")) {

        # Create WinRE folder structure
        $rePath = "R:\Recovery\WindowsRE"
        if (-not (Test-Path -LiteralPath $rePath)) {
            New-Item -ItemType Directory -Path $rePath -Force | Out-Null
        }

        # Copy Winre.wim from applied image
        $srcWinre = "W:\Windows\System32\Recovery\Winre.wim"
        if (Test-Path -LiteralPath $srcWinre) {
            Copy-Item -LiteralPath $srcWinre -Destination (Join-Path $rePath "Winre.wim") -Force
            Write-Ok "Copied Winre.wim to $rePath"
        } else {
            Write-Warn "Winre.wim not found at $srcWinre (image may not include it at that path)."
        }

        # Register WinRE offline:
        # reagentc /setreimage /path R:\Recovery\WindowsRE /target W:\Windows
        # reagentc /enable /target W:\Windows
        Invoke-Native -FilePath "reagentc.exe" -Arguments @(
            "/setreimage",
            "/path", $rePath,
            "/target", "W:\Windows"
        ) | Out-Null

        Invoke-Native -FilePath "reagentc.exe" -Arguments @(
            "/enable",
            "/target", "W:\Windows"
        ) | Out-Null

        Write-Ok "WinRE configured for offline Windows."
        # ReAgentC offline syntax is documented by Microsoft. microsoft.com/en-us/windows-hardware/manufacture/desktop/reagentc-command-line-options?view=windows-11)
    } else {
        Write-Warn "Skipped WinRE configuration due to ShouldProcess."
    }

    Start-Step "Downloading Best-Matched Driver Package and Injecting Drivers (Offline)"
    if ($result.Matched -and $result.URL) {

        $drvFileName = Get-LeafNameFromUrl -Url $result.URL -FallbackName "driverpack.bin"
        $drvPath     = Join-Path $script:TempRoot $drvFileName

        if ($PSCmdlet.ShouldProcess($drvPath, "Download driver pack")) {
            Invoke-FileDownload -Url $result.URL -DestPath $drvPath -Retries 2 | Out-Null
            Confirm-FileHash -FilePath $drvPath -ExpectedSha1 $result.Sha1 -ExpectedSha256 $result.Sha256
        } else {
            Write-Warn "Skipped driver pack download due to ShouldProcess."
        }

        # Extract to folder (ZIP/CAB supported)
        $extractRoot = Join-Path $script:TempRoot ("Drivers_{0}" -f ($hw.CSModel -replace '[^\w\-]+','_'))
        if (-not (Test-Path -LiteralPath $extractRoot)) {
            New-Item -ItemType Directory -Path $extractRoot -Force | Out-Null
        }

        $ext = [IO.Path]::GetExtension($drvPath).ToLowerInvariant()

        if ($PSCmdlet.ShouldProcess($extractRoot, "Extract driver pack ($ext)")) {
            switch ($ext) {
                ".zip" {
                    Expand-Archive -LiteralPath $drvPath -DestinationPath $extractRoot -Force
                    Write-Ok "Extracted ZIP to $extractRoot"
                }
                ".cab" {
                    # expand.exe is available in WinPE/WinRE typically
                    Invoke-Native -FilePath "expand.exe" -Arguments @(
                        "-F:*", $drvPath, $extractRoot
                    ) | Out-Null
                    Write-Ok "Extracted CAB to $extractRoot"
                }
                default {
                    Write-Warn "Unknown driver pack format '$ext'. Download complete, but extraction is not implemented for this type."
                    Write-Warn "If this is an EXE-based vendor pack, consider publishing as ZIP/CAB or add a vendor-specific silent extract routine."
                }
            }
        }

        # Inject drivers offline (requires .inf files in extracted tree)
        if ($PSCmdlet.ShouldProcess("W:\\", "DISM /Add-Driver /Recurse from $extractRoot")) {
            Invoke-Native -FilePath "dism.exe" -Arguments @(
                "/Image:W:\",
                "/Add-Driver",
                "/Driver:$extractRoot",
                "/Recurse"
            ) | Out-Null

            Write-Ok "Offline driver injection complete."
            # DISM /Add-Driver /Recurse guidance documented by Microsoft. [1](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/add-and-remove-drivers-to-an-offline-windows-image?view=windows-11)
        }

    } else {
        Write-Warn "No driver pack was injected because a single best-match driver URL was not selected."
    }

    Start-Step "Finalizing and Displaying Summary"
    Write-Ok "Build completed."
    Write-Info "OS image: $osFileName (Index $osIndex)"
    Write-Info ("Disk: #{0} -> EFI=S:, Windows=W:, Recovery=R:" -f $disk.Number)
    Write-Info "Log file: $(Join-Path $script:TempRoot 'BuildForce.log')"

} catch {
    Write-Fail "Fatal error: $($_.Exception.Message)"
    Write-Fail $_.ScriptStackTrace
    throw
}
