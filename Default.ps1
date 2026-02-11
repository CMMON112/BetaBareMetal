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

    $xRoot         = 'X:\Windows\Temp\BuildForge'
    $wRootNoWin    = 'W:\BuildForge'
    $wRootWinTemp  = 'W:\Windows\Temp\BuildForge'

    function Ensure-Dir([string]$Path) {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }
    }

    function Move-BuildForgeContents([string]$Source, [string]$Destination) {
        # Best-effort only — never throw
        try {
            if (-not (Test-Path -LiteralPath $Source)) { return }
            Ensure-Dir $Destination

            $items = Get-ChildItem -LiteralPath $Source -Force -ErrorAction SilentlyContinue
            foreach ($i in $items) {
                $destPath = Join-Path $Destination $i.Name
                Move-Item -LiteralPath $i.FullName -Destination $destPath -Force -ErrorAction SilentlyContinue
            }

            Remove-Item -LiteralPath $Source -Force -Recurse -ErrorAction SilentlyContinue
        } catch {
            # swallow
        }
    }

    $hasW    = Test-Path -LiteralPath 'W:\'
    $hasWWin = Test-Path -LiteralPath 'W:\Windows'
    $hasX    = Test-Path -LiteralPath 'X:\'

    # Prefer W: as soon as it exists (bigger than X: RAM drive)
    if ($hasW) {
        if ($hasWWin) {
            Ensure-Dir $wRootWinTemp
            Move-BuildForgeContents -Source $xRoot      -Destination $wRootWinTemp
            Move-BuildForgeContents -Source $wRootNoWin -Destination $wRootWinTemp
            return $wRootWinTemp
        }

        Ensure-Dir $wRootNoWin
        Move-BuildForgeContents -Source $xRoot -Destination $wRootNoWin
        return $wRootNoWin
    }

    if ($hasX) {
        Ensure-Dir $xRoot
        return $xRoot
    }

    throw "Get-TempRoot: Neither X:\ nor W:\ is available to host BuildForge temp logs."
}


# Core unified output + logging function
function Write-Status {
    param(
        [string] $Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS','STEP')]
        [string] $Level = 'INFO'
    )

    # Always re-evaluate TempRoot; diskpart reruns can invalidate old paths
    try {
        $script:TempRoot = Get-TempRoot
    } catch {
        # Worst case fallback
        $script:TempRoot = 'X:\Windows\Temp\BuildForge'
        if (-not (Test-Path -LiteralPath $script:TempRoot)) {
            New-Item -ItemType Directory -Path $script:TempRoot -Force | Out-Null
        }
    }

    switch ($Level) {
        'INFO'    { $prefix = 'INFO';    $color = 'Gray' }
        'WARN'    { $prefix = 'WARN';    $color = 'Yellow' }
        'ERROR'   { $prefix = 'ERROR';   $color = 'Red' }
        'SUCCESS' { $prefix = 'OK';      $color = 'Green' }
        'STEP'    { $prefix = 'STEP';    $color = 'Cyan' }
    }

    Write-Host ("  [{0}]    {1}" -f $prefix, $Message) -ForegroundColor $color

    $logFile   = Join-Path $script:TempRoot 'BuildForce.log'
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line      = "$timestamp [$Level] $Message"

    # Ensure directory exists, ensure log file exists, retry once if it disappears mid-write
    for ($i = 0; $i -lt 2; $i++) {
        try {
            if (-not (Test-Path -LiteralPath $script:TempRoot)) {
                New-Item -ItemType Directory -Path $script:TempRoot -Force | Out-Null
            }

            if (-not (Test-Path -LiteralPath $logFile)) {
                New-Item -ItemType File -Path $logFile -Force | Out-Null
            }

            Add-Content -Path $logFile -Value $line
            break
        } catch {
            # TempRoot may have vanished; re-resolve once
            if ($i -eq 0) {
                try { $script:TempRoot = Get-TempRoot } catch { }
                $logFile = Join-Path $script:TempRoot 'BuildForce.log'
                Start-Sleep -Milliseconds 50
                continue
            }
            # On second failure, don't crash the whole build just because logging failed
        }
    }
}
``

# Convenience wrappers
function Write-Info  { param([string] $Message) Write-Status -Message $Message -Level INFO }
function Write-Warn  { param([string] $Message) Write-Status -Message $Message -Level WARN }
function Write-Fail  { param([string] $Message) Write-Status -Message $Message -Level ERROR }
function Write-Ok    { param([string] $Message) Write-Status -Message $Message -Level SUCCESS }

function Write-Divider {
    $line = "─" * 72
    Write-Host $line -ForegroundColor DarkGray
    Write-Status -Message $line -Level INFO
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

        [int]$RecoverySizeMB = 750,
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
function Get-WindowsImageIndexByExactName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ImagePath,
        [Parameter(Mandatory)][string]$ExactName
    )

    # Prefer DISM PowerShell cmdlets when available
    if (Get-Command Get-WindowsImage -ErrorAction SilentlyContinue) {
        $images = Get-WindowsImage -ImagePath $ImagePath
        $hit = $images | Where-Object { $_.ImageName -eq $ExactName } | Select-Object -First 1
        if (-not $hit) {
            $names = ($images | Select-Object -ExpandProperty ImageName) -join '; '
            throw "No image named '$ExactName' found in $ImagePath. Available: $names"
        }
        return [int]$hit.ImageIndex
    }

    # Fallback to DISM.exe enumeration
    $out = & dism.exe /English /Get-WimInfo /WimFile:"$ImagePath" 2>&1 | Out-String

    # Parse blocks like:
    # Index : 6
    # Name  : Windows 11 Enterprise
    $matches = [regex]::Matches($out, "Index\s*:\s*(\d+)\s+Name\s*:\s*(.+?)\s*(?:\r?\n|$)",
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    if ($matches.Count -eq 0) {
        throw "Failed to parse DISM /Get-WimInfo output for $ImagePath"
    }

    $entries = foreach ($m in $matches) {
        [pscustomobject]@{
            Index = [int]$m.Groups[1].Value
            Name  = $m.Groups[2].Value.Trim()
        }
    }

    $hit = $entries | Where-Object { $_.Name -eq $ExactName } | Select-Object -First 1
    if (-not $hit) {
        $names = ($entries.Name | Sort-Object -Unique) -join '; '
        throw "No image named '$ExactName' found in $ImagePath. Available: $names"
    }

    return [int]$hit.Index
}

function Apply-WindowsImageSmart {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ImagePath,
        [Parameter(Mandatory)][string]$ApplyPath,
        [Parameter(Mandatory)][string]$ExactName
    )

    $index = Get-WindowsImageIndexByExactName -ImagePath $ImagePath -ExactName $ExactName
    Write-Ok "Selected image: '$ExactName' (Index $index)"

    # Prefer Expand-WindowsImage if available (cleaner than DISM.exe)
    if (Get-Command Expand-WindowsImage -ErrorAction SilentlyContinue) {
        # Expand-WindowsImage can apply by Name directly [1](https://learn.microsoft.com/en-us/powershell/module/dism/expand-windowsimage?view=windowsserver2025-ps)
        Expand-WindowsImage -ImagePath $ImagePath -ApplyPath $ApplyPath -Name $ExactName -CheckIntegrity
        return
    }

    # Fallback to DISM.exe /Apply-Image (Index-based)
    & dism.exe /Apply-Image /ImageFile:"$ImagePath" /Index:$index /ApplyDir:"$ApplyPath"
    if ($LASTEXITCODE -ne 0) {
        throw "DISM /Apply-Image failed with exit code $LASTEXITCODE"
    }
}

function Invoke-BuildForge {
    [CmdletBinding()]
    param()

    $ErrorActionPreference = 'Stop'
    $script:CurrentStep = 0
    $script:TotalSteps  = 12

    function Ensure-Dir([string]$Path) {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }
    }

    function Get-CacheRoot {
        # After partitioning we WANT payloads on W:
        if (Test-Path -LiteralPath 'W:\') {
            $p = 'W:\BuildForge\Cache'
            Ensure-Dir $p
            return $p
        }

        # Before partitioning, fall back to TempRoot (likely X:)
        if (-not $script:TempRoot) { $script:TempRoot = Get-TempRoot }
        $p = Join-Path $script:TempRoot 'Cache'
        Ensure-Dir $p
        return $p
    }

    function Get-IndexByExactName {
        param(
            [Parameter(Mandatory)][string]$ImagePath,
            [Parameter(Mandatory)][string]$ExactName
        )

        # Prefer PowerShell DISM module if present [1](https://learn.microsoft.com/en-us/powershell/module/dism/get-windowsimage?view=windowsserver2025-ps)
        if (Get-Command Get-WindowsImage -ErrorAction SilentlyContinue) {
            $img = Get-WindowsImage -ImagePath $ImagePath |
                   Where-Object { $_.ImageName -eq $ExactName } |
                   Select-Object -First 1
            if (-not $img) {
                $names = (Get-WindowsImage -ImagePath $ImagePath | Select-Object -Expand ImageName) -join '; '
                throw "Image '$ExactName' not found. Available: $names"
            }
            return [int]$img.ImageIndex
        }

        # Fallback: DISM.exe list and parse [3](https://www.ninjaone.com/blog/add-or-remove-hardware-device-drivers/)[4](https://www.recastsoftware.com/resources/apply-package-of-drivers-manually-dism/)
        $out = (& dism.exe /English /Get-WimInfo /WimFile:"$ImagePath" 2>&1 | Out-String)

        $rx = [regex]"Index\s*:\s*(\d+)\s+Name\s*:\s*(.+?)\s*(?:\r?\n|$)"
        $matches = $rx.Matches($out)
        if ($matches.Count -eq 0) { throw "Could not parse DISM /Get-WimInfo output." }

        $entries = foreach ($m in $matches) {
            [pscustomobject]@{ Index=[int]$m.Groups[1].Value; Name=$m.Groups[2].Value.Trim() }
        }

        $hit = $entries | Where-Object { $_.Name -eq $ExactName } | Select-Object -First 1
        if (-not $hit) {
            $names = ($entries.Name | Sort-Object -Unique) -join '; '
            throw "Image '$ExactName' not found. Available: $names"
        }
        return $hit.Index
    }

    function Apply-Image {
        param(
            [Parameter(Mandatory)][string]$ImagePath,
            [Parameter(Mandatory)][string]$ApplyPath,
            [Parameter(Mandatory)][string]$ExactName
        )

        $idx = Get-IndexByExactName -ImagePath $ImagePath -ExactName $ExactName
        Write-Ok "Selected image '$ExactName' (Index $idx)"

        # Prefer Expand-WindowsImage if present (apply by Name or Index) [2](https://learn.microsoft.com/en-us/powershell/module/dism/expand-windowsimage?view=windowsserver2025-ps)
        if (Get-Command Expand-WindowsImage -ErrorAction SilentlyContinue) {
            Expand-WindowsImage -ImagePath $ImagePath -ApplyPath $ApplyPath -Name $ExactName -CheckIntegrity
            return
        }

        # Fallback to dism.exe apply
        & dism.exe /Apply-Image /ImageFile:"$ImagePath" /Index:$idx /ApplyDir:"$ApplyPath"
        if ($LASTEXITCODE -ne 0) { throw "DISM /Apply-Image failed with exit code $LASTEXITCODE" }
    }

    try {
        Start-Step "Init Temp + Banner"
        $script:TempRoot = Get-TempRoot
        Write-Info "TempRoot: $script:TempRoot"
        Show-Banner

        Start-Step "System Info"
        $sys = Get-SystemInfo
        Write-Info "PowerShell: $($sys.PSVersion)"
        Write-Info "OS: $($sys.OSCaption)"

        Start-Step "Download OS catalog + pick entry"
        $osCatalog = Get-Catalog -CatalogUrl $OSCatalogUrl
        $osEntry = Resolve-OsCatalogEntry -Catalog $osCatalog `
            -OperatingSystem $OperatingSystem `
            -ReleaseId $ReleaseId `
            -Architecture $Architecture `
            -LanguageCode $LanguageCode `
            -License $License
        $osUrl    = ($osEntry | Select-Object -ExpandProperty URL -ErrorAction SilentlyContinue)
        if (-not $osUrl) { $osUrl = ($osEntry | Select-Object -ExpandProperty DownloadUrl -ErrorAction SilentlyContinue) }
        if (-not $osUrl) { throw "OS entry missing URL/DownloadUrl." }

        $osSha1   = $osEntry.Sha1
        $osSha256 = $osEntry.Sha256

        Start-Step "Download driver catalog + match hardware"
        $drvCatalog = Get-Catalog -CatalogUrl $DriverCatalogUrl
        $hw = Get-HardwareIdentity
        $drvMatch = Find-DriverPackMatch -Hardware $hw -DriverCatalog $drvCatalog

        if ($drvMatch.Matched) {
            Write-Ok "Driver pack match: $($drvMatch.URL)"
        } else {
            Write-Warn "No driver pack match: $($drvMatch.Reason)"
        }

        Start-Step "Select disk + partition"
        $disk = Get-TargetDisk
        Write-Ok ("Disk #{0} {1} {2:N1}GB" -f $disk.Number, $disk.BusType, ($disk.Size/1GB))
        New-UEFIPartitionLayout -DiskNumber $disk.Number

        # IMPORTANT: after partitioning W: exists -> move cache there
        Start-Step "Set cache on W: (avoid X: filling)"
        $cacheRoot = Get-CacheRoot
        Write-Info "CacheRoot: $cacheRoot"

        Start-Step "Download OS image to cache"
        $osFileName = ([IO.Path]::GetFileName(([Uri]$osUrl).AbsolutePath))
        if ([string]::IsNullOrWhiteSpace($osFileName)) { $osFileName = "install.esd" }
        $osPath = Join-Path $cacheRoot $osFileName
        Invoke-FileDownload -Url $osUrl -DestPath $osPath -Retries 2 | Out-Null
        Confirm-FileHash -FilePath $osPath -ExpectedSha1 $osSha1 -ExpectedSha256 $osSha256

        Start-Step "Enumerate ESD + apply Windows 11 Enterprise"
        # Optional: print images for troubleshooting
        if (Get-Command Get-WindowsImage -ErrorAction SilentlyContinue) {
            Get-WindowsImage -ImagePath $osPath | Select ImageIndex,ImageName,Architecture | Format-Table -AutoSize |
                Out-String | ForEach-Object { Write-Info $_.TrimEnd() }
        } else {
            (& dism.exe /English /Get-WimInfo /WimFile:"$osPath" | Out-String) |
                ForEach-Object { Write-Info $_.TrimEnd() }
        }

        Apply-Image -ImagePath $osPath -ApplyPath "W:\" -ExactName "Windows 11 Enterprise"

        Start-Step "BCDBoot"
        & bcdboot.exe W:\Windows /s S: /f UEFI
        if ($LASTEXITCODE -ne 0) { throw "bcdboot failed: $LASTEXITCODE" }

        Start-Step "Configure WinRE on R:"
        $rePath = "R:\Recovery\WindowsRE"
        Ensure-Dir $rePath
        $srcWinre = "W:\Windows\System32\Recovery\Winre.wim"
        if (Test-Path $srcWinre) {
            Copy-Item $srcWinre (Join-Path $rePath "Winre.wim") -Force
        } else {
            Write-Warn "Winre.wim not found at $srcWinre"
        }

        & reagentc.exe /setreimage /path $rePath /target W:\Windows
        & reagentc.exe /enable /target W:\Windows

        Start-Step "Download + inject drivers (if matched)"
        if ($drvMatch.Matched -and $drvMatch.URL) {
            $drvFileName = ([IO.Path]::GetFileName(([Uri]$drvMatch.URL).AbsolutePath))
            if ([string]::IsNullOrWhiteSpace($drvFileName)) { $drvFileName = "driverpack.cab" }
            $drvPath = Join-Path $cacheRoot $drvFileName
            Invoke-FileDownload -Url $drvMatch.URL -DestPath $drvPath -Retries 2 | Out-Null
            Confirm-FileHash -FilePath $drvPath -ExpectedSha1 $drvMatch.Sha1 -ExpectedSha256 $drvMatch.Sha256

            $extractRoot = Join-Path $cacheRoot "Drivers"
            Ensure-Dir $extractRoot

            $ext = [IO.Path]::GetExtension($drvPath).ToLowerInvariant()
            if ($ext -eq ".zip") {
                Expand-Archive -LiteralPath $drvPath -DestinationPath $extractRoot -Force
            } elseif ($ext -eq ".cab") {
                & expand.exe -F:* $drvPath $extractRoot | Out-Null
            } else {
                throw "Unsupported driver pack format: $ext (use .cab or .zip)"
            }

            & dism.exe /Image:W:\ /Add-Driver /Driver:$extractRoot /Recurse
            if ($LASTEXITCODE -ne 0) { throw "Driver injection failed: $LASTEXITCODE" }
        }

        Start-Step "Done"
        Write-Ok "Build complete"
        Write-Info "OS image: $osPath"
        Write-Info "Cache: $cacheRoot"
        Write-Info "Log: $(Join-Path $script:TempRoot 'BuildForce.log')"
    }
    catch {
        Write-Fail "Fatal: $($_.Exception.Message)"
        Write-Fail $_.ScriptStackTrace
        throw
    }
}

Invoke-BuildForge
