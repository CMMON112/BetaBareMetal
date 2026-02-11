[CmdletBinding()]
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

    [string] $DriverCatalogUrl = "https://raw.githubusercontent.com/CMMON112/BetaBareMetal/refs/heads/main/build-driverpackcatalog.xml",
    [string] $OSCatalogUrl     = "https://raw.githubusercontent.com/CMMON112/BetaBareMetal/refs/heads/main/build-oscatalog.xml"
)

$ErrorActionPreference = 'Stop'

# ---------------------------
# Step tracking
# ---------------------------
$script:CurrentStep = 0
$script:TotalSteps  = 12
$script:TempRoot    = $null

# ---------------------------
# TempRoot + Logging (re-runnable)
# ---------------------------
function Get-TempRoot {
    $xRoot        = 'X:\Windows\Temp\BuildForge'
    $wRootNoWin   = 'W:\BuildForge'
    $wRootWinTemp = 'W:\Windows\Temp\BuildForge'

    function Ensure-Dir([string]$Path) {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }
    }

    function Move-BuildForgeContents([string]$Source, [string]$Destination) {
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
            # best effort only
        }
    }

    $hasW    = Test-Path -LiteralPath 'W:\'
    $hasWWin = Test-Path -LiteralPath 'W:\Windows'
    $hasX    = Test-Path -LiteralPath 'X:\'

    # Prefer W: as soon as it exists
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

function Write-Status {
    param(
        [string] $Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS','STEP')]
        [string] $Level = 'INFO'
    )

    # Always re-resolve: diskpart reruns can invalidate old paths
    try {
        $script:TempRoot = Get-TempRoot
    } catch {
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

    $logFile = Join-Path $script:TempRoot 'BuildForce.log'
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "$timestamp [$Level] $Message"

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
            if ($i -eq 0) {
                try { $script:TempRoot = Get-TempRoot } catch { }
                $logFile = Join-Path $script:TempRoot 'BuildForce.log'
                Start-Sleep -Milliseconds 50
            }
        }
    }
}

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

# ---------------------------
# Small helpers (no backtick line continuations)
# ---------------------------
function Show-Banner {
@"
            ███╗   ███╗ ██████╗ ███╗   ██╗ █████╗ ███████╗██╗  ██╗
            ████╗ ████║██╔═══██╗████╗  ██║██╔══██╗██╔════╝██║  ██║
            ██╔████╔██║██║   ██║██╔██╗ ██║███████║███████╗███████║
            ██║╚██╔╝██║██║   ██║██║╚██╗██║██╔══██║╚════██║██╔══██║
            ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║  ██║███████║██║  ██║
            ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
"@ -split "`r?`n" | ForEach-Object { Write-Host $_ -ForegroundColor Cyan }
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
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
}

function Resolve-CurlPath {
    $candidates = @(
        (Join-Path $env:WINDIR 'System32\curl.exe'),
        'curl.exe'
    )
    foreach ($path in $candidates) {
        $cmd = Get-Command $path -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Path }
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

    $parent = Split-Path -Parent $DestPath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $curl = Resolve-CurlPath
    $attempts = $Retries + 1

    for ($try = 1; $try -le $attempts; $try++) {
        Write-Info ("Downloading (attempt {0}/{1}): {2}" -f $try, $attempts, $Url)

        try {
            if ($curl) {
                Write-Info "Using native curl.exe..."
                $args = @(
                    '--fail','--location','--silent','--show-error',
                    '--connect-timeout','30',
                    '--output', $DestPath,
                    $Url
                )
                & $curl @args
                if ($LASTEXITCODE -ne 0) { throw "curl exited with code $LASTEXITCODE" }
            } else {
                Write-Info "curl.exe not found – using Invoke-WebRequest..."
                Invoke-WebRequest -Uri $Url -OutFile $DestPath -UseBasicParsing -ErrorAction Stop
            }

            if (-not (Test-Path -LiteralPath $DestPath)) {
                throw "Download reported success but file missing: $DestPath"
            }

            Write-Ok "Download complete"
            return $DestPath
        }
        catch {
            Write-Warn ("Attempt {0} failed: {1}" -f $try, $_.Exception.Message)
            if ($try -lt $attempts) { Start-Sleep -Seconds 3 }
            else { throw "All download attempts failed for $Url" }
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
        $actual = (Get-FileHash -Algorithm SHA1 -Path $FilePath).Hash.ToLowerInvariant()
        $expect = $ExpectedSha1.ToLowerInvariant().Trim()
        if ($actual -ne $expect) {
            throw "SHA1 mismatch. Expected $expect got $actual"
        }
        Write-Ok "SHA1 verified"
    }

    if ($ExpectedSha256) {
        $actual = (Get-FileHash -Algorithm SHA256 -Path $FilePath).Hash.ToLowerInvariant()
        $expect = $ExpectedSha256.ToLowerInvariant().Trim()
        if ($actual -ne $expect) {
            throw "SHA256 mismatch. Expected $expect got $actual"
        }
        Write-Ok "SHA256 verified"
    }
}

# ---------------------------
# Disk + Partitioning
# ---------------------------
function Get-TargetDisk {
    Write-Info "Selecting best internal disk..."
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

    $disks = Get-Disk | Where-Object { $_.BusType -notin @('USB','SD','MMC') }
    if (-not $disks) { throw "No suitable disks found." }

    $ranked = foreach ($d in $disks) {
        $busScore = if ($busTypePreference.ContainsKey($d.BusType)) { $busTypePreference[$d.BusType] } else { 10 }
        [pscustomobject]@{
            Disk = $d
            BusScore = $busScore
        }
    }

    $best = $ranked | Sort-Object BusScore, @{Expression={$_.Disk.IsBoot}}, @{Expression={$_.Disk.IsSystem}}, @{Expression={$_.Disk.Size}; Descending=$true} | Select-Object -First 1
    return $best.Disk
}

function New-UEFIPartitionLayout {
    param(
        [Parameter(Mandatory)][int]$DiskNumber,
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
        "exit"
    )

    $scriptText = $commands -join "`r`n"
    $temp = Join-Path (Get-TempRoot) "diskpart-uefi.txt"
    Set-Content -Path $temp -Value $scriptText -Encoding ASCII

    Write-Info "Running diskpart layout script..."
    & diskpart /s $temp | Out-String | ForEach-Object { Write-Info $_.TrimEnd() }
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

function Get-Catalog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CatalogUrl
    )

    # Ensure we have a usable temp root even on reruns after diskpart
    if (-not $script:TempRoot) { $script:TempRoot = Get-TempRoot }

    # Prefer W:\BuildForge\Cache if W: exists (big downloads)
    $cacheRoot = (Get-CacheRoot)
    if (-not (Test-Path -LiteralPath $cacheRoot)) { New-Item -ItemType Directory -Path $cacheRoot -Force | Out-Null }

    # Use the URL leaf name as the file name (fallback if needed)
    $leaf = "catalog.clixml"
    try {
        $uri = [Uri]$CatalogUrl
        $leaf = [IO.Path]::GetFileName($uri.AbsolutePath)
        if ([string]::IsNullOrWhiteSpace($leaf)) { $leaf = "catalog.clixml" }
    } catch { }

    $localPath = Join-Path $cacheRoot $leaf

    Write-Info ("Downloading catalog: {0}" -f $CatalogUrl)
    Invoke-FileDownload -Url $CatalogUrl -DestPath $localPath -Retries 2 | Out-Null

    Write-Info ("Importing catalog: {0}" -f $localPath)

    try {
        return Import-Clixml -Path $localPath
    } catch {
        throw "Get-Catalog: Failed to Import-Clixml '$localPath'. If this file is real XML (not CLIXML), the parser must be changed."
    }
}
function Get-HardwareIdentity {
    [CmdletBinding()]
    param()

    $bb = $null
    $cs = $null

    try { $bb = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue } catch {}
    try { $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue } catch {}

    # Normalize SKU – some systems populate different fields
    $bbSku = $null
    if ($bb) {
        if (-not [string]::IsNullOrWhiteSpace($bb.SKU)) {
            $bbSku = $bb.SKU
        } elseif (-not [string]::IsNullOrWhiteSpace($bb.SKUNumber)) {
            $bbSku = $bb.SKUNumber
        }
    }

    [pscustomobject]@{
        CSManufacturer = if ($cs) { $cs.Manufacturer } else { $null }
        CSModel        = if ($cs) { $cs.Model } else { $null }

        BBManufacturer = if ($bb) { $bb.Manufacturer } else { $null }
        BBModel        = if ($bb) { $bb.Model } else { $null }
        BBSKU          = $bbSku
        BBProduct      = if ($bb) { $bb.Product } else { $null }
    }
}
function Resolve-OsCatalogEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Catalog,
        [Parameter(Mandatory)][string] $OperatingSystem,
        [Parameter(Mandatory)][string] $ReleaseId,
        [Parameter(Mandatory)][string] $Architecture,
        [Parameter(Mandatory)][string] $LanguageCode,
        [Parameter(Mandatory)][string] $License
    )

    if (-not $Catalog) { throw "Resolve-OsCatalogEntry: Catalog is empty." }

    # Catalog might be a single object or array
    $entries = @($Catalog)

    $filtered = $entries | Where-Object {
        ($_.OperatingSystem -eq $OperatingSystem) -and
        ($_.ReleaseId       -eq $ReleaseId)       -and
        ($_.Architecture    -eq $Architecture)    -and
        ($_.LanguageCode    -eq $LanguageCode)    -and
        ($_.License         -eq $License)
    }

    if (-not $filtered) {
        throw "Resolve-OsCatalogEntry: No match for OS='$OperatingSystem' ReleaseId='$ReleaseId' Arch='$Architecture' Lang='$LanguageCode' License='$License'."
    }

    # Prefer newest build if property exists
    if ($filtered[0].PSObject.Properties.Name -contains 'Build') {
        return ($filtered | Sort-Object -Property Build -Descending | Select-Object -First 1)
    }

    return ($filtered | Select-Object -First 1)
}

# ---------------------------
# Image selection & apply (no backtick continuations)
# ---------------------------
function Get-IndexByExactName {
    param(
        [Parameter(Mandatory)][string]$ImagePath,
        [Parameter(Mandatory)][string]$ExactName
    )

    if (Get-Command Get-WindowsImage -ErrorAction SilentlyContinue) {
        $img = Get-WindowsImage -ImagePath $ImagePath | Where-Object { $_.ImageName -eq $ExactName } | Select-Object -First 1
        if (-not $img) {
            $names = (Get-WindowsImage -ImagePath $ImagePath | Select-Object -ExpandProperty ImageName) -join '; '
            throw "Image '$ExactName' not found. Available: $names"
        }
        return [int]$img.ImageIndex
    }

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
    Write-Ok ("Selected image '{0}' (Index {1})" -f $ExactName, $idx)

    if (Get-Command Expand-WindowsImage -ErrorAction SilentlyContinue) {
        Expand-WindowsImage -ImagePath $ImagePath -ApplyPath $ApplyPath -Name $ExactName -CheckIntegrity
        return
    }

    & dism.exe /Apply-Image /ImageFile:"$ImagePath" /Index:$idx /ApplyDir:"$ApplyPath"
    if ($LASTEXITCODE -ne 0) { throw "DISM /Apply-Image failed with exit code $LASTEXITCODE" }
}

function Get-CacheRoot {
    if (Test-Path -LiteralPath 'W:\') {
        $p = 'W:\BuildForge\Cache'
        if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
        return $p
    }

    $t = Get-TempRoot
    $p = Join-Path $t 'Cache'
    if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    return $p
}

# ---------------------------
# MAIN
# ---------------------------
function Invoke-BuildForge {
    try {
        Start-Step "Init"
        $script:TempRoot = Get-TempRoot
        Write-Info "TempRoot: $script:TempRoot"
        Show-Banner

        Start-Step "System info"
        $sys = Get-SystemInfo
        Write-Info ("PowerShell: {0}" -f $sys.PSVersion)
        Write-Info ("OS: {0}" -f $sys.OSCaption)

        Start-Step "OS catalog -> pick entry"
        $catalog = Get-Catalog -CatalogUrl $OSCatalogUrl

        $osArgs = @{
            Catalog         = $catalog
            OperatingSystem = $OperatingSystem
            ReleaseId       = $ReleaseId
            Architecture    = $Architecture
            LanguageCode    = $LanguageCode
            License         = $License
        }
        $osEntry = Resolve-OsCatalogEntry @osArgs

        $osUrl = $null
        foreach ($n in @('URL','Url','Uri','DownloadUrl','ESDUrl','WimUrl')) {
            $p = $osEntry.PSObject.Properties[$n]
            if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) { $osUrl = [string]$p.Value; break }
        }
        if (-not $osUrl) { throw "OS entry missing URL/DownloadUrl." }

        $osSha1   = $osEntry.Sha1
        $osSha256 = $osEntry.Sha256

        Start-Step "Driver catalog -> match"
        $driverCatalog = Get-Catalog -CatalogUrl $DriverCatalogUrl
        $hw = Get-HardwareIdentity
        Write-Info ("Hardware: CS={0} {1} | BB={2} {3} SKU={4} Prod={5}" -f
            $hw.CSManufacturer, $hw.CSModel, $hw.BBManufacturer, $hw.BBModel, $hw.BBSKU, $hw.BBProduct
        )

        $drvMatch = Find-DriverPackMatch -Hardware $hw -DriverCatalog $driverCatalog
        if ($drvMatch.Matched) { Write-Ok ("Driver URL: {0}" -f $drvMatch.URL) }
        else { Write-Warn ("No driver match: {0}" -f $drvMatch.Reason) }

        Start-Step "Disk -> partition"
        $disk = Get-TargetDisk
        Write-Ok ("Disk #{0} {1} {2:N1}GB" -f $disk.Number, $disk.BusType, ($disk.Size/1GB))
        New-UEFIPartitionLayout -DiskNumber $disk.Number

        Start-Step "Cache root (W: preferred)"
        $cacheRoot = Get-CacheRoot
        Write-Info ("CacheRoot: {0}" -f $cacheRoot)

        Start-Step "Download OS image"
        $osFileName = "install.esd"
        try {
            $osFileName = [IO.Path]::GetFileName(([Uri]$osUrl).AbsolutePath)
            if ([string]::IsNullOrWhiteSpace($osFileName)) { $osFileName = "install.esd" }
        } catch { }

        $osPath = Join-Path $cacheRoot $osFileName
        Invoke-FileDownload -Url $osUrl -DestPath $osPath -Retries 2 | Out-Null
        Confirm-FileHash -FilePath $osPath -ExpectedSha1 $osSha1 -ExpectedSha256 $osSha256

        Start-Step "Enumerate + apply Enterprise"
        if (Get-Command Get-WindowsImage -ErrorAction SilentlyContinue) {
            Get-WindowsImage -ImagePath $osPath |
                Select-Object ImageIndex, ImageName, Architecture |
                Format-Table -AutoSize | Out-String |
                ForEach-Object { Write-Info $_.TrimEnd() }
        } else {
            (& dism.exe /English /Get-WimInfo /WimFile:"$osPath" | Out-String) |
                ForEach-Object { Write-Info $_.TrimEnd() }
        }

        Apply-Image -ImagePath $osPath -ApplyPath "W:\" -ExactName "Windows 11 Enterprise"

        Start-Step "BCDBoot"
        & bcdboot.exe W:\Windows /s S: /f UEFI
        if ($LASTEXITCODE -ne 0) { throw "bcdboot failed: $LASTEXITCODE" }

        Start-Step "WinRE config"
        $rePath = "R:\Recovery\WindowsRE"
        if (-not (Test-Path -LiteralPath $rePath)) { New-Item -ItemType Directory -Path $rePath -Force | Out-Null }

        $srcWinre = "W:\Windows\System32\Recovery\Winre.wim"
        if (Test-Path -LiteralPath $srcWinre) {
            Copy-Item -LiteralPath $srcWinre -Destination (Join-Path $rePath "Winre.wim") -Force
        } else {
            Write-Warn ("Winre.wim not found at {0}" -f $srcWinre)
        }

        & reagentc.exe /setreimage /path $rePath /target W:\Windows
        & reagentc.exe /enable /target W:\Windows

        Start-Step "Drivers (download/extract/add)"
        if ($drvMatch.Matched -and $drvMatch.URL) {
            $drvFileName = "driverpack.cab"
            try {
                $drvFileName = [IO.Path]::GetFileName(([Uri]$drvMatch.URL).AbsolutePath)
                if ([string]::IsNullOrWhiteSpace($drvFileName)) { $drvFileName = "driverpack.cab" }
            } catch { }

            $drvPath = Join-Path $cacheRoot $drvFileName
            Invoke-FileDownload -Url $drvMatch.URL -DestPath $drvPath -Retries 2 | Out-Null
            Confirm-FileHash -FilePath $drvPath -ExpectedSha1 $drvMatch.Sha1 -ExpectedSha256 $drvMatch.Sha256

            $extractRoot = Join-Path $cacheRoot "Drivers"
            if (-not (Test-Path -LiteralPath $extractRoot)) { New-Item -ItemType Directory -Path $extractRoot -Force | Out-Null }

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
        Write-Info ("OS: {0}" -f $osPath)
        Write-Info ("Cache: {0}" -f $cacheRoot)
        Write-Info ("Log: {0}" -f (Join-Path (Get-TempRoot) 'BuildForce.log'))
    }
    catch {
        Write-Fail ("Fatal: {0}" -f $_.Exception.Message)
        Write-Fail $_.ScriptStackTrace
        throw
    }
}

Invoke-BuildForge
