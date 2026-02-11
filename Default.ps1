[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Windows 11')]
    [string] $OperatingSystem = 'Windows 11',

    [ValidateSet('24H2','25H2','26H2')]
    [string] $ReleaseId = '25H2',

    [ValidateSet('amd64','arm64')]
    [string] $Architecture = 'amd64',

    [ValidateSet('en-us')]
    [string] $LanguageCode = 'en-us',

    [ValidateSet('Volume')]
    [string] $License = 'Volume',

    [ValidateSet('Enterprise','Professional')]
    [string] $SKU = 'Enterprise',

    [string] $DriverCatalogUrl = "https://raw.githubusercontent.com/CMMON112/BetaBareMetal/refs/heads/main/build-driverpackcatalog.xml",
    [string] $OSCatalogUrl     = "https://raw.githubusercontent.com/CMMON112/BetaBareMetal/refs/heads/main/build-oscatalog.xml",

    # Optional targeting & rerun controls
    [int]    $TargetDiskNumber = -1,
    [bool] $ForceRepartition = $true,
    [switch] $ForceRedownload,
    [switch] $ForceApplyImage
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
# StrictMode-safe script-scope initialization
$script:BuildForgeRoot = $null
$script:Hardware       = $null
$script:OSCatalog       = $null
$script:DriverCatalog   = $null
$script:OsEntry         = $null
$script:OsUrl           = $null
$script:OsSha1          = $null
$script:OsSha256        = $null
$script:OsPath          = $null
$script:DriverMatch     = $null
$script:DriverPackPath  = $null
$script:DriverExtractDir= $null
$script:TargetDisk      = $null
$script:ImageIndexes    = $null
$script:SelectedIndex   = $null
# ---------------------------
# Fixed logging location (never moves)
# ---------------------------
$script:LogRoot = 'X:\Windows\Temp\BuildForge'
$script:LogFile = Join-Path $script:LogRoot 'BuildForge.log'

function Initialize-Logging {
    if (-not (Test-Path -LiteralPath $script:LogRoot)) {
        New-Item -ItemType Directory -Path $script:LogRoot -Force | Out-Null
    }
    if (-not (Test-Path -LiteralPath $script:LogFile)) {
        New-Item -ItemType File -Path $script:LogFile -Force | Out-Null
    }
}

function Write-Log {
    param(
        [AllowEmptyString()]
        [string] $Message,

        [ValidateSet('INFO','WARN','ERROR','OK','STEP')]
        [string] $Level = 'INFO'
    )

    # Skip empty/whitespace messages safely
    if ([string]::IsNullOrWhiteSpace($Message)) { return }

    Initialize-Logging

    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "$ts [$Level] $Message"

    $color = switch ($Level) {
        'STEP'  { 'Cyan' }
        'OK'    { 'Green' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        default { 'Gray' }
    }

    Write-Host "[$Level] $Message" -ForegroundColor $color
    [System.IO.File]::AppendAllText($script:LogFile, $line + "`r`n")
}

function Invoke-Step {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    Write-Log "==================== $Name ====================" 'STEP'
    try {
        & $Action
        Write-Log "$Name - complete" 'OK'
    } catch {
        Write-Log "$Name - FAILED: $($_.Exception.Message)" 'ERROR'
        Write-Log $_.ScriptStackTrace 'ERROR'
        throw
    }
}

# ---------------------------
# BuildForge root management (moves as W: becomes available)
# ---------------------------
function Get-BuildForgeRoot {
    # Rule set:
    #  - Until W: exists -> X:\Windows\Temp\BuildForge
    #  - If W:\ exists but W:\Windows doesn't -> W:\BuildForge
    #  - If W:\Windows exists -> W:\Windows\Temp\BuildForge
    if (Test-Path -LiteralPath 'W:\Windows') { return 'W:\Windows\Temp\BuildForge' }
    if (Test-Path -LiteralPath 'W:\')        { return 'W:\BuildForge' }
    return 'X:\Windows\Temp\BuildForge'
}

function Ensure-Dir([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Move-BuildForgeContents {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination
    )
    if (-not (Test-Path -LiteralPath $Source)) { return }
    Ensure-Dir $Destination

    # Move everything except the fixed log file (kept in X:\Windows\Temp\BuildForge)
    $items = Get-ChildItem -LiteralPath $Source -Force -ErrorAction SilentlyContinue
    foreach ($i in $items) {
        if ($i.FullName -ieq $script:LogFile) { continue } # do not move log
        if ($i.Name -ieq 'BuildForge.log')     { continue } # safety
        $dest = Join-Path $Destination $i.Name
        try {
            Move-Item -LiteralPath $i.FullName -Destination $dest -Force -ErrorAction Stop
        } catch {
            # If a move collision happens, move into destination root
            Move-Item -LiteralPath $i.FullName -Destination $Destination -Force -ErrorAction SilentlyContinue
        }
    }
}

function Update-BuildForgeRoot {
    $newRoot = Get-BuildForgeRoot
    if (-not $script:BuildForgeRoot) {
        $script:BuildForgeRoot = $newRoot
        Ensure-Dir $script:BuildForgeRoot
        return
    }
    if ($script:BuildForgeRoot -ne $newRoot) {
        Write-Log "BuildForgeRoot relocating: '$($script:BuildForgeRoot)' -> '$newRoot'" 'INFO'
        Move-BuildForgeContents -Source $script:BuildForgeRoot -Destination $newRoot
        $script:BuildForgeRoot = $newRoot
        Ensure-Dir $script:BuildForgeRoot
    }
}

# ---------------------------
# Native execution / curl downloads (WinRE friendly)
# ---------------------------
function Resolve-CurlPath {
    $candidates = @(
        (Join-Path $env:WINDIR 'System32\curl.exe'),
        'curl.exe'
    )
    foreach ($c in $candidates) {
        $cmd = Get-Command $c -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Path }
    }
    throw "curl.exe not found (expected in WinRE/Windows)."
}

function Invoke-Native {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @(),
        [switch]$IgnoreExitCode
    )
    Write-Log "Running: $FilePath $($Arguments -join ' ')" 'INFO'

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

    if ($stdout) {
    $stdout -split "`r?`n" |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { Write-Log $_ 'INFO' }
    }

    if ($stderr) {
    $stderr -split "`r?`n" |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { Write-Log $_ 'WARN' }
    }

    if (-not $IgnoreExitCode -and $p.ExitCode -ne 0) {
        throw "Command failed (exit $($p.ExitCode)): $FilePath $($Arguments -join ' ')"
    }

    [pscustomobject]@{ ExitCode=$p.ExitCode; StdOut=$stdout; StdErr=$stderr }
}

function Invoke-Download {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$DestPath
    )
    Ensure-Dir (Split-Path -Parent $DestPath)

    if ((Test-Path -LiteralPath $DestPath) -and -not $ForceRedownload) {
        Write-Log "Already exists, skipping download: $DestPath" 'INFO'
        return $DestPath
    }

    $curl = Resolve-CurlPath
    Write-Log "Downloading: $Url" 'INFO'
    & $curl --fail --location --silent --show-error --retry 2 --retry-delay 3 --connect-timeout 30 --output $DestPath $Url
    if ($LASTEXITCODE -ne 0) { throw "curl failed ($LASTEXITCODE) for $Url" }

    if (-not (Test-Path -LiteralPath $DestPath)) {
        throw "Download reported success but file missing: $DestPath"
    }
    Write-Log "Download complete: $DestPath" 'OK'
    return $DestPath
}

function Confirm-FileHash {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string]$ExpectedSha1,
        [string]$ExpectedSha256
    )
    if ($ExpectedSha1) {
        $a = (Get-FileHash -Algorithm SHA1 -Path $FilePath).Hash.ToLowerInvariant()
        $e = $ExpectedSha1.ToLowerInvariant().Trim()
        if ($a -ne $e) { throw "SHA1 mismatch. Expected=$e Got=$a" }
        Write-Log "SHA1 verified." 'OK'
    }
    if ($ExpectedSha256) {
        $a = (Get-FileHash -Algorithm SHA256 -Path $FilePath).Hash.ToLowerInvariant()
        $e = $ExpectedSha256.ToLowerInvariant().Trim()
        if ($a -ne $e) { throw "SHA256 mismatch. Expected=$e Got=$a" }
        Write-Log "SHA256 verified." 'OK'
    }
}

# ---------------------------
# Catalog + matching
# ---------------------------
function Get-LeafNameFromUrl([string]$Url, [string]$Fallback) {
    try {
        $u = [Uri]$Url
        $leaf = [IO.Path]::GetFileName($u.AbsolutePath)
        if ([string]::IsNullOrWhiteSpace($leaf)) { return $Fallback }
        return $leaf
    } catch { return $Fallback }
}

function Get-Catalog {
    param([Parameter(Mandatory)][string]$CatalogUrl)

    Update-BuildForgeRoot
    $catalogDir = Join-Path $script:BuildForgeRoot 'Catalogs'
    Ensure-Dir $catalogDir

    $leaf = Get-LeafNameFromUrl -Url $CatalogUrl -Fallback 'catalog.clixml'
    $local = Join-Path $catalogDir $leaf

    Invoke-Download -Url $CatalogUrl -DestPath $local | Out-Null
    Write-Log "Importing catalog (CLIXML): $local" 'INFO'
    return Import-Clixml -Path $local
}

function Resolve-OsCatalogEntry {
    param(
        [Parameter(Mandatory)]$Catalog
    )
    $filtered = $Catalog | Where-Object {
        $_.OperatingSystem -eq $OperatingSystem -and
        $_.ReleaseId       -eq $ReleaseId       -and
        $_.Architecture    -eq $Architecture    -and
        $_.LanguageCode    -eq $LanguageCode    -and
        $_.License         -eq $License
    }
    if (-not $filtered) {
        throw "No matching OS entry for OS=$OperatingSystem ReleaseId=$ReleaseId Arch=$Architecture Lang=$LanguageCode License=$License"
    }
    $filtered | Sort-Object Build -Descending | Select-Object -First 1
}

function Get-EntryValue($Obj, [string[]]$Names) {
    foreach ($n in $Names) {
        $p = $Obj.PSObject.Properties[$n]
        if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) { return [string]$p.Value }
    }
    return $null
}

function Get-HardwareIdentity {
    $bb = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue

    $bbSku = $bb.SKU
    if ([string]::IsNullOrWhiteSpace($bbSku)) { $bbSku = $bb.SKU }

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
    param(
        [Parameter(Mandatory)][object]$Hardware,
        [Parameter(Mandatory)][object[]]$DriverCatalog,
        [int]$MinScore = 6
    )

    function Normalize([string]$s) {
        if ([string]::IsNullOrWhiteSpace($s)) { return $null }
        (($s -replace '\s+',' ').Trim()).ToUpperInvariant()
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

    $hw = [pscustomobject]@{
        CSManufacturer = Normalize $Hardware.CSManufacturer
        CSModel        = Normalize $Hardware.CSModel
        BBManufacturer = Normalize $Hardware.BBManufacturer
        BBModel        = Normalize $Hardware.BBModel
        BBSKU          = Normalize $Hardware.BBSKU
        BBProduct      = Normalize $Hardware.BBProduct
    }

    $scored = foreach ($item in $DriverCatalog) {
        $entry = [pscustomobject]@{
            CSManufacturer = Normalize (Get-EntryValue $item @('CSManufacturer','ComputerSystemManufacturer','Manufacturer'))
            CSModel        = Normalize (Get-EntryValue $item @('CSModel','ComputerSystemModel','Model'))
            BBManufacturer = Normalize (Get-EntryValue $item @('BBManufacturer','BaseBoardManufacturer'))
            BBModel        = Normalize (Get-EntryValue $item @('BBModel','BaseBoardModel'))
            BBSKU          = Normalize (Get-EntryValue $item @('BBSKU','SKUNumber','SKU'))
            BBProduct      = Normalize (Get-EntryValue $item @('BBProduct','Product'))
            URL            = Get-EntryValue $item @('URL','Url','Uri','DownloadUrl','DriverUrl')
            Sha1           = Get-EntryValue $item @('Sha1','SHA1','SHA-1','HashSha1')
            Sha256         = Get-EntryValue $item @('Sha256','SHA256','SHA-256','HashSha256')
        }

        $score=0; $compared=0; $exact=0; $matched=@()
        foreach ($k in $weights.Keys) {
            $hv = $hw.$k
            $ev = $entry.$k
            if ($hv -and $ev) {
                $compared++
                if ($hv -eq $ev) { $exact++; $score += $weights[$k]; $matched += $k }
                else { $score -= $penalty }
            }
        }

        [pscustomobject]@{
            Score=$score; Compared=$compared; Exact=$exact; HasUrl=[bool]$entry.URL;
            Matched=($matched -join ','); Entry=$entry
        }
    }

    if (($scored | Measure-Object Compared -Maximum).Maximum -eq 0) {
        return [pscustomobject]@{ Matched=$false; Reason="No comparable fields."; Candidates=$scored }
    }

    $ordered = $scored | Sort-Object Score,Exact,Compared,HasUrl -Descending
    $top = $ordered | Select-Object -First 1

    if ($top.Score -lt $MinScore -or -not $top.HasUrl) {
        return [pscustomobject]@{
            Matched=$false
            Reason="No driver match met minimum score ($MinScore). BestScore=$($top.Score)"
            Candidates=($ordered | Select-Object -First 10)
        }
    }

    [pscustomobject]@{
        Matched=$true
        Score=$top.Score
        Compared=$top.Compared
        Exact=$top.Exact
        URL=$top.Entry.URL
        Sha1=$top.Entry.Sha1
        Sha256=$top.Entry.Sha256
        MatchInfo=$top.Matched
    }
}

# ---------------------------
# Disk selection + partitioning
# ---------------------------
function Get-BestOsDiskNumber {
    $pref = @{
        'NVMe'=1; 'SSD'=2; 'SATA'=3; 'RAID'=4; 'SAS'=5; 'ATA'=6; 'Unknown'=10
        'USB'=99; 'SD'=99; 'MMC'=99
    }

    $disks = Get-Disk | Where-Object { $_.BusType -notin @('USB','SD','MMC') }
    if (-not $disks) { throw "No suitable non-USB disks found." }

    $ranked = $disks | ForEach-Object {
        $bus = if ($pref.ContainsKey($_.BusType)) { $pref[$_.BusType] } else { 10 }
        [pscustomobject]@{ Number=$_.Number; Size=$_.Size; BusScore=$bus; IsBoot=$_.IsBoot; IsSystem=$_.IsSystem; BusType=$_.BusType }
    }

    ($ranked | Sort-Object BusScore,IsBoot,IsSystem,@{e='Size';Descending=$true} | Select-Object -First 1).Number
}

function Get-TargetDisk {
    if ($TargetDiskNumber -ge 0) {
        $d = Get-Disk -Number $TargetDiskNumber -ErrorAction Stop
        if ($d.BusType -eq 'USB') { throw "Refusing to target USB disk $TargetDiskNumber." }
        return $d
    }
    $n = Get-BestOsDiskNumber
    Get-Disk -Number $n -ErrorAction Stop
}

function Apply-UEFIPartitionLayout {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][int]$DiskNumber, [int]$RecoveryMB=800, [int]$EfiMB=300)

    $dp = @(
        "select disk $DiskNumber",
        "clean",
        "convert gpt",
        "create partition efi size=$EfiMB",
        "format quick fs=fat32 label=System",
        "assign letter=S",
        "create partition msr size=16",
        "create partition primary",
        "shrink minimum=$RecoveryMB",
        "format quick fs=ntfs label=Windows",
        "assign letter=W",
        "create partition primary",
        "format quick fs=ntfs label=Recovery",
        "assign letter=R",
        'set id="de94bba4-06d1-4d40-a16a-bfd50179d6ac"',
        "gpt attributes=0x8000000000000001",
        "exit"
    ) -join "`r`n"

    if ($PSCmdlet.ShouldProcess("Disk $DiskNumber", "Wipe and apply UEFI/GPT layout (S:,W:,R:)")) {
        $dp | diskpart | Out-Null
    }
}

# ---------------------------
# ESD index discovery & selection
# ---------------------------
function Get-ImageIndexesFromEsd {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ImageFile
    )

    if (-not (Test-Path -LiteralPath $ImageFile)) {
        throw "Image file not found: $ImageFile"
    }

    # PowerShell-only: requires DISM PowerShell module cmdlets (no dism.exe usage)
    if (-not (Get-Command -Name Get-WindowsImage -ErrorAction SilentlyContinue)) {
        try { Import-Module Dism -ErrorAction Stop } catch {
            throw "Get-WindowsImage is not available (Dism module missing). Cannot enumerate ESD/WIM without dism.exe."
        }
    }

    $images = Get-WindowsImage -ImagePath $ImageFile -ErrorAction Stop

    $list = New-Object System.Collections.Generic.List[object]
    foreach ($img in $images) {

        $idx  = $img.ImageIndex; if (-not $idx)  { $idx  = $img.Index }
        $name = $img.ImageName;  if (-not $name) { $name = $img.Name }

        if (-not $idx -or -not $name) { continue }

        # Exclude " N" editions (case-insensitive), e.g. "Windows 11 Pro N"
        if ($name -match '(?i)\sN$') { continue }

        $list.Add([pscustomobject]@{
            Index = [int]$idx
            Name  = [string]$name
        })
    }

    return $list
}

function Select-DesiredIndex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]] $Indexes
    )

    if (-not $Indexes -or $Indexes.Count -eq 0) {
        throw "Select-DesiredIndex: No indexes were provided."
    }

    # Filter out " N" editions defensively (in case caller didn't)
    $clean = $Indexes | Where-Object { $_.Name -and $_.Name -notmatch '(?i)\sN$' }

    if (-not $clean -or $clean.Count -eq 0) {
        throw "Select-DesiredIndex: All discovered images were N editions (or had no Name)."
    }

    # Exact target names (non-N only)
    $desired = switch ($SKU) {
        'Enterprise'   { 'Windows 11 Enterprise' }
        'Professional' { 'Windows 11 Pro' }
        default        { throw "Select-DesiredIndex: Unsupported SKU '$SKU'." }
    }

    # 1) Prefer exact match (case-insensitive)
    $exact = $clean | Where-Object {
        $_.Name.Equals($desired, [System.StringComparison]::OrdinalIgnoreCase)
    } | Select-Object -First 1
    if ($exact) { return [int]$exact.Index }

    # 2) Fallback for Pro: some media calls it "Windows 11 Professional"
    if ($SKU -eq 'Professional') {
        $alt = $clean | Where-Object {
            $_.Name.Equals('Windows 11 Professional', [System.StringComparison]::OrdinalIgnoreCase) -or
            $_.Name -match '(?i)^Windows 11 Professional(\b|$)'
        } | Select-Object -First 1
        if ($alt) { return [int]$alt.Index }
    }

    # 3) Fallback: "starts with" desired (still excludes N due to $clean)
    $starts = $clean | Where-Object {
        $_.Name.StartsWith($desired, [System.StringComparison]::OrdinalIgnoreCase)
    } | Select-Object -First 1
    if ($starts) { return [int]$starts.Index }

    # 4) Last resort: contain token (Enterprise / Pro) but still non-N
    $token = if ($SKU -eq 'Enterprise') { 'Enterprise' } else { 'Pro' }
    $contains = $clean | Where-Object {
        $_.Name -match "(?i)\b$token\b"
    } | Select-Object -First 1
    if ($contains) { return [int]$contains.Index }

    $names = ($clean | ForEach-Object { "Index=$($_.Index) Name=$($_.Name)" }) -join "; "
    throw "Could not find a suitable NON-N index for SKU='$SKU'. Available (non-N): $names"
}


# ---------------------------
# HP SoftPaq extractor + wait-for-child-procs
# ---------------------------
function Get-ProcessTreePids {
    param([Parameter(Mandatory)][int]$RootPid)

    $seen = New-Object System.Collections.Generic.HashSet[int]
    $queue = New-Object System.Collections.Generic.Queue[int]
    $queue.Enqueue($RootPid) | Out-Null

    while ($queue.Count -gt 0) {
        $pid = $queue.Dequeue()
        if (-not $seen.Add($pid)) { continue }

        $children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$pid" -ErrorAction SilentlyContinue
        foreach ($c in $children) {
            $queue.Enqueue([int]$c.ProcessId) | Out-Null
        }
    }

    return $seen
}

function Wait-ProcessTree {
    param([Parameter(Mandatory)][int]$RootPid, [int]$PollSeconds=1)

    while ($true) {
        $pids = Get-ProcessTreePids -RootPid $RootPid
        $alive = $false
        foreach ($pid in $pids) {
            if (Get-Process -Id $pid -ErrorAction SilentlyContinue) { $alive = $true; break }
        }
        if (-not $alive) { break }
        Start-Sleep -Seconds $PollSeconds
    }
}

function Expand-HPSoftPaq {
    param(
        [Parameter(Mandatory)][string]$SoftPaqExe,
        [Parameter(Mandatory)][string]$Destination
    )
    Ensure-Dir $Destination

    # HP SoftPaq unpack: sp####.exe -pdf -f<path> -s  (silent, override path) [4](https://h30434.www3.hp.com/t5/Commercial-PC-Software/FAQ-23-Unpacking-downloaded-SoftPaqs/td-p/5046732)
    $args = @("-pdf", "-f$Destination", "-s")
    Write-Log "Extracting HP SoftPaq -> $Destination" 'INFO'

    $p = Start-Process -FilePath $SoftPaqExe -ArgumentList $args -PassThru -WindowStyle Hidden
    Wait-ProcessTree -RootPid $p.Id

    Write-Log "SoftPaq extraction complete: $Destination" 'OK'
}

# ---------------------------
# MAIN
# ---------------------------
Invoke-Step "1) Setup BuildForge root + fixed logging" {
    Initialize-Logging
    Update-BuildForgeRoot
    Write-Log "Fixed Log:  $script:LogFile" 'INFO'
    Write-Log "Root Dir:   $script:BuildForgeRoot" 'INFO'
}

Invoke-Step "2) List PowerShell + environment info" {
    $osCap = 'Unknown / WinRE'
    try { $osCap = (Get-CimInstance Win32_OperatingSystem).Caption } catch {}
    Write-Log "PowerShell: $($PSVersionTable.PSVersion)" 'INFO'
    Write-Log "OS:         $osCap" 'INFO'
}

Invoke-Step "3) List hardware identity" {
    $hw = Get-HardwareIdentity
    $script:Hardware = $hw
    Write-Log ("CS: {0} {1}" -f $hw.CSManufacturer, $hw.CSModel) 'INFO'
    Write-Log ("BB: {0} {1} SKU={2} Prod={3}" -f $hw.BBManufacturer, $hw.BBModel, $hw.BBSKU, $hw.BBProduct) 'INFO'
}

Invoke-Step "4) List target OS parameters" {
    Write-Log "OS=$OperatingSystem ReleaseId=$ReleaseId Arch=$Architecture Lang=$LanguageCode License=$License SKU=$SKU" 'INFO'
}

Invoke-Step "5) Download catalogs" {
    $script:OSCatalog     = Get-Catalog -CatalogUrl $OSCatalogUrl
    $script:DriverCatalog = Get-Catalog -CatalogUrl $DriverCatalogUrl
}

Invoke-Step "6) Match OS entry from catalog" {
    $osEntry = Resolve-OsCatalogEntry -Catalog $script:OSCatalog
    $script:OsEntry = $osEntry

    $osUrl    = Get-EntryValue $osEntry @('URL','Url','Uri','DownloadUrl','ESDUrl','WimUrl')
    $osSha1   = Get-EntryValue $osEntry @('Sha1','SHA1','HashSha1','SHA-1')
    $osSha256 = Get-EntryValue $osEntry @('Sha256','SHA256','HashSha256','SHA-256')

    if (-not $osUrl) { throw "OS catalog entry missing URL/DownloadUrl/ESDUrl/WimUrl." }

    $script:OsUrl    = $osUrl
    $script:OsSha1   = $osSha1
    $script:OsSha256 = $osSha256

    Write-Log "Selected OS URL: $osUrl" 'OK'
}

Invoke-Step "7) Match driver pack from hardware + catalog" {
    $res = Find-DriverPackMatch -Hardware $script:Hardware -DriverCatalog $script:DriverCatalog
    $script:DriverMatch = $res

    if ($res.Matched) {
        Write-Log "Driver match: Score=$($res.Score) Fields=$($res.MatchInfo)" 'OK'
        Write-Log "Driver URL: $($res.URL)" 'INFO'
    } else {
        Write-Log "No single driver match: $($res.Reason)" 'WARN'
    }
}

Invoke-Step "8) Select best local disk for OS" {
    $disk = Get-TargetDisk
    $script:TargetDisk = $disk
    Write-Log ("Disk #{0} BusType={1} Size={2:N2}GB Boot={3} System={4}" -f $disk.Number, $disk.BusType, ($disk.Size/1GB), $disk.IsBoot, $disk.IsSystem) 'OK'
}

Invoke-Step "9) Partition disk (UEFI/GPT) if needed" {
    $haveW = Test-Path -LiteralPath 'W:\'
    $haveS = Test-Path -LiteralPath 'S:\'
    $haveR = Test-Path -LiteralPath 'R:\'

    if ($ForceRepartition -or -not ($haveW -and $haveS -and $haveR)) {
        Write-Log "Partitioning required (ForceRepartition=$ForceRepartition, S=$haveS W=$haveW R=$haveR)" 'WARN'
        Apply-UEFIPartitionLayout -DiskNumber $script:TargetDisk.Number
        Write-Log "Partition layout applied. Expect S:, W:, R:" 'OK'
    } else {
        Write-Log "Partitions already present (S:,W:,R:). Skipping repartition." 'INFO'
    }
}

Invoke-Step "10) Move BuildForge root to W: (when W: exists)" {
    Update-BuildForgeRoot
    Write-Log "Current Root Dir: $script:BuildForgeRoot" 'INFO'
}

Invoke-Step "11) Download correct OS ESD/WIM (best match)" {
    Update-BuildForgeRoot
    $osDir = Join-Path $script:BuildForgeRoot 'OS'
    Ensure-Dir $osDir

    $osFile = Get-LeafNameFromUrl -Url $script:OsUrl -Fallback 'install.esd'
    $osPath = Join-Path $osDir $osFile

    Invoke-Download -Url $script:OsUrl -DestPath $osPath | Out-Null
    if ($script:OsSha1 -or $script:OsSha256) {
        Confirm-FileHash -FilePath $osPath -ExpectedSha1 $script:OsSha1 -ExpectedSha256 $script:OsSha256
    } else {
        Write-Log "No hashes provided by catalog; skipping hash verification." 'WARN'
    }

    $script:OsPath = $osPath
}

Invoke-Step "12) Download best-match driver pack (if match) (no extract yet)" {
    Update-BuildForgeRoot
    if (-not ($script:DriverMatch.Matched -and $script:DriverMatch.URL)) {
        Write-Log "No driver URL matched; skipping download." 'WARN'
        return
    }
    $drvDir = Join-Path $script:BuildForgeRoot 'Drivers'
    Ensure-Dir $drvDir

    $drvFile = Get-LeafNameFromUrl -Url $script:DriverMatch.URL -Fallback 'driverpack.exe'
    $drvPath = Join-Path $drvDir $drvFile

    Invoke-Download -Url $script:DriverMatch.URL -DestPath $drvPath | Out-Null
    Confirm-FileHash -FilePath $drvPath -ExpectedSha1 $script:DriverMatch.Sha1 -ExpectedSha256 $script:DriverMatch.Sha256

    $script:DriverPackPath = $drvPath
}

Invoke-Step "13) List ESD/WIM indexes (DISM)" {
    # DISM /Get-ImageInfo lists images in WIM/ESD [1](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/take-inventory-of-an-image-or-component-using-dism?view=windows-11)
    $idx = Get-ImageIndexesFromEsd -ImageFile $script:OsPath
    $script:ImageIndexes = $idx

    Write-Log "Images found in $($script:OsPath):" 'INFO'
    $idx | ForEach-Object { Write-Log ("  Index {0}: {1}" -f $_.Index, $_.Name) 'INFO' }

    if (-not $idx -or $idx.Count -eq 0) { throw "No indexes parsed from DISM output." }
}

Invoke-Step "14) Select desired index (Windows 11 $SKU)" {
    $index = Select-DesiredIndex -Indexes $script:ImageIndexes
    $script:SelectedIndex = $index
    Write-Log "Selected index: $index (SKU=$SKU)" 'OK'
}

Invoke-Step "15) Expand selected index to W:\" {

    $already = Test-Path -LiteralPath 'W:\Windows\System32'
    if ($already -and -not $ForceApplyImage) {
        Write-Log "W:\Windows already present. Skipping Expand-image (use -ForceApplyImage to reapply)." 'INFO'
        return
    }

    # Ensure DISM PowerShell cmdlets are available (PowerShell-only, no dism.exe)
    if (-not (Get-Command -Name Expand-WindowsImage -ErrorAction SilentlyContinue)) {
        try {
            Import-Module Dism -ErrorAction Stop
        } catch {
            throw "Expand-WindowsImage cmdlet not available (Dism module missing). Cannot Expand image without dism.exe."
        }
    }

    if ($PSCmdlet.ShouldProcess("W:\", "Expand-WindowsImage (Index $($script:SelectedIndex))")) {

        # Expand the selected index to W:\
        Expand-WindowsImage -ImagePath $script:OsPath `
                           -Index $script:SelectedIndex `
                           -ApplyPath 'W:\' `
                           -ErrorAction Stop | Out-Null

        Write-Log "Windows image applied to W:\ (PowerShell Apply-WindowsImage)" 'OK'
    }
}

Invoke-Step "16) Configure boot (BCDBoot UEFI)" {
    # BCDBoot sets up boot files for an applied image
    if ($PSCmdlet.ShouldProcess("S:\", "BCDBoot UEFI from W:\Windows")) {

        # Prefer full path (WinRE PATH can be odd)
        $bcdboot = Join-Path $env:WINDIR 'System32\bcdboot.exe'
        if (-not (Test-Path -LiteralPath $bcdboot)) { $bcdboot = "bcdboot.exe" }

        Invoke-Native -FilePath $bcdboot -Arguments @(
            "W:\Windows",
            "/s","S:",
            "/f","UEFI"
        ) | Out-Null

        Write-Log "Boot files created (UEFI)." 'OK'
    }
}

Invoke-Step "17) Setup WinRE WIM on recovery partition + register offline" {
    $reDir = 'R:\Recovery\WindowsRE'
    Ensure-Dir $reDir

    $src = 'W:\Windows\System32\Recovery\Winre.wim'
    $dst = Join-Path $reDir 'Winre.wim'

    if (Test-Path -LiteralPath $src) {
        Copy-Item -LiteralPath $src -Destination $dst -Force
        Write-Log "Copied Winre.wim -> $dst" 'OK'
    } else {
        Write-Log "Winre.wim not found at $src (some images store it differently)." 'WARN'
    }

    # Call reagentc.exe by full path
    $reagentc = 'W:\Windows\System32\reagentc.exe'
    if (-not (Test-Path -LiteralPath $reagentc)) {
        throw "reagentc.exe not found at expected path: $reagentc"
    }

    # REAgentC offline: /setreimage /path <dir> /target <offline windows>
    if ($PSCmdlet.ShouldProcess("W:\Windows", "Register and enable WinRE offline")) {

        Invoke-Native -FilePath $reagentc -Arguments @(
            "/setreimage",
            "/path", $reDir,
            "/target", "W:\Windows"
        ) | Out-Null

        Invoke-Native -FilePath $reagentc -Arguments @(
            "/enable",
            "/target", "W:\Windows"
        ) | Out-Null

        Write-Log "WinRE configured for offline Windows." 'OK'
    }
}

Invoke-Step "18) Extract HP driver pack silently (wait for full process tree)" {
    if (-not $script:DriverPackPath) {
        Write-Log "No driver pack downloaded; skipping extraction." 'WARN'
        return
    }

    Update-BuildForgeRoot
    $extractDir = Join-Path $script:BuildForgeRoot 'ExtractedDrivers'
    Ensure-Dir $extractDir

    # If it’s an HP SoftPaq EXE, use -pdf -f<path> -s [4](https://h30434.www3.hp.com/t5/Commercial-PC-Software/FAQ-23-Unpacking-downloaded-SoftPaqs/td-p/5046732)
    $ext = [IO.Path]::GetExtension($script:DriverPackPath).ToLowerInvariant()
    if ($ext -eq '.exe') {
        Expand-HPSoftPaq -SoftPaqExe $script:DriverPackPath -Destination $extractDir
    } elseif ($ext -eq '.zip') {
        Expand-Archive -LiteralPath $script:DriverPackPath -DestinationPath $extractDir -Force
        Write-Log "Extracted ZIP -> $extractDir" 'OK'
    } elseif ($ext -eq '.cab') {
        Invoke-Native -FilePath "expand.exe" -Arguments @("-F:*", $script:DriverPackPath, $extractDir) | Out-Null
        Write-Log "Extracted CAB -> $extractDir" 'OK'
    } else {
        Write-Log "Unknown driver pack extension '$ext' (downloaded but not extracted)." 'WARN'
        return
    }

    $script:DriverExtractDir = $extractDir
}

Invoke-Step "19) Inject drivers into offline image (DISM /Add-Driver /Recurse)" {
    if (-not $script:DriverExtractDir) {
        Write-Log "No extracted drivers directory; skipping injection." 'WARN'
        return
    }

    if ($PSCmdlet.ShouldProcess("W:\", "DISM Add-Driver /Recurse from $($script:DriverExtractDir)")) {
        Invoke-Native -FilePath "dism.exe" -Arguments @(
            "/Image:W:\",
            "/Add-Driver",
            "/Driver:$($script:DriverExtractDir)",
            "/Recurse"
        ) | Out-Null
        Write-Log "Driver injection complete." 'OK'
    }
}

Invoke-Step "Summary" {
    Write-Log "Log file: $script:LogFile" 'INFO'
    Write-Log "BuildForge root: $script:BuildForgeRoot" 'INFO'
    if ($script:OsPath) { Write-Log "OS image: $script:OsPath" 'INFO' }
    if ($script:SelectedIndex) { Write-Log "Applied index: $script:SelectedIndex" 'INFO' }
    if ($script:TargetDisk) { Write-Log "Disk used: #$($script:TargetDisk.Number)" 'INFO' }
    Write-Log "Done." 'OK'
}
