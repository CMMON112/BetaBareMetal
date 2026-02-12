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

$script:BuildForgeRootHistory = New-Object System.Collections.Generic.List[string]

# Track current step name for consistent log tagging
$script:CurrentStepName = $null

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

function Format-LogMessage {
    param(
        [AllowEmptyString()]
        [string] $Message
    )

    if ([string]::IsNullOrWhiteSpace($Message)) { return $Message }

    # Messaging-only normalization:
    # - remove shorthand arrows in output for non-technical audiences
    # - keep technical detail intact (paths, URLs, parameters)
    $m = $Message

    # Convert common arrow shorthands to plain wording
    $m = $m -replace '\s*-\>\s*', ' to '
    $m = $m -replace '\s*=\>\s*', ' to '

    # Collapse repeated whitespace (safe for readability)
    $m = $m -replace '\s{2,}', ' '

    return $m.Trim()
}

function Write-Log {
    param(
        [AllowEmptyString()]
        [string] $Message,

        [ValidateSet('INFO','WARN','ERROR','OK','STEP')]
        [string] $Level = 'INFO',

        [string] $StepName,
        [string] $Context,
        [string] $Detail
    )

    if ([string]::IsNullOrWhiteSpace($Message)) { return }

    Initialize-Logging

    # Auto-tag with current step if not provided
    if ([string]::IsNullOrWhiteSpace($StepName) -and $script:CurrentStepName) {
        $StepName = $script:CurrentStepName
    }

    # Format message for readability (your existing helper)
    $msg = Format-LogMessage -Message $Message

    $stepTag = if ([string]::IsNullOrWhiteSpace($StepName)) { '' } else { " [STEP:$StepName]" }
    $ctxTag  = if ([string]::IsNullOrWhiteSpace($Context)) { '' } else { " Context: $Context." }
    $detTag  = if ([string]::IsNullOrWhiteSpace($Detail))  { '' } else { " Detail: $Detail" }

    # Console line: no datetime (easy to read)
    $consoleLine = "[$Level]$stepTag $msg$ctxTag$detTag"

    # File line: include datetime (keeps forensic value)
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $fileLine = "$ts [$Level]$stepTag $msg$ctxTag$detTag"

    $color = switch ($Level) {
        'STEP'  { 'Cyan' }
        'OK'    { 'Green' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        default { 'Gray' }
    }

    Write-Host $consoleLine -ForegroundColor $color
    [System.IO.File]::AppendAllText($script:LogFile, $fileLine + "`r`n")
}


function Invoke-Step {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )

    $script:CurrentStepName = $Name

    Write-Log "Starting step." 'STEP' -Context "Execution" -Detail "Entering step block"
    try {
        & $Action
        Write-Log "Step completed successfully." 'OK' -Context "Execution" -Detail "No errors reported"
    } catch {
        Write-Log "Step failed." 'ERROR' -Context "Execution" -Detail $_.Exception.Message
        if ($_.ScriptStackTrace) {
            Write-Log "Stack trace follows." 'ERROR' -Context "Execution"
            Write-Log $_.ScriptStackTrace 'ERROR' -Context "Execution"
        }
        throw
    } finally {
        $script:CurrentStepName = $null
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
        $script:BuildForgeRootHistory.Add($script:BuildForgeRoot) | Out-Null
        Write-Log "BuildForgeRoot relocating: '$($script:BuildForgeRoot)' -> '$newRoot'" 'INFO' -Context "Storage" -Detail "Workspace folder location changed"
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
    Write-Log "Running native command." 'INFO' -Context "Process" -Detail "$FilePath $($Arguments -join ' ')"

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
            ForEach-Object { Write-Log $_ 'INFO' -Context "ProcessOutput" }
    }

    if ($stderr) {
        $stderr -split "`r?`n" |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { Write-Log $_ 'WARN' -Context "ProcessError" }
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
        Write-Log "Download skipped because the file already exists." 'INFO' -Context "Download" -Detail $DestPath
        return $DestPath
    }

    $curl = Resolve-CurlPath
    Write-Log "Downloading file from URL." 'INFO' -Context "Download" -Detail $Url
    & $curl --fail --location --silent --show-error --retry 2 --retry-delay 3 --connect-timeout 30 --output $DestPath $Url
    if ($LASTEXITCODE -ne 0) { throw "curl failed ($LASTEXITCODE) for $Url" }

    if (-not (Test-Path -LiteralPath $DestPath)) {
        throw "Download reported success but file missing: $DestPath"
    }
    Write-Log "Download completed successfully." 'OK' -Context "Download" -Detail $DestPath
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
        Write-Log "File hash verified using SHA1." 'OK' -Context "Integrity" -Detail $FilePath
    }
    if ($ExpectedSha256) {
        $a = (Get-FileHash -Algorithm SHA256 -Path $FilePath).Hash.ToLowerInvariant()
        $e = $ExpectedSha256.ToLowerInvariant().Trim()
        if ($a -ne $e) { throw "SHA256 mismatch. Expected=$e Got=$a" }
        Write-Log "File hash verified using SHA256." 'OK' -Context "Integrity" -Detail $FilePath
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
    Write-Log "Importing catalog file in CLIXML format." 'INFO' -Context "Catalog" -Detail $local
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

function Get-OffineWindowsOsGuid {
    param(
        [Parameter(Mandatory)]
        [string] $BcdStorePath
    )

    $out = & bcdedit.exe /enum all /store $BcdStorePath 2>&1

    $current = @{}
    foreach ($line in $out) {
        if ($line -match '^\s*identifier\s+(\{.+\})') {
            $current.Identifier = $Matches[1]
        }
        elseif ($line -match '^\s*device\s+partition=(.+)') {
            $current.Device = $Matches[1]
        }
        elseif ($line -match '^\s*path\s+\\windows\\system32\\winload\.efi') {
            if ($current.Device -match 'W:') {
                return $current.Identifier
            }
        }
    }

    throw "Unable to locate OS GUID for W:\Windows in BCD store"
}

function Get-OfflineOsGuidFromBcd {
    [CmdletBinding()]
    param(
        [string] $BcdStorePath = 'S:\EFI\Microsoft\Boot\BCD',
        [string] $WindowsPartition = 'W:'
    )

    if (-not (Test-Path -LiteralPath $BcdStorePath)) {
        throw "BCD store not found at '$BcdStorePath'. Is the EFI partition mounted as S:?"
    }

    function Is-GuidIdentifier([string]$id) {
        return ($id -match '^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$')
    }

    $out = & bcdedit.exe /enum all /v /store $BcdStorePath 2>&1
    if (-not $out) { throw "bcdedit returned no output for '$BcdStorePath'" }

    $candidates = New-Object System.Collections.Generic.List[string]
    $fallbackAliases = New-Object System.Collections.Generic.List[string]

    $block = New-Object System.Collections.Generic.List[string]
    foreach ($line in $out + '') {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            $block.Add($line) | Out-Null
            continue
        }

        if ($block.Count -gt 0) {
            $text = ($block -join "`n")

            if ($text -match '(?im)^\s*path\s+\\Windows\\System32\\winload\.efi\s*$' -and
                $text -match "(?im)^\s*device\s+partition=$([regex]::Escape($WindowsPartition))\s*$") {

                $id = $null
                if ($text -match '(?im)^\s*identifier\s+(\{.+?\})\s*$') {
                    $id = $Matches[1].Trim()
                }

                if ($id) {
                    if (Is-GuidIdentifier $id) {
                        $candidates.Add($id) | Out-Null
                    } else {
                        $fallbackAliases.Add($id) | Out-Null
                    }
                }
            }

            $block.Clear()
        }
    }

    if ($candidates.Count -gt 0) {
        return $candidates[0]
    }

    $bm = & bcdedit.exe /enum '{bootmgr}' /v /store $BcdStorePath 2>&1
    if ($bm -and ($bm -match '(?im)^\s*default\s+(\{.+?\})\s*$')) {
        $defaultId = $Matches[1].Trim()
        if (Is-GuidIdentifier $defaultId) {
            return $defaultId
        }
    }

    $aliases = if ($fallbackAliases.Count -gt 0) { ($fallbackAliases | Select-Object -Unique) -join ', ' } else { '(none)' }
    throw "Could not resolve a GUID OS loader identifier for $WindowsPartition. Found only aliases: $aliases. reagentc requires a GUID identifier (not {default}/{current})."
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

    $clean = $Indexes | Where-Object { $_.Name -and $_.Name -notmatch '(?i)\sN$' }

    if (-not $clean -or $clean.Count -eq 0) {
        throw "Select-DesiredIndex: All discovered images were N editions (or had no Name)."
    }

    $desired = switch ($SKU) {
        'Enterprise'   { 'Windows 11 Enterprise' }
        'Professional' { 'Windows 11 Pro' }
        default        { throw "Select-DesiredIndex: Unsupported SKU '$SKU'." }
    }

    $exact = $clean | Where-Object {
        $_.Name.Equals($desired, [System.StringComparison]::OrdinalIgnoreCase)
    } | Select-Object -First 1
    if ($exact) { return [int]$exact.Index }

    if ($SKU -eq 'Professional') {
        $alt = $clean | Where-Object {
            $_.Name.Equals('Windows 11 Professional', [System.StringComparison]::OrdinalIgnoreCase) -or
            $_.Name -match '(?i)^Windows 11 Professional(\b|$)'
        } | Select-Object -First 1
        if ($alt) { return [int]$alt.Index }
    }

    $starts = $clean | Where-Object {
        $_.Name.StartsWith($desired, [System.StringComparison]::OrdinalIgnoreCase)
    } | Select-Object -First 1
    if ($starts) { return [int]$starts.Index }

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
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int] $RootPid,

        [int] $PollSeconds = 1
    )

    while ($true) {
        $pids = Get-ProcessTreePids -RootPid $RootPid

        $anyAlive = $false
        foreach ($p in $pids) {
            if (Get-Process -Id $p -ErrorAction SilentlyContinue) { $anyAlive = $true; break }
        }

        if (-not $anyAlive) { break }
        Start-Sleep -Seconds $PollSeconds
    }
}

function Expand-HPSoftPaq {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $SoftPaqExe,

        [Parameter(Mandatory)]
        [string] $Destination
    )

    $SoftPaqExe = Resolve-ArtifactPath -Path $SoftPaqExe
    if (-not (Test-Path -LiteralPath $SoftPaqExe)) {
        throw "Expand-HPSoftPaq: SoftPaq EXE not found: $SoftPaqExe"
    }

    Ensure-Dir $Destination
    $exeAbs = (Resolve-Path -LiteralPath $SoftPaqExe).Path

    Write-Log "Extracting HP SoftPaq package." 'INFO' -Context "Drivers" -Detail "Destination: $Destination"
    Write-Log "SoftPaq executable resolved path." 'INFO' -Context "Drivers" -Detail $exeAbs

    $argsModern = @('/s','/e','/f', $Destination)
    try {
        Write-Log "Attempting extraction using modern SoftPaq switches." 'INFO' -Context "Drivers" -Detail ($argsModern -join ' ')
        $p = Start-Process -FilePath $exeAbs -ArgumentList $argsModern -PassThru -WindowStyle Hidden
        Wait-ProcessTree -RootPid $p.Id
    } catch {
        Write-Log "Modern switch extraction raised an exception." 'WARN' -Context "Drivers" -Detail $_.Exception.Message
    }

    $infCount = (Get-ChildItem -LiteralPath $Destination -Recurse -Filter *.inf -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Log "INF file count after modern extraction attempt." 'INFO' -Context "Drivers" -Detail $infCount
    if ($infCount -gt 0) {
        Write-Log "SoftPaq extraction completed using modern switches." 'OK' -Context "Drivers" -Detail $Destination
        return
    }

    $argsLegacy = @('-pdf', "-f$Destination", '-s')
    Write-Log "Falling back to legacy SoftPaq switches." 'WARN' -Context "Drivers" -Detail ($argsLegacy -join ' ')

    $p2 = Start-Process -FilePath $exeAbs -ArgumentList $argsLegacy -PassThru -WindowStyle Hidden
    Wait-ProcessTree -RootPid $p2.Id

    $infCount2 = (Get-ChildItem -LiteralPath $Destination -Recurse -Filter *.inf -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Log "INF file count after legacy extraction attempt." 'INFO' -Context "Drivers" -Detail $infCount2

    if ($infCount2 -eq 0) {
        Write-Log "SoftPaq extraction completed but no INF files were found under the destination folder. Content may be nested or extracted elsewhere." 'WARN' -Context "Drivers" -Detail $Destination
    } else {
        Write-Log "SoftPaq extraction completed using legacy switches." 'OK' -Context "Drivers" -Detail $Destination
    }
}

function Resolve-ArtifactPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    if (Test-Path -LiteralPath $Path) { return $Path }

    $leaf = [IO.Path]::GetFileName($Path)

    $candidates = @()

    if (Get-Variable -Name BuildForgeRoot -Scope Script -ErrorAction SilentlyContinue) {
        if ($script:BuildForgeRoot) {
            $candidates += @(
                (Join-Path $script:BuildForgeRoot $leaf),
                (Join-Path $script:BuildForgeRoot (Join-Path 'Drivers' $leaf)),
                (Join-Path $script:BuildForgeRoot (Join-Path 'Downloads' $leaf))
            )
        }
    }

    if (Get-Variable -Name BuildForgeRootHistory -Scope Script -ErrorAction SilentlyContinue) {
        foreach ($r in $script:BuildForgeRootHistory) {
            if ($r) {
                $candidates += @(
                    (Join-Path $r $leaf),
                    (Join-Path $r (Join-Path 'Drivers' $leaf)),
                    (Join-Path $r (Join-Path 'Downloads' $leaf))
                )
            }
        }
    }

    $found = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($found) { return $found }

    throw "Resolve-ArtifactPath: File not found. Original='$Path'. Looked for '$leaf' under current/known BuildForge roots."
}

function Get-ProcessTreePids {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int] $RootPid
    )

    $seen  = New-Object System.Collections.Generic.HashSet[int]
    $queue = New-Object System.Collections.Generic.Queue[int]
    [void]$queue.Enqueue($RootPid)

    while ($queue.Count -gt 0) {
        $curPid = $queue.Dequeue()
        if (-not $seen.Add($curPid)) { continue }

        $children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$curPid" -ErrorAction SilentlyContinue
        foreach ($c in $children) {
            [void]$queue.Enqueue([int]$c.ProcessId)
        }
    }

    return $seen
}

# ---------------------------
# MAIN
# ---------------------------
Invoke-Step "  1) Setup BuildForge root + fixed logging" {
    Initialize-Logging
    Update-BuildForgeRoot
    Write-Log "Fixed log file location." 'INFO' -Context "Logging" -Detail $script:LogFile
    Write-Log "Current working root directory." 'INFO' -Context "Storage" -Detail $script:BuildForgeRoot
}

Invoke-Step "  2) List PowerShell + environment info" {
    $osCap = 'Unknown / WinRE'
    try { $osCap = (Get-CimInstance Win32_OperatingSystem).Caption } catch {}
    Write-Log "PowerShell version detected." 'INFO' -Context "Environment" -Detail $($PSVersionTable.PSVersion)
    Write-Log "Operating system caption detected." 'INFO' -Context "Environment" -Detail $osCap
}

Invoke-Step "  3) List hardware identity" {
    $hw = Get-HardwareIdentity
    $script:Hardware = $hw
    Write-Log ("Computer system identity." -f $null) 'INFO' -Context "Hardware" -Detail ("{0} {1}" -f $hw.CSManufacturer, $hw.CSModel)
    Write-Log ("Baseboard identity." -f $null) 'INFO' -Context "Hardware" -Detail ("{0} {1} SKU={2} Product={3}" -f $hw.BBManufacturer, $hw.BBModel, $hw.BBSKU, $hw.BBProduct)
}

Invoke-Step "  4) List target OS parameters" {
    Write-Log "Target operating system parameters." 'INFO' -Context "Configuration" -Detail "OS=$OperatingSystem ReleaseId=$ReleaseId Arch=$Architecture Lang=$LanguageCode License=$License SKU=$SKU"
}

Invoke-Step "  5) Download catalogs" {
    $script:OSCatalog     = Get-Catalog -CatalogUrl $OSCatalogUrl
    $script:DriverCatalog = Get-Catalog -CatalogUrl $DriverCatalogUrl
}

Invoke-Step "  6) Match OS entry from catalog" {
    $osEntry = Resolve-OsCatalogEntry -Catalog $script:OSCatalog
    $script:OsEntry = $osEntry

    $osUrl    = Get-EntryValue $osEntry @('URL','Url','Uri','DownloadUrl','ESDUrl','WimUrl')
    $osSha1   = Get-EntryValue $osEntry @('Sha1','SHA1','HashSha1','SHA-1')
    $osSha256 = Get-EntryValue $osEntry @('Sha256','SHA256','HashSha256','SHA-256')

    if (-not $osUrl) { throw "OS catalog entry missing URL/DownloadUrl/ESDUrl/WimUrl." }

    $script:OsUrl    = $osUrl
    $script:OsSha1   = $osSha1
    $script:OsSha256 = $osSha256

    Write-Log "Operating system image selected from catalog." 'OK' -Context "OS Catalog" -Detail $osUrl
}

Invoke-Step "  7) Match driver pack from hardware + catalog" {
    $res = Find-DriverPackMatch -Hardware $script:Hardware -DriverCatalog $script:DriverCatalog
    $script:DriverMatch = $res

    if ($res.Matched) {
        Write-Log "Driver pack match found for current hardware." 'OK' -Context "Drivers" -Detail "Score=$($res.Score) MatchedFields=$($res.MatchInfo)"
        Write-Log "Selected driver pack download URL." 'INFO' -Context "Drivers" -Detail $res.URL
    } else {
        Write-Log "No suitable driver pack match met the minimum score. Driver download will be skipped." 'WARN' -Context "Drivers" -Detail $res.Reason
    }
}

Invoke-Step "  8) Select best local disk for OS" {
    $disk = Get-TargetDisk
    $script:TargetDisk = $disk
    Write-Log "Target disk selected for installation." 'OK' -Context "Disk" -Detail ("Disk #{0} BusType={1} Size={2:N2}GB Boot={3} System={4}" -f $disk.Number, $disk.BusType, ($disk.Size/1GB), $disk.IsBoot, $disk.IsSystem)
}

Invoke-Step "  9) Partition disk (UEFI/GPT) if needed" {
    $haveW = Test-Path -LiteralPath 'W:\'
    $haveS = Test-Path -LiteralPath 'S:\'
    $haveR = Test-Path -LiteralPath 'R:\'

    if ($ForceRepartition -or -not ($haveW -and $haveS -and $haveR)) {
        Write-Log "Disk partitioning is required for the expected layout." 'WARN' -Context "Disk" -Detail "ForceRepartition=$ForceRepartition, S=$haveS W=$haveW R=$haveR"
        Apply-UEFIPartitionLayout -DiskNumber $script:TargetDisk.Number
        Write-Log "Disk partition layout applied. Expected drive letters are now available." 'OK' -Context "Disk" -Detail "S: (EFI), W: (Windows), R: (Recovery)"
    } else {
        Write-Log "Expected partitions already present. Disk repartitioning skipped." 'INFO' -Context "Disk" -Detail "S:, W:, and R: are available"
    }
}

Invoke-Step " 10) Move BuildForge root to W: (when W: exists)" {
    Update-BuildForgeRoot
    Write-Log "Current working root directory confirmed." 'INFO' -Context "Storage" -Detail $script:BuildForgeRoot
}

Invoke-Step " 11) Download correct OS ESD/WIM (best match)" {
    Update-BuildForgeRoot
    $osDir = Join-Path $script:BuildForgeRoot 'OS'
    Ensure-Dir $osDir

    $osFile = Get-LeafNameFromUrl -Url $script:OsUrl -Fallback 'install.esd'
    $osPath = Join-Path $osDir $osFile

    Invoke-Download -Url $script:OsUrl -DestPath $osPath | Out-Null
    if ($script:OsSha1 -or $script:OsSha256) {
        Confirm-FileHash -FilePath $osPath -ExpectedSha1 $script:OsSha1 -ExpectedSha256 $script:OsSha256
    } else {
        Write-Log "Integrity check skipped because the catalog did not provide file hashes." 'WARN' -Context "Integrity" -Detail $osPath
    }

    $script:OsPath = $osPath
}

Invoke-Step " 12) Download best-match driver pack (if match) (no extract yet)" {
    Update-BuildForgeRoot
    if (-not ($script:DriverMatch.Matched -and $script:DriverMatch.URL)) {
        Write-Log "Driver pack download skipped because no matching driver URL was available." 'WARN' -Context "Drivers"
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

Invoke-Step " 13) List ESD/WIM indexes (DISM)" {
    $idx = Get-ImageIndexesFromEsd -ImageFile $script:OsPath
    $script:ImageIndexes = $idx

    Write-Log "Enumerating images within the OS installation file." 'INFO' -Context "Image" -Detail $script:OsPath
    $idx | ForEach-Object { Write-Log ("Image index discovered. Index={0} Name={1}" -f $_.Index, $_.Name) 'INFO' -Context "Image" }

    if (-not $idx -or $idx.Count -eq 0) { throw "No indexes parsed from DISM output." }
}

Invoke-Step " 14) Select desired index (Windows 11 $SKU)" {
    $index = Select-DesiredIndex -Indexes $script:ImageIndexes
    $script:SelectedIndex = $index
    Write-Log "Selected image index for installation based on SKU preference." 'OK' -Context "Image" -Detail "Index=$index SKU=$SKU"
}

Invoke-Step " 15) Expand selected index to W:\" {
    $already = Test-Path -LiteralPath 'W:\Windows\System32'
    if ($already -and -not $ForceApplyImage) {
        Write-Log "Windows folder already exists. Applying the image has been skipped. Use ForceApplyImage to reapply." 'INFO' -Context "Image" -Detail "W:\Windows\System32 detected"
        return
    }

    if (-not (Get-Command -Name Expand-WindowsImage -ErrorAction SilentlyContinue)) {
        try {
            Import-Module Dism -ErrorAction Stop
        } catch {
            throw "Expand-WindowsImage cmdlet not available (Dism module missing). Cannot Expand image without dism.exe."
        }
    }

    if ($PSCmdlet.ShouldProcess("W:\", "Expand-WindowsImage (Index $($script:SelectedIndex))")) {
        Expand-WindowsImage -ImagePath $script:OsPath `
                           -Index $script:SelectedIndex `
                           -ApplyPath 'W:\' `
                           -ErrorAction Stop | Out-Null

        Write-Log "Windows image applied successfully to the Windows partition." 'OK' -Context "Image" -Detail "ApplyPath=W:\ Index=$($script:SelectedIndex)"
    }
}

Invoke-Step " 16) Configure boot (BCDBoot UEFI)" {
    if ($PSCmdlet.ShouldProcess("S:\", "BCDBoot UEFI from W:\Windows")) {
        $bcdboot = Join-Path $env:WINDIR 'System32\bcdboot.exe'
        if (-not (Test-Path -LiteralPath $bcdboot)) { $bcdboot = "bcdboot.exe" }

        Invoke-Native -FilePath $bcdboot -Arguments @(
            "W:\Windows",
            "/s","S:",
            "/f","UEFI"
        ) | Out-Null

        Write-Log "Boot configuration files created successfully for UEFI." 'OK' -Context "Boot" -Detail "Source=W:\Windows Target=S: Firmware=UEFI"
    }
}

Invoke-Step " 17) Setup WinRE WIM on recovery partition + register offline" {

    $reDir = 'R:\Recovery\WindowsRE'
    Ensure-Dir $reDir

    $src = 'W:\Windows\System32\Recovery\Winre.wim'
    $dst = Join-Path $reDir 'Winre.wim'

    if (Test-Path -LiteralPath $src) {
        Copy-Item -LiteralPath $src -Destination $dst -Force
        Write-Log "WinRE image copied to the recovery partition." 'OK' -Context "Recovery" -Detail $dst
    } else {
        throw "Winre.wim not found at $src (some images store it differently)."
    }

    $reagentc = 'W:\Windows\System32\reagentc.exe'
    if (-not (Test-Path -LiteralPath $reagentc)) {
        throw "reagentc.exe not found at expected path: $reagentc"
    }

    if ($PSCmdlet.ShouldProcess("W:\Windows", "Register and enable WinRE offline")) {

        Invoke-Native -FilePath $reagentc -Arguments @(
            "/setreimage",
            "/path", $reDir,
            "/target", "W:\Windows"
        ) | Out-Null

        $osGuid = Get-OfflineOsGuidFromBcd -BcdStorePath 'S:\EFI\Microsoft\Boot\BCD' -WindowsPartition 'W:'
        Write-Log "Resolved OS loader GUID for WinRE binding." 'INFO' -Context "Recovery" -Detail $osGuid

        Invoke-Native -FilePath $reagentc -Arguments @(
            "/enable",
            "/osguid", $osGuid
        ) | Out-Null

        Write-Log "WinRE configured and enabled for the offline operating system." 'OK' -Context "Recovery" -Detail "OSGUID=$osGuid"
    }
}

Invoke-Step "18) Extract HP driver pack silently (wait for full process tree)" {

    if (-not $script:DriverPackPath) {
        Write-Log "Driver extraction skipped because no driver pack was downloaded." 'WARN' -Context "Drivers"
        return
    }

    Update-BuildForgeRoot

    $extractDir = Join-Path $script:BuildForgeRoot 'ExtractedDrivers'
    Ensure-Dir $extractDir

    $script:DriverPackPath = Resolve-ArtifactPath -Path $script:DriverPackPath

    $ext = [IO.Path]::GetExtension($script:DriverPackPath).ToLowerInvariant()
    Write-Log "Driver pack prepared for extraction." 'INFO' -Context "Drivers" -Detail "Path=$($script:DriverPackPath) Extension=$ext"
    Write-Log "Driver extraction destination directory confirmed." 'INFO' -Context "Drivers" -Detail $extractDir

    switch ($ext) {
        '.exe' {
            Expand-HPSoftPaq -SoftPaqExe $script:DriverPackPath -Destination $extractDir
        }
        '.zip' {
            Expand-Archive -LiteralPath $script:DriverPackPath -DestinationPath $extractDir -Force
            Write-Log "ZIP driver pack extracted successfully." 'OK' -Context "Drivers" -Detail $extractDir
        }
        '.cab' {
            Invoke-Native -FilePath "expand.exe" -Arguments @("-F:*", $script:DriverPackPath, $extractDir) | Out-Null
            Write-Log "CAB driver pack extracted successfully." 'OK' -Context "Drivers" -Detail $extractDir
        }
        default {
            throw "Unknown driver pack extension '$ext' - cannot extract."
        }
    }

    $infCount = (Get-ChildItem -LiteralPath $extractDir -Recurse -Filter *.inf -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Log "INF files discovered under driver extraction root." 'INFO' -Context "Drivers" -Detail $infCount

    if ($infCount -eq 0) {
        throw "Extraction completed but produced 0 .INF files under '$extractDir'. Cannot inject drivers."
    }

    $script:DriverExtractDir = $extractDir
    Write-Log "Driver extraction directory set for injection." 'OK' -Context "Drivers" -Detail $script:DriverExtractDir
}

Invoke-Step "19) Inject drivers into offline image (Add-WindowsDriver /Recurse)" {

    if (-not $script:DriverExtractDir) {
        Write-Log "Driver injection skipped because no extracted driver directory is available." 'WARN' -Context "Drivers"
        return
    }

    if (-not (Test-Path -LiteralPath $script:DriverExtractDir)) {
        throw "DriverExtractDir does not exist: $($script:DriverExtractDir)"
    }

    $infCount = (Get-ChildItem -LiteralPath $script:DriverExtractDir -Recurse -Filter *.inf -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Log "INF files available for injection." 'INFO' -Context "Drivers" -Detail "Count=$infCount Root=$($script:DriverExtractDir)"
    if ($infCount -eq 0) {
        throw "No .INF files found under '$($script:DriverExtractDir)'. Cannot inject drivers."
    }

    if ($PSCmdlet.ShouldProcess("W:\", "Add-WindowsDriver -Recurse from $($script:DriverExtractDir)")) {

        Add-WindowsDriver -Path 'W:\' `
                          -Driver $script:DriverExtractDir `
                          -Recurse `
                          -ErrorAction Stop | Out-Null

        Write-Log "Driver injection completed successfully." 'OK' -Context "Drivers" -Detail "OfflinePath=W:\ DriverRoot=$($script:DriverExtractDir)"
    }
}

Invoke-Step "Summary" {
    Write-Log "Log file location." 'INFO' -Context "Summary" -Detail $script:LogFile
    Write-Log "BuildForge working root directory." 'INFO' -Context "Summary" -Detail $script:BuildForgeRoot
    if ($script:OsPath) { Write-Log "Operating system image file used." 'INFO' -Context "Summary" -Detail $script:OsPath }
    if ($script:SelectedIndex) { Write-Log "Image index applied." 'INFO' -Context "Summary" -Detail $script:SelectedIndex }
    if ($script:TargetDisk) { Write-Log "Disk number used for installation." 'INFO' -Context "Summary" -Detail "#$($script:TargetDisk.Number)" }
    Write-Log "Script execution completed." 'OK' -Context "Summary"
}
