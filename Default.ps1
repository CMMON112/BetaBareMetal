[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $OsUrl,  # direct URL to install.esd or install.wim

    [string] $EditionExactName = 'Windows 11 Enterprise',

    [int] $EfiSizeMB = 200,
    [int] $RecoverySizeMB = 500
)

$ErrorActionPreference = 'Stop'
$script:CurrentStep = 0
$script:TotalSteps  = 9
$script:TempRoot    = $null

# -----------------------
# TempRoot + Logging (rerun-safe)
# -----------------------
function Get-TempRoot {
    $xRoot = 'X:\Windows\Temp\BuildForge'
    $wRoot = 'W:\BuildForge'

    function Ensure-Dir([string]$Path) {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }
    }

    $hasW = Test-Path -LiteralPath 'W:\'
    $hasX = Test-Path -LiteralPath 'X:\'

    if ($hasW) { Ensure-Dir $wRoot; return $wRoot }
    if ($hasX) { Ensure-Dir $xRoot; return $xRoot }

    throw "Get-TempRoot: Neither W:\ nor X:\ exists."
}

function Write-Status {
    param(
        [string] $Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS','STEP')]
        [string] $Level = 'INFO'
    )

    try { $script:TempRoot = Get-TempRoot } catch { $script:TempRoot = 'X:\Windows\Temp\BuildForge' }

    $color = switch ($Level) {
        'INFO'    { 'Gray' }
        'WARN'    { 'Yellow' }
        'ERROR'   { 'Red' }
        'SUCCESS' { 'Green' }
        'STEP'    { 'Cyan' }
    }

    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $color

    $logDir  = $script:TempRoot
    $logFile = Join-Path $logDir 'BuildForce.log'

    for ($i=0; $i -lt 2; $i++) {
        try {
            if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
            if (-not (Test-Path -LiteralPath $logFile)) { New-Item -ItemType File -Path $logFile -Force | Out-Null }
            $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            Add-Content -Path $logFile -Value "$ts [$Level] $Message"
            break
        } catch {
            Start-Sleep -Milliseconds 50
            try { $script:TempRoot = Get-TempRoot } catch { }
            $logDir  = $script:TempRoot
            $logFile = Join-Path $logDir 'BuildForce.log'
        }
    }
}

function Start-Step([string]$Text) {
    $script:CurrentStep++
    Write-Status -Level STEP -Message ("STEP {0}/{1}: {2}" -f $script:CurrentStep, $script:TotalSteps, $Text)
}

# -----------------------
# Download helpers
# -----------------------
function Enable-Tls12 {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
}

function Resolve-CurlPath {
    $c1 = Join-Path $env:WINDIR 'System32\curl.exe'
    $cmd = Get-Command $c1 -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Path }
    $cmd = Get-Command 'curl.exe' -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Path }
    return $null
}

function Invoke-FileDownload {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$DestPath
    )

    Enable-Tls12

    $parent = Split-Path -Parent $DestPath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $curl = Resolve-CurlPath
    Write-Status -Message ("Downloading: {0}" -f $Url)

    if ($curl) {
        $args = @('--fail','--location','--silent','--show-error','--connect-timeout','30','--output', $DestPath, $Url)
        & $curl @args
        if ($LASTEXITCODE -ne 0) { throw "curl failed: $LASTEXITCODE" }
    } else {
        Invoke-WebRequest -Uri $Url -OutFile $DestPath -UseBasicParsing
    }

    if (-not (Test-Path -LiteralPath $DestPath)) { throw "Download succeeded but file missing: $DestPath" }
    Write-Status -Level SUCCESS -Message ("Downloaded to: {0}" -f $DestPath)
}

# -----------------------
# Disk selection + partitioning
# -----------------------
function Get-TargetDisk {
    $pref = @{
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
    if (-not $disks) { throw "No suitable internal disks found." }

    $ranked = foreach ($d in $disks) {
        $score = if ($pref.ContainsKey($d.BusType)) { $pref[$d.BusType] } else { 10 }
        [pscustomobject]@{ Disk=$d; Score=$score }
    }

    $best = $ranked |
        Sort-Object Score, @{Expression={$_.Disk.IsBoot}}, @{Expression={$_.Disk.IsSystem}}, @{Expression={$_.Disk.Size}; Descending=$true} |
        Select-Object -First 1

    return $best.Disk
}

function New-UEFIPartitionLayout {
    param(
        [Parameter(Mandatory)][int]$DiskNumber,
        [int]$EfiSizeMB = 200,
        [int]$RecoverySizeMB = 500
    )

    $lines = @(
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

    $dp = Join-Path (Get-TempRoot) 'diskpart-uefi.txt'
    Set-Content -Path $dp -Value ($lines -join "`r`n") -Encoding ASCII

    Write-Status -Message "Running diskpart..."
    & diskpart /s $dp | Out-String | ForEach-Object { if ($_) { Write-Status -Message $_.TrimEnd() } }
}

# -----------------------
# Image enumeration + apply
# -----------------------
function Get-CacheRoot {
    $root = 'W:\BuildForge\Cache'
    if (-not (Test-Path -LiteralPath 'W:\')) {
        $root = Join-Path (Get-TempRoot) 'Cache'
    }
    if (-not (Test-Path -LiteralPath $root)) { New-Item -ItemType Directory -Path $root -Force | Out-Null }
    return $root
}

function Get-IndexByExactName {
    param(
        [Parameter(Mandatory)][string]$ImagePath,
        [Parameter(Mandatory)][string]$ExactName
    )

    if (Get-Command Get-WindowsImage -ErrorAction SilentlyContinue) {
        $hit = Get-WindowsImage -ImagePath $ImagePath | Where-Object { $_.ImageName -eq $ExactName } | Select-Object -First 1
        if (-not $hit) {
            $names = (Get-WindowsImage -ImagePath $ImagePath | Select-Object -ExpandProperty ImageName) -join '; '
            throw "Image '$ExactName' not found. Available: $names"
        }
        return [int]$hit.ImageIndex
    }

    # DISM enumeration supported via /Get-WimInfo [3](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-image-management-command-line-options-s14?view=windows-11)
    $out = (& dism.exe /English /Get-WimInfo /WimFile:"$ImagePath" 2>&1 | Out-String)
    $rx = [regex]"Index\s*:\s*(\d+)\s+Name\s*:\s*(.+?)\s*(?:\r?\n|$)"
    $m = $rx.Matches($out)
    if ($m.Count -eq 0) { throw "Could not parse DISM /Get-WimInfo output." }

    $entries = foreach ($x in $m) {
        [pscustomobject]@{ Index=[int]$x.Groups[1].Value; Name=$x.Groups[2].Value.Trim() }
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
    Write-Status -Level SUCCESS -Message ("Selected '{0}' (Index {1})" -f $ExactName, $idx)

    # Expand-WindowsImage supports -Name / -ApplyPath [2](https://learn.microsoft.com/en-us/powershell/module/dism/expand-windowsimage?view=windowsserver2025-ps)
    if (Get-Command Expand-WindowsImage -ErrorAction SilentlyContinue) {
        Expand-WindowsImage -ImagePath $ImagePath -Name $ExactName -ApplyPath $ApplyPath -CheckIntegrity
        return
    }

    & dism.exe /Apply-Image /ImageFile:"$ImagePath" /Index:$idx /ApplyDir:"$ApplyPath"
    if ($LASTEXITCODE -ne 0) { throw "DISM /Apply-Image failed: $LASTEXITCODE" }
}

# -----------------------
# MAIN
# -----------------------
try {
    Start-Step "Select target disk"
    $disk = Get-TargetDisk
    Write-Status -Level SUCCESS -Message ("Disk #{0} {1} {2:N1}GB" -f $disk.Number, $disk.BusType, ($disk.Size/1GB))

    Start-Step "Partition disk (UEFI/GPT)"
    New-UEFIPartitionLayout -DiskNumber $disk.Number -EfiSizeMB $EfiSizeMB -RecoverySizeMB $RecoverySizeMB

    Start-Step "Prepare cache (W: preferred)"
    $cache = Get-CacheRoot
    Write-Status -Message ("Cache: {0}" -f $cache)

    Start-Step "Download OS image"
    $name = "install.esd"
    try {
        $name = [IO.Path]::GetFileName(([Uri]$OsUrl).AbsolutePath)
        if (:IsNullOrWhiteSpace($name)) { $name = "install.esd" }
    } catch { }

    $osPath = Join-Path $cache $name
    Invoke-FileDownload -Url $OsUrl -DestPath $osPath

    Start-Step "Enumerate editions (for troubleshooting)"
    if (Get-Command Get-WindowsImage -ErrorAction SilentlyContinue) {
        Get-WindowsImage -ImagePath $osPath |
            Select-Object ImageIndex, ImageName, Architecture |
            Format-Table -AutoSize | Out-String |
            ForEach-Object { if ($_) { Write-Status -Message $_.TrimEnd() } }
    } else {
        (& dism.exe /English /Get-WimInfo /WimFile:"$osPath" | Out-String) |
            ForEach-Object { if ($_) { Write-Status -Message $_.TrimEnd() } }
    }

    Start-Step "Apply OS image"
    Apply-Image -ImagePath $osPath -ApplyPath 'W:\' -ExactName $EditionExactName

    Start-Step "BCDBoot"
    & bcdboot.exe W:\Windows /s S: /f UEFI
    if ($LASTEXITCODE -ne 0) { throw "bcdboot failed: $LASTEXITCODE" }

    Start-Step "Configure WinRE (offline)"
    $rePath = 'R:\Recovery\WindowsRE'
    if (-not (Test-Path -LiteralPath $rePath)) { New-Item -ItemType Directory -Path $rePath -Force | Out-Null }

    $srcWinre = 'W:\Windows\System32\Recovery\Winre.wim'
    if (Test-Path -LiteralPath $srcWinre) {
        Copy-Item -LiteralPath $srcWinre -Destination (Join-Path $rePath 'Winre.wim') -Force
    } else {
        Write-Status -Level WARN -Message "Winre.wim not found at W:\Windows\System32\Recovery\Winre.wim"
    }

    # reagentc supports offline /target for setreimage & enable [1](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/reagentc-command-line-options?view=windows-11)
    & reagentc.exe /setreimage /path $rePath /target W:\Windows
    & reagentc.exe /enable /target W:\Windows

    Start-Step "Done"
    Write-Status -Level SUCCESS -Message "OS-only build complete."
    Write-Status -Message ("Log: {0}" -f (Join-Path (Get-TempRoot) 'BuildForce.log'))

} catch {
    Write-Status -Level ERROR -Message $_.Exception.Message
    Write-Status -Level ERROR -Message $_.ScriptStackTrace
    throw
}
