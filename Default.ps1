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
# Simple WinRE driver bootstrap + one-partition disk prep (PS 5.1)

$ErrorActionPreference = 'Stop'

function Log { param([string]$m) Write-Host ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $m) }

function Enable-Tls12 {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
}

function Download-File {
    param([string]$Url, [string]$DestPath)
    Enable-Tls12
    Log "Downloading: $Url"
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        & $curl --fail --location --silent --show-error -o "$DestPath" "$Url"
        if ($LASTEXITCODE -ne 0) { throw "curl download failed." }
    } else {
        Invoke-WebRequest -Uri $Url -OutFile $DestPath -UseBasicParsing
    }
    if (-not (Test-Path -LiteralPath $DestPath)) { throw "Download failed: file missing." }
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
        # Try to bring internal disks online (best effort) and re-filter
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

function Prep-Disk-OnePartition {
    param([int]$DiskNumber)

    Log "Clearing Disk $DiskNumber (this erases ALL data)"
    Set-Disk -Number $DiskNumber -IsReadOnly:$false -ErrorAction SilentlyContinue | Out-Null
    Set-Disk -Number $DiskNumber -IsOffline:$false -ErrorAction SilentlyContinue | Out-Null

    Clear-Disk -Number $DiskNumber -RemoveData -Confirm:$false
    Initialize-Disk -Number $DiskNumber -PartitionStyle GPT

    Log "Creating single NTFS partition and assigning drive letter"
    $part = New-Partition -DiskNumber $DiskNumber -UseMaximumSize -AssignDriveLetter
    # Force it to C:
    try {
        # If C: exists, remove access path from that partition first
        $cPart = Get-Partition -DriveLetter C -ErrorAction SilentlyContinue
        if ($cPart) {
            Remove-PartitionAccessPath -DiskNumber $cPart.DiskNumber -PartitionNumber $cPart.PartitionNumber -AccessPath "C:\" -ErrorAction SilentlyContinue
        }
    } catch {}
    Format-Volume -Partition $part -FileSystem NTFS -NewFileSystemLabel "Windows" -Confirm:$false -Force
    Set-Partition -DiskNumber $part.DiskNumber -PartitionNumber $part.PartitionNumber -NewDriveLetter C | Out-Null
    Log "Disk prepared. C: ready."
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
    param([string]$ExePath, [string]$DestDir)
    if (-not (Test-Path -LiteralPath $ExePath)) { throw "SoftPaq not found: $ExePath" }
    if (-not (Test-Path -LiteralPath $DestDir)) { New-Item -ItemType Directory -Path $DestDir -Force | Out-Null }

    # Common HP SoftPaq silent extract: /e /s /f "<dir>"
    Log "Extracting SoftPaq silently → $DestDir"
    & "$ExePath" /e /s /f "$DestDir"
    if ($LASTEXITCODE -ne 0) {
        # Some SoftPaqs use -e -s -f
        & "$ExePath" -e -s -f "$DestDir"
    }
    # Basic check: look for INF presence
    $inf = Get-ChildItem -Path $DestDir -Recurse -Filter *.inf -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $inf) { Log "Warning: No INF found yet—extraction may have nested folder, continuing." }
}

function Load-Drivers {
    param([string]$Root)
    $infFiles = Get-ChildItem -Path $Root -Recurse -Filter *.inf -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
    if (-not $infFiles -or $infFiles.Count -eq 0) { throw "No .inf files found under $Root." }

    $drvload = Get-Command drvload.exe -ErrorAction SilentlyContinue
    if ($drvload) {
        $ok=0;$fail=0
        foreach ($inf in $infFiles) {
            Log "drvload $inf"
            & $drvload "$inf"
            if ($LASTEXITCODE -eq 0) { $ok++ } else { $fail++ }
        }
        Log "drvload results: loaded=$ok, failed=$fail"
    } else {
        # Fallback: pnputil stage+install (best-effort)
        $pnp = Get-Command pnputil.exe -ErrorAction SilentlyContinue
        if (-not $pnp) { throw "Neither drvload nor pnputil is available to load drivers." }
        Log "pnputil /add-driver ""$Root\*.inf"" /subdirs /install"
        & $pnp /add-driver "$Root\*.inf" /subdirs /install
    }
}

function Rescan-Devices {
    Log "Rescanning storage (diskpart)..."
    $dp = Join-Path 'X:\' 'rescan.txt'
    @("rescan","list disk","list volume") | Out-File -FilePath $dp -Encoding ascii -Force
    try { diskpart /s $dp | Out-Null } catch { Log "diskpart rescan failed (continuing)" }

    try { & wpeutil UpdateBootInfo | Out-Null } catch {}
    $pnp = Get-Command pnputil.exe -ErrorAction SilentlyContinue
    if ($pnp) { try { & $pnp /scan-devices | Out-Null } catch {} }
}

# ------------------ MAIN ------------------

try {
    Log "Locating internal (non-USB) target disk..."
    $disk = Get-InternalTargetDisk
    Log ("Selected Disk {0} ({1} GB) Bus={2}" -f $disk.Number, [math]::Round($disk.Size/1GB), $disk.BusType)

    Prep-Disk-OnePartition -DiskNumber $disk.Number

    $sku = Get-DeviceSkuName
    $driversRoot = Join-Path 'C:\Drivers' $sku
    if (-not (Test-Path -LiteralPath $driversRoot)) { New-Item -ItemType Directory -Path $driversRoot -Force | Out-Null }
    Log "Drivers folder: $driversRoot"

    $url = 'https://ftp.hp.com/pub/softpaq/sp160001-160500/sp160195.exe'
    $dlPath = Join-Path $driversRoot 'sp160195.exe'
    Download-File -Url $url -DestPath $dlPath

    $extractDir = Join-Path $driversRoot 'extracted'
    Extract-SoftPaq -ExePath $dlPath -DestDir $extractDir

    Load-Drivers -Root $extractDir
    Rescan-Devices

    Log "Done. C: formatted, drivers injected, devices rescanned."
    Write-Host "Success. You can proceed with imaging or disk operations." -ForegroundColor Green
} catch {
    Write-Host ("ERROR: {0}" -f $_.Exception.Message) -ForegroundColor Red
    exit 1
}
    exit 2
}
