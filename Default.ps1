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

# ----------------------------
# Discovery helpers
# ----------------------------
function Get-WritableDisks {
    <#
      Returns internal, non-USB, non-readonly, online disks >= 16 GB.
      Accepts RAW or initialized disks; we will (re)initialize as GPT.
    #>
    $preferredBuses = @('NVMe','RAID','SATA','SAS','ATA','PCIe')

    # Try to bring offline disks online (best effort)
    $offline = Get-Disk | Where-Object {
        $_.BusType -in $preferredBuses -and $_.IsOffline -eq $true
    }
    foreach ($d in $offline) {
        Write-Log "Attempting to bring Disk $($d.Number) online..." "INFO"
        try { Set-Disk -Number $d.Number -IsOffline:$false -ErrorAction Stop } catch {}
    }

    # Re-evaluate with consistent filters
    $minSizeGB = 16
    $disks = Get-Disk | Where-Object {
        $_.BusType -in $preferredBuses -and
        $_.IsOffline -eq $false -and
        $_.IsReadOnly -eq $false -and
        $_.IsBoot -eq $false -and
        $_.IsSystem -eq $false -and
        [math]::Floor($_.Size/1GB) -ge $minSizeGB
    }

    $disks | Sort-Object -Property Size -Descending
}

function Get-HardwareReport {
    Write-Host ""
    Write-Log "No writable local disks were found. Printing a concise hardware report for escalation..." "WARN"

    try { $cs = Get-CimInstance Win32_ComputerSystem } catch { $cs = $null }
    try { $bb = Get-CimInstance Win32_BaseBoard } catch { $bb = $null }
    try { $sysSku = if ($cs) { $cs.SystemSKUNumber } else { $null } } catch { $sysSku = $null }

    $manu  = Coalesce $(if ($cs) { $cs.Manufacturer } else { $null }) 'N/A'
    $model = Coalesce $(if ($cs) { $cs.Model } else { $null }) 'N/A'
    $bbProd = Coalesce $(if ($bb) { $bb.Product } else { $null }) 'N/A'
    $bbMfg  = Coalesce $(if ($bb) { $bb.Manufacturer } else { $null }) 'N/A'
    $sysSku = Coalesce $sysSku 'N/A'

    # Storage "mode" best-effort from controller names
    $mode = "Unknown"
    try {
        $controllers = Get-CimInstance Win32_PnPEntity -Filter "PNPClass='SCSIAdapter'"
        $ctrlNames = $controllers | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue
        if ($ctrlNames -match 'NVMe') { $mode = 'NVMe' }
        elseif ($ctrlNames -match 'RAID|RST|VMD') { $mode = 'RAID' }
        elseif ($ctrlNames -match 'AHCI') { $mode = 'AHCI' }
    } catch {}

    # Disk drive HWIDs
    $diskPnP = @()
    try {
        $diskPnP = Get-CimInstance Win32_PnPEntity -Filter "PNPClass='DiskDrive'" | Select-Object Name, Manufacturer, HardwareID
    } catch {}

    # Chipset/System device HWIDs (PCI)
    $chipsetPnP = @()
    try {
        $chipsetPnP = Get-CimInstance Win32_PnPEntity | Where-Object {
            $_.PNPClass -eq 'System' -and $_.HardwareID -and ($_.PNPDeviceID -like 'PCI*')
        } | Select-Object Name, HardwareID
    } catch {}

    Write-Host "-----------------------------" -ForegroundColor DarkCyan
    Write-Host " Hardware Summary (Report)   " -ForegroundColor DarkCyan
    Write-Host "-----------------------------" -ForegroundColor DarkCyan
    Write-Host (" Manufacturer : {0}" -f $manu)
    Write-Host (" Model        : {0}" -f $model)
    Write-Host (" Baseboard    : {0} (Mfg: {1})" -f $bbProd, $bbMfg)
    Write-Host (" System SKU   : {0}" -f $sysSku)
    Write-Host (" Storage Mode : {0}" -f $mode)
    Write-Host ""
    Write-Host " Disk Hardware IDs:" -ForegroundColor Yellow
    foreach ($d in $diskPnP) {
        $mfg = Coalesce $d.Manufacturer ''
        Write-Host ("  - {0} [{1}]" -f (Coalesce $d.Name 'Unknown'), $mfg)
        if ($d.HardwareID) {
            @($d.HardwareID) | Select-Object -First 6 | ForEach-Object {
                Write-Host ("      * {0}" -f $_)
            }
        }
    }
    Write-Host ""
    Write-Host " Chipset / System Device Hardware IDs:" -ForegroundColor Yellow
    foreach ($c in ($chipsetPnP | Select-Object -First 12)) {
        Write-Host ("  - {0}" -f (Coalesce $c.Name 'Unknown'))
        if ($c.HardwareID) {
            @($c.HardwareID) | Select-Object -First 4 | ForEach-Object {
                Write-Host ("      * {0}" -f $_)
            }
        }
    }
    Write-Host ""
    Write-Host ("Saved a copy to: {0}" -f $script:LogPath) -ForegroundColor DarkGray
}

# ----------------------------
# Disk provisioning (Storage cmdlets)
# ----------------------------
function Provision-DiskWithStorageCmdlets {
    param(
        [Parameter(Mandatory=$true)][int]$DiskNumber,
        [int]$EfiSizeMB = 260,
        [int]$MsrSizeMB = 16,
        [int]$RecoverySizeMB = 1024
    )

    Write-Log "Preparing Disk $DiskNumber using Storage module..."
    $disk = Get-Disk -Number $DiskNumber

    if ($disk.IsReadOnly) {
        Write-Log "Disk is read-only, attempting to clear read-only attribute..." "WARN"
        Set-Disk -Number $DiskNumber -IsReadOnly:$false
    }
    if ($disk.IsOffline) {
        Write-Log "Disk is offline, bringing online..." "WARN"
        Set-Disk -Number $DiskNumber -IsOffline:$false
    }

    Write-Log "Cleaning disk (this will remove ALL partitions)..." "WARN"
    Clear-Disk -Number $DiskNumber -RemoveData -Confirm:$false

    Write-Log "Initializing disk as GPT..."
    Initialize-Disk -Number $DiskNumber -PartitionStyle GPT

    # Create EFI System partition
    Write-Log "Creating EFI System partition (${EfiSizeMB}MB, FAT32)..."
    $efi = New-Partition -DiskNumber $DiskNumber -Size ($EfiSizeMB*1MB) -GptType "{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}"
    Format-Volume -Partition $efi -FileSystem FAT32 -NewFileSystemLabel "SYSTEM" -Confirm:$false -Force

    # Create MSR (unformatted)
    Write-Log "Creating MSR partition (${MsrSizeMB}MB)..."
    $msr = New-Partition -DiskNumber $DiskNumber -Size ($MsrSizeMB*1MB) -GptType "{E3C9E316-0B5C-4DB8-817D-F92DF00215AE}"

    # Compute remaining space and carve recovery at END
    Write-Log "Creating OS placeholder partition (will be repurposed later)..."
    $sup = Get-PartitionSupportedSize -DiskNumber $DiskNumber
    $recoveryBytes = $RecoverySizeMB * 1MB
    $osSize = $sup.SizeMax - $recoveryBytes
    if ($osSize -le 0) { throw "Not enough space to reserve a recovery partition at the end." }

    $osPart = New-Partition -DiskNumber $DiskNumber -Size $osSize -GptType "{EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}"  # Basic data
    Format-Volume -Partition $osPart -FileSystem NTFS -NewFileSystemLabel "Windows" -Confirm:$false -Force

    # Now the end of disk should have ~RecoverySizeMB free; create Recovery at end
    Write-Log "Creating Recovery partition at END (${RecoverySizeMB}MB, NTFS)..."
    $recovery = New-Partition -DiskNumber $DiskNumber -Size $recoveryBytes -GptType "{DE94BBA4-06D1-4D40-A16A-BFD50179D6AC}"
    try {
        Set-Partition -DiskNumber $DiskNumber -PartitionNumber $recovery.PartitionNumber -GptType "{DE94BBA4-06D1-4D40-A16A-BFD50179D6AC}"
        # 0x8000000000000001 => GPT attributes: required + hidden (WinRE)
        Set-Partition -DiskNumber $DiskNumber -PartitionNumber $recovery.PartitionNumber -Attributes 0x8000000000000001 -ErrorAction SilentlyContinue
    } catch {}
    Format-Volume -Partition $recovery -FileSystem NTFS -NewFileSystemLabel "Recovery" -Confirm:$false -Force

    Write-Log "Partitioning complete:"
    Get-Partition -DiskNumber $DiskNumber | Sort-Object Offset | ForEach-Object {
        $sizeGB = "{0:N2}" -f ($_.Size/1GB)
        Write-Host ("  - Part {0}: Type={1} Size={2} GB" -f $_.PartitionNumber, $_.GptType, $sizeGB)
    }

    Write-Log "Done. Log saved to: $script:LogPath"
    Write-Host ""
    Write-Host "Standing by for next steps..." -ForegroundColor Cyan
}

# ----------------------------
# Disk provisioning (DiskPart fallback)
# ----------------------------
function Provision-DiskWithDiskPart {
    param(
        [Parameter(Mandatory=$true)][int]$DiskNumber,
        [int]$EfiSizeMB = 260,
        [int]$MsrSizeMB = 16,
        [int]$RecoverySizeMB = 1024
    )

    Write-Log "Storage module unavailable. Falling back to DiskPart..." "WARN"
    $dp = @()
    $dp += "select disk $DiskNumber"
    $dp += "detail disk"
    $dp += "online disk"
    $dp += "attributes disk clear readonly"
    $dp += "clean"
    $dp += "convert gpt"

    # EFI
    $dp += "create partition efi size=$EfiSizeMB"
    $dp += 'format fs=fat32 quick label="SYSTEM"'

    # MSR
    $dp += "create partition msr size=$MsrSizeMB"

    # OS placeholder (takes the rest for now)
    $dp += 'create partition primary'
    $dp += 'format fs=ntfs quick label="Windows"'

    # Shrink the last partition to leave space at END for Recovery
    $dp += "shrink desired=$RecoverySizeMB minimum=$RecoverySizeMB"

    # Recovery at end (WinRE attributes + label)
    $dp += "create partition primary size=$RecoverySizeMB"
    $dp += "set id=de94bba4-06d1-4d40-a16a-bfd50179d6ac"
    $dp += "gpt attributes=0x8000000000000001"
    $dp += 'format fs=ntfs quick label="Recovery"'

    $dptxt = Join-Path -Path (Get-TempRoot) -ChildPath 'bf_diskpart.txt'
    $dp | Out-File -FilePath $dptxt -Encoding ascii -Force

    Write-Log "Running DiskPart script..."
    try {
        diskpart /s $dptxt | ForEach-Object { Write-Host $_ }
    } catch {
        Write-Log ("DiskPart failed: {0}" -f $_.Exception.Message) "ERROR"
        throw
    }
    Write-Log "DiskPart complete."
    Write-Host ""
    Write-Host "Standing by for next steps..." -ForegroundColor Cyan
}

# ----------------------------
# Main flow
# ----------------------------
try {
    Write-Log "Scanning for suitable local disks..."
    $candidates = Get-WritableDisks
    if (-not $candidates -or $candidates.Count -eq 0) {
        Get-HardwareReport
        Write-Host ""
        Write-Host "No writable internal disks found. Please report the above details to the technical team." -ForegroundColor Red
        Start-Sleep -Seconds 15
        exit 1
    }

    # Choose the largest candidate
    $target = $candidates | Select-Object -First 1
    Write-Host "Found writable disk(s):" -ForegroundColor Green
    foreach ($d in $candidates) {
        $sz = [math]::Round($d.Size/1GB)
        $name = Coalesce $d.FriendlyName 'Unnamed'
        Write-Host ("  - Disk {0}: {1} GB ({2}) Bus={3}" -f $d.Number, $sz, $name, $d.BusType)
    }
    Write-Host ""
    Write-Host ("Selecting Disk {0} ({1} GB) for provisioning..." -f $target.Number, [math]::Round($target.Size/1GB)) -ForegroundColor Yellow

    # Decide path
    if (Get-Command -Name Get-Disk -ErrorAction SilentlyContinue) {
       Provision-DiskWithStorageCmdlets -DiskNumber $target.Number
    } else {
       Provision-DiskWithDiskPart -DiskNumber $target.Number
    }

    Write-Host ""
    Write-Host "Finished baseline layout: SYSTEM (EFI), MSR, OS placeholder, Recovery at end." -ForegroundColor Green
    Write-Host "Log: $script:LogPath" -ForegroundColor DarkGray
    Write-Host "Waiting for the next steps script..." -ForegroundColor Cyan
    Start-Sleep -Seconds 10

} catch {
    Write-Log ("Error: {0}" -f $_.Exception.Message) "ERROR"
    Write-Host "Something went wrong: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "A log was saved to: $script:LogPath" -ForegroundColor DarkGray
    Start-Sleep -Seconds 10
    exit 2
}
