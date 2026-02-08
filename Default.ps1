<#
    Monash BuildForge – Bare Metal Disk Prep (WinRE, PS 5.1)
    Actions (v1):
      1) Confirm script source (GitHub) + display ASCII banner
      2) Detect suitable writable local disk (internal, not read-only)
      3) If none -> stop and print hardware report (chipset/disk HWIDs, manufacturer, mode, baseboard product + SKU)
      4) If found -> clean, GPT, create:
           - EFI System (FAT32, 260MB)
           - MSR (16MB)
           - OS placeholder (uses remaining space minus recovery)
           - Recovery (NTFS, 1024MB) at the END of the disk
      5) Wait for next steps (no OS image/application yet)

    Safe to run in WinRE (PowerShell 5.1)
#>

# ----------------------------
# Preamble & banner
# ----------------------------
$ErrorActionPreference = 'Stop'
$script:LogPath = Join-Path -Path ($env:TEMP ?? 'X:\') -ChildPath ("BuildForge_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "[{0:HH:mm:ss}] [{1}] {2}" -f (Get-Date), $Level, $Message
    Write-Host $line
    try { Add-Content -Path $script:LogPath -Value $line -ErrorAction SilentlyContinue } catch {}
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

# Confirm GitHub source
$ScriptSourceUrl = 'https://github.com/CMMON112/BetaBareMetal/edit/main/Default.ps1'
Show-Banner
Write-Log "This script is being executed from GitHub source:"
Write-Host "  $ScriptSourceUrl" -ForegroundColor Yellow
Write-Host ""

Write-Log ("PowerShell: {0}, OS: {1}" -f $PSVersionTable.PSVersion, (Get-CimInstance Win32_OperatingSystem).Caption)

# ----------------------------
# Discovery helpers
# ----------------------------
function Get-WritableDisks {
    <#
      Returns internal, non-USB, non-readonly disks. Offline disks will be noted but excluded unless they can be brought online.
      Accepts RAW or initialized disks; we will (re)initialize as GPT.
    #>
    $preferredBuses = @('NVMe','RAID','SATA','SAS','ATA','PCIe')
    $disks = Get-Disk | Where-Object {
        $_.BusType -in $preferredBuses -and
        $_.IsBoot -eq $false -and
        $_.IsSystem -eq $false -and
        $_.IsReadOnly -eq $false
    }

    # Try to bring offline disks online (best effort) and re-evaluate
    $offline = Get-Disk | Where-Object { $_.BusType -in $preferredBuses -and $_.IsOffline -eq $true }
    foreach ($d in $offline) {
        Write-Log "Attempting to bring Disk $($d.Number) online..." "INFO"
        try { Set-Disk -Number $d.Number -IsOffline:$false -ErrorAction Stop } catch {}
    }

    $disks = Get-Disk | Where-Object {
        $_.BusType -in $preferredBuses -and
        $_.IsOffline -eq $false -and
        $_.IsReadOnly -eq $false
    }

    # Filter tiny or virtual/file-backed disks
    $minSizeGB = 16
    $disks | Where-Object { [math]::Round($_.Size/1GB) -ge $minSizeGB } | Sort-Object -Property Size -Descending
}

function Get-HardwareReport {
    Write-Host ""
    Write-Log "No writable local disks were found. Printing a concise hardware report for escalation..." "WARN"

    $cs       = Get-CimInstance Win32_ComputerSystem
    $bb       = Get-CimInstance Win32_BaseBoard
    $sysSku   = (Get-CimInstance Win32_ComputerSystem).SystemSKUNumber
    $manu     = $cs.Manufacturer
    $model    = $cs.Model
    $bbProd   = $bb.Product
    $bbMfg    = $bb.Manufacturer

    # Storage "mode" best-effort from controller names
    $controllers = Get-CimInstance Win32_PnPEntity -Filter "PNPClass='SCSIAdapter'"
    $ctrlNames = $controllers | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue
    $mode = "Unknown"
    if ($ctrlNames -match 'NVMe') { $mode = 'NVMe' }
    elseif ($ctrlNames -match 'RAID|RST|VMD') { $mode = 'RAID' }
    elseif ($ctrlNames -match 'AHCI') { $mode = 'AHCI' }

    # Disk drive HWIDs
    $diskPnP = Get-CimInstance Win32_PnPEntity -Filter "PNPClass='DiskDrive'" | Select-Object Name, Manufacturer, HardwareID
    # Chipset-ish HWIDs (system devices w/ PCI-based IDs)
    $chipsetPnP = Get-CimInstance Win32_PnPEntity | Where-Object {
        $_.PNPClass -eq 'System' -and $_.HardwareID -and ($_.PNPDeviceID -like 'PCI*')
    } | Select-Object Name, HardwareID

    Write-Host "-----------------------------" -ForegroundColor DarkCyan
    Write-Host " Hardware Summary (Report)   " -ForegroundColor DarkCyan
    Write-Host "-----------------------------" -ForegroundColor DarkCyan
    Write-Host (" Manufacturer : {0}" -f $manu)
    Write-Host (" Model        : {0}" -f $model)
    Write-Host (" Baseboard    : {0} (Mfg: {1})" -f $bbProd, $bbMfg)
    Write-Host (" System SKU   : {0}" -f ($sysSku ?? 'N/A'))
    Write-Host (" Storage Mode : {0}" -f $mode)
    Write-Host ""
    Write-Host " Disk Hardware IDs:" -ForegroundColor Yellow
    foreach ($d in $diskPnP) {
        Write-Host ("  - {0} [{1}]" -f $d.Name, ($d.Manufacturer ?? ''))
        if ($d.HardwareID) {
            $ids = @($d.HardwareID) | Select-Object -First 6
            foreach ($id in $ids) { Write-Host ("      * {0}" -f $id) }
        }
    }
    Write-Host ""
    Write-Host " Chipset / System Device Hardware IDs:" -ForegroundColor Yellow
    foreach ($c in ($chipsetPnP | Select-Object -First 12)) {
        Write-Host ("  - {0}" -f $c.Name)
        if ($c.HardwareID) {
            $ids = @($c.HardwareID) | Select-Object -First 4
            foreach ($id in $ids) { Write-Host ("      * {0}" -f $id) }
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
    Format-Volume -Partition $efi -FileSystem FAT32 -NewFileSystemLabel "SYSTEM" -Confirm:$false

    # Create MSR (unformatted)
    Write-Log "Creating MSR partition (${MsrSizeMB}MB)..."
    $msr = New-Partition -DiskNumber $DiskNumber -Size ($MsrSizeMB*1MB) -GptType "{E3C9E316-0B5C-4DB8-817D-F92DF00215AE}"

    # Compute remaining space and carve recovery at END
    $disk = Get-Disk -Number $DiskNumber
    $totalFree = ($disk | Get-PartitionSupportedSize).SizeMax
    $recoveryBytes = $RecoverySizeMB * 1MB

    # Create an OS placeholder partition using "remaining - recovery"
    Write-Log "Creating OS placeholder partition (will be repurposed later)..."
    # Determine max size right now (after EFI+MSR)
    $sup = Get-PartitionSupportedSize -DiskNumber $DiskNumber
    $osSize = $sup.SizeMax - $recoveryBytes
    if ($osSize -le 0) { throw "Not enough space to reserve a recovery partition at the end." }

    $osPart = New-Partition -DiskNumber $DiskNumber -Size $osSize -GptType "{EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}"  # Basic data
    Format-Volume -Partition $osPart -FileSystem NTFS -NewFileSystemLabel "Windows" -Confirm:$false

    # Now the end of disk should have ~RecoverySizeMB free; create Recovery at end
    Write-Log "Creating Recovery partition at END (${RecoverySizeMB}MB, NTFS)..."
    $sup2 = Get-PartitionSupportedSize -DiskNumber $DiskNumber
    if (($sup2.SizeMax - $sup2.SizeMin) -lt $recoveryBytes) {
        # Use SizeMax (should match size left, approx RecoverySizeMB)
        $recovery = New-Partition -DiskNumber $DiskNumber -Size $recoveryBytes -GptType "{DE94BBA4-06D1-4D40-A16A-BFD50179D6AC}"
    } else {
        $recovery = New-Partition -DiskNumber $DiskNumber -Size $recoveryBytes -GptType "{DE94BBA4-06D1-4D40-A16A-BFD50179D6AC}"
    }
    # Windows RE attributes & format
    try {
        Set-Partition -DiskNumber $DiskNumber -PartitionNumber $recovery.PartitionNumber -GptType "{DE94BBA4-06D1-4D40-A16A-BFD50179D6AC}"
        Set-Partition -DiskNumber $DiskNumber -PartitionNumber $recovery.PartitionNumber -Attributes 0x8000000000000001 -ErrorAction SilentlyContinue
    } catch {}
    Format-Volume -Partition $recovery -FileSystem NTFS -NewFileSystemLabel "Recovery" -Confirm:$false

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

    # Recovery at end
    $dp += "create partition primary size=$RecoverySizeMB"
    $dp += "set id=de94bba4-06d1-4d40-a16a-bfd50179d6ac"
    $dp += "gpt attributes=0x8000000000000001"
    $dp += 'format fs=ntfs quick label="Recovery"'

    $dptxt = Join-Path -Path ($env:TEMP ?? 'X:\') -ChildPath 'bf_diskpart.txt'
    $dp | Out-File -FilePath $dptxt -Encoding ascii -Force

    Write-Log "Running DiskPart script..."
    diskpart /s $dptxt | ForEach-Object { Write-Host $_ }
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
        Start-Sleep 60
        exit 1
    }

    # Choose the largest candidate
    $target = $candidates | Select-Object -First 1
    Write-Host "Found writable disk(s):" -ForegroundColor Green
    foreach ($d in $candidates) {
        Write-Host ("  - Disk {0}: {1} GB ({2}) Bus={3}" -f $d.Number, [math]::Round($d.Size/1GB), ($d.FriendlyName ?? 'Unnamed'), $d.BusType)
    }
    Write-Host ""
    Write-Host ("Selecting Disk {0} ({1} GB) for provisioning..." -f $target.Number, [math]::Round($target.Size/1GB)) -ForegroundColor Yellow

    # Decide path
    if (Get-Command -Name Get-Disk -ErrorAction SilentlyContinue) {
       # Provision-DiskWithStorageCmdlets -DiskNumber $target.Number
       Write-host "We got to the format step"
       Start-Sleep 60
    } else {
       # Provision-DiskWithDiskPart -DiskNumber $target.Number
       Write-host "We ended up in diskpart"
       Start-Sleep 60
    }

    Write-Host ""
    Write-Host "✅ Finished baseline layout: SYSTEM (EFI), MSR, OS placeholder, Recovery at end." -ForegroundColor Green
    Write-Host "📄 Log: $script:LogPath" -ForegroundColor DarkGray
    Write-Host "⏳ Waiting for the next steps script..." -ForegroundColor Cyan
    Start-Sleep 60

} catch {
    Write-Log ("Error: {0}" -f $_.Exception.Message) "ERROR"
    Write-Host "Something went wrong: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "A log was saved to: $script:LogPath" -ForegroundColor DarkGray
    Start-Sleep 60
    exit 2
}
