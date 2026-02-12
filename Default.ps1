<# Assumtions:
1. Always runs in WinRE
2. WinRE allways has powershell 5.1
3. Always runs with StrictMode Version 2.0
4. Must be able to be re-run without reloading or rebooting into WinRE
5. WinRE has WinPE OCs installed
6. Must never use syntax or features that are not present in Powershell 5.1
7. Must be easy to diagnose from the console window for Jr Techs but with enough information on errors to diagnose via escalation to a more senior tech

#>


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
    [bool]   $ForceRepartition = $true,
    [switch] $ForceRedownload,
    [switch] $ForceApplyImage,
    
    # Step targeting (optional; safe default when called with no args)
    [AllowNull()]
    [AllowEmptyString()]
    [ValidateScript({
        if ([string]::IsNullOrWhiteSpace($_)) { return $true }
        return ($_ -match '^\d+(\.\d+)?$')
    })]
    [string] $FromStep = $null,

    [AllowNull()]
    [AllowEmptyString()]
    [ValidateScript({
        if ([string]::IsNullOrWhiteSpace($_)) { return $true }
        return ($_ -match '^\d+(\.\d+)?$')
    })]
    [string] $OnlyStep = $null
)

# ---------------------------
# StrictMode-safe bootstrapping for ScriptBlock/IEX execution
# - Under ScriptBlock/Invoke-Expression, script params may not bind -> vars may not exist.
# - StrictMode 2.0 throws on uninitialized variables, so predeclare everything we might read.
# ---------------------------
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# =====================================================================
# BuildForge StrictMode + ScriptBlock SAFE VARIABLE BOOTSTRAP
# =====================================================================
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
function Ensure-LocalVar {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter()][AllowNull()]$DefaultValue = $null
    )

    # Scope 1 = the caller's scope (this is what you intended)
    $v = Get-Variable -Name $Name -Scope 1 -ErrorAction SilentlyContinue

    # Not present in caller
    if (-not $v) {
        Set-Variable -Name $Name -Scope 1 -Value $DefaultValue -Force
        return
    }

    # Present but empty string in caller
    if ($v.Value -is [string] -and [string]::IsNullOrWhiteSpace($v.Value)) {
        Set-Variable -Name $Name -Scope 1 -Value $DefaultValue -Force
    }
}

function Ensure-ScriptVar {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter()][AllowNull()]$DefaultValue = $null
    )
    if (-not (Get-Variable -Name $Name -Scope Script -ErrorAction SilentlyContinue)) {
        Set-Variable -Name $Name -Scope Script -Value $DefaultValue -Force
    }
}

# ---------------------------------------------------------------------
# Execution / control flags
# ---------------------------------------------------------------------
Ensure-LocalVar -Name 'Resume'           -DefaultValue $false
Ensure-LocalVar -Name 'FromStep'         -DefaultValue $null
Ensure-LocalVar -Name 'OnlyStep'         -DefaultValue $null

Ensure-LocalVar -Name 'ForceRepartition' -DefaultValue $true
Ensure-LocalVar -Name 'ForceRedownload'  -DefaultValue $false
Ensure-LocalVar -Name 'ForceApplyImage'  -DefaultValue $false
Ensure-LocalVar -Name 'TargetDiskNumber' -DefaultValue -1

# ---------------------------------------------------------------------
# OS identity (Windows 11 24H2+ ONLY)
# ---------------------------------------------------------------------
Ensure-LocalVar -Name 'OperatingSystem' -DefaultValue 'Windows 11'
Ensure-LocalVar -Name 'ReleaseId'       -DefaultValue '25H2'
Ensure-LocalVar -Name 'Architecture'    -DefaultValue 'amd64'
Ensure-LocalVar -Name 'LanguageCode'    -DefaultValue 'en-us'
Ensure-LocalVar -Name 'License'         -DefaultValue 'Volume'
Ensure-LocalVar -Name 'SKU'             -DefaultValue 'Enterprise'

# ---------------------------------------------------------------------
# Catalog URLs (always non-empty)
# ---------------------------------------------------------------------
Ensure-LocalVar -Name 'OSCatalogUrl'  -DefaultValue 'https://raw.githubusercontent.com/CMMON112/BetaBareMetal/refs/heads/main/build-oscatalog.xml'

Ensure-LocalVar -Name 'DriverCatalogUrl' -DefaultValue 'https://raw.githubusercontent.com/CMMON112/BetaBareMetal/refs/heads/main/build-driverpackcatalog.xml'

# HP REAL driver pack catalog (OSDCloud / OSD uses this)
Ensure-LocalVar -Name 'HpDriverPackCatalogCabUrl' -DefaultValue 'https://ftp.hp.com/pub/caps-softpaq/cmit/HPClientDriverPackCatalog.cab'

# ---------------------------------------------------------------------
# Script-scope state (used by banners, logging, steps)
# ---------------------------------------------------------------------
Ensure-ScriptVar -Name 'BuildForgeRoot' -DefaultValue $null
Ensure-ScriptVar -Name 'LogRoot'        -DefaultValue 'X:\Windows\Temp\BuildForge'
Ensure-ScriptVar -Name 'LogFile'        -DefaultValue (Join-Path 'X:\Windows\Temp\BuildForge' 'BuildForge.log')

Ensure-ScriptVar -Name 'CurrentStepNumber' -DefaultValue ''
Ensure-ScriptVar -Name 'CurrentStepName'   -DefaultValue ''

# ---------------------------------------------------------------------
# Hardware identity (populated later)
# ---------------------------------------------------------------------
Ensure-ScriptVar -Name 'Hardware' -DefaultValue $null

# ---------------------------------------------------------------------
# Driver selection & processing state
# ---------------------------------------------------------------------
Ensure-ScriptVar -Name 'DriverMatch'        -DefaultValue $null
Ensure-ScriptVar -Name 'DriverExtractDir'   -DefaultValue $null
Ensure-ScriptVar -Name 'TargetDisk'          -DefaultValue $null

# ---------------------------------------------------------------------
# WinRE / imaging state
# ---------------------------------------------------------------------
Ensure-ScriptVar -Name 'WinreWimPath' `
    -DefaultValue 'R:\Recovery\WindowsRE\Winre.wim'

Ensure-ScriptVar -Name 'MountedWindowsPath' -DefaultValue 'W:\'

# =====================================================================
# END BOOTSTRAP
# =====================================================================


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

function Get-IsVerbose {
    return ($env:BUILD_FORGE_VERBOSE -and $env:BUILD_FORGE_VERBOSE.Trim() -eq '1')
}

function Format-Message {
    param([AllowEmptyString()][string]$Message)
    if ([string]::IsNullOrWhiteSpace($Message)) { return $Message }

    $m = $Message
    # Display-only: remove arrow shorthand
    $m = $m -replace '\s*-\>\s*', ' to '
    $m = $m -replace '\s*=\>\s*', ' to '
    # Collapse whitespace
    $m = $m -replace '\s{2,}', ' '
    return $m.Trim()
}

function Write-LogFileOnly {
    param(
        [AllowEmptyString()][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','OK','STEP')][string]$Level = 'INFO'
    )
    if ([string]::IsNullOrWhiteSpace($Message)) { return }
    Initialize-Logging

    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $stepTag = if ($script:CurrentStepNumber) { " STEP $($script:CurrentStepNumber)" } else { "" }
    $line = "$ts [$Level]$stepTag $Message"
    [System.IO.File]::AppendAllText($script:LogFile, $line + "`r`n")
}

function Write-Log {
    param(
        [AllowEmptyString()][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','OK','STEP')][string]$Level = 'INFO'
    )

    if ([string]::IsNullOrWhiteSpace($Message)) { return }
    Initialize-Logging

    $msg = Format-Message $Message

    # Always log full message to file with timestamp
    Write-LogFileOnly -Message $msg -Level $Level

    # Console prefixes (fixed width, aligned)
    $prefix = switch ($Level) {
        'OK'    { ' OK  ' }
        'WARN'  { 'WARN ' }
        'ERROR' { 'ERR  ' }
        'STEP'  { '     ' }  # banners print without prefix
        default { 'INFO ' }
    }

    $color = switch ($Level) {
        'OK'    { 'Green' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        'STEP'  { 'Cyan' }
        default { 'Gray' }
    }

    if ($Level -eq 'STEP') {
        # No prefix for banner lines
        Write-Host $msg -ForegroundColor $color
    } else {
        Write-Host ("{0}{1}" -f $prefix, $msg) -ForegroundColor $color
    }
}

function Write-Detail {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR','OK')][string]$Level='INFO')

    # Always to file. Only to console if verbose.
    Write-LogFileOnly -Message (Format-Message $Message) -Level $Level
    if (Get-IsVerbose) {
        Write-Log -Message $Message -Level $Level
    }
}

function Write-StepBanner {
    param(
        [Parameter(Mandatory)][string]$Number,
        [Parameter(Mandatory)][string]$Name
    )

    $script:CurrentStepNumber = $Number
    $script:CurrentStepName   = $Name

    # Strong visual boundary + blank line
    Write-Host ""
    Write-Log "────────────────────────────────────────────────────────" 'STEP'
    Write-Log ("STEP {0}: {1}" -f $Number, $Name) 'STEP'
    Write-Log "────────────────────────────────────────────────────────" 'STEP'

    # Multiline status (short lines to avoid wrapping)
    $root = if ($script:BuildForgeRoot) { $script:BuildForgeRoot } else { "(not set yet)" }

    $diskLine = "Disk   : (not selected yet)"
    if ($script:TargetDisk) {
        $d = $script:TargetDisk
        $diskLine = ("Disk   : #{0} {1} {2}GB" -f $d.Number, $d.BusType, ([math]::Round($d.Size/1GB, 1)))
    }

    Write-Host ("  OS     : Windows 11 {0} {1} ({2}, {3})" -f $ReleaseId, $Architecture, $SKU, $License) -ForegroundColor Gray
    Write-Host ("  Root   : {0}" -f $root) -ForegroundColor Gray
    Write-Host ("  Flags  : Repartition={0}  Redownload={1}  Reapply={2}  Resume={3}  Steps={4}" -f `
        ($(if($ForceRepartition){'Yes'}else{'No'})),
        ($(if([bool]$ForceRedownload){'Yes'}else{'No'})),
        ($(if([bool]$ForceApplyImage){'Yes'}else{'No'})),
        ($(if([bool]$Resume){'Yes'}else{'No'})),
        (Get-StepSelectionLabel)
) -ForegroundColor Gray
    Write-Host ("  {0}" -f $diskLine) -ForegroundColor Gray
    Write-Host ""

    # File log gets the same banner details
    Write-LogFileOnly -Message ("STEP {0}: {1}" -f $Number, $Name) -Level 'STEP'
    Write-LogFileOnly -Message ("OS=Windows 11 {0} {1} ({2}, {3})" -f $ReleaseId, $Architecture, $SKU, $License) -Level 'INFO'
    Write-LogFileOnly -Message ("Root={0}" -f $root) -Level 'INFO'
    Write-LogFileOnly -Message ("Flags: Repartition={0} Redownload={1} Reapply={2}" -f $ForceRepartition, [bool]$ForceRedownload, [bool]$ForceApplyImage) -Level 'INFO'
    Write-LogFileOnly -Message $diskLine -Level 'INFO'
    Write-LogFileOnly -Message ("StepSelection={0}" -f (Get-StepSelectionLabel)) -Level 'INFO'
}

function Convert-StepIdToNumber {
    param([Parameter(Mandatory)][string]$StepId)

    # Decimal parse supports "9.5" etc. (Invariant culture avoids locale commas)
    try {
        return [decimal]::Parse($StepId, [System.Globalization.CultureInfo]::InvariantCulture)
    } catch {
        return $null
    }
}

function Should-RunStep {
    param([Parameter(Mandatory)][string]$Number)

    # OnlyStep overrides everything
    if (-not [string]::IsNullOrWhiteSpace($OnlyStep)) {
        return ($Number -eq $OnlyStep)
    }

    if (-not [string]::IsNullOrWhiteSpace($FromStep)) {
        $n = Convert-StepIdToNumber -StepId $Number
        $f = Convert-StepIdToNumber -StepId $FromStep

        # If either fails to parse, be conservative: run the step
        if ($n -ne $null -and $f -ne $null) {
            if ($n -lt $f) { return $false }
        }
    }

    return $true
}

function Get-StepSelectionLabel {
    if (-not [string]::IsNullOrWhiteSpace($OnlyStep)) { return ("OnlyStep={0}" -f $OnlyStep) }
    if (-not [string]::IsNullOrWhiteSpace($FromStep)) { return ("FromStep={0}" -f $FromStep) }
    return "AllSteps"
}

function Invoke-Step {
    param(
        [Parameter(Mandatory)][string]$Number,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )

    
Write-StepBanner -Number $Number -Name $Name

    # NEW: FromStep / OnlyStep logic
    if (-not (Should-RunStep -Number $Number)) {
        Write-Log ("Skipped (step selection): Step {0} not in requested range." -f $Number) 'OK'
        return
    }


    try {
        & $Action
        Write-Log "RESULT: Step completed successfully" 'OK'
    } catch {
        Write-Log ("RESULT: Step failed - {0}" -f $_.Exception.Message) 'ERROR'
        if ($_.ScriptStackTrace) {
            # Avoid console spam; stack trace always to file, console only if verbose
            Write-LogFileOnly -Message $_.ScriptStackTrace -Level 'ERROR'
            if (Get-IsVerbose) {
                Write-Log "Stack trace (also written to log file):" 'WARN'
                Write-Log $_.ScriptStackTrace 'ERROR'
            } else {
                Write-Log ("Stack trace written to log file: {0}" -f $script:LogFile) 'WARN'
            }
        }
        throw
    }
}

function Finalize-LogPersistence {
    [CmdletBinding()]
    param()

    $sourceLog = $script:LogFile
    if (-not (Test-Path -LiteralPath $sourceLog)) {
        return
    }

    $destRoot = 'W:\Windows\Temp\BuildForge'
    $destLog  = Join-Path $destRoot 'BuildForge.log'

    try {
        if (-not (Test-Path -LiteralPath 'W:\Windows')) {
            Write-Log "Windows volume not present. Log will remain in WinRE only." 'WARN'
            return
        }

        if (-not (Test-Path -LiteralPath $destRoot)) {
            New-Item -ItemType Directory -Path $destRoot -Force | Out-Null
        }

        if (Test-Path -LiteralPath $destLog) {
            # Append to existing log to avoid losing earlier runs
            Add-Content -LiteralPath $destLog -Value (
                "`r`n----- Appended log from WinRE session at $(Get-Date) -----`r`n"
            )
            Get-Content -LiteralPath $sourceLog | Add-Content -LiteralPath $destLog
            Write-Log "Log appended to existing Windows log location." 'OK'
        }
        else {
            Copy-Item -LiteralPath $sourceLog -Destination $destLog -Force
            Write-Log "Log copied to Windows volume for persistence." 'OK'
        }

        Write-Detail ("Persistent log path: {0}" -f $destLog) 'INFO'
    }
    catch {
        Write-Log ("Failed to persist log to Windows volume: {0}" -f $_.Exception.Message) 'WARN'
    }
}

# ---------------------------
# BuildForge root management (moves as W: becomes available)
# ---------------------------
function Get-BuildForgeRoot {
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

    $items = Get-ChildItem -LiteralPath $Source -Force -ErrorAction SilentlyContinue
    foreach ($i in $items) {
        if ($i.FullName -ieq $script:LogFile) { continue }
        if ($i.Name -ieq 'BuildForge.log')     { continue }
        $dest = Join-Path $Destination $i.Name
        try {
            Move-Item -LiteralPath $i.FullName -Destination $dest -Force -ErrorAction Stop
        } catch {
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
        Write-Log ("Working root directory moved to {0}" -f $newRoot) 'INFO'
        Write-Detail ("Previous root was {0}" -f $script:BuildForgeRoot) 'INFO'
        Move-BuildForgeContents -Source $script:BuildForgeRoot -Destination $newRoot
        $script:BuildForgeRoot = $newRoot
        Ensure-Dir $script:BuildForgeRoot
    }
}
function Invoke-FilesystemPreflight {
    [CmdletBinding()]
    param(
        [switch] $RequireWindowsPartition,
        [switch] $RequireEfiPartition,
        [switch] $RequireRecoveryPartition
    )

    Write-Log "Pre-flight check: validating filesystem and workspace layout." 'INFO'

    # Always re-evaluate root after any disk operations or reruns
    Update-BuildForgeRoot

    # ---- Drive presence checks ----
    function Test-Drive([string]$Drive, [string]$Purpose, [switch]$Required) {
        $path = "$Drive\"
        if (Test-Path -LiteralPath $path) {
            Write-Log ("Drive present: {0} ({1})" -f $Drive, $Purpose) 'OK'
            return $true
        }

        if ($Required) {
            throw "Required drive is missing: $Drive ($Purpose). Cannot continue."
        } else {
            Write-Log ("Drive missing: {0} ({1})" -f $Drive, $Purpose) 'WARN'
            return $false
        }
    }

    $haveW = Test-Drive -Drive 'W:' -Purpose 'Windows (offline OS target)' -Required:$RequireWindowsPartition
    $haveS = Test-Drive -Drive 'S:' -Purpose 'EFI System Partition'         -Required:$RequireEfiPartition
    $haveR = Test-Drive -Drive 'R:' -Purpose 'Recovery Partition'           -Required:$RequireRecoveryPartition

    # ---- BuildForge root checks ----
    if (-not $script:BuildForgeRoot) {
        throw "BuildForgeRoot is not set. Update-BuildForgeRoot did not resolve a workspace root."
    }

    Ensure-Dir $script:BuildForgeRoot
    Write-Log ("Workspace root ready: {0}" -f $script:BuildForgeRoot) 'OK'

    # Required subfolders for deterministic reruns
    $dirs = @(
        (Join-Path $script:BuildForgeRoot 'Catalogs'),
        (Join-Path $script:BuildForgeRoot 'OS'),
        (Join-Path $script:BuildForgeRoot 'Drivers'),
        (Join-Path $script:BuildForgeRoot 'ExtractedDrivers')
    )

    foreach ($d in $dirs) {
        Ensure-Dir $d
        Write-Log ("Directory ready: {0}" -f $d) 'OK'
    }

    # ---- Writability checks (tiny file, then remove) ----
    function Assert-Writable([string]$Folder) {
        $testFile = Join-Path $Folder ("__write_test_{0}.tmp" -f ([Guid]::NewGuid().ToString('N')))
        try {
            "test" | Set-Content -LiteralPath $testFile -Encoding ASCII -Force
            Remove-Item -LiteralPath $testFile -Force
            Write-Log ("Writable: {0}" -f $Folder) 'OK'
        } catch {
            throw "Folder is not writable: $Folder. Error: $($_.Exception.Message)"
        }
    }

    # Always test root; test OS/Catalogs as those are most sensitive to rerun failures
    Assert-Writable -Folder $script:BuildForgeRoot
    Assert-Writable -Folder (Join-Path $script:BuildForgeRoot 'Catalogs')
    Assert-Writable -Folder (Join-Path $script:BuildForgeRoot 'OS')

    # If W: is expected, verify it is writable too (catches partial mount issues)
    if ($RequireWindowsPartition -and $haveW) {
        Assert-Writable -Folder 'W:\'
    }

    Write-Log "Pre-flight check passed." 'OK'
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

    $argLine = ($Arguments -join ' ')
    Write-Log ("Running command: {0}" -f ([IO.Path]::GetFileName($FilePath))) 'INFO'
    Write-Detail ("Full command: {0} {1}" -f $FilePath, $argLine) 'INFO'

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $FilePath
    $psi.Arguments              = $argLine
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true
    
        try {
    if (Test-Path -LiteralPath $env:WINDIR) {
        $psi.WorkingDirectory = $env:WINDIR
    } else {
        $psi.WorkingDirectory = 'X:\'
    }
} catch {
    $psi.WorkingDirectory = 'X:\'
}

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    [void]$p.Start()

    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()

    # Always write raw output to file for support
    if ($stdout) {
        ($stdout -split "`r?`n") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { Write-LogFileOnly -Message $_ -Level 'INFO' }
    }
    if ($stderr) {
        ($stderr -split "`r?`n") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { Write-LogFileOnly -Message $_ -Level 'WARN' }
    }

    # Console: show stderr lines, stdout only if verbose
    if ($stderr) {
        ($stderr -split "`r?`n") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { Write-Log $_ 'WARN' }
    }
    if ((Get-IsVerbose) -and $stdout) {
        ($stdout -split "`r?`n") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { Write-Log $_ 'INFO' }
    }

    if (-not $IgnoreExitCode -and $p.ExitCode -ne 0) {
        throw "Command failed (exit $($p.ExitCode)): $FilePath $argLine"
    }

    [pscustomobject]@{ ExitCode=$p.ExitCode; StdOut=$stdout; StdErr=$stderr }
}

function Invoke-Download {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$DestPath
    )

    # CRITICAL: re-evaluate BuildForgeRoot after disk operations
    Update-BuildForgeRoot

    # Ensure full destination directory exists (WinRE-safe)
    $parent = Split-Path -Parent $DestPath
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $leaf = [IO.Path]::GetFileName($DestPath)

    if ((Test-Path -LiteralPath $DestPath) -and -not $ForceRedownload) {
        Write-Log ("Download skipped (already present): {0}" -f $leaf) 'OK'
        Write-Detail ("Path: {0}" -f $DestPath) 'INFO'
        return $DestPath
    }

    $curl = Resolve-CurlPath
    Write-Log ("Downloading: {0}" -f $leaf) 'INFO'
    Write-Detail ("URL: {0}" -f $Url) 'INFO'
    Write-Detail ("Destination: {0}" -f $DestPath) 'INFO'

    & $curl --fail --location --silent --show-error `
            --retry 2 --retry-delay 3 `
            --connect-timeout 30 `
            --output $DestPath $Url

    if ($LASTEXITCODE -ne 0) {
        throw "curl failed ($LASTEXITCODE) for $Url"
    }

    # WinRE defensive verification
    if (-not (Test-Path -LiteralPath $DestPath)) {
        throw "Download reported success but file missing: $DestPath"
    }

    Write-Log ("Downloaded: {0}" -f $leaf) 'OK'
    return $DestPath
}

function Confirm-FileHash {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string]$ExpectedSha1,
        [string]$ExpectedSha256
    )

    $leaf = [IO.Path]::GetFileName($FilePath)

    if ($ExpectedSha1) {
        $a = (Get-FileHash -Algorithm SHA1 -Path $FilePath).Hash.ToLowerInvariant()
        $e = $ExpectedSha1.ToLowerInvariant().Trim()
        if ($a -ne $e) { throw "SHA1 mismatch. Expected=$e Got=$a" }
        Write-Log ("Integrity OK: {0} (SHA1)" -f $leaf) 'OK'
    }
    if ($ExpectedSha256) {
        $a = (Get-FileHash -Algorithm SHA256 -Path $FilePath).Hash.ToLowerInvariant()
        $e = $ExpectedSha256.ToLowerInvariant().Trim()
        if ($a -ne $e) { throw "SHA256 mismatch. Expected=$e Got=$a" }
        Write-Log ("Integrity OK: {0} (SHA256)" -f $leaf) 'OK'
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

    $leaf  = Get-LeafNameFromUrl -Url $CatalogUrl -Fallback 'catalog.clixml'
    $local = Join-Path $catalogDir $leaf

    Invoke-Download -Url $CatalogUrl -DestPath $local | Out-Null
    Write-Log ("Catalog ready: {0}" -f $leaf) 'OK'
    Write-Detail ("Catalog path: {0}" -f $local) 'INFO'

    return Import-Clixml -Path $local
}

function Resolve-OsCatalogEntry {
    param([Parameter(Mandatory)]$Catalog)

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

function Get-HPClientDriverPackCatalogXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CabUrl,
        [Parameter(Mandatory)][string]$WorkingDir
    )

    Update-BuildForgeRoot
    Ensure-Dir $WorkingDir

    $cabPath = Join-Path $WorkingDir "HPClientDriverPackCatalog.cab"
    $xmlPath = Join-Path $WorkingDir "HPClientDriverPackCatalog.xml"

    Invoke-Download -Url $CabUrl -DestPath $cabPath | Out-Null

    # Expand CAB to XML. OSD does: Expand "cab" "xml" [1](https://www.powershellgallery.com/packages/OSD/21.4.8.1/Content/Public%5CCatalog%5CGet-CatalogHPDriverPack.ps1)
    $expandExe = Join-Path $env:WINDIR "System32\expand.exe"
    if (-not (Test-Path -LiteralPath $expandExe)) { $expandExe = "expand.exe" }

    # Expand supports: expand <cab> <dest>
    Invoke-Native -FilePath $expandExe -Arguments @($cabPath, $xmlPath) | Out-Null

    if (-not (Test-Path -LiteralPath $xmlPath)) {
        throw "Failed to expand HP catalog CAB to XML. Expected: $xmlPath"
    }

    Write-Log "HP DriverPack catalog expanded successfully." 'OK'
    return $xmlPath
}

function Import-HPClientDriverPackCatalog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$XmlPath
    )

    if (-not (Test-Path -LiteralPath $XmlPath)) {
        throw "HP catalog XML not found: $XmlPath"
    }

    [xml]$x = Get-Content -LiteralPath $XmlPath -Raw

    # These nodes are the canonical dataset paths used by OSD/OSDCloud [1](https://www.powershellgallery.com/packages/OSD/21.4.8.1/Content/Public%5CCatalog%5CGet-CatalogHPDriverPack.ps1)
    $softPaqs = @($x.NewDataSet.HPClientDriverPackCatalog.SoftPaqList.SoftPaq)
    $mapRows  = @($x.NewDataSet.HPClientDriverPackCatalog.ProductOSDriverPackList.ProductOSDriverPack)

    if (-not $softPaqs -or $softPaqs.Count -eq 0) {
        throw "HP catalog parse failure: SoftPaqList is empty."
    }
    if (-not $mapRows -or $mapRows.Count -eq 0) {
        throw "HP catalog parse failure: ProductOSDriverPackList is empty."
    }

    # Build SoftPaq hashtable by Id (lower invariant key)
    $softPaqById = @{}
    foreach ($sp in $softPaqs) {
        $id = [string]$sp.Id
        if ([string]::IsNullOrWhiteSpace($id)) { continue }

        $key = $id.Trim().ToLowerInvariant()

        # Parse DateReleased safely (PS 5.1)
        $dateReleased = $null
        if ($sp.DateReleased) {
            try { $dateReleased = [datetime]$sp.DateReleased } catch { $dateReleased = $null }
        }

        $softPaqById[$key] = [pscustomobject]@{
            Id           = $id.Trim()
            Name         = [string]$sp.Name
            Version      = [string]$sp.Version
            Category     = [string]$sp.Category
            DateReleased = $dateReleased
            Url          = [string]$sp.Url
            Sha256       = [string]$sp.SHA256
            Size         = [string]$sp.Size
            CvaFileUrl   = [string]$sp.CvaFileUrl
        }
    }

    # Normalize and project ProductOSDriverPack rows
    $driverPackMap = New-Object System.Collections.Generic.List[object]
    foreach ($m in $mapRows) {
        $sysId = [string]$m.SystemId
        if (-not [string]::IsNullOrWhiteSpace($sysId)) { $sysId = $sysId.Trim() }

        $driverPackMap.Add([pscustomobject]@{
            Architecture = [string]$m.Architecture
            ProductType  = [string]$m.ProductType
            SystemId     = $sysId
            SystemName   = [string]$m.SystemName
            OSName       = [string]$m.OSName
            OSId         = [string]$m.OSId
            SoftPaqId    = [string]$m.SoftPaqId
            ProductId    = [string]$m.ProductId
        }) | Out-Null
    }

    $result = [pscustomobject]@{
        SoftPaqById   = $softPaqById
        DriverPackMap = $driverPackMap
    }

    Write-Log ("HP catalog parsed: SoftPaqs={0}  DriverPackMap={1}" -f $softPaqById.Count, $driverPackMap.Count) 'OK'
    return $result
}


function Find-HPDriverPackBestMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Hardware,

        [Parameter(Mandatory)]
        [object]$HpCatalog,   # output of Import-HPClientDriverPackCatalog

        [Parameter(Mandatory)]
        [string]$ReleaseId
    )

    function IsNullOrWhite([string]$s) { return [string]::IsNullOrWhiteSpace($s) }

    # Only HP systems
    $mfg = [string]$Hardware.CSManufacturer
    if ($mfg -notmatch '(?i)HP|Hewlett') {
        return [pscustomobject]@{ Matched=$false; Reason='Not an HP system'; Candidates=@() }
    }

    $bbProduct = [string]$Hardware.BBProduct
    if (IsNullOrWhite $bbProduct) {
        return [pscustomobject]@{ Matched=$false; Reason='BBProduct is empty (cannot match SystemId)'; Candidates=@() }
    }
    $bbProductU = $bbProduct.Trim().ToUpperInvariant()

    # Preference order: requested ReleaseId first, then best-effort fallbacks
    $pref = New-Object System.Collections.Generic.List[string]
    $pref.Add($ReleaseId.ToUpperInvariant()) | Out-Null
    foreach ($x in @('26H2','25H2','24H2','23H2','22H2','21H2')) {
        if ($pref -notcontains $x) { $pref.Add($x) | Out-Null }
    }

    function GetWin11Rank([string]$osName) {
        if (IsNullOrWhite $osName) { return 0 }
        $u = $osName.ToUpperInvariant()

        if ($u -notmatch 'WINDOWS 11') { return 0 }
        if ($u -match 'WINDOWS 10')    { return 0 }

        $base = 100
        if ($u -match '64-BIT') { $base += 10 }

        for ($i = 0; $i -lt $pref.Count; $i++) {
            $token = $pref[$i]
            if ($u -match [regex]::Escape($token)) {
                return $base + (1000 - ($i * 50))
            }
        }

        # Win11 but no known token
        return $base + 100
    }

    # Filter to exact SystemId match + Win11 OSName
    $candidates = @()
    foreach ($row in $HpCatalog.DriverPackMap) {

        if (IsNullOrWhite $row.SystemId) { continue }
        if ($row.SystemId.Trim().ToUpperInvariant() -ne $bbProductU) { continue }

        $rank = GetWin11Rank $row.OSName
        if ($rank -le 0) { continue }

        $spid = [string]$row.SoftPaqId
        if (IsNullOrWhite $spid) { continue }

        $key = $spid.Trim().ToLowerInvariant()
        if (-not $HpCatalog.SoftPaqById.ContainsKey($key)) { continue }

        $sp = $HpCatalog.SoftPaqById[$key]

        # Require URL + SHA256 for your download/verify pipeline
        if (IsNullOrWhite $sp.Url)    { continue }
        if (IsNullOrWhite $sp.Sha256) { continue }

        $dt = $sp.DateReleased
        if (-not $dt) { $dt = [datetime]::MinValue }

        $candidates += [pscustomobject]@{
            Rank        = $rank
            Date        = $dt
            OSName      = $row.OSName
            SystemId    = $bbProductU
            SoftPaqId   = $sp.Id
            Url         = $sp.Url
            Sha256      = $sp.Sha256
            Name        = $sp.Name
            Version     = $sp.Version
            DateReleased= $sp.DateReleased
        }
    }

    if ($candidates.Count -eq 0) {
        return [pscustomobject]@{
            Matched=$false
            Reason=("No Windows 11 driver packs for SystemId '{0}'" -f $bbProductU)
            Candidates=@()
        }
    }

    # Pick best: highest Rank then newest DateReleased
    $best = $candidates | Sort-Object Rank, Date -Descending | Select-Object -First 1

    return [pscustomobject]@{
        Matched      = $true
        SystemId     = $best.SystemId
        OSName       = $best.OSName
        SoftPaqId    = $best.SoftPaqId
        Url          = $best.Url
        Sha256       = $best.Sha256
        Name         = $best.Name
        Version      = $best.Version
        DateReleased = $best.DateReleased
        Rank         = $best.Rank
    }
}

function Inject-DriversOfflineWindows {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WindowsPath,   # e.g. W:\

        [Parameter(Mandatory)]
        [string]$DriverRoot     # extracted INF folder
    )

    if (-not (Test-Path -LiteralPath $WindowsPath)) {
        throw "WindowsPath does not exist: $WindowsPath"
    }

    if (-not (Test-Path -LiteralPath $DriverRoot)) {
        throw "DriverRoot does not exist: $DriverRoot"
    }

    $infCount = (
        Get-ChildItem -LiteralPath $DriverRoot -Recurse -Filter *.inf -ErrorAction SilentlyContinue |
        Measure-Object
    ).Count

    if ($infCount -eq 0) {
        throw "No INF files found under '$DriverRoot'."
    }

    Ensure-DismModule
    Write-Log ("Injecting drivers to offline Windows: {0} INF(s)" -f $infCount) 'INFO'

    Add-WindowsDriver `
        -Path $WindowsPath `
        -Driver $DriverRoot `
        -Recurse `
        -ErrorAction Stop | Out-Null

    Write-Log "Offline Windows driver injection complete." 'OK'
}

function Get-InfClass {
    param([Parameter(Mandatory)][string]$InfPath)
    try {
        $lines = Get-Content -LiteralPath $InfPath -ErrorAction Stop | Select-Object -First 200
        foreach ($l in $lines) {
            if ($l -match '^\s*Class\s*=\s*(.+?)\s*$') {
                return $Matches[1].Trim()
            }
        }
    } catch {}
    return $null
}

function Stage-DriversByClass {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DriverRoot,
        [Parameter(Mandatory)][string]$StageRoot,
        [Parameter(Mandatory)][string[]]$IncludeClasses
    )

    Ensure-Dir $StageRoot
    $infs = Get-ChildItem -LiteralPath $DriverRoot -Recurse -Filter *.inf -ErrorAction SilentlyContinue
    if (-not $infs) { throw "No INF files found under '$DriverRoot'." }

    $wanted = New-Object System.Collections.Generic.List[string]
    foreach ($inf in $infs) {
        $cls = Get-InfClass -InfPath $inf.FullName
        if ($cls -and ($IncludeClasses -contains $cls)) {
            $wanted.Add($inf.FullName) | Out-Null
        }
    }

    if ($wanted.Count -eq 0) {
        Write-Log ("No INFs matched classes: {0}" -f ($IncludeClasses -join ',')) 'WARN'
        return $null
    }

    # Copy entire directories that contain matching INFs (keeps referenced binaries alongside)
    $dirs = $wanted | ForEach-Object { Split-Path -Parent $_ } | Select-Object -Unique
    foreach ($d in $dirs) {
        $leaf = [IO.Path]::GetFileName($d)
        $dest = Join-Path $StageRoot $leaf
        Copy-Item -LiteralPath $d -Destination $dest -Recurse -Force
    }

    Write-Log ("Staged WinRE-class drivers. INF matches: {0}" -f $wanted.Count) 'OK'
    return $StageRoot
}

function Inject-DriversIntoWinREWim {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WinreWimPath,
        [Parameter(Mandatory)][string]$DriverRoot
    )

    if (-not (Test-Path -LiteralPath $WinreWimPath)) { throw "WinRE WIM not found: $WinreWimPath" }

    Ensure-DismModule

    $mountDir = Join-Path $script:BuildForgeRoot ("MountWinRE_{0}" -f ([Guid]::NewGuid().ToString('N')))
    Ensure-Dir $mountDir

    try {
        Write-Log ("Mounting WinRE WIM: {0}" -f $WinreWimPath) 'INFO'
        Mount-WindowsImage -ImagePath $WinreWimPath -Index 1 -Path $mountDir -ErrorAction Stop | Out-Null

        Write-Log "Injecting drivers into WinRE image..." 'INFO'
        Add-WindowsDriver -Path $mountDir -Driver $DriverRoot -Recurse -ErrorAction Stop | Out-Null

        Write-Log "Committing WinRE changes..." 'INFO'
        Dismount-WindowsImage -Path $mountDir -Save -ErrorAction Stop | Out-Null

        Write-Log "WinRE driver injection complete." 'OK'
    }
    catch {
        # attempt discard if mounted
        try { Dismount-WindowsImage -Path $mountDir -Discard -ErrorAction SilentlyContinue | Out-Null } catch {}
        throw
    }
    finally {
        Remove-Item -LiteralPath $mountDir -Recurse -Force -ErrorAction SilentlyContinue
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
        [pscustomobject]@{
            Number=$_.Number; Size=$_.Size; BusScore=$bus;
            IsBoot=$_.IsBoot; IsSystem=$_.IsSystem; BusType=$_.BusType
        }
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

    $dpLines = @(
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
    )

    if (-not $PSCmdlet.ShouldProcess("Disk $DiskNumber", "Wipe and apply UEFI/GPT layout (S:,W:,R:)")) {
        return
    }

    # Always write script to a stable location on X: in WinRE
    Initialize-Logging
    $dpFile = Join-Path $script:LogRoot ("diskpart_{0}.txt" -f ([Guid]::NewGuid().ToString('N')))
    Set-Content -LiteralPath $dpFile -Value ($dpLines -join "`r`n") -Encoding ASCII -Force

    # Resolve diskpart path reliably
    $diskpart = Join-Path $env:WINDIR 'System32\diskpart.exe'
    if (-not (Test-Path -LiteralPath $diskpart)) { $diskpart = 'diskpart.exe' }

    # Ensure current location is valid BEFORE starting an external process
    try { Set-Location -LiteralPath $env:WINDIR } catch { Set-Location -LiteralPath 'X:\' }

    Write-Log ("Running disk partitioning script: {0}" -f $dpFile) 'INFO'

    # Run diskpart with a script file (more reliable than piping)
    $null = Invoke-Native -FilePath $diskpart -Arguments @("/s", $dpFile)

    # Cleanup the script file (optional)
    Remove-Item -LiteralPath $dpFile -Force -ErrorAction SilentlyContinue
}

# ---------------------------
# ESD index discovery & selection
# ---------------------------
function Get-ImageIndexesFromEsd {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $ImageFile)

    if (-not (Test-Path -LiteralPath $ImageFile)) {
        throw "Image file not found: $ImageFile"
    }

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
        if ($name -match '(?i)\sN$') { continue }

        $list.Add([pscustomobject]@{
            Index = [int]$idx
            Name  = [string]$name
        })
    }
    return $list
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
                $text -match ("(?im)^\s*device\s+partition={0}\s*$" -f [regex]::Escape($WindowsPartition))) {

                $id = $null
                if ($text -match '(?im)^\s*identifier\s+(\{.+?\})\s*$') {
                    $id = $Matches[1].Trim()
                }

                if ($id) {
                    if (Is-GuidIdentifier $id) { $candidates.Add($id) | Out-Null }
                    else { $fallbackAliases.Add($id) | Out-Null }
                }
            }
            $block.Clear()
        }
    }

    if ($candidates.Count -gt 0) { return $candidates[0] }

    $bm = & bcdedit.exe /enum '{bootmgr}' /v /store $BcdStorePath 2>&1
    if ($bm -and ($bm -match '(?im)^\s*default\s+(\{.+?\})\s*$')) {
        $defaultId = $Matches[1].Trim()
        if (Is-GuidIdentifier $defaultId) { return $defaultId }
    }

    $aliases = if ($fallbackAliases.Count -gt 0) { ($fallbackAliases | Select-Object -Unique) -join ', ' } else { '(none)' }
    throw "Could not resolve a GUID OS loader identifier for $WindowsPartition. Found only aliases: $aliases. reagentc requires a GUID identifier (not {default}/{current})."
}

function Select-DesiredIndex {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]] $Indexes)

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

    $exact = $clean | Where-Object { $_.Name.Equals($desired, [System.StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
    if ($exact) { return [int]$exact.Index }

    if ($SKU -eq 'Professional') {
        $alt = $clean | Where-Object {
            $_.Name.Equals('Windows 11 Professional', [System.StringComparison]::OrdinalIgnoreCase) -or
            $_.Name -match '(?i)^Windows 11 Professional(\b|$)'
        } | Select-Object -First 1
        if ($alt) { return [int]$alt.Index }
    }

    $starts = $clean | Where-Object { $_.Name.StartsWith($desired, [System.StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
    if ($starts) { return [int]$starts.Index }

    $token = if ($SKU -eq 'Enterprise') { 'Enterprise' } else { 'Pro' }
    $contains = $clean | Where-Object { $_.Name -match "(?i)\b$token\b" } | Select-Object -First 1
    if ($contains) { return [int]$contains.Index }

    $names = ($clean | ForEach-Object { "Index=$($_.Index) Name=$($_.Name)" }) -join "; "
    throw "Could not find a suitable NON-N index for SKU='$SKU'. Available (non-N): $names"
}

# ---------------------------
# HP SoftPaq extractor + wait-for-child-procs
# ---------------------------
function Get-ProcessTreePids {
    [CmdletBinding()]
    param([Parameter(Mandatory)][int] $RootPid)

    $seen  = New-Object System.Collections.Generic.HashSet[int]
    $queue = New-Object System.Collections.Generic.Queue[int]
    [void]$queue.Enqueue($RootPid)

    while ($queue.Count -gt 0) {
        $curPid = $queue.Dequeue()
        if (-not $seen.Add($curPid)) { continue }

        $children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$curPid" -ErrorAction SilentlyContinue
        foreach ($c in $children) { [void]$queue.Enqueue([int]$c.ProcessId) }
    }

    return $seen
}

function Wait-ProcessTree {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int] $RootPid,
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

function Resolve-ArtifactPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)

    if (Test-Path -LiteralPath $Path) { return $Path }

    $leaf = [IO.Path]::GetFileName($Path)
    $candidates = @()

    if ($script:BuildForgeRoot) {
        $candidates += @(
            (Join-Path $script:BuildForgeRoot $leaf),
            (Join-Path $script:BuildForgeRoot (Join-Path 'Drivers' $leaf)),
            (Join-Path $script:BuildForgeRoot (Join-Path 'Downloads' $leaf))
        )
    }

    foreach ($r in $script:BuildForgeRootHistory) {
        if ($r) {
            $candidates += @(
                (Join-Path $r $leaf),
                (Join-Path $r (Join-Path 'Drivers' $leaf)),
                (Join-Path $r (Join-Path 'Downloads' $leaf))
            )
        }
    }

    $found = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($found) { return $found }

    throw "Resolve-ArtifactPath: File not found. Original='$Path'. Looked for '$leaf' under current/known BuildForge roots."
}

function Expand-HPSoftPaq {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $SoftPaqExe,
        [Parameter(Mandatory)][string] $Destination
    )

    $SoftPaqExe = Resolve-ArtifactPath -Path $SoftPaqExe
    if (-not (Test-Path -LiteralPath $SoftPaqExe)) {
        throw "Expand-HPSoftPaq: SoftPaq EXE not found: $SoftPaqExe"
    }

    Ensure-Dir $Destination
    $exeAbs = (Resolve-Path -LiteralPath $SoftPaqExe).Path

    Write-Log ("Extracting driver pack: {0}" -f ([IO.Path]::GetFileName($exeAbs))) 'INFO'
    Write-Detail ("Extraction destination: {0}" -f $Destination) 'INFO'

    # Modern syntax first
    $argsModern = @('/s','/e','/f', $Destination)
    try {
        Write-Detail ("SoftPaq switches: {0}" -f ($argsModern -join ' ')) 'INFO'
        $p = Start-Process -FilePath $exeAbs -ArgumentList $argsModern -PassThru -WindowStyle Hidden
        Wait-ProcessTree -RootPid $p.Id
    } catch {
        Write-Log ("SoftPaq modern extraction failed: {0}" -f $_.Exception.Message) 'WARN'
    }

    $infCount = (Get-ChildItem -LiteralPath $Destination -Recurse -Filter *.inf -ErrorAction SilentlyContinue | Measure-Object).Count
    if ($infCount -gt 0) {
        Write-Log ("Driver pack extracted (INF found: {0})" -f $infCount) 'OK'
        return
    }

    # Fallback legacy syntax
    $argsLegacy = @('-pdf', "-f$Destination", '-s')
    Write-Log "Falling back to legacy SoftPaq switches." 'WARN'
    Write-Detail ("Legacy switches: {0}" -f ($argsLegacy -join ' ')) 'INFO'

    $p2 = Start-Process -FilePath $exeAbs -ArgumentList $argsLegacy -PassThru -WindowStyle Hidden
    Wait-ProcessTree -RootPid $p2.Id

    $infCount2 = (Get-ChildItem -LiteralPath $Destination -Recurse -Filter *.inf -ErrorAction SilentlyContinue | Measure-Object).Count
    if ($infCount2 -eq 0) {
        Write-Log "Driver pack extracted but no INF files were found." 'WARN'
    } else {
        Write-Log ("Driver pack extracted (INF found: {0})" -f $infCount2) 'OK'
    }
}
function Cleanup-And-Restart {
    [CmdletBinding()]
    param()

    # Safety checks
    if (-not (Test-Path -LiteralPath 'W:\Windows')) {
        Write-Log "Windows volume not detected. Cleanup and restart skipped." 'WARN'
        return
    }

    $persistentLog = 'W:\Windows\Temp\BuildForge\BuildForge.log'
    if (-not (Test-Path -LiteralPath $persistentLog)) {
        Write-Log "Persistent log not found. Cleanup aborted to avoid data loss." 'ERROR'
        return
    }

    # Cleanup temporary BuildForge working directory
    $tempRoot = 'W:\BuildForge'
    if (Test-Path -LiteralPath $tempRoot) {
        try {
            Write-Log "Removing temporary BuildForge working directory." 'INFO'
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction Stop
            Write-Log "Temporary BuildForge directory removed." 'OK'
        }
        catch {
            Write-Log ("Failed to remove W:\BuildForge: {0}" -f $_.Exception.Message) 'WARN'
        }
    }
    else {
        Write-Log "Temporary BuildForge directory not present. Nothing to clean." 'INFO'
    }

    # Ensure filesystem buffers are flushed
    Write-Log "Finalizing and restarting system." 'INFO'

    try {
        # Preferred in WinRE
        wpeutil reboot
    }
    catch {
        # Fallback if wpeutil is unavailable
        Write-Log "wpeutil not available. Falling back to Restart-Computer." 'WARN'
        Restart-Computer -Force
    }
}

# ---------------------------
# MAIN
# ---------------------------
Invoke-Step "1" "Setup BuildForge root and logging" {
    Initialize-Logging
    Update-BuildForgeRoot
    Write-Log ("Log file: {0}" -f $script:LogFile) 'OK'
    Write-Log ("Working root: {0}" -f $script:BuildForgeRoot) 'OK'
}

Invoke-Step "2" "List PowerShell and environment info" {
    $osCap = 'Unknown / WinRE'
    try { $osCap = (Get-CimInstance Win32_OperatingSystem).Caption } catch {}
    Write-Log ("PowerShell: {0}" -f $PSVersionTable.PSVersion) 'INFO'
    Write-Log ("OS: {0}" -f $osCap) 'INFO'
}

Invoke-Step "3" "List hardware identity" {
    $hw = Get-HardwareIdentity
    $script:Hardware = $hw
    Write-Log ("CS: {0} {1}" -f $hw.CSManufacturer, $hw.CSModel) 'INFO'
    Write-Log ("BB: {0} {1} SKU={2} Prod={3}" -f $hw.BBManufacturer, $hw.BBModel, $hw.BBSKU, $hw.BBProduct) 'INFO'
}

Invoke-Step "4" "List target OS parameters" {
    Write-Log ("OS: Windows 11 {0} {1} ({2}, {3})" -f $ReleaseId, $Architecture, $SKU, $License) 'OK'
    Write-Detail ("Language: {0}" -f $LanguageCode) 'INFO'
}

Invoke-Step "5" "Download catalogs" {

    # Re-evaluate BuildForgeRoot in case disks or roots changed
    Update-BuildForgeRoot

    # Explicitly ensure catalog directory exists
    $catalogDir = Join-Path $script:BuildForgeRoot 'Catalogs'
    Ensure-Dir $catalogDir

    Write-Log ("Catalog directory prepared: {0}" -f $catalogDir) 'INFO'

    # Download OS catalog
    Write-Log "Downloading OS catalog" 'INFO'
    $script:OSCatalog = Get-Catalog -CatalogUrl $OSCatalogUrl

    # Download driver catalog
    Write-Log "Downloading driver pack catalog" 'INFO'
    $script:DriverCatalog = Get-Catalog -CatalogUrl $DriverCatalogUrl

    Write-Log "Catalogs downloaded and loaded successfully" 'OK'
}

Invoke-Step "6" "Match OS entry from catalog" {
    $osEntry = Resolve-OsCatalogEntry -Catalog $script:OSCatalog
    $script:OsEntry = $osEntry

    $osUrl    = Get-EntryValue $osEntry @('URL','Url','Uri','DownloadUrl','ESDUrl','WimUrl')
    $osSha1   = Get-EntryValue $osEntry @('Sha1','SHA1','HashSha1','SHA-1')
    $osSha256 = Get-EntryValue $osEntry @('Sha256','SHA256','HashSha256','SHA-256')

    if (-not $osUrl) { throw "OS catalog entry missing URL/DownloadUrl/ESDUrl/WimUrl." }

    $script:OsUrl    = $osUrl
    $script:OsSha1   = $osSha1
    $script:OsSha256 = $osSha256

    # Console: show leaf only to prevent wrapping; file: full URL
    $leaf = Get-LeafNameFromUrl -Url $osUrl -Fallback 'install.esd'
    Write-Log ("OS image selected: {0}" -f $leaf) 'OK'
    Write-Detail ("OS image URL: {0}" -f $osUrl) 'INFO'
}

Invoke-Step "7" "HP DriverPack match via HPClientDriverPackCatalog.cab" {

    # -----------------------------------------------------------------
    # Guard: HP systems only
    # -----------------------------------------------------------------
    if (-not ($script:Hardware.CSManufacturer -match '(?i)HP|Hewlett')) {
        Write-Log "Not an HP system. HP DriverPack catalog step skipped." 'INFO'
        return
    }

    # -----------------------------------------------------------------
    # Debug: CAB URL sanity
    # -----------------------------------------------------------------
    $raw = $HpDriverPackCatalogCabUrl
    $isEmpty = [string]::IsNullOrWhiteSpace($raw)

    Write-Log ("DEBUG HpDriverPackCatalogCabUrl raw: '{0}'" -f $raw) 'INFO'
    Write-Log ("DEBUG HpDriverPackCatalogCabUrl isNullOrWhiteSpace: {0}" -f $isEmpty) 'INFO'

    if ($isEmpty) {
        throw "HpDriverPackCatalogCabUrl is empty at Step 7."
    }

    # -----------------------------------------------------------------
    # Download + expand HP catalog CAB
    # -----------------------------------------------------------------
    Update-BuildForgeRoot
    $hpCatDir = Join-Path $script:BuildForgeRoot 'Catalogs'
    Ensure-Dir $hpCatDir

    Write-Log "Downloading and expanding HP DriverPack catalog CAB..." 'INFO'
    $xmlPath = Get-HPClientDriverPackCatalogXml `
        -CabUrl $HpDriverPackCatalogCabUrl `
        -WorkingDir $hpCatDir

    # -----------------------------------------------------------------
    # Parse catalog XML
    # -----------------------------------------------------------------
    Write-Log "Parsing HP DriverPack catalog XML..." 'INFO'
    $hpCatalog = Import-HPClientDriverPackCatalog -XmlPath $xmlPath

    # -----------------------------------------------------------------
    # DEBUG: prove SystemId + Win11 rows exist
    # -----------------------------------------------------------------
    $sys = [string]$script:Hardware.BBProduct
    if ($sys) { $sys = $sys.Trim() }
    $sysU = if ($sys) { $sys.ToUpperInvariant() } else { '' }

    $rowsForSys = @($hpCatalog.DriverPackMap | Where-Object {
        $_.SystemId -and ($_.SystemId.Trim().ToUpperInvariant() -eq $sysU)
    })

    Write-Log ("DEBUG HP map rows for SystemId '{0}': {1}" -f $sysU, $rowsForSys.Count) 'INFO'

    $rowsWin11 = @($rowsForSys | Where-Object {
        $_.OSName -and
        ($_.OSName -match '(?i)Windows\s+11') -and
        ($_.OSName -notmatch '(?i)Windows\s+10')
    })

    Write-Log ("DEBUG Win11 rows for SystemId '{0}': {1}" -f $sysU, $rowsWin11.Count) 'INFO'

    $rowsWin11 |
        Select-Object OSName, SoftPaqId -Unique |
        Select-Object -First 3 |
        ForEach-Object {
            Write-Log ("DEBUG Example: OSName='{0}' SoftPaqId='{1}'" -f $_.OSName, $_.SoftPaqId) 'INFO'
        }

    # -----------------------------------------------------------------
    # Select best HP DriverPack (Win11 only, ReleaseId preferred)
    # -----------------------------------------------------------------
    Write-Log "Selecting best HP DriverPack match for Windows 11 (Release preference applied)..." 'INFO'

    $match = Find-HPDriverPackBestMatch `
        -Hardware  $script:Hardware `
        -HpCatalog $hpCatalog `
        -ReleaseId $ReleaseId

    if (-not $match.Matched) {
        Write-Log ("HP DriverPack match failed: {0}" -f $match.Reason) 'WARN'
        return
    }

    # -----------------------------------------------------------------
    # Success logging
    # -----------------------------------------------------------------
    Write-Log ("HP DriverPack matched: {0} ({1})" -f $match.SoftPaqId, $match.OSName) 'OK'
    Write-Detail ("HP DriverPack URL: {0}" -f $match.Url) 'INFO'
    Write-Detail ("HP DriverPack SHA256: {0}" -f $match.Sha256) 'INFO'
    Write-Detail ("Rank={0} DateReleased={1}" -f $match.Rank, $match.DateReleased) 'INFO'

    # -----------------------------------------------------------------
    # Seed DriverMatch for downstream steps (download / hash / extract)
    # -----------------------------------------------------------------
    $script:DriverMatch = [pscustomobject]@{
        Matched   = $true
        URL       = $match.Url
        Sha1      = $null
        Sha256    = $match.Sha256
        Score     = $match.Rank
        MatchInfo = ("SystemId={0}; OSName={1}; SoftPaqId={2}" -f `
                        $match.SystemId, $match.OSName, $match.SoftPaqId)
    }
}

Invoke-Step "8" "Select best local disk for OS" {
    $disk = Get-TargetDisk
    $script:TargetDisk = $disk
    Write-Log ("Target disk: #{0} {1} {2}GB" -f $disk.Number, $disk.BusType, ([math]::Round($disk.Size/1GB, 2))) 'OK'
}

Invoke-Step "9" "Partition disk (UEFI/GPT) if needed" {
    $haveW = Test-Path -LiteralPath 'W:\'
    $haveS = Test-Path -LiteralPath 'S:\'
    $haveR = Test-Path -LiteralPath 'R:\'

    if ($ForceRepartition -or -not ($haveW -and $haveS -and $haveR)) {
        Write-Log "Partitioning required." 'WARN'
        Write-Detail ("Current letters: S={0} W={1} R={2}" -f $haveS, $haveW, $haveR) 'INFO'
        Apply-UEFIPartitionLayout -DiskNumber $script:TargetDisk.Number
        Write-Log "Partition layout applied (S:, W:, R:)." 'OK'
    } else {
        Write-Log "Partition layout already present (S:, W:, R:). Skipped." 'OK'
    }
}


Invoke-Step "9.5" "Pre-flight filesystem sanity check" {
    # After partitioning, require W: and S: (R: optional depending on your layout timing)
    Invoke-FilesystemPreflight -RequireWindowsPartition -RequireEfiPartition
}


Invoke-Step "10" "Move BuildForge root to W: (when W: exists)" {
    Update-BuildForgeRoot
    Write-Log ("Working root: {0}" -f $script:BuildForgeRoot) 'OK'
}

Invoke-Step "11" "Download correct OS ESD/WIM (best match)" {

    # Re-evaluate BuildForgeRoot after any disk / partition changes
    Update-BuildForgeRoot

    # Explicitly ensure OS download directory exists
    $osDir = Join-Path $script:BuildForgeRoot 'OS'
    Ensure-Dir $osDir

    Write-Log ("OS download directory prepared: {0}" -f $osDir) 'INFO'

    # Resolve file name from catalog URL
    $osFile = Get-LeafNameFromUrl -Url $script:OsUrl -Fallback 'install.esd'
    $osPath = Join-Path $osDir $osFile

    Write-Log ("Preparing to download OS image: {0}" -f $osFile) 'INFO'
    Write-Detail ("OS image URL: {0}" -f $script:OsUrl) 'INFO'
    Write-Detail ("Destination path: {0}" -f $osPath) 'INFO'

    # Perform download (Invoke-Download now defensively recreates parent dirs)
    Invoke-Download -Url $script:OsUrl -DestPath $osPath | Out-Null

    # Optional integrity verification
    if ($script:OsSha1 -or $script:OsSha256) {
        Confirm-FileHash -FilePath $osPath `
                         -ExpectedSha1   $script:OsSha1 `
                         -ExpectedSha256 $script:OsSha256
    }
    else {
        Write-Log "No hashes provided by catalog. Integrity verification skipped." 'WARN'
    }

    # Persist resolved OS path
    $script:OsPath = $osPath

    Write-Log ("OS image ready for deployment: {0}" -f $osFile) 'OK'
}

Invoke-Step "12" "Download best-match driver pack (if matched)" {
    Update-BuildForgeRoot
    if (-not ($script:DriverMatch.Matched -and $script:DriverMatch.URL)) {
        Write-Log "Driver download skipped (no matched URL)." 'WARN'
        return
    }

    $drvDir = Join-Path $script:BuildForgeRoot 'Drivers'
    Ensure-Dir $drvDir

    $drvFile = Get-LeafNameFromUrl -Url $script:DriverMatch.URL -Fallback 'driverpack.exe'
    $drvPath = Join-Path $drvDir $drvFile

    Invoke-Download -Url $script:DriverMatch.URL -DestPath $drvPath | Out-Null
    Confirm-FileHash -FilePath $drvPath -ExpectedSha1 $script:DriverMatch.Sha1 -ExpectedSha256 $script:DriverMatch.Sha256

    $script:DriverPackPath = $drvPath
    Write-Log ("Driver pack ready: {0}" -f $drvFile) 'OK'
}

Invoke-Step "13" "List ESD/WIM indexes" {
    $idx = Get-ImageIndexesFromEsd -ImageFile $script:OsPath
    $script:ImageIndexes = $idx

    if (-not $idx -or $idx.Count -eq 0) { throw "No indexes discovered in image." }

    Write-Log ("Image indexes discovered: {0}" -f $idx.Count) 'OK'

    # Console: show first 3 (prevents walls of text). Full list to file always.
    $top = $idx | Select-Object -First 3
    foreach ($i in $top) {
        Write-Log ("Index {0}: {1}" -f $i.Index, $i.Name) 'INFO'
    }
    if ($idx.Count -gt 3) {
        Write-Log ("Additional indexes written to log file: {0}" -f $script:LogFile) 'INFO'
    }

    foreach ($i in $idx) {
        Write-LogFileOnly -Message ("Index {0}: {1}" -f $i.Index, $i.Name) -Level 'INFO'
    }
}

Invoke-Step "14" "Select desired index (Windows 11 SKU)" {
    $index = Select-DesiredIndex -Indexes $script:ImageIndexes
    $script:SelectedIndex = $index
    Write-Log ("Selected image index: {0}" -f $index) 'OK'
}

Invoke-Step "15" "Apply selected image to W:\" {
    $already = Test-Path -LiteralPath 'W:\Windows\System32'
    if ($already -and -not $ForceApplyImage) {
        Write-Log "Windows folder already present. Image apply skipped." 'OK'
        return
    }

    if (-not (Get-Command -Name Expand-WindowsImage -ErrorAction SilentlyContinue)) {
        try { Import-Module Dism -ErrorAction Stop } catch {
            throw "Expand-WindowsImage cmdlet not available (Dism module missing). Cannot apply image without dism.exe."
        }
    }

    Write-Log ("Applying image (Index {0}) to W:\" -f $script:SelectedIndex) 'INFO'

    if ($PSCmdlet.ShouldProcess("W:\", "Expand-WindowsImage (Index $($script:SelectedIndex))")) {
        Expand-WindowsImage -ImagePath $script:OsPath `
                           -Index $script:SelectedIndex `
                           -ApplyPath 'W:\' `
                           -ErrorAction Stop | Out-Null
        Write-Log "Windows image applied to W:\" 'OK'
    }
}

Invoke-Step "16" "Configure boot (BCDBoot UEFI)" {
    if ($PSCmdlet.ShouldProcess("S:\", "BCDBoot UEFI from W:\Windows")) {
        $bcdboot = Join-Path $env:WINDIR 'System32\bcdboot.exe'
        if (-not (Test-Path -LiteralPath $bcdboot)) { $bcdboot = "bcdboot.exe" }

        Invoke-Native -FilePath $bcdboot -Arguments @("W:\Windows","/s","S:","/f","UEFI") | Out-Null
        Write-Log "Boot files created for UEFI." 'OK'
    }
}

Invoke-Step "17" "Setup WinRE on recovery partition and register offline" {
    $reDir = 'R:\Recovery\WindowsRE'
    Ensure-Dir $reDir

    $src = 'W:\Windows\System32\Recovery\Winre.wim'
    $dst = Join-Path $reDir 'Winre.wim'

    if (Test-Path -LiteralPath $src) {
        Copy-Item -LiteralPath $src -Destination $dst -Force
        Write-Log "WinRE image copied to R:\Recovery\WindowsRE" 'OK'
    } else {
        throw "Winre.wim not found at $src (some images store it differently)."
    }

    $reagentc = 'W:\Windows\System32\reagentc.exe'
    if (-not (Test-Path -LiteralPath $reagentc)) {
        throw "reagentc.exe not found at expected path: $reagentc"
    }

    if ($PSCmdlet.ShouldProcess("W:\Windows", "Register and enable WinRE offline")) {
        Invoke-Native -FilePath $reagentc -Arguments @("/setreimage","/path",$reDir,"/target","W:\Windows") | Out-Null

        $osGuid = Get-OfflineOsGuidFromBcd -BcdStorePath 'S:\EFI\Microsoft\Boot\BCD' -WindowsPartition 'W:'
        Write-Detail ("Resolved OS loader GUID: {0}" -f $osGuid) 'INFO'

        Invoke-Native -FilePath $reagentc -Arguments @("/enable","/osguid",$osGuid) | Out-Null
        Write-Log "WinRE configured and enabled." 'OK'
    }
}

Invoke-Step "18" "Extract HP driver pack silently" {
    if (-not $script:DriverPackPath) {
        Write-Log "No driver pack downloaded. Extraction skipped." 'WARN'
        return
    }

    Update-BuildForgeRoot
    $extractDir = Join-Path $script:BuildForgeRoot 'ExtractedDrivers'
    Ensure-Dir $extractDir

    $script:DriverPackPath = Resolve-ArtifactPath -Path $script:DriverPackPath
    $ext = [IO.Path]::GetExtension($script:DriverPackPath).ToLowerInvariant()

    Write-Log ("Driver pack type: {0}" -f $ext) 'INFO'

    switch ($ext) {
        '.exe' { Expand-HPSoftPaq -SoftPaqExe $script:DriverPackPath -Destination $extractDir }
        '.zip' {
            Expand-Archive -LiteralPath $script:DriverPackPath -DestinationPath $extractDir -Force
            Write-Log "ZIP extracted successfully." 'OK'
        }
        '.cab' {
            Invoke-Native -FilePath "expand.exe" -Arguments @("-F:*", $script:DriverPackPath, $extractDir) | Out-Null
            Write-Log "CAB extracted successfully." 'OK'
        }
        default { throw "Unknown driver pack extension '$ext' - cannot extract." }
    }

    $infCount = (Get-ChildItem -LiteralPath $extractDir -Recurse -Filter *.inf -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Log ("INF files found: {0}" -f $infCount) 'OK'

    if ($infCount -eq 0) {
        throw "Extraction completed but produced 0 .INF files under '$extractDir'. Cannot inject drivers."
    }

    $script:DriverExtractDir = $extractDir
}

Invoke-Step "19" "Inject drivers into offline image (Add-WindowsDriver)" {
    if (-not $script:DriverExtractDir) {
        Write-Log "No extracted drivers directory. Injection skipped." 'WARN'
        return
    }

    if (-not (Test-Path -LiteralPath $script:DriverExtractDir)) {
        throw "DriverExtractDir does not exist: $($script:DriverExtractDir)"
    }

    $infCount = (Get-ChildItem -LiteralPath $script:DriverExtractDir -Recurse -Filter *.inf -ErrorAction SilentlyContinue | Measure-Object).Count
    if ($infCount -eq 0) {
        throw "No .INF files found under '$($script:DriverExtractDir)'. Cannot inject drivers."
    }

    Write-Log ("Injecting drivers (INF count: {0})" -f $infCount) 'INFO'

    if ($PSCmdlet.ShouldProcess("W:\", "Add-WindowsDriver -Recurse from $($script:DriverExtractDir)")) {
        Add-WindowsDriver -Path 'W:\' `
                          -Driver $script:DriverExtractDir `
                          -Recurse `
                          -ErrorAction Stop | Out-Null
        Write-Log "Driver injection completed." 'OK'
    }
}
Invoke-Step "19.5" "Inject System/HID/USB/Net drivers into WinRE.wim" {

    if (-not $script:DriverExtractDir -or -not (Test-Path -LiteralPath $script:DriverExtractDir)) {
        Write-Log "No extracted drivers directory found. WinRE injection skipped." 'WARN'
        return
    }

    $subsetStage = Join-Path $script:BuildForgeRoot 'WinRE_ClassDrivers'
    $subset = Stage-DriversByClass -DriverRoot $script:DriverExtractDir -StageRoot $subsetStage -IncludeClasses @('System','HIDClass','USB','Net')
    if (-not $subset) { return }

    # WinRE.wim path per your existing Step 17 copy location
    $winreWim = 'R:\Recovery\WindowsRE\Winre.wim'
    Inject-DriversIntoWinREWim -WinreWimPath $winreWim -DriverRoot $subset
}

Invoke-Step "20" "Summary" {
    Write-Log ("Log file: {0}" -f $script:LogFile) 'OK'
    Write-Log ("Working root: {0}" -f $script:BuildForgeRoot) 'INFO'
    if ($script:OsPath)        { Write-Log ("OS image: {0}" -f $script:OsPath) 'INFO' }
    if ($script:SelectedIndex) { Write-Log ("Applied index: {0}" -f $script:SelectedIndex) 'INFO' }
    if ($script:TargetDisk)    { Write-Log ("Disk used: #{0}" -f $script:TargetDisk.Number) 'INFO' }
    Write-Log "Done." 'OK'
}

Invoke-Step "21" "Summary and log preservation" {
    Write-Log ("Log file (WinRE): {0}" -f $script:LogFile) 'OK'
    Write-Log ("Working root: {0}" -f $script:BuildForgeRoot) 'INFO'

    if ($script:OsPath)        { Write-Log ("OS image: {0}" -f $script:OsPath) 'INFO' }
    if ($script:SelectedIndex) { Write-Log ("Applied index: {0}" -f $script:SelectedIndex) 'INFO' }
    if ($script:TargetDisk)    { Write-Log ("Disk used: #{0}" -f $script:TargetDisk.Number) 'INFO' }

    Write-Log "Finalizing log persistence to Windows volume." 'INFO'
    Finalize-LogPersistence

    Write-Log "Done." 'OK'
}

Invoke-Step "22" "Cleanup temporary files and restart computer" {

    Write-Log "Persistent log confirmed at Windows volume." 'OK'
    Write-Log "Beginning final cleanup and system restart." 'INFO'

    Cleanup-And-Restart

    # No further output expected after this point
}
