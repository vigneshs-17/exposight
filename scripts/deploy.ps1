<#
.SYNOPSIS
    One-command deploy orchestrator for Exposight.
.DESCRIPTION
    Runs from a Windows laptop to deploy Exposight to the Azure production VM.
    Executes preflight, remote phases via SSH, database backup copy, health
    and security header checks, and outputs a deployment summary.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Vm = "exposight@172.198.136.164",

    [Parameter(Position = 1)]
    [string]$Key = "$HOME\.ssh\exposight_ed25519",

    [Parameter(Position = 2)]
    [string]$BackupDir = "D:\exposight-backups",

    [Parameter(Position = 3)]
    [string]$ExpectedRevision = "0015_domain_subdomains_inventory",

    [switch]$DryRun,
    [switch]$VerifyOnly,
    [switch]$Yes
)

# Prevent PowerShell 5.1 / 7 from aborting native commands on stderr output.
# Every external command is evaluated strictly via $LASTEXITCODE.
$origErrorActionPreference = $ErrorActionPreference
$origGlobalErrorActionPreference = $global:ErrorActionPreference
$global:ErrorActionPreference = 'Continue'
$ErrorActionPreference = 'Continue'

$origNativeCommandEAP = $null
if (Test-Path variable:global:PSNativeCommandUseErrorActionPreference) {
    $origNativeCommandEAP = $global:PSNativeCommandUseErrorActionPreference
    $global:PSNativeCommandUseErrorActionPreference = $false
}

$preCommit = "N/A"
$preRevision = "N/A"
$postCommit = "N/A"
$postRevision = "N/A"
$upStarted = $null
$localBackupPath = "N/A"
$afterPull = $false
$logFile = $null

function Write-Log {
    param([string]$Message)
    $ts = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $line = "[$ts] $Message"
    Write-Host $line
    if ($logFile) {
        Add-Content -Path $logFile -Value $line -Encoding UTF8
    }
}

function Fail-Deploy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [switch]$AfterPull
    )

    Write-Log "FAIL: $Message"

    if ($AfterPull) {
        Write-Host ""
        Write-Host "=================================================================" -ForegroundColor Red
        Write-Host "CRITICAL: DEPLOYMENT FAILED AFTER CODE PULL" -ForegroundColor Red
        Write-Host "Pre-deploy commit: $preCommit" -ForegroundColor Yellow
        Write-Host "Please refer to Section 5 (Rollback) of docs/DEPLOY_NEXT.md" -ForegroundColor Yellow
        Write-Host "NEVER automatically roll back or run a database restore." -ForegroundColor Yellow
        Write-Host "A database restore destroys data and must remain an explicit manual decision." -ForegroundColor Yellow
        Write-Host "=================================================================" -ForegroundColor Red
        Write-Host ""
    }

    Restore-Environment
    exit 1
}

function Restore-Environment {
    $global:ErrorActionPreference = $origGlobalErrorActionPreference
    $script:ErrorActionPreference = $origErrorActionPreference
    if ($null -ne $origNativeCommandEAP -and (Test-Path variable:global:PSNativeCommandUseErrorActionPreference)) {
        $global:PSNativeCommandUseErrorActionPreference = $origNativeCommandEAP
    }
}

function Invoke-RemotePhase {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Phase,
        [string]$Arg = $null
    )

    $cmd = if ($Arg) { "bash -s -- $Phase $Arg" } else { "bash -s -- $Phase" }
    Write-Log "=== Executing remote phase: $Phase ==="
    $lines = New-Object System.Collections.Generic.List[string]

    # Stream script without carriage returns (\r)
    $cleanScriptContent | & ssh -i $Key -o BatchMode=yes -o ConnectTimeout=15 $Vm $cmd 2>&1 | ForEach-Object {
        $str = $_.ToString()
        Write-Log $str
        $lines.Add($str)
    }

    $code = $LASTEXITCODE
    return [PSCustomObject]@{
        ExitCode = $code
        Output   = $lines
    }
}

function Invoke-LiveChecks {
    Write-Log "=== Phase 7: Live HTTP Checks from Laptop ==="

    # 1. /health returns 200
    Write-Log "Checking https://exposight.dev/health..."
    $healthCode = & curl.exe -s -o NUL -w "%{http_code}" https://exposight.dev/health
    if ($LASTEXITCODE -ne 0 -or $healthCode -ne "200") {
        Fail-Deploy "Live check failed: /health returned HTTP $healthCode (exit code $LASTEXITCODE)" -AfterPull:$afterPull
    }
    Write-Log "OK: /health returned 200"

    # 2. HEAD https://exposight.dev/
    Write-Log "Checking HEAD https://exposight.dev/ headers..."
    $headOutput = & curl.exe -sI https://exposight.dev/
    if ($LASTEXITCODE -ne 0) {
        Fail-Deploy "Live check failed: HEAD https://exposight.dev/ exited with code $LASTEXITCODE" -AfterPull:$afterPull
    }

    # Verify status 200
    $firstLine = if ($headOutput.Count -gt 0) { $headOutput[0] } else { "" }
    if ($firstLine -notmatch "200") {
        Fail-Deploy "Live check failed: HEAD https://exposight.dev/ status was '$firstLine' (expected 200)" -AfterPull:$afterPull
    }

    # Check required security headers
    $hsts = $headOutput | Where-Object { $_ -match "^(?i)Strict-Transport-Security:" }
    if (-not $hsts) {
        Fail-Deploy "Live check failed: missing Strict-Transport-Security header" -AfterPull:$afterPull
    }

    $csp = $headOutput | Where-Object { $_ -match "^(?i)Content-Security-Policy:" }
    if (-not $csp -or $csp -notmatch "frame-ancestors\s+'none'") {
        Fail-Deploy "Live check failed: CSP missing or does not contain frame-ancestors 'none'" -AfterPull:$afterPull
    }

    $nosniff = $headOutput | Where-Object { $_ -match "^(?i)X-Content-Type-Options:\s*nosniff" }
    if (-not $nosniff) {
        Fail-Deploy "Live check failed: missing or invalid X-Content-Type-Options: nosniff" -AfterPull:$afterPull
    }

    $xframe = $headOutput | Where-Object { $_ -match "^(?i)X-Frame-Options:\s*DENY" }
    if (-not $xframe) {
        Fail-Deploy "Live check failed: missing or invalid X-Frame-Options: DENY" -AfterPull:$afterPull
    }

    $refPolicy = $headOutput | Where-Object { $_ -match "^(?i)Referrer-Policy:\s*no-referrer" }
    if (-not $refPolicy) {
        Fail-Deploy "Live check failed: missing or invalid Referrer-Policy: no-referrer" -AfterPull:$afterPull
    }

    $permPolicy = $headOutput | Where-Object { $_ -match "^(?i)Permissions-Policy:" }
    if (-not $permPolicy) {
        Fail-Deploy "Live check failed: missing Permissions-Policy header" -AfterPull:$afterPull
    }

    # Ensure no Server or Via header
    $serverHeader = $headOutput | Where-Object { $_ -match "^(?i)Server:" }
    if ($serverHeader) {
        Fail-Deploy "Live check failed: unexpected Server header present ($serverHeader)" -AfterPull:$afterPull
    }

    $viaHeader = $headOutput | Where-Object { $_ -match "^(?i)Via:" }
    if ($viaHeader) {
        Fail-Deploy "Live check failed: unexpected Via header present ($viaHeader)" -AfterPull:$afterPull
    }
    Write-Log "OK: HEAD https://exposight.dev/ security headers verified"

    # 3. http://exposight.dev/ returns 308 with no Server header
    Write-Log "Checking http://exposight.dev/ redirect..."
    $httpOutput = & curl.exe -sI http://exposight.dev/
    if ($LASTEXITCODE -ne 0) {
        Fail-Deploy "Live check failed: http://exposight.dev/ curl exited with code $LASTEXITCODE" -AfterPull:$afterPull
    }
    $httpFirstLine = if ($httpOutput.Count -gt 0) { $httpOutput[0] } else { "" }
    if ($httpFirstLine -notmatch "308") {
        Fail-Deploy "Live check failed: http://exposight.dev/ status was '$httpFirstLine' (expected 308)" -AfterPull:$afterPull
    }
    $httpServer = $httpOutput | Where-Object { $_ -match "^(?i)Server:" }
    if ($httpServer) {
        Fail-Deploy "Live check failed: unexpected Server header on HTTP redirect ($httpServer)" -AfterPull:$afterPull
    }
    Write-Log "OK: http://exposight.dev/ returned 308 without Server header"

    # 4. /robots.txt contains Disallow: /app
    Write-Log "Checking /robots.txt..."
    $robots = & curl.exe -s https://exposight.dev/robots.txt
    if ($LASTEXITCODE -ne 0 -or ($robots -join "`n") -notmatch "Disallow:\s*/app") {
        Fail-Deploy "Live check failed: /robots.txt does not contain 'Disallow: /app'" -AfterPull:$afterPull
    }
    Write-Log "OK: /robots.txt contains Disallow: /app"

    # 5. /.well-known/security.txt contains Contact and Expires
    Write-Log "Checking /.well-known/security.txt..."
    $securityTxt = & curl.exe -s https://exposight.dev/.well-known/security.txt
    $secContent = $securityTxt -join "`n"
    if ($LASTEXITCODE -ne 0 -or $secContent -notmatch "Contact:" -or $secContent -notmatch "Expires:") {
        Fail-Deploy "Live check failed: /.well-known/security.txt does not contain Contact and Expires" -AfterPull:$afterPull
    }
    Write-Log "OK: /.well-known/security.txt contains Contact and Expires"

    # 6. /privacy returns 200
    Write-Log "Checking /privacy..."
    $privacyCode = & curl.exe -s -o NUL -w "%{http_code}" https://exposight.dev/privacy
    if ($LASTEXITCODE -ne 0 -or $privacyCode -ne "200") {
        Fail-Deploy "Live check failed: /privacy returned HTTP $privacyCode (exit code $LASTEXITCODE)" -AfterPull:$afterPull
    }
    Write-Log "OK: /privacy returned 200"
}

try {
    # VerifyOnly short-circuit: runs only Step 7
    if ($VerifyOnly) {
        if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
            Write-Host "FAIL: curl.exe not found in PATH" -ForegroundColor Red
            Restore-Environment
            exit 1
        }
        Invoke-LiveChecks
        Write-Host "`nAll live HTTP verification checks passed successfully." -ForegroundColor Green
        Restore-Environment
        exit 0
    }

    # Step 1: Local Preflight
    if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
        Fail-Deploy "preflight: ssh not found in PATH"
    }
    if (-not (Get-Command scp -ErrorAction SilentlyContinue)) {
        Fail-Deploy "preflight: scp not found in PATH"
    }
    if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
        Fail-Deploy "preflight: curl.exe not found in PATH"
    }
    if (-not (Test-Path $Key)) {
        Fail-Deploy "preflight: SSH key file not found at $Key"
    }

    # Initialize BackupDir and transcript log
    if (-not (Test-Path $BackupDir)) {
        New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
    }
    $utcTimestamp = [DateTime]::UtcNow.ToString("yyyyMMdd_HHmmss\Z")
    $logFile = Join-Path $BackupDir "deploy-$utcTimestamp.log"
    Write-Log "Deploy transcript started at $logFile"

    # Read and sanitize deploy_remote.sh (strip any \r)
    $remoteScriptPath = Join-Path $PSScriptRoot "deploy_remote.sh"
    if (-not (Test-Path $remoteScriptPath)) {
        $remoteScriptPath = Join-Path (Get-Location) "scripts\deploy_remote.sh"
    }
    if (-not (Test-Path $remoteScriptPath)) {
        Fail-Deploy "preflight: deploy_remote.sh not found at $remoteScriptPath"
    }
    $cleanScriptContent = [System.IO.File]::ReadAllText($remoteScriptPath).Replace("`r`n", "`n").Replace("`r", "`n")

    # Step 2: Phase 'precheck'
    $precheckRes = Invoke-RemotePhase -Phase "precheck"
    if ($precheckRes.ExitCode -ne 0) {
        Fail-Deploy "precheck phase failed with exit code $($precheckRes.ExitCode)"
    }

    foreach ($line in $precheckRes.Output) {
        if ($line -match '^PRE_COMMIT=(.*)$') {
            $preCommit = $matches[1].Trim()
        }
        if ($line -match '^PRE_REVISION=(.*)$') {
            $preRevision = $matches[1].Trim()
        }
    }
    if ($preCommit -eq "N/A" -or $preRevision -eq "N/A") {
        Fail-Deploy "precheck: failed to parse PRE_COMMIT or PRE_REVISION markers"
    }
    Write-Log "Pre-deploy state: commit=$preCommit, revision=$preRevision"

    # Step 3: Phase 'backup'
    if ($DryRun) {
        Write-Log "[DRY-RUN] Would run remote database backup and scp dump to $BackupDir"
    } else {
        $backupRes = Invoke-RemotePhase -Phase "backup"
        if ($backupRes.ExitCode -ne 0) {
            Fail-Deploy "backup phase failed with exit code $($backupRes.ExitCode)"
        }

        $remoteBackupPath = $null
        $remoteBackupBytes = $null
        foreach ($line in $backupRes.Output) {
            if ($line -match '^BACKUP_PATH=(.*)$') {
                $remoteBackupPath = $matches[1].Trim()
            }
            if ($line -match '^BACKUP_BYTES=(.*)$') {
                $remoteBackupBytes = $matches[1].Trim()
            }
        }
        if (-not $remoteBackupPath -or -not $remoteBackupBytes) {
            Fail-Deploy "backup: failed to parse BACKUP_PATH or BACKUP_BYTES markers"
        }

        $backupFileName = Split-Path -Leaf $remoteBackupPath
        $localBackupPath = Join-Path $BackupDir $backupFileName
        Write-Log "Copying remote backup ($remoteBackupBytes bytes) to $localBackupPath..."

        & scp -i $Key -o BatchMode=yes -o ConnectTimeout=15 "${Vm}:${remoteBackupPath}" "$localBackupPath"
        if ($LASTEXITCODE -ne 0) {
            Fail-Deploy "backup: scp failed with exit code $LASTEXITCODE"
        }

        if (-not (Test-Path $localBackupPath)) {
            Fail-Deploy "backup: local backup file not found at $localBackupPath"
        }

        $localBytes = (Get-Item $localBackupPath).Length
        if ($localBytes -ne [int64]$remoteBackupBytes) {
            Fail-Deploy "backup: byte count mismatch (remote: $remoteBackupBytes, local: $localBytes)"
        }
        Write-Log "OK: Backup verified locally ($localBytes bytes)"
    }

    # Step 4: Phase 'incoming'
    $incomingRes = Invoke-RemotePhase -Phase "incoming"
    if ($incomingRes.ExitCode -ne 0) {
        Fail-Deploy "incoming phase failed with exit code $($incomingRes.ExitCode)"
    }

    $nothingToDeploy = $false
    foreach ($line in $incomingRes.Output) {
        if ($line -match 'NOTHING_TO_DEPLOY') {
            $nothingToDeploy = $true
            break
        }
    }

    if ($nothingToDeploy) {
        Write-Log "No new commits incoming. Skipping pull, up, and verify phases."
        Invoke-LiveChecks
    } else {
        if ($DryRun) {
            Write-Log "[DRY-RUN] Incoming commits detected above. Would prompt for 'deploy' confirmation, pull, up, and verify."
            Invoke-LiveChecks
        } else {
            if (-not $Yes) {
                Write-Host ""
                $confirmation = Read-Host "Incoming commits ready. Type 'deploy' to proceed with production deployment"
                if ($confirmation -ne "deploy") {
                    Fail-Deploy "Deployment aborted by user (confirmation was '$confirmation')"
                }
            }

            # Step 5: Phase 'pull' and 'up'
            $afterPull = $true

            $pullRes = Invoke-RemotePhase -Phase "pull"
            if ($pullRes.ExitCode -ne 0) {
                Fail-Deploy "pull phase failed with exit code $($pullRes.ExitCode)" -AfterPull
            }
            foreach ($line in $pullRes.Output) {
                if ($line -match '^POST_COMMIT=(.*)$') {
                    $postCommit = $matches[1].Trim()
                }
            }

            $upRes = Invoke-RemotePhase -Phase "up"
            if ($upRes.ExitCode -ne 0) {
                Fail-Deploy "up phase failed with exit code $($upRes.ExitCode)" -AfterPull
            }

            foreach ($line in $upRes.Output) {
                if ($line -match '^UP_STARTED=(.*)$') {
                    $upStarted = $matches[1].Trim()
                }
                if ($line -match '^POST_REVISION=(.*)$') {
                    $postRevision = $matches[1].Trim()
                }
            }
            if ($postRevision -eq "N/A" -or -not $postRevision) {
                Fail-Deploy "up: failed to parse POST_REVISION marker" -AfterPull
            }
            if ($postRevision -ne $ExpectedRevision) {
                Fail-Deploy "up: alembic_version was '$postRevision' (expected '$ExpectedRevision')" -AfterPull
            }

            # Step 6: Phase 'verify'
            $verifyRes = Invoke-RemotePhase -Phase "verify" -Arg $upStarted
            if ($verifyRes.ExitCode -ne 0) {
                Fail-Deploy "verify phase failed with exit code $($verifyRes.ExitCode)" -AfterPull
            }

            # Step 7: Live HTTP checks from laptop
            Invoke-LiveChecks
        }
    }

    # Step 8: Summary
    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Green
    Write-Host "DEPLOYMENT SUMMARY" -ForegroundColor Green
    Write-Host "=================================================================" -ForegroundColor Green
    Write-Host "Pre-deploy commit:    $preCommit"
    Write-Host "Post-deploy commit:   $postCommit"
    Write-Host "Pre-deploy revision:  $preRevision"
    Write-Host "Post-deploy revision: $postRevision"
    Write-Host "Local backup file:    $localBackupPath"
    Write-Host "Transcript log:       $logFile"
    if ($DryRun) {
        Write-Host "Execution mode:       DRY RUN (no destructive actions taken)" -ForegroundColor Cyan
    }
    Write-Host ""
    Write-Host "Owner manual steps required (from docs/DEPLOY_NEXT.md):" -ForegroundColor Yellow
    Write-Host "  1. Supabase Dashboard (Auth -> Sign In / Providers -> Email):"
    Write-Host "     Confirm 'Confirm email' is ON and 'Allow new users to sign up' is OFF."
    Write-Host "  2. One manual scan of exposight.dev:"
    Write-Host "     Sign in at https://exposight.dev/app, trigger scan on exposight.dev, verify results."
    Write-Host "  3. SMTP alert test:"
    Write-Host "     Confirm delivery of transactional alert emails."
    Write-Host "=================================================================" -ForegroundColor Green
}
finally {
    Restore-Environment
}
