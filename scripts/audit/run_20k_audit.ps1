<#
.SYNOPSIS
    Runs the full QResP 20,000-model stratified audit end to end.

.DESCRIPTION
    Five steps, each resumable and independently runnable:

      0  estimate    Measure registry size and project request cost. No writes.
      1  head        Audit the top 10,000 by downloads (Stratum A).
      2  sample      Enumerate the registry and draw the long-tail sample.
      3  tail        Audit the 10,000 drawn ids (Stratum B).
      4  stats       Three-block stratified analysis.

    Every step writes a timestamped log to logs\. Steps 1 and 3 resume
    automatically: if interrupted, rerun the same command and they continue
    from where they stopped. Step 2 is the long one.

.PARAMETER Step
    Run a single step by name: estimate, head, sample, tail, stats, or all.
    Default is 'all'.

.PARAMETER Seed
    RNG seed for the long-tail draw. Recorded in the manifest. Changing it
    changes the sample, so keep it fixed once the run has started.

.PARAMETER Date
    Snapshot date used in output filenames. Defaults to today. Do not change
    it mid-run or the steps will stop finding each other's output.

.PARAMETER Sleep
    Seconds to pause between enumeration pages. Raise if you get throttled.

.EXAMPLE
    $env:HF_TOKEN = "hf_xxxxxxxxxxxxxxxxxxxx"
    .\scripts\run_20k_audit.ps1 -Step estimate

.EXAMPLE
    .\scripts\run_20k_audit.ps1

.EXAMPLE
    # resume after an interruption
    .\scripts\run_20k_audit.ps1 -Step tail
#>
[CmdletBinding()]
param(
    [ValidateSet('all', 'estimate', 'head', 'sample', 'tail', 'stats')]
    [string]$Step = 'all',

    [int]$Seed = 20260725,

    [string]$Date = (Get-Date -Format 'yyyy-MM-dd'),

    [double]$Sleep = 0.0,

    [int]$HeadN = 10000,

    [int]$TailK = 10000
)

$ErrorActionPreference = 'Stop'

# Run from the repo root regardless of where the script was invoked from.
$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $RepoRoot

# ---------------------------------------------------------------------------
# Output paths.
#
# Names carry the snapshot date. The Phase I memo specifies the bare names
# 'head_10k.jsonl' and 'longtail_10k.jsonl'; those are deliberately not used
# here, because an undated filename is what allowed the 2026-07-06 re-scan to
# overwrite the published 2026-05-21 dataset in place. See data\DATASETS.md.
# To follow the memo literally, drop the "_$Date" from the three lines below.
# ---------------------------------------------------------------------------
$HeadOut     = "data\head_10k_$Date.jsonl"
$TailOut     = "data\longtail_10k_$Date.jsonl"
$SampleFile  = "data\longtail_sample_$Date.txt"
$FrameFile   = "data\longtail_frame_$Date.txt"
$Manifest    = "data\longtail_manifest_$Date.json"
$LogDir      = 'logs'

New-Item -ItemType Directory -Force -Path $LogDir, 'data' | Out-Null

function Write-Banner($Text) {
    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor Cyan
}

function Get-LogPath($Name) {
    Join-Path $LogDir ("{0}_{1}.log" -f $Name, (Get-Date -Format 'yyyyMMdd-HHmmss'))
}

function Invoke-Step($Name, [scriptblock]$Body) {
    $log = Get-LogPath $Name
    Write-Host "Logging to $log" -ForegroundColor DarkGray
    $started = Get-Date

    # Python's logging module writes to stderr, including ordinary INFO lines.
    # With ErrorActionPreference = 'Stop', PowerShell turns any stderr output
    # from a native command merged via 2>&1 into a fatal NativeCommandError, so
    # the first progress message would abort the run. Relax the preference for
    # the duration of the native call and judge success by the exit code, which
    # is the only reliable signal from a native process anyway.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Body 2>&1 | Tee-Object -FilePath $log
    } finally {
        $ErrorActionPreference = $previous
    }

    if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        Write-Host "Step '$Name' exited with code $LASTEXITCODE. Log: $log" -ForegroundColor Red
        throw "Step '$Name' failed. See $log"
    }
    $mins = [math]::Round(((Get-Date) - $started).TotalMinutes, 1)
    Write-Host "Step '$Name' finished in $mins min." -ForegroundColor Green
}

function Get-LineCount($Path) {
    if (-not (Test-Path $Path)) { return 0 }
    return (Get-Content $Path | Measure-Object -Line).Lines
}

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
Write-Banner "QResP 20k stratified audit  |  snapshot $Date  |  seed $Seed"

# Native commands below may write to stderr without failing, so the strict
# preference is relaxed around them and exit codes are checked explicitly.
$previous = $ErrorActionPreference
$ErrorActionPreference = 'Continue'

python --version
if ($LASTEXITCODE -ne 0) { $ErrorActionPreference = $previous; throw "python not found on PATH." }

# The package must be importable AND must resolve to this repository.
#
# Checking only that `import qresp` succeeds is not enough. An editable install
# left over from a previous checkout will satisfy the import while pointing at
# a different source tree, and the run would then silently execute the wrong
# code -- old enough, in this project's case, to predate the rate-limit
# handling. Verify the resolved path, not just the import.
$resolved = (python -c "import qresp, os; print(os.path.dirname(os.path.abspath(qresp.__file__)))" 2>$null)
$expected = Join-Path $RepoRoot 'src\qresp'

if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($resolved)) {
    Write-Host "qresp is not installed. Installing in editable mode..." -ForegroundColor Yellow
    python -m pip install -e . --quiet
    if ($LASTEXITCODE -ne 0) { $ErrorActionPreference = $previous; throw "pip install -e . failed." }
    $resolved = (python -c "import qresp, os; print(os.path.dirname(os.path.abspath(qresp.__file__)))" 2>$null)
}

if ($resolved.Trim().TrimEnd('\') -ne $expected.TrimEnd('\')) {
    Write-Host @"
qresp resolves to a different source tree than this repository:

    imported from : $resolved
    expected      : $expected

That is almost certainly a stale editable install from an earlier checkout.
Reinstalling from here so the run uses this repository's code.
"@ -ForegroundColor Yellow
    python -m pip install -e . --force-reinstall --no-deps --quiet
    if ($LASTEXITCODE -ne 0) { $ErrorActionPreference = $previous; throw "pip install -e . failed." }

    $resolved = (python -c "import qresp, os; print(os.path.dirname(os.path.abspath(qresp.__file__)))" 2>$null)
    if ($resolved.Trim().TrimEnd('\') -ne $expected.TrimEnd('\')) {
        $ErrorActionPreference = $previous
        throw @"
qresp still resolves to $resolved rather than $expected.
Refusing to run: the audit would execute code from the wrong checkout.
Try:  python -m pip uninstall -y qresp   then rerun this script.
"@
    }
}
Write-Host "qresp resolves to $resolved" -ForegroundColor Green

$ErrorActionPreference = $previous

$HasToken = -not [string]::IsNullOrWhiteSpace($env:HF_TOKEN)
if ($HasToken) {
    Write-Host "HF_TOKEN is set. Running authenticated." -ForegroundColor Green
} else {
    Write-Host @"
HF_TOKEN is NOT set. This run needs roughly 12,000-13,000 requests and will
almost certainly be rate limited without a token. Get a free read-only token
at https://huggingface.co/settings/tokens then:

    `$env:HF_TOKEN = "hf_xxxxxxxxxxxxxxxxxxxx"

The scan will still work unauthenticated, just slowly and with many pauses.
"@ -ForegroundColor Yellow
    $reply = Read-Host "Continue without a token? (y/N)"
    if ($reply -ne 'y') { Write-Host "Aborted."; exit 1 }
}

$TokenArgs = @()
if ($HasToken) { $TokenArgs = @('--token', $env:HF_TOKEN) }

# ---------------------------------------------------------------------------
# Step 0: estimate
# ---------------------------------------------------------------------------
if ($Step -in @('all', 'estimate')) {
    Write-Banner "STEP 0 of 4  --  Estimate cost (no writes)"
    Invoke-Step 'estimate' {
        python scripts\sample_longtail.py --estimate-only --seed $Seed @TokenArgs
    }
    if ($Step -eq 'estimate') {
        Write-Host "`nEstimate only. Rerun without -Step estimate to do the real run." -ForegroundColor Cyan
        exit 0
    }
    Write-Host ''
    $reply = Read-Host "Proceed with the full run? (y/N)"
    if ($reply -ne 'y') { Write-Host "Stopped after estimate."; exit 0 }
}

# ---------------------------------------------------------------------------
# Step 1: head stratum
# ---------------------------------------------------------------------------
if ($Step -in @('all', 'head')) {
    Write-Banner "STEP 1 of 4  --  Head stratum: top $HeadN by downloads"
    $before = Get-LineCount $HeadOut
    if ($before -gt 0) {
        Write-Host "$HeadOut already has $before rows. Resuming." -ForegroundColor Yellow
    }
    Invoke-Step 'head' {
        python -m qresp scan --n $HeadN --out $HeadOut @TokenArgs
    }
    $after = Get-LineCount $HeadOut
    Write-Host "Head stratum: $after rows in $HeadOut" -ForegroundColor Green
    if ($after -lt $HeadN) {
        Write-Host @"
Only $after of $HeadN models were recorded. Models left unrecorded after a
transient failure are deliberately not written, so rerunning this step will
retry exactly those. Run:  .\scripts\run_20k_audit.ps1 -Step head
"@ -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# Step 2: draw the long-tail sample
# ---------------------------------------------------------------------------
if ($Step -in @('all', 'sample')) {
    Write-Banner "STEP 2 of 4  --  Enumerate registry and draw $TailK ids"
    if (-not (Test-Path $HeadOut)) {
        throw "$HeadOut not found. Run -Step head first: the head ids are needed for exclusion."
    }
    if (Test-Path $SampleFile) {
        Write-Host "$SampleFile already exists. Skipping the draw." -ForegroundColor Yellow
        Write-Host "Delete it (and $FrameFile) to redraw." -ForegroundColor DarkGray
    } else {
        Write-Host @"
This is the long step. It pages through the entire registry to build a
sampling frame, which is what makes the draw genuinely uniform rather than
'the next 10,000 by downloads'. Expect this to take a while. It is safe to
leave running; progress is logged every 100 pages.
"@ -ForegroundColor DarkGray
        $frameArg = @()
        if (Test-Path $FrameFile) {
            Write-Host "Reusing existing frame $FrameFile (no network needed)." -ForegroundColor Yellow
            $frameArg = @('--frame', $FrameFile)
        }
        Invoke-Step 'sample' {
            python scripts\sample_longtail.py `
                --seed $Seed `
                --k $TailK `
                --head-ids $HeadOut `
                --out-dir data `
                --sleep $Sleep `
                @frameArg @TokenArgs
        }
    }
    Write-Host "Sample: $(Get-LineCount $SampleFile) ids in $SampleFile" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Step 3: tail stratum
# ---------------------------------------------------------------------------
if ($Step -in @('all', 'tail')) {
    Write-Banner "STEP 3 of 4  --  Long-tail stratum: audit the drawn sample"
    if (-not (Test-Path $SampleFile)) {
        throw "$SampleFile not found. Run -Step sample first."
    }
    $target = Get-LineCount $SampleFile
    $before = Get-LineCount $TailOut
    if ($before -gt 0) {
        Write-Host "$TailOut already has $before of $target rows. Resuming." -ForegroundColor Yellow
        Write-Host "Completed models are skipped before their metadata is requested." -ForegroundColor DarkGray
    }
    Invoke-Step 'tail' {
        python -m qresp scan-ids --ids $SampleFile --out $TailOut @TokenArgs
    }
    $after = Get-LineCount $TailOut
    Write-Host "Long-tail stratum: $after of $target rows in $TailOut" -ForegroundColor Green
    if ($after -lt $target) {
        Write-Host "Rerun to retry the $($target - $after) outstanding models:  .\scripts\run_20k_audit.ps1 -Step tail" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# Step 4: stats
# ---------------------------------------------------------------------------
if ($Step -in @('all', 'stats')) {
    Write-Banner "STEP 4 of 4  --  Stratified analysis"
    foreach ($f in @($HeadOut, $TailOut)) {
        if (-not (Test-Path $f)) { throw "$f not found. Earlier steps incomplete." }
    }
    $manifestArg = @()
    if (Test-Path $Manifest) {
        $manifestArg = @('--manifest', $Manifest)
    } else {
        Write-Host "No manifest at $Manifest; stats will need --tail-population." -ForegroundColor Yellow
    }
    $statsLog = Join-Path $LogDir "stats_$Date.txt"
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        python stats.py --head $HeadOut --tail $TailOut @manifestArg 2>&1 |
            Tee-Object -FilePath $statsLog
    } finally {
        $ErrorActionPreference = $previous
    }
    if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        throw "stats.py exited with code $LASTEXITCODE. See $statsLog"
    }
    Write-Host "`nStats saved to $statsLog" -ForegroundColor Green
}

Write-Banner "Done"
Write-Host @"
Outputs
  head stratum : $HeadOut          ($(Get-LineCount $HeadOut) rows)
  tail stratum : $TailOut          ($(Get-LineCount $TailOut) rows)
  sample ids   : $SampleFile
  frame        : $FrameFile
  manifest     : $Manifest
  logs         : $LogDir\

The two strata are kept separate on purpose. Do not concatenate them: the
combined estimate in stats.py weights them by population size, and merging
the files would silently treat a 10,000-model census of the head and a
10,000-model draw from millions as though they carried equal weight.
"@ -ForegroundColor Cyan
