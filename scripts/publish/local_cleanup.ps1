# Local-only cleanup before / after making the repo public.
# Does NOT touch git history (already purged). Removes working-tree junk and
# reminds you about secrets that must never be committed.
#
#   powershell -ExecutionPolicy Bypass -File scripts\publish\local_cleanup.ps1

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $Root

Write-Host "Working tree: $Root"
Write-Host ""

# 1) History must already be clean (prints nothing if OK)
Write-Host "=== History checks (must print nothing) ===" -ForegroundColor Cyan
$paths = @(
    "security/leaked_token_repos.redacted.json",
    "docs/OPEN-QUESTIONS.md",
    "docs/PAPER-SPRINT-PLAN.md",
    "docs/EXPERT-REPORT-04-residual-3-closed.md",
    "security/leaked_token_repos.PRIVATE.txt"
)
foreach ($p in $paths) {
    $out = git log --all --oneline -- $p 2>$null
    if ($out) {
        Write-Host "FAIL: still in history: $p" -ForegroundColor Red
        Write-Host $out
    } else {
        Write-Host "OK  : $p" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "=== Remove local packaging / mirror scratch ===" -ForegroundColor Cyan
$junk = @(
    "qresp-0.1.0",
    "qresp.git",
    "dist"
)
foreach ($j in $junk) {
    $full = Join-Path $Root $j
    if (Test-Path $full) {
        Remove-Item -Recurse -Force $full
        Write-Host "removed: $j" -ForegroundColor Yellow
    } else {
        Write-Host "absent : $j"
    }
}

Write-Host ""
Write-Host "=== Secret / disclosure files (kept if present; gitignored) ===" -ForegroundColor Cyan
$sensitive = @(
    "security\leaked_token_repos.PRIVATE.txt",
    "security\leaked_token_repos.redacted.json",
    "release\keys\ml-dsa-87.key"
)
foreach ($s in $sensitive) {
    $full = Join-Path $Root $s
    if (Test-Path $full) {
        Write-Host "LOCAL ONLY (do not git add): $s" -ForegroundColor Yellow
    } else {
        Write-Host "absent: $s"
    }
}

Write-Host ""
Write-Host "=== git status (should not list secrets) ===" -ForegroundColor Cyan
git status -sb
Write-Host ""
Write-Host "Done. Commit .gitignore + docs fixes if dirty, then push." -ForegroundColor Green
