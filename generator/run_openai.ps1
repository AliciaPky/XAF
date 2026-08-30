# Run the XAF rule generator against the chosen OpenAI model, writing the validated
# rules to rules/experiments/auto_rules.conf as CANDIDATES awaiting approval (the WAF
# does NOT load that dir). Approve them in the console's Rule Approval gate to promote
# them into rules/custom/ and go live. Single-model workflow — settled on gpt-5.4-mini.
#
# Reuses generate_modsec_rules_llm.py unchanged, the key is taken from the shell env or,
# if unset, loaded from .env (same file the generator reads).
#
# Usage:
#   $env:OPENAI_API_KEY = "sk-..."; .\generator\run_openai.ps1
#   .\generator\run_openai.ps1 -Models "gpt-5.4-mini"   # override the model
#   .\generator\run_openai.ps1 -DryRun                  # build prompts only, no API calls
param(
    [string[]]$Models = @("gpt-5.4-mini"),
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

# Clear any stray base URL / placeholder key so we always target OpenAI
if (Test-Path env:XAF_BASE_URL) { Remove-Item env:XAF_BASE_URL }
if ($env:OPENAI_API_KEY -eq "ollama") { Remove-Item env:OPENAI_API_KEY }

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot  = Split-Path -Parent $scriptDir

# If the key isn't set in this shell, load it from .env
if ([string]::IsNullOrWhiteSpace($env:OPENAI_API_KEY)) {
    $envFile = Join-Path $repoRoot ".env"
    if (Test-Path $envFile) {
        foreach ($line in Get-Content $envFile) {
            if ($line -match '^\s*OPENAI_API_KEY\s*=\s*(.+?)\s*$') {
                $env:OPENAI_API_KEY = $matches[1].Trim().Trim('"').Trim("'")
                break
            }
        }
    }
}

if ([string]::IsNullOrWhiteSpace($env:OPENAI_API_KEY) -or
    $env:OPENAI_API_KEY -eq "ollama" -or
    $env:OPENAI_API_KEY -eq "sk-your-key-here") {
    Write-Error "No real OpenAI key found. Set it with  `$env:OPENAI_API_KEY = 'sk-...'  or add OPENAI_API_KEY to .env"
    exit 1
}
Push-Location $repoRoot
try {
    $runDir = "output/model_runs"
    New-Item -ItemType Directory -Force -Path $runDir | Out-Null

    foreach ($m in $Models) {
        Write-Host "`n==================== $m ====================" -ForegroundColor Cyan

        # Write candidates to rules/experiments/ (NOT loaded by the WAF). The
        # generator overwrites this file each run and renumbers IDs above anything
        # already deployed (starting_rule_id), so a rule can't collide once approved
        # and promoted into rules/custom/.
        $safe = ($m -replace '[:/\\]', '_')
        $env:XAF_MODEL      = $m
        $env:XAF_OUTPUT     = "rules/experiments/auto_rules.conf"
        $env:XAF_PROMPT_LOG = "output/prompts/$safe"
        $log                = "$runDir/$safe.log"

        Write-Host "Generating -> $($env:XAF_OUTPUT)" -ForegroundColor Green
        if ($DryRun) {
            python generator/generate_modsec_rules_llm.py --dry-run | Tee-Object -FilePath $log
        } else {
            python generator/generate_modsec_rules_llm.py | Tee-Object -FilePath $log
        }
    }

    if (-not $DryRun) {
        if (Test-Path "generator/compare_models.py") {
            Write-Host "`nScoring models..." -ForegroundColor Cyan
            python generator/compare_models.py
        } else {
            Write-Host "`nSkipping scoring: generator/compare_models.py not present." -ForegroundColor DarkYellow
        }
    }
}
finally {
    Pop-Location
}
