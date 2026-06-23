# Run the XAF rule generator against OpenAI models (one .conf per model), then
# score them with compare_models.py alongside any local-model runs.
#
# Reuses generate_modsec_rules_llm.py unchanged: OpenAI is selected simply by
# leaving XAF_BASE_URL UNSET (the generator then uses the default OpenAI client).
#
# Usage:
#   $env:OPENAI_API_KEY = "sk-..."; .\generator\run_openai.ps1
#   .\generator\run_openai.ps1 -Models "gpt-4o-mini","gpt-4o","gpt-4.1"
#   .\generator\run_openai.ps1 -DryRun        # build prompts only, no API calls
param(
    [string[]]$Models = @("gpt-4o-mini", "gpt-4o"),
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

# --- Require a real key, and make sure we do NOT inherit the Ollama base URL ---
if ([string]::IsNullOrWhiteSpace($env:OPENAI_API_KEY) -or $env:OPENAI_API_KEY -eq "ollama") {
    Write-Error "Set a real OpenAI key first:  `$env:OPENAI_API_KEY = 'sk-...'"
    exit 1
}
if (Test-Path env:XAF_BASE_URL) { Remove-Item env:XAF_BASE_URL }   # unset => target OpenAI

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot  = Split-Path -Parent $scriptDir
Push-Location $repoRoot
try {
    $runDir = "output/model_runs"
    New-Item -ItemType Directory -Force -Path $runDir | Out-Null

    foreach ($m in $Models) {
        Write-Host "`n==================== $m ====================" -ForegroundColor Cyan

        # Per-model output paths so runs never overwrite each other.
        $safe = ($m -replace '[:/\\]', '_')
        $env:XAF_MODEL      = $m
        $env:XAF_OUTPUT     = "rules/custom/auto_sqli.$safe.conf"
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
        Write-Host "`nScoring models..." -ForegroundColor Cyan
        python generator/compare_models.py
    }
}
finally {
    Pop-Location
}
