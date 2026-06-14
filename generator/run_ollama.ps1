# Run the ModSecurity rule generator against a local Ollama server (free, no API key).
# Usage:
#   .\generator\run_ollama.ps1            # generate rules via Ollama
#   .\generator\run_ollama.ps1 -DryRun    # print prompts only, no model call
#   $env:XAF_MODEL="llama3.1:8b"; .\generator\run_ollama.ps1   # override the model
param([switch]$DryRun)

$ErrorActionPreference = "Stop"

# --- Ollama connection (override XAF_MODEL before calling to swap models) ---
$env:XAF_BASE_URL = "http://localhost:11434/v1"
$env:OPENAI_API_KEY = "ollama"            # dummy key; Ollama ignores it
if (-not $env:XAF_MODEL) { $env:XAF_MODEL = "qwen2.5-coder:7b" }

# --- Sanity check: is the Ollama server up? ---
try {
    $null = Invoke-WebRequest -UseBasicParsing -Uri "http://localhost:11434/api/tags" -TimeoutSec 3
} catch {
    Write-Error "Ollama server not reachable at http://localhost:11434. Start it with 'ollama serve' (and 'ollama pull $env:XAF_MODEL' first)."
    exit 1
}

Write-Host "Using Ollama model: $($env:XAF_MODEL)" -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot  = Split-Path -Parent $scriptDir
Push-Location $repoRoot
try {
    if ($DryRun) {
        python generator/generate_modsec_rules_llm.py --dry-run
    } else {
        python generator/generate_modsec_rules_llm.py
    }
} finally {
    Pop-Location
}
