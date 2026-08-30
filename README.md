# XAF - Self-Improving Web Application Firewall

XAF is a self-improving WAF that learns from the attacks that slip past a
traditional rule set. It runs live attack traffic through **nginx + ModSecurity +
OWASP CRS**, parses the audit log, clusters the payloads that bypassed CRS by attack family, and uses an LLM to generate new ModSecurity rules to close those gaps. Every generated rule is functionally validated and then held for **human approval** before it goes live, so nothing self-deploys.

```
attack traffic → ModSecurity/CRS → audit.log
      │
      ▼
   parse → cluster (per family) → LLM rule-gen + validation → human approval → deploy → reload WAF
```

## Components

| Service | Role |
|---------|------|
| `nginx-modsec` | nginx + ModSecurity v3 + OWASP CRS reverse proxy (the WAF), on port **8080** |
| `lms` | Vulnerable target LMS (Flask + MySQL), direct on port **5000** |
| `db` | MySQL 8 backing the LMS |

The pipeline itself is plain Python (parser / clustering / generator) plus a
Streamlit operator console.

## Repository layout

| Path | What it holds |
|------|---------------|
| `parser/parse_audit_log_json.py` | Parses `modsec-logs/audit.log` → `output/parsed_logs.json` (one row per payload, with a `blocked`/`bypassed` status and a normalized form for clustering) |
| `clustering/cluster_attacks.py` | Labels payloads by family (SQLi / XSS / SSTI), drops benign, clusters each family with TF-IDF + DBSCAN → `output/clustered_attacks.csv` |
| `generator/generate_modsec_rules_llm.py` | One validated ModSecurity rule per cluster → `rules/experiments/auto_rules.conf` (a candidate; **not** loaded by the WAF) |
| `rules/crs` | OWASP Core Rule Set (git submodule) |
| `rules/custom/` | Rules the WAF actually loads, including human-approved auto rules |
| `rules/experiments/` | Generated candidates awaiting approval |
| `prompts/` | LLM prompt template |
| `ui/` | Streamlit operator console (dashboard, clusters, rule approval, attack simulator) |
| `targets/lms/` | The vulnerable LMS app and its Docker build |
| `attackScript.py` | Generates SQLi / XSS / SSTI traffic through the WAF (lab use) |
| `reset_system.py` | Returns the whole pipeline to a clean, CRS-only state |

## Getting started

### 1. Configure secrets

```bash
cp .env.example .env
# set OPENAI_API_KEY (required for rule generation)
# optionally set XAF_MODEL (default: gpt-5.4-mini)
```

`.env` is gitignored — never commit your real key.

### 2. Bring up the stack

```bash
git submodule update --init   # fetch the OWASP CRS
docker compose up --build
```

- WAF-protected LMS: <http://localhost:8080>
- LMS direct (no WAF, for baseline tests): <http://localhost:5000>

### 3. Generate attack traffic

```bash
python attackScript.py                  # SQLi + XSS + SSTI through the WAF
python attackScript.py --type xss       # one attack type only (sqli | xss | ssti)
```

These write real entries into `modsec-logs/audit.log`.

### 4. Run the pipeline

```bash
python parser/parse_audit_log_json.py       # audit.log  → parsed_logs.json
python clustering/cluster_attacks.py         # parsed_logs → clustered_attacks.csv
python generator/generate_modsec_rules_llm.py  # clusters   → candidate rules
#   add --dry-run to print prompts without calling the API
```

### 5. Review and deploy (operator console)

```bash
python -m venv ui/.venv
ui/.venv/Scripts/activate                    # Windows PowerShell: ui\.venv\Scripts\Activate.ps1
pip install -r ui/requirements.txt
cd ui && streamlit run app.py                # run from ui/ so Streamlit secrets load
```

Open <http://localhost:8501>. The console (behind a Google OIDC login gate) shows
the threat dashboard, cluster explorer, and a **Rule Approval** gate where you
review each candidate's validation evidence and promote it into `rules/custom/`,
then reload the WAF.

## Resetting

```bash
python reset_system.py          # prompts before wiping; --yes to skip
```

Clears logs → parse → cluster → generate → approve/deploy, resets run-state, and
restarts the WAF back to CRS-only. FYP model-comparison artifacts and hand-written
analyst rules are preserved. Run `python reset_system.py -h` for options.

## Notes

- Generated rules are **candidates only** — the WAF loads `rules/custom/`, not
  `rules/experiments/`. A rule goes live only after human approval.
- Clustering trains on the attacks that *bypassed* CRS, so the system learns from
  its gaps rather than regenerating rules for attacks it already blocks.
- Lab use only: the LMS is intentionally vulnerable. Do not expose it publicly.
