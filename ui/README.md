# XAF Operator Console (Streamlit)

Operator UI for the self-improving WAF. Five pages bound to the pipeline's
output files:

| Page | Reads / does | Source |
|------|--------------|--------|
| **Threat Dashboard** | KPIs, blocked-vs-bypassed, top rule IDs, recent attacks | `output/clustered_attacks.csv` / `output/parsed_logs.json` |
| **Attack Monitor** | Filterable attack table + CSV export | same |
| **Clusters** | Cluster summary cards + live PCA scatter of TF-IDF vectors | `output/cluster*_payloads.txt` / clustered CSV |
| **Rules** | Generate, view validation evidence, approve → deploy, reload WAF | `output/prompts/*`, `rules/custom/*.conf` |
| **Attack Simulator** | Fire a payload at the LMS, see blocked vs bypassed, re-run pipeline | `http://localhost:8080` + the scripts |

The app reuses the generator's own `functional_validate` / `extract_regex`
helpers (imported from `generator/generate_modsec_rules_llm.py`) so the
validation shown in the UI is exactly what the generator enforces.

## Run

From the **project root** (not from `ui/`):

```bash
# one-time: create an isolated env and install deps
python -m venv ui/.venv
ui/.venv/Scripts/activate          # Windows (PowerShell: ui\.venv\Scripts\Activate.ps1)
pip install -r ui/requirements.txt

# launch
streamlit run ui/app.py
```

Open http://localhost:8501.

The theme lives in `../.streamlit/config.toml` (dark, XAF blue). It's picked up
automatically when you launch from the project root.

## Notes

- **Works before Docker is up.** The read-only pages just render whatever output
  files exist; missing files show an empty-state message instead of crashing.
- **Live actions need the stack.** Firing payloads needs `nginx-modsec` + `lms`
  (`docker compose up`); "Reload ModSecurity" runs `docker restart nginx-modsec`.
- **Generating rules** uses your configured model via env vars
  (`XAF_MODEL`, `XAF_BASE_URL`, `OPENAI_API_KEY`) — same as the CLI generator.
- **Approvals** are recorded in `ui/state/approvals.json`; approved rules are
  appended to `rules/custom/auto_approved.conf` (the generator's
  `auto_rules.conf` is never overwritten by the UI).
- The Attack Simulator can re-cluster and regenerate, but turning a freshly-fired
  request into `parsed_logs.json` depends on your parser step — wire that in once
  the parser writes the full audit log (today `parser/test.py` only reads one line).
