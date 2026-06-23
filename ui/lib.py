"""
XAF Operator Console — data + integration layer
------------------------------------------------
Everything the Streamlit pages need to read the pipeline's output files,
inspect Docker, fire test payloads, run pipeline steps and reuse the
generator's functional validation. Pure functions, no Streamlit imports,
so they're easy to test and reason about.

Path model: this file lives in <ROOT>/ui/, so ROOT is its parent's parent.
All pipeline artefacts are addressed relative to ROOT.
"""

from __future__ import annotations

import json
import re
import sys
import glob
import importlib.util
import subprocess
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent

# --- pipeline artefacts (match the existing scripts' defaults) ---
PARSED_LOGS   = ROOT / "output" / "parsed_logs.json"
CLUSTERED_CSV = ROOT / "output" / "clustered_attacks.csv"
PROMPT_LOG    = ROOT / "output" / "prompts"
RULES_DIR     = ROOT / "rules" / "custom"
GENERATED_CONF = RULES_DIR / "auto_sqli.conf"        # generator's primary output
APPROVED_CONF  = RULES_DIR / "auto_approved.conf"    # operator-approved, deployable rules
# zz_ prefix => loads AFTER the rules above, so SecRuleRemoveById can roll them back
DISABLED_CONF  = RULES_DIR / "zz_disabled.conf"
MANUAL_CONF    = RULES_DIR / "manual.conf"           # analyst-crafted rules
MANUAL_ID_BASE = 1100000                              # manual IDs live above the generator's 1000000+

# --- operator state (approvals live here, never touched by the pipeline) ---
STATE_DIR  = Path(__file__).resolve().parent / "state"
STATE_FILE = STATE_DIR / "approvals.json"

# --- scripts we can trigger from the UI ---
SCRIPTS = {
    "cluster":  ROOT / "clustering" / "cluster_attacks.py",
    "generate": ROOT / "generator" / "generate_modsec_rules_llm.py",
}

# Matches "# Cluster 3" and "# Cluster 3 / time_based" headers + the SecRule
# that follows (same shape the generator writes and compare_models.py reads).
BLOCK_RE = re.compile(r"# Cluster (\d+)(?:\s*/\s*(\w+))?\s*\n(SecRule.*?)(?=\n# Cluster |\Z)", re.S)


# ----------------------------------------------------------------------------
# generator reuse — import the module so we share its validation helpers
# ----------------------------------------------------------------------------
_GEN = None


def generator():
    """Lazily import the generator module so we reuse functional_validate,
    extract_regex, compile_pattern and attack_signature instead of forking them."""
    global _GEN
    if _GEN is None:
        spec = importlib.util.spec_from_file_location(
            "xaf_gen", SCRIPTS["generate"])
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _GEN = mod
    return _GEN


# ----------------------------------------------------------------------------
# readers — every one degrades gracefully when its file is missing
# ----------------------------------------------------------------------------
def load_attacks() -> pd.DataFrame:
    """Parsed attacks. Prefers the clustered CSV (it adds a `cluster` column);
    falls back to parsed_logs.json; returns an empty frame if neither exists."""
    if CLUSTERED_CSV.exists():
        df = pd.read_csv(CLUSTERED_CSV)
    elif PARSED_LOGS.exists():
        df = pd.DataFrame(json.loads(PARSED_LOGS.read_text(encoding="utf-8")))
    else:
        return pd.DataFrame()

    for col in ("payload", "uri", "status", "rule_id", "rule_msg", "timestamp", "method"):
        if col not in df.columns:
            df[col] = ""
    if "cluster" not in df.columns:
        df["cluster"] = pd.NA
    df["status"] = df["status"].fillna("").astype(str)
    return df


def attack_metrics(df: pd.DataFrame) -> dict:
    """KPI numbers for the dashboard, computed from real rows."""
    if df.empty:
        return {"total": 0, "blocked": 0, "bypassed": 0, "unique": 0, "clusters": 0}
    status = df["status"].str.lower()
    clusters = df["cluster"].dropna()
    n_clusters = clusters[clusters.astype(str) != "-1"].nunique() if not clusters.empty else 0
    return {
        "total": len(df),
        "blocked": int((status == "blocked").sum()),
        "bypassed": int((status == "bypassed").sum()),
        "unique": int(df["payload"].astype(str).nunique()),
        "clusters": int(n_clusters),
    }


def coverage_over_time(df: pd.DataFrame) -> pd.DataFrame:
    """Cumulative CRS coverage as attacks arrive: for each attack (in time order)
    the running % that were caught (status == blocked). Returns columns
    [time, coverage]. Falls back to attack order if timestamps don't parse."""
    if df.empty:
        return pd.DataFrame(columns=["time", "coverage"])
    d = df.copy()
    d["_ts"] = pd.to_datetime(d["timestamp"], errors="coerce")
    if d["_ts"].notna().any():
        d = d.sort_values("_ts")
        x = d["_ts"].to_numpy()
    else:
        d = d.reset_index(drop=True)
        x = range(1, len(d) + 1)
    caught = (d["status"].str.lower() == "blocked").astype(int).to_numpy()
    seen = range(1, len(d) + 1)
    coverage = (caught.cumsum() / list(seen) * 100).round(1)
    return pd.DataFrame({"time": x, "coverage": coverage})


def top_endpoints(df: pd.DataFrame, n: int = 8) -> pd.DataFrame:
    """Most-targeted endpoints by request count. The endpoint is the URI path
    with any query string stripped. Returns columns [endpoint, hits]."""
    if df.empty:
        return pd.DataFrame(columns=["endpoint", "hits"])
    ep = (df["uri"].astype(str).str.split("?").str[0]
          .replace("", "/"))
    return (ep.value_counts().head(n)
            .rename_axis("endpoint").reset_index(name="hits"))


def attacks_per_minute(df: pd.DataFrame) -> pd.DataFrame:
    """Attack counts bucketed per minute, split into Blocked vs Uncaught, ready
    for a stacked area chart. Index is the minute; columns are Blocked, Uncaught.
    Empty frame if no timestamps parse."""
    if df.empty:
        return pd.DataFrame()
    d = df.copy()
    d["_ts"] = pd.to_datetime(d["timestamp"], errors="coerce")
    d = d[d["_ts"].notna()]
    if d.empty:
        return pd.DataFrame()
    d["_label"] = d["status"].str.lower().map({"blocked": "Blocked", "bypassed": "Uncaught"})
    d = d[d["_label"].notna()]
    g = (d.groupby([pd.Grouper(key="_ts", freq="1min"), "_label"]).size()
         .unstack(fill_value=0))
    for col in ("Blocked", "Uncaught"):
        if col not in g.columns:
            g[col] = 0
    g = g[["Blocked", "Uncaught"]]
    g.index.name = "minute"
    return g


def load_cluster_payloads() -> dict[int, list[str]]:
    """Per-cluster payloads. Prefers output/cluster<N>_payloads.txt; otherwise
    derives them from the clustered CSV so the page still works."""
    out: dict[int, list[str]] = {}
    files = glob.glob(str(ROOT / "output" / "cluster*_payloads.txt"))
    for f in files:
        m = re.search(r"cluster(-?\d+)_payloads", Path(f).name)
        if not m:
            continue
        cid = int(m.group(1))
        out[cid] = [l.rstrip("\n") for l in Path(f).read_text(encoding="utf-8").splitlines() if l.strip()]
    if out:
        return dict(sorted(out.items()))

    if CLUSTERED_CSV.exists():
        df = load_attacks()
        if "cluster" in df.columns:
            for cid, grp in df.groupby("cluster"):
                try:
                    cid = int(cid)
                except (ValueError, TypeError):
                    continue
                if cid == -1:
                    continue
                out[cid] = sorted(set(grp["payload"].astype(str)))
    return dict(sorted(out.items()))


def cluster_signature_label(payloads: list[str]) -> str:
    """Human label for a cluster, derived from the generator's attack_signature."""
    gen = generator()
    sigs = {gen.attack_signature(p) for p in payloads}
    pretty = {
        "union": "Union-based", "time_based": "Time-based blind",
        "error_based": "Error-based", "boolean_or": "Boolean OR",
        "boolean_and": "Boolean AND", "other": "Mixed / other",
    }
    return " · ".join(sorted(pretty.get(s, s) for s in sigs))


def load_deployed_rules() -> list[dict]:
    """SecRule blocks written to the deployable confs. Each carries its rule ID
    and whether the operator has rolled it back (disabled)."""
    disabled = disabled_ids()
    rules = []
    for conf in (GENERATED_CONF, APPROVED_CONF, MANUAL_CONF):
        if not conf.exists():
            continue
        text = conf.read_text(encoding="utf-8")
        for cid, sub, rule in BLOCK_RE.findall(text):
            m = re.search(r"id:(\d+)", rule)
            rid = m.group(1) if m else None
            rules.append({"id": rid, "cluster": int(cid), "subgroup": sub or None,
                          "rule": rule.strip(), "source": conf.name,
                          "disabled": rid in disabled})
    return rules


def disabled_ids() -> set[str]:
    """Rule IDs the operator has rolled back (kept in operator state)."""
    return set(_read_state().get("disabled", []))


def set_rule_disabled(rule_id: str, disabled: bool) -> None:
    """Roll a rule back (disable) or restore it, then rewrite zz_disabled.conf.
    Caller should reload ModSecurity afterwards for the change to take effect."""
    state = _read_state()
    ids = set(state.get("disabled", []))
    if disabled:
        ids.add(str(rule_id))
    else:
        ids.discard(str(rule_id))
    state["disabled"] = sorted(ids)
    _write_state(state)
    _write_disabled_conf(ids)


def _write_disabled_conf(ids: set[str]) -> None:
    RULES_DIR.mkdir(parents=True, exist_ok=True)
    lines = [
        "# XAF disabled rules — auto-managed by the operator console.",
        "# Loads after the generated rules (zz_ prefix) so SecRuleRemoveById",
        "# can remove them. Reload ModSecurity to apply.",
        "",
    ]
    lines += [f"SecRuleRemoveById {rid}" for rid in sorted(ids)]
    DISABLED_CONF.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ----------------------------------------------------------------------------
# analyst-crafted rules — write your own SecRule, validate, optionally ask the
# LLM for a second opinion, then deploy it for a chosen cluster
# ----------------------------------------------------------------------------
def next_manual_id() -> int:
    """Next free rule ID in the manual band, scanning all deployable confs."""
    ids = []
    for conf in (GENERATED_CONF, APPROVED_CONF, MANUAL_CONF):
        if conf.exists():
            ids += [int(x) for x in re.findall(r"id:(\d+)", conf.read_text(encoding="utf-8"))]
    manual = [i for i in ids if i >= MANUAL_ID_BASE]
    return max(manual) + 1 if manual else MANUAL_ID_BASE


def review_manual_rule(rule_text: str, cluster: int, rule_id: int) -> dict:
    """Run the SAME gate generated rules pass: structural check, then the
    generator's functional_validate (regex compiles, matches every payload in
    the cluster, no benign false positives). Returns a result dict; `cleaned`
    is the normalised rule (fences stripped, id forced) ready to deploy."""
    gen = generator()
    cleaned = gen.clean_rule(rule_text, rule_id)
    out = {"cleaned": cleaned, "structural_ok": bool(cleaned and gen.validate_rule(cleaned)),
           "valid": None, "missed": [], "false_pos": [], "error": None, "scope": 0}
    if not out["structural_ok"]:
        out["error"] = "Not a structurally valid SecRule (needs SecRule, id, phase, deny)."
        return out
    scope = load_cluster_payloads().get(cluster, [])
    out["scope"] = len(scope)
    if not scope:
        out["error"] = "No payloads for this cluster to validate against."
        return out
    ok, missed, false_pos, err = gen.functional_validate(cleaned, scope)
    out.update({"valid": ok, "missed": missed, "false_pos": false_pos, "error": err})
    return out


def llm_review_rule(rule_text: str, payloads: list[str]) -> dict:
    """Advisory only — ask the configured model to critique a crafted rule.
    Never gates deployment; functional validation is the real check."""
    gen = generator()
    try:
        from openai import OpenAI
        client = (OpenAI(api_key=gen.API_KEY, base_url=gen.BASE_URL)
                  if gen.BASE_URL else OpenAI(api_key=gen.API_KEY))
        system = ("You are a senior WAF engineer reviewing a ModSecurity rule. "
                  "Give concise, actionable feedback. Do not rewrite the rule unless asked.")
        user = (
            "Sample attack payloads the rule should catch:\n"
            f"{json.dumps(payloads[:20], indent=2)}\n\n"
            f"Rule under review:\n{rule_text}\n\n"
            "Assess: (1) does the regex plausibly catch these payloads and common evasions, "
            "(2) false-positive risk on benign input, (3) ReDoS / performance risk, "
            "(4) concrete improvements. Keep it short."
        )
        resp = client.chat.completions.create(
            model=gen.MODEL, temperature=0,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user}],
        )
        return {"ok": True, "text": resp.choices[0].message.content}
    except Exception as e:  # noqa: BLE001 — surface any API/config error to the UI
        return {"ok": False, "error": str(e)}


def deploy_manual_rule(cleaned_rule: str, cluster: int) -> Path:
    """Append a validated, analyst-crafted rule to manual.conf (tagged with its
    cluster so it shows in the deployed list and can be rolled back by ID)."""
    MANUAL_CONF.parent.mkdir(parents=True, exist_ok=True)
    header = "# XAF manual (analyst-crafted) rules\n\n"
    existing = MANUAL_CONF.read_text(encoding="utf-8") if MANUAL_CONF.exists() else header
    existing += f"# Cluster {cluster}\n{cleaned_rule}\n\n"
    MANUAL_CONF.write_text(existing, encoding="utf-8")
    return MANUAL_CONF


def count_deployed_rules() -> int:
    return len(load_deployed_rules())


# ----------------------------------------------------------------------------
# rule queue + approval workflow (operator state)
# ----------------------------------------------------------------------------
def _read_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


def _write_state(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def load_rule_queue() -> list[dict]:
    """Build the review queue from the generator's trace files in output/prompts/.
    Each item carries its prompt, raw response, cleaned rule and approval status,
    plus live functional-validation against that cluster's payloads."""
    state = _read_state()
    payloads_by_cluster = load_cluster_payloads()
    gen = generator()

    queue = []
    for rule_file in sorted(glob.glob(str(PROMPT_LOG / "cluster_*_rule.conf"))):
        key = Path(rule_file).stem.replace("_rule", "")          # e.g. cluster_0  /  cluster_0_union
        cid_match = re.search(r"cluster_(-?\d+)", key)
        cid = int(cid_match.group(1)) if cid_match else None

        rule = Path(rule_file).read_text(encoding="utf-8").strip()
        if not rule:
            continue
        prompt_file = PROMPT_LOG / f"{key}_prompt.txt"
        resp_file = PROMPT_LOG / f"{key}_response.txt"

        scope = payloads_by_cluster.get(cid, []) if cid is not None else []
        ok, missed, false_pos, err = gen.functional_validate(rule, scope) if scope else (None, [], [], None)

        queue.append({
            "id": key,
            "cluster": cid,
            "rule": rule,
            "prompt": prompt_file.read_text(encoding="utf-8") if prompt_file.exists() else "",
            "response": resp_file.read_text(encoding="utf-8") if resp_file.exists() else "",
            "status": state.get(key, {}).get("status", "pending"),
            "scope_size": len(scope),
            "valid": ok,
            "missed": missed,
            "false_pos": false_pos,
            "error": err,
        })
    return queue


def approve_rule(item: dict) -> Path:
    """Append the rule to the approved conf (deduping by id) and record it."""
    APPROVED_CONF.parent.mkdir(parents=True, exist_ok=True)
    header = f"# {item['id']} (approved via operator console)\n"
    block = f"{header}{item['rule']}\n\n"

    existing = APPROVED_CONF.read_text(encoding="utf-8") if APPROVED_CONF.exists() else \
        "# XAF operator-approved rules\n\n"
    if header not in existing:
        existing += block
        APPROVED_CONF.write_text(existing, encoding="utf-8")

    state = _read_state()
    state[item["id"]] = {"status": "approved"}
    _write_state(state)
    return APPROVED_CONF


def reject_rule(item: dict) -> None:
    state = _read_state()
    state[item["id"]] = {"status": "rejected"}
    _write_state(state)


# ----------------------------------------------------------------------------
# environment actions — docker, firing payloads, running pipeline steps
# ----------------------------------------------------------------------------
def docker_status() -> dict:
    """Which expected containers are up. 'unknown' if docker isn't reachable."""
    want = ["nginx-modsec", "juice"]
    try:
        out = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=8,
        )
        running = set(out.stdout.split())
        return {name: ("up" if name in running else "down") for name in want}
    except (FileNotFoundError, subprocess.SubprocessError):
        return {name: "unknown" for name in want}


def fire_payload(payload: str, path: str = "/rest/products/search", param: str = "q",
                 base: str = "http://localhost") -> dict:
    """Send one request through nginx-modsec. 403 == blocked, anything else == bypassed."""
    import requests
    url = f"{base}{path}"
    try:
        r = requests.get(url, params={param: payload}, timeout=8)
        return {
            "ok": True,
            "status_code": r.status_code,
            "blocked": r.status_code == 403,
            "url": r.url,
        }
    except requests.RequestException as e:
        return {"ok": False, "error": str(e), "url": url}


def run_script(name: str, extra_env: dict | None = None, timeout: int = 600) -> dict:
    """Run a pipeline script with the current Python interpreter from ROOT."""
    script = SCRIPTS.get(name)
    if not script or not script.exists():
        return {"ok": False, "stdout": "", "stderr": f"script not found: {name}", "code": -1}
    import os
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    try:
        proc = subprocess.run(
            [sys.executable, str(script)],
            cwd=str(ROOT), capture_output=True, text=True, timeout=timeout, env=env,
        )
        return {"ok": proc.returncode == 0, "stdout": proc.stdout,
                "stderr": proc.stderr, "code": proc.returncode}
    except subprocess.TimeoutExpired:
        return {"ok": False, "stdout": "", "stderr": f"timed out after {timeout}s", "code": -1}


def reload_modsecurity(container: str = "nginx-modsec") -> dict:
    """Restart the WAF container so newly-approved rules take effect."""
    try:
        proc = subprocess.run(
            ["docker", "restart", container],
            capture_output=True, text=True, timeout=60,
        )
        return {"ok": proc.returncode == 0, "stdout": proc.stdout, "stderr": proc.stderr}
    except (FileNotFoundError, subprocess.SubprocessError) as e:
        return {"ok": False, "stdout": "", "stderr": str(e)}
