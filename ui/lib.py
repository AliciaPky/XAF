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
import os
import re
import sys
import glob
import importlib.util
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

import pandas as pd
import requests

ROOT = Path(__file__).resolve().parent.parent


def _load_env(path: Path) -> None:
    """Load KEY=VALUE lines from .env into os.environ without overriding existing
    vars. Tiny and dependency-free — the UI has no python-dotenv, but the pages
    still need TELEGRAM_* (and any OPENAI_* overrides) from .env at runtime."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


_load_env(ROOT / ".env")

# --- pipeline artefacts (match the existing scripts' defaults) ---
PARSED_LOGS   = ROOT / "output" / "parsed_logs.json"
CLUSTERED_CSV = ROOT / "output" / "clustered_attacks.csv"
PROMPT_LOG    = ROOT / "output" / "prompts"
RULES_DIR     = ROOT / "rules" / "custom"
# The console reflects every *.conf the WAF loads from RULES_DIR (see
# deployed_confs()), so no single "generator output" path is hardcoded — the
# generator's filename can change without hiding rules from the operator.
# zz_ prefix => loads AFTER the rules above, so SecRuleRemoveById can roll them back
DISABLED_CONF  = RULES_DIR / "zz_disabled.conf"
MANUAL_CONF    = RULES_DIR / "manual.conf"           # analyst-crafted rules
APPROVED_CONF  = RULES_DIR / "auto_approved.conf"    # generated rules the operator has approved
MANUAL_ID_BASE = 1100000                              # manual IDs live above the generator's 1000000+

# --- operator state (approvals live here, never touched by the pipeline) ---
STATE_DIR  = Path(__file__).resolve().parent / "state"
STATE_FILE = STATE_DIR / "approvals.json"

# --- scripts we can trigger from the UI ---
SCRIPTS = {
    "parse":    ROOT / "parser" / "parse_audit_log_json.py",
    "cluster":  ROOT / "clustering" / "cluster_attacks.py",
    "generate": ROOT / "generator" / "generate_modsec_rules_llm.py",
}

# --- attack lab: where the simulator gets its ammunition and how it fires ---
DEFAULT_BASE = "http://localhost:8080"     # the WAF proxy — NOT the LMS (:5000)
LMS_USER, LMS_PASS = "student1", "pass123"  # session for authenticated sinks

# The project's own attack scripts double as the payload catalog, so the
# simulator fires exactly what the traffic generators do (single source of truth).
ATTACK_SCRIPTS = {
    "sqli": ROOT / "attackScript.py",
}

# Attack vectors = how a payload reaches the WAF. Mirrors the sinks the
VECTORS = {
    "courses_q":      {"method": "GET",  "path": "/courses",    "param": "q",        "auth": False, "label": "GET /courses?q="},
    "login_username": {"method": "POST", "path": "/login",      "param": "username", "auth": False, "extra": {"password": "wrongpass"}, "label": "POST /login · username"},
    "login_password": {"method": "POST", "path": "/login",      "param": "password", "auth": False, "extra": {"username": "admin"},     "label": "POST /login · password"},
    "xss_search":     {"method": "GET",  "path": "/xss-search", "param": "q",        "auth": True,  "label": "GET /xss-search?q="},
    "feedback":       {"method": "POST", "path": "/feedback",   "param": "message",  "auth": True,  "label": "POST /feedback · message"},
}

# One deployed SecRule plus the comment lines directly above it. The cluster
# number in that comment is OPTIONAL metadata — headers vary ("# Cluster 3",
# "# Cluster 3 / sub", "# Cluster 15 (note) — ...", or an approval/manual header
# with no cluster at all) — so EVERY deployed rule is captured regardless of how
# its header is worded. Handles single-line and backslash-continued SecRules.
RULE_BLOCK_RE = re.compile(
    r"(?P<comments>(?:^[ \t]*#[^\n]*\n)*)"
    r"(?P<rule>^[ \t]*SecRule\b.*?)"
    r"(?=\n[ \t]*#|\n[ \t]*SecRule|\n[ \t]*\n|\Z)",
    re.M | re.S,
)
CLUSTER_RE = re.compile(r"Cluster\s+(\d+)(?:\s*/\s*(\w+))?", re.I)


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
# attack lab — the payload catalog, drawn from the project's own attack scripts
# ----------------------------------------------------------------------------
_ATTACK_MODS: dict[str, object] = {}


def _attack_module(key: str):
    """Import an attackScript_*.py by path (like generator()) so its payload
    dicts are reused verbatim rather than copied into the UI."""
    if key not in _ATTACK_MODS:
        spec = importlib.util.spec_from_file_location(f"xaf_attack_{key}", ATTACK_SCRIPTS[key])
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _ATTACK_MODS[key] = mod
    return _ATTACK_MODS[key]


def attack_catalog() -> dict:
    """Payload catalog for the simulator, grouped attack type -> {vector,
    families{family: [payloads]}, benign[]}. This is the same ammunition the
    attackScript*.py generators fire at the WAF, surfaced for the console."""
    mod = _attack_module("sqli")  # single merged attackScript.py holds all families
    return {
        "sqli": {"vector": "courses_q",  "families": dict(mod.SQLI_PAYLOADS), "benign": list(mod.BENIGN_SQLI)},
        "xss":  {"vector": "xss_search", "families": dict(mod.XSS_PAYLOADS),  "benign": list(mod.BENIGN_XSS)},
        "ssti": {"vector": "feedback",   "families": dict(mod.SSTI_PAYLOADS), "benign": list(mod.BENIGN_XSS)},
    }


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
    df["timestamp"] = _to_malaysia_time(df["timestamp"])
    return df


# Malaysia Time is a fixed UTC+8 (no DST since 1982), so a plain 8-hour shift is
# exact and needs no tz database.
_MYT_OFFSET = pd.Timedelta(hours=8)


def _to_malaysia_time(ts_col: pd.Series) -> pd.Series:
    """ModSecurity stamps audit records with the container's UTC clock (e.g.
    'Fri Jul 10 15:05:32 2026'). The operator is in Malaysia, so shift those
    naive UTC timestamps to MYT and re-emit them in the same string format.
    Rows whose timestamp doesn't parse are passed through untouched."""
    parsed = pd.to_datetime(ts_col, errors="coerce")
    mask = parsed.notna()
    if not mask.any():
        return ts_col
    out = ts_col.astype(object).copy()
    out.loc[mask] = (parsed[mask] + _MYT_OFFSET).dt.strftime("%a %b %d %H:%M:%S %Y")
    return out


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


def attack_type_breakdown(df: pd.DataFrame) -> pd.DataFrame:
    """Counts per attack family (sqli / xss / ssti / …) for the donut. Uses the
    `family` column the clustering step writes; empty frame if it isn't there."""
    if df.empty or "family" not in df.columns:
        return pd.DataFrame(columns=["family", "count"])
    fam = df["family"].fillna("").astype(str).str.strip()
    fam = fam[fam != ""]
    if fam.empty:
        return pd.DataFrame(columns=["family", "count"])
    return fam.value_counts().rename_axis("family").reset_index(name="count")


def clustered_count(df: pd.DataFrame) -> int:
    """How many attacks landed in a real cluster (DBSCAN label != -1 noise)."""
    if df.empty or "cluster" not in df.columns:
        return 0
    cid = pd.to_numeric(df["cluster"], errors="coerce")
    return int((cid.fillna(-1) != -1).sum())


def generated_rules_count() -> int:
    """Rules the generator has produced — non-empty cluster_*_rule.conf traces.
    Cheap count for the dashboard (no functional validation, unlike the queue)."""
    n = 0
    for f in glob.glob(str(PROMPT_LOG / "cluster_*_rule.conf")):
        if Path(f).read_text(encoding="utf-8").strip():
            n += 1
    return n


def approval_counts() -> dict:
    """Approval-workflow tallies from operator state: approved / rejected / pending.
    Reads the same state file the Rule Approval page writes, so counts stay in sync
    without running the (heavier) load_rule_queue validation path."""
    state = _read_state()
    counts = {"approved": 0, "rejected": 0, "pending": 0}
    for key, val in state.items():
        if not isinstance(val, dict) or "status" not in val:   # skips "disabled" list
            continue
        s = str(val.get("status", "pending"))
        counts[s] = counts.get(s, 0) + 1
    return counts


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


def deployed_confs() -> list[Path]:
    """Every *.conf the WAF actually loads from the custom-rules dir (the WAF
    includes `custom-rules/*.conf`). The console should reflect exactly this, not
    a hardcoded subset — otherwise rules the generator writes to another filename
    (e.g. auto_rules.conf) go live but never appear in the operator UI."""
    return sorted(RULES_DIR.glob("*.conf"))


def _parse_conf(path: Path, disabled=frozenset()) -> list[dict]:
    """Parse the SecRule blocks out of one .conf file into rule dicts (id, cluster,
    subgroup, rule text, source filename, disabled flag). Shared by the live-rules
    reader (rules/custom) and the candidate reader (rules/experiments)."""
    out = []
    if not path.exists():
        return out
    text = path.read_text(encoding="utf-8")
    for m in RULE_BLOCK_RE.finditer(text):
        rule = m.group("rule").strip()
        idm = re.search(r"id:\s*(\d+)", rule)
        if not idm:                       # not a real rule (e.g. stray comment)
            continue
        rid = idm.group(1)
        cm = CLUSTER_RE.search(m.group("comments") or "")
        cid = int(cm.group(1)) if cm else None
        sub = cm.group(2) if cm else None
        out.append({"id": rid, "cluster": cid, "subgroup": sub, "rule": rule,
                    "source": path.name, "disabled": rid in disabled})
    return out


def load_deployed_rules() -> list[dict]:
    """SecRule blocks the WAF loads from rules/custom/. Each carries its rule ID
    and whether the operator has rolled it back (disabled)."""
    disabled = disabled_ids()
    rules = []
    for conf in deployed_confs():
        rules += _parse_conf(conf, disabled)
    return rules


def candidates_conf() -> Path:
    """The generator's output file — CANDIDATE rules awaiting approval. It lives
    OUTSIDE rules/custom (e.g. rules/experiments/auto_rules.conf) so the WAF does
    NOT load it; only an operator Approve promotes a rule into rules/custom to go
    live. Follows generator.OUTPUT_FILE so it tracks the configured path."""
    p = Path(generator().OUTPUT_FILE)
    return p if p.is_absolute() else (ROOT / p)


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
    for conf in deployed_confs():
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
    scope = csv_cluster_payloads().get(cluster, [])
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
    except Exception as e: 
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
    plus its family/subgroup and live functional-validation against that cluster's
    payloads (from the clustered CSV, subgroup-aware — same source as the finalized
    rules, so both review surfaces agree)."""
    state = _read_state()
    families = cluster_families()
    gen = generator()

    # cluster -> payloads from the clustered CSV (complete, unlike the partial
    # cluster*_payloads.txt files), so every cluster can actually be validated.
    df = load_attacks()
    payloads_by_cluster: dict[int, list[str]] = {}
    if not df.empty and "cluster" in df.columns:
        for pc, grp in df.groupby("cluster"):
            try:
                pc = int(pc)
            except (ValueError, TypeError):
                continue
            if pc == -1:
                continue
            payloads_by_cluster[pc] = sorted({str(p) for p in grp["payload"] if str(p).strip()})

    queue = []
    for rule_file in sorted(glob.glob(str(PROMPT_LOG / "cluster_*_rule.conf"))):
        key = Path(rule_file).stem.replace("_rule", "")          # e.g. cluster_0  /  cluster_0_union
        cid_match = re.search(r"cluster_(-?\d+)", key)
        cid = int(cid_match.group(1)) if cid_match else None
        subgroup = key.replace(f"cluster_{cid}", "", 1).lstrip("_") if cid is not None else ""

        rule = Path(rule_file).read_text(encoding="utf-8").strip()
        if not rule:
            continue
        prompt_file = PROMPT_LOG / f"{key}_prompt.txt"
        resp_file = PROMPT_LOG / f"{key}_response.txt"

        scope = payloads_by_cluster.get(cid, []) if cid is not None else []
        if subgroup and scope:                      # narrow to the subgroup it covers
            scope = [p for p in scope if gen.attack_signature(p) == subgroup]
        ok, missed, false_pos, err = gen.functional_validate(rule, scope) if scope else (None, [], [], None)

        queue.append({
            "id": key,
            "cluster": cid,
            "subgroup": subgroup or None,
            "family": families.get(cid),
            "rule": rule,
            "prompt": prompt_file.read_text(encoding="utf-8") if prompt_file.exists() else "",
            "response": resp_file.read_text(encoding="utf-8") if resp_file.exists() else "",
            "status": state.get(key, {}).get("status", "pending"),
            "scope": scope,
            "scope_size": len(scope),
            "valid": ok,
            "missed": missed,
            "false_pos": false_pos,
            "error": err,
        })
    return queue


def telegram_configured() -> bool:
    """True when a bot token and chat id are both set (in .env or the environment)."""
    return bool(os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_CHAT_ID"))


def send_telegram(text: str, *, timeout: float = 8.0) -> dict:
    """Send a Markdown message to the configured Telegram chat. Returns
    {'ok': bool, 'error': str|None}; a no-op (ok=False) when not configured."""
    token = (os.getenv("TELEGRAM_BOT_TOKEN") or "").strip()
    chat = (os.getenv("TELEGRAM_CHAT_ID") or "").strip()
    if not token or not chat:
        return {"ok": False, "error": "Telegram not configured — set TELEGRAM_BOT_TOKEN "
                                       "and TELEGRAM_CHAT_ID in .env."}
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data={"chat_id": chat, "text": text, "parse_mode": "Markdown",
                  "disable_web_page_preview": True},
            timeout=timeout)
        if r.status_code == 200 and r.json().get("ok"):
            return {"ok": True, "error": None}
        return {"ok": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
    except Exception as e:  
        return {"ok": False, "error": str(e)}


def _alerts_path() -> Path:
    return STATE_DIR / "alerts.json"


def _read_alerts_state() -> dict:
    try:
        return json.loads(_alerts_path().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _write_alerts_state(state: dict) -> None:
    _alerts_path().parent.mkdir(parents=True, exist_ok=True)
    _alerts_path().write_text(json.dumps(state, indent=2), encoding="utf-8")


def _uncaught_attacks() -> list[dict]:
    """Attacks that bypassed CRS, de-duplicated by attack PATTERN — endpoint path +
    payload — not per request. The same payload replayed many times is ONE
    alert-worthy event; keying on the per-request unique_id (or timestamp) used to
    flood Telegram with an alert for every repeated request of the same payload."""
    df = load_attacks()
    if df.empty or "status" not in df.columns:
        return []
    hits = df[df["status"].astype(str).str.lower() == "bypassed"]
    out, seen = [], set()
    for _, r in hits.iterrows():
        uri = str(r.get("uri", ""))
        payload = str(r.get("payload", ""))
        key = f"{uri.split('?', 1)[0]}|{payload}"   # path + payload, stable across requests
        if key in seen:                             # collapse repeats within this batch too
            continue
        seen.add(key)
        out.append({"key": key, "uri": uri, "payload": payload})
    return out


ALERT_TYPES = ("attack", "candidate", "deployed")   # the toggle-able alert kinds


def get_alert_settings() -> dict:
    """Notification prefs: a master 'enabled' flag + one flag per alert type
    (attack / candidate / deployed). All default on."""
    s = _read_alerts_state().get("settings") or {}
    out = {"enabled": s.get("enabled", True)}
    out.update({t: s.get(t, True) for t in ALERT_TYPES})
    return out


def set_alert_settings(**flags) -> None:
    """Persist notification prefs (enabled / attack / candidate / deployed),
    merging into whatever's already stored."""
    state = _read_alerts_state()
    cur = state.get("settings") or {}
    cur.update({k: bool(v) for k, v in flags.items()})
    state["settings"] = cur
    _write_alerts_state(state)


_alert_lock = threading.Lock()


def _rule_alert_key(r: dict) -> str:
    """Stable de-dup key for a rule alert (candidate OR deployed). Keyed on the
    CLUSTER, not the rule ID: the generator assigns IDs positionally over the sorted
    clusters, so adding/removing one cluster shifts every later ID — an ID-keyed
    alert would then re-fire Telegram notifications for clusters already announced,
    and re-announce the same rule on every regeneration. Cluster keys stay put across
    regenerations. Falls back to the rule ID only for a rule with no cluster (e.g.
    hand-crafted)."""
    k = cluster_key(r.get("cluster"), r.get("subgroup"))
    return k or f"id:{r.get('id')}"


def run_alert_checks() -> list[str]:
    """Thread-safe wrapper: both the UI rerun and the scheduler thread call this,
    so serialize the read-modify-write of state/alerts.json."""
    with _alert_lock:
        return _run_alert_checks()


def _run_alert_checks() -> list[str]:
    """Send a Telegram alert for each NEW event since the last check — an uncaught
    attack, a candidate rule awaiting approval, or a newly deployed rule — subject
    to the operator's notification settings. Idempotent per event (tracked in
    state/alerts.json). On first run, or while an alert type is switched off, it
    silently records events as seen so nothing floods the chat when re-enabled.
    No-op unless Telegram is configured. Returns the kinds of alerts sent."""
    if not telegram_configured():
        return []
    s = get_alert_settings()

    fam_disp = {"sqli": "SQLi", "xss": "XSS", "ssti": "SSTI"}
    fams = cluster_families()
    uncaught = _uncaught_attacks()
    cand = _parse_conf(candidates_conf())                         # light: no validation
    deployed = [d for d in load_deployed_rules() if not d["disabled"]]

    cur_a = {a["key"] for a in uncaught}
    cur_c = {_rule_alert_key(c) for c in cand}      # keyed on cluster, not the volatile rule ID
    cur_d = {_rule_alert_key(d) for d in deployed}  # same — a regen renumbers IDs, cluster stays

    def _save(a, c, d):                                           # preserve settings
        st = _read_alerts_state()
        st.update({"initialized": True, "attacks": list(a),
                   "candidates": list(c), "deployed": list(d)})
        _write_alerts_state(st)

    state = _read_alerts_state()
    # One-time migration: deployed alerts switched from volatile rule-ID keys to
    # stable cluster keys. Adopt the currently-deployed set as the baseline so the
    # change doesn't re-announce every already-live rule exactly once.
    if not state.get("deployed_cluster_keyed"):
        state["deployed"] = list(cur_d)
        state["deployed_cluster_keyed"] = True
        _write_alerts_state(state)

    # First run OR notifications fully off: keep the baseline current (consume events
    # silently) so re-enabling doesn't dump everything that happened while off.
    if not state.get("initialized") or not s["enabled"]:
        _save(cur_a, cur_c, cur_d)
        return []

    seen_a, seen_c, seen_d = (set(state.get("attacks", [])),
                              set(state.get("candidates", [])),
                              set(state.get("deployed", [])))
    sent = []
    # Per type: if on, alert new ones (mark seen on success, [:5] to drain bursts);
    # if off, mark all seen so turning it back on doesn't replay the backlog.
    if s["attack"]:
        for a in [x for x in uncaught if x["key"] not in seen_a][:5]:
            p = (a["payload"][:120] + "…") if len(a["payload"]) > 120 else a["payload"]
            if send_telegram(f"⚠️ *Uncaught attack* (bypassed CRS)\n`{p}`\n→ `{a['uri']}`")["ok"]:
                sent.append("attack")
                seen_a.add(a["key"])
    else:
        seen_a |= cur_a

    if s["candidate"]:
        cand_by_key = {_rule_alert_key(c): c for c in cand}
        for ckey in [k for k in cur_c if k not in seen_c][:5]:
            c = cand_by_key[ckey]
            cl = f"Cluster {c['cluster']}" if c["cluster"] is not None else "rule"
            fam = fam_disp.get(str(fams.get(c["cluster"])).lower(), "")
            if send_telegram(f"🧩 *New rule candidate* awaiting approval\n{cl}"
                             f"{' · ' + fam if fam else ''}\nRule #{c['id']}")["ok"]:
                sent.append("candidate")
                seen_c.add(ckey)
    else:
        seen_c |= cur_c

    if s["deployed"]:
        dep_by_key = {_rule_alert_key(d): d for d in deployed}
        for dkey in [k for k in cur_d if k not in seen_d][:5]:
            d = dep_by_key[dkey]
            cl = f"Cluster {d['cluster']}" if d["cluster"] is not None else "rule"
            if send_telegram(f"✅ *Rule deployed* to the live WAF\n{cl} · Rule #{d['id']}")["ok"]:
                sent.append("deployed")
                seen_d.add(dkey)
    else:
        seen_d |= cur_d

    _save(seen_a, seen_c, seen_d)
    return sent


# --auto-generate scheduler--
SCHEDULER_INTERVAL = 60             # seconds between auto-runs
_scheduler_lock = threading.Lock()
_scheduler_thread = None

def _scheduler_path() -> Path:
    return STATE_DIR / "scheduler.json"

def get_scheduler_state() -> dict:
    try:
        s = json.loads(_scheduler_path().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        s = {}
    return {"enabled": bool(s.get("enabled", False)),
            "interval": int(s.get("interval", SCHEDULER_INTERVAL)),
            "last_run": s.get("last_run"), "last_ok": s.get("last_ok"),
            "last_msg": s.get("last_msg", ""), "runs": int(s.get("runs", 0)),
            "running": bool(s.get("running", False)), "step": s.get("step")}

def _write_scheduler_state(s: dict) -> None:
    _scheduler_path().parent.mkdir(parents=True, exist_ok=True)
    _scheduler_path().write_text(json.dumps(s, indent=2), encoding="utf-8")

def set_scheduler_enabled(enabled: bool) -> None:
    s = get_scheduler_state()
    s["enabled"] = bool(enabled)
    _write_scheduler_state(s)

# Full self-healing loop, in order. Halts at the first failing step.
_PIPELINE = ("parse", "cluster", "generate")

def _set_running(step: str | None) -> None:
    s = get_scheduler_state()
    s["running"], s["step"] = step is not None, step
    _write_scheduler_state(s)

def _do_scheduled_run() -> None:
    """One self-healing cycle: parse the audit log → re-cluster → generate candidate
    rules, halting at the first failing step. Records the outcome, then fires Telegram alerts"""
    ok, msg = True, ""
    try:
        for step in _PIPELINE:
            _set_running(step)
            res = run_script(step)
            if not res.get("ok"):
                ok, msg = False, f"{step} failed (exit {res.get('code')})"
                break
    except Exception as e:  
        ok, msg = False, str(e)[:200]
    if ok:
        msg = "parsed → clustered → generated"

    s = get_scheduler_state()          # re-read: enabled may have been toggled meanwhile
    s.update({"running": False, "step": None,
              "last_run": datetime.now().isoformat(timespec="seconds"),
              "last_ok": ok, "last_msg": msg, "runs": s.get("runs", 0) + 1})
    _write_scheduler_state(s)
    try:
        run_alert_checks()             # alert on new attacks / candidates, headless-safe
    except Exception:  
        pass


def _due(state: dict) -> bool:
    last = state.get("last_run")
    if not last:
        return True
    try:
        return (datetime.now() - datetime.fromisoformat(last)).total_seconds() >= state["interval"]
    except (ValueError, TypeError):
        return True


def _scheduler_loop() -> None:
    while True:
        try:
            s = get_scheduler_state()
            if s["enabled"] and _due(s):
                _do_scheduled_run()
        except Exception:  
            pass
        time.sleep(5)     # check every 5s, run when the interval elapses


def ensure_scheduler_running() -> None:
    """Start the background scheduler thread once. Idempotent — safe to call every
    Streamlit rerun. The thread idles while the toggle is off."""
    global _scheduler_thread
    with _scheduler_lock:
        if _scheduler_thread is None or not _scheduler_thread.is_alive():
            _scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True,
                                                 name="xaf-scheduler")
            _scheduler_thread.start()


def cluster_families() -> dict[int, str]:
    """cluster id -> attack family ('sqli' / 'xss' / 'ssti') from the clustered
    CSV's `family` column — the authoritative, complete classification (every
    cluster), unlike deriving it from the partial cluster*_payloads.txt files."""
    df = load_attacks()
    out: dict[int, str] = {}
    if df.empty or "cluster" not in df.columns or "family" not in df.columns:
        return out
    for cid, grp in df.groupby("cluster"):
        try:
            cid = int(cid)
        except (ValueError, TypeError):
            continue
        if cid == -1:
            continue
        fams = grp["family"].dropna().astype(str)
        fams = fams[fams.str.strip() != ""]
        if not fams.empty:
            out[cid] = fams.value_counts().index[0]
    return out


def csv_cluster_payloads() -> dict[int, list[str]]:
    """cluster id -> its payloads, from the clustered CSV (complete — every cluster,
    unlike the partial cluster*_payloads.txt files). Used to validate generated and
    analyst-crafted rules alike."""
    df = load_attacks()
    out: dict[int, list[str]] = {}
    if df.empty or "cluster" not in df.columns:
        return out
    for cid, grp in df.groupby("cluster"):
        try:
            cid = int(cid)
        except (ValueError, TypeError):
            continue
        if cid == -1:                              # DBSCAN noise, not a real cluster
            continue
        out[cid] = sorted({str(p) for p in grp["payload"] if str(p).strip()})
    return out


def _enrich_rules(rule_dicts: list[dict], *, with_status: bool = False) -> list[dict]:
    """Add the CSV family + subgroup-aware functional validation (and, optionally,
    approval status) to parsed rule dicts. Shared by the live-rules and candidate
    readers so both surfaces agree on family/validation."""
    gen = generator()
    family_by_cluster = cluster_families()
    payloads_by_cluster = csv_cluster_payloads()
    state = _read_state() if with_status else {}
    out = []
    for r in rule_dicts:
        cid = r["cluster"]
        scope = payloads_by_cluster.get(cid, []) if cid is not None else []
        if r.get("subgroup") and scope:            # narrow to the subgroup it covers
            scope = [p for p in scope if gen.attack_signature(p) == r["subgroup"]]
        ok, missed, false_pos, err = (gen.functional_validate(r["rule"], scope)
                                      if scope else (None, [], [], None))
        item = {**r, "family": family_by_cluster.get(cid),
                "scope": scope, "scope_size": len(scope),
                "valid": ok, "missed": missed, "false_pos": false_pos, "error": err}
        if with_status:
            item["status"] = state.get(r["id"], {}).get("status", "pending")
        out.append(item)
    return out


def load_finalized_rules() -> list[dict]:
    """LIVE rules — every SecRule the WAF actually loads from rules/custom/ (approved
    generated rules + analyst-crafted ones), enriched with family and subgroup-aware
    validation. This is the live set Rule Approval manages (roll back / restore)."""
    return _enrich_rules(load_deployed_rules())


def cluster_key(cluster, subgroup) -> str:
    """Stable coverage key for de-dup: '<cluster>' or '<cluster>/<subgroup>'. Empty
    for rules with no cluster (e.g. hand-crafted). Used instead of the rule ID, which
    the generator reassigns on every run."""
    if cluster is None:
        return ""
    return f"{cluster}" if not subgroup else f"{cluster}/{subgroup}"


def rejected_clusters() -> set:
    """Cluster keys the operator has rejected (so their candidates stay suppressed)."""
    return set(_read_state().get("rejected_clusters", []))


def set_cluster_rejected(ckey: str, rejected: bool) -> None:
    """Reject (or un-reject) a whole cluster's coverage. Keyed by cluster, so a regen
    that hands the same cluster a new rule ID still stays rejected / undo-able."""
    state = _read_state()
    rej = set(state.get("rejected_clusters", []))
    rej.add(ckey) if rejected else rej.discard(ckey)
    state["rejected_clusters"] = sorted(rej)
    _write_state(state)


def load_candidate_rules() -> list[dict]:
    """CANDIDATE rules awaiting approval — the generator's validated output
    (candidates_conf(), which the WAF does NOT load), enriched with family and
    subgroup-aware validation.

    De-duplicated by cluster so a repeated auto-generate cycle doesn't re-offer rules
    for clusters already handled:
      • a candidate whose (cluster, subgroup) already has a rule in rules/custom is
        dropped — that cluster is managed as a live / rolled-back rule instead;
      • a candidate whose cluster the operator rejected is kept but marked 'rejected'
        (hidden from the pending list, still visible/undo-able under the Rejected
        filter);
      • everything else is 'pending'.
    """
    covered = {cluster_key(r["cluster"], r["subgroup"]) for r in load_deployed_rules()}
    covered.discard("")
    rejected = rejected_clusters()
    out = []
    for item in _enrich_rules(_parse_conf(candidates_conf())):
        k = cluster_key(item["cluster"], item.get("subgroup"))
        if k and k in covered:
            continue                       # already covered by a rule in rules/custom
        item["ckey"] = k
        item["status"] = "rejected" if k in rejected else "pending"
        out.append(item)
    return out


def set_rule_status(key: str, status: str) -> None:
    """Record an approval decision (approved / rejected / pending) for a queue
    item, keyed the same way load_rule_queue keys it (e.g. 'cluster_0'). This is
    the state the Rule Approval page and approval_counts() read back."""
    state = _read_state()
    entry = state.get(key)
    if not isinstance(entry, dict):
        entry = {}
    entry["status"] = status
    state[key] = entry
    _write_state(state)


def rule_is_live(rule_text: str) -> bool:
    """True if this rule's ID is already loaded by the WAF (the generator writes
    validated rules straight to rules/custom, so they're often already live).
    Re-deploying such a rule would duplicate the ID and crash-loop ModSecurity."""
    idm = re.search(r"id:\s*(\d+)", rule_text or "")
    if not idm:
        return False
    return idm.group(1) in {r["id"] for r in load_deployed_rules()}


def deploy_generated_rule(rule_text: str, cluster, key: str, subgroup=None) -> dict:
    """Approve a generated rule and make sure the WAF enforces it. Records the
    approval in operator state; then, ONLY if the rule's ID isn't already loaded,
    appends it to auto_approved.conf (never touching the generator's auto_rules.conf)
    so a reload picks it up."""
    set_rule_status(key, "approved")
    if rule_is_live(rule_text):
        return {"approved": True, "appended": False, "already_live": True, "path": None}
    APPROVED_CONF.parent.mkdir(parents=True, exist_ok=True)
    header = "# XAF approved (operator-deployed) rules — appended by the console.\n\n"
    existing = APPROVED_CONF.read_text(encoding="utf-8") if APPROVED_CONF.exists() else header
    tag = f"Cluster {cluster}" + (f" / {subgroup}" if subgroup else "")
    existing += f"# {tag} (approved via console)\n{rule_text.strip()}\n\n"
    APPROVED_CONF.write_text(existing, encoding="utf-8")
    return {"approved": True, "appended": True, "already_live": False, "path": APPROVED_CONF}


# ----------------------------------------------------------------------------
# environment actions — docker, firing payloads, running pipeline steps
# ----------------------------------------------------------------------------
def docker_status() -> dict:
    """Which expected containers are up. 'unknown' if docker isn't reachable."""
    want = ["nginx-modsec", "lms"]
    try:
        out = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=8,
        )
        running = set(out.stdout.split())
        return {name: ("up" if name in running else "down") for name in want}
    except (FileNotFoundError, subprocess.SubprocessError):
        return {name: "unknown" for name in want}


def open_waf_session(base: str = DEFAULT_BASE, auth: bool = False):
    """A requests.Session for firing at the WAF. When `auth`, log into the LMS
    first (xss-search / feedback need a session); a blocked login is tolerated —
    the payload fire still reports its own verdict."""
    import requests
    s = requests.Session()
    if auth:
        try:
            s.post(f"{base}/login", data={"username": LMS_USER, "password": LMS_PASS}, timeout=8)
        except requests.RequestException:
            pass
    return s


def fire_payload(payload: str, vector: str = "courses_q", base: str = DEFAULT_BASE,
                 session=None) -> dict:
    """Send one payload through nginx-modsec using the given vector.
    403 == blocked by the WAF, anything else == uncaught. Reuses `session` if
    given, else opens one (logging in when the vector is authenticated)."""
    import requests
    spec = VECTORS.get(vector) or VECTORS["courses_q"]
    url = f"{base}{spec['path']}"
    params = {spec["param"]: payload} if spec["method"] == "GET" else None
    data = dict(spec.get("extra", {}))
    if spec["method"] != "GET":
        data[spec["param"]] = payload
    sess = session or open_waf_session(base, spec["auth"])
    try:
        r = sess.request(spec["method"], url, params=params, data=data or None,
                         timeout=8, allow_redirects=False)
        return {"ok": True, "payload": payload, "vector": vector,
                "status_code": r.status_code, "blocked": r.status_code == 403,
                "url": r.url, "elapsed_ms": r.elapsed.total_seconds() * 1000}
    except requests.RequestException as e:
        return {"ok": False, "payload": payload, "vector": vector,
                "error": str(e), "url": url}


def attribute_block(payload: str) -> dict:
    """Best-effort: which deployed custom rule would catch this payload. The
    WAF's 403 doesn't name the offending rule in the HTTP response, so we re-test
    the payload against the @rx of each live (enabled) rule to attribute the
    block — reusing the generator's own regex helpers so attribution agrees with
    how the rule was validated. Returns {"rule_id", "cluster"}; both are None when
    no custom rule matches (e.g. a CRS core rule made the block, or it was uncaught)."""
    gen = generator()
    for r in load_deployed_rules():
        if r["disabled"]:
            continue
        pat = gen.extract_regex(r["rule"])
        if not pat:
            continue
        try:
            rx = gen.compile_pattern(pat)
        except Exception:   
            continue
        if rx.search(payload):
            return {"rule_id": r["id"], "cluster": r["cluster"]}
    return {"rule_id": None, "cluster": None}


def fire_payloads(tasks: list[dict], base: str = DEFAULT_BASE) -> list[dict]:
    # Fire a batch of payloads through the live WAF, reusing one session per auth requirement
    results, sessions = [], {}
    for t in tasks:
        vector = t.get("vector", "courses_q")
        auth = (VECTORS.get(vector) or VECTORS["courses_q"])["auth"]
        if auth not in sessions:
            sessions[auth] = open_waf_session(base, auth)
        res = fire_payload(t["payload"], vector, base, session=sessions[auth])
        res["family"] = t.get("family", "")
        res["type"] = t.get("type", "")
        results.append(res)
    return results


def run_script(name: str, extra_env: dict | None = None, timeout: int = 600) -> dict:
    # Run a pipeline script with the current Python interpreter from ROOT
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
    # Restart the WAF container so newly-approved rules take effect.
    try:
        proc = subprocess.run(
            ["docker", "restart", container],
            capture_output=True, text=True, timeout=60,
        )
        return {"ok": proc.returncode == 0, "stdout": proc.stdout, "stderr": proc.stderr}
    except (FileNotFoundError, subprocess.SubprocessError) as e:
        return {"ok": False, "stdout": "", "stderr": str(e)}
