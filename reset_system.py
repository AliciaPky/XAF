#!/usr/bin/env python3
"""
reset_system.py — return XAF to a fresh state.

Clears the whole pipeline (logs -> parse -> cluster -> generate -> approve/deploy),
resets operator run-state, and restarts the nginx-modsec container so the live WAF
comes back CRS-only.

Deliberately PRESERVED (things you didn't ask to lose):
  - FYP model-comparison artifacts:
      rules/experiments/auto_sqli.*.conf
      output/prompts/<model>/   (gemma4, gpt-4o, gpt-5.4, ...)
      output/model_runs/
  - hand-written analyst rules: rules/custom/manual.conf
  - your notification preferences: the "settings" block in ui/state/alerts.json

IMPORTANT: this turns Auto-generate OFF. If the Streamlit console is running with
Auto-generate on, its background scheduler re-runs parse->cluster->generate every
~60s and would immediately repopulate everything you just cleared. Forcing it off
here makes the reset actually stick. Pass --keep-schedule to preserve the setting
(only safe if the console isn't running). Re-enable Auto-generate from the UI when
you're ready.

Usage:
    python reset_system.py                 # prompts before wiping
    python reset_system.py --yes           # no prompt
    python reset_system.py --keep-logs     # keep modsec-logs/audit.log (raw capture)
    python reset_system.py --keep-schedule # don't force Auto-generate off
    python reset_system.py --no-restart    # skip the docker restart
"""
from __future__ import annotations

import argparse
import glob
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# ── header stubs the console expects rule files to start from ────────────────
AUTO_APPROVED_HEADER = "# XAF approved (operator-deployed) rules — appended by the console.\n"
ZZ_DISABLED_HEADER = (
    "# XAF disabled rules — auto-managed by the operator console.\n"
    "# Loads after the generated rules (zz_ prefix) so SecRuleRemoveById\n"
    "# can remove them. Reload ModSecurity to apply.\n"
)

NGINX_SERVICE = "nginx-modsec"


def _rm(path: Path) -> bool:
    """Delete a file if present. Returns True if something was removed."""
    if path.is_file():
        path.unlink()
        return True
    return False


def _truncate(path: Path) -> None:
    """Empty a file in place (keeps the inode so a container's bind-mounted
    handle stays valid)."""
    if path.exists():
        path.write_text("", encoding="utf-8")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def clear_logs(keep_logs: bool) -> None:
    print("• Logs")
    if keep_logs:
        print("    kept modsec-logs/audit.log (--keep-logs)")
        return
    _truncate(ROOT / "modsec-logs" / "audit.log")
    print("    truncated modsec-logs/audit.log")


def clear_parse_cluster() -> None:
    print("• Parse + cluster output")
    out = ROOT / "output"
    removed = 0
    for p in (out / "parsed_logs.json", out / "clustered_attacks.csv"):
        removed += _rm(p)
    for f in glob.glob(str(out / "cluster*_payloads.txt")):
        removed += _rm(Path(f))
    print(f"    removed {removed} parse/cluster file(s)")


def clear_generate_history() -> None:
    print("• Generate history (candidates, prompt traces, gen log)")
    removed = _rm(ROOT / "rules" / "experiments" / "auto_rules.conf")
    removed += _rm(ROOT / "output" / "gen_run.log")
    # Only the ACTIVE top-level traces in output/prompts/ — the per-model archive
    # subdirs (gemma4/, gpt-4o/, ...) are FYP data and are left alone.
    prompts = ROOT / "output" / "prompts"
    traces = 0
    if prompts.is_dir():
        for f in prompts.iterdir():
            if f.is_file():
                f.unlink()
                traces += 1
    print(f"    removed {removed} rule/log file(s), {traces} prompt trace(s)")
    print("    preserved output/prompts/<model>/ archives + output/model_runs/")


def clear_rules() -> None:
    print("• Deployed / approved / disabled rules (live WAF files)")
    _write(ROOT / "rules" / "custom" / "auto_approved.conf", AUTO_APPROVED_HEADER)
    _write(ROOT / "rules" / "custom" / "zz_disabled.conf", ZZ_DISABLED_HEADER)
    print("    reset auto_approved.conf + zz_disabled.conf to headers")
    print("    preserved rules/custom/manual.conf + rules/experiments/auto_sqli.*.conf")


def clear_operator_state(keep_schedule: bool) -> None:
    print("• Operator state (approvals, alert dedup, scheduler)")
    state = ROOT / "ui" / "state"

    # Approvals: wipe all approve/reject/disable decisions.
    _write(state / "approvals.json", json.dumps({"disabled": []}, indent=2) + "\n")

    # Alerts: clear the "seen" baseline so alerts fire fresh, but KEEP the
    # operator's notification toggles.
    alerts = _load_json(state / "alerts.json")
    settings = alerts.get("settings")
    fresh_alerts: dict = {
        "initialized": False,
        "attacks": [], "candidates": [], "deployed": [],
        "deployed_cluster_keyed": True,
    }
    if settings is not None:
        fresh_alerts["settings"] = settings
    _write(state / "alerts.json", json.dumps(fresh_alerts, indent=2) + "\n")

    # Scheduler: reset run status. Force Auto-generate OFF by default so a running
    # console's background scheduler can't immediately re-run the pipeline and undo
    # this wipe. --keep-schedule preserves whatever it was.
    sched = _load_json(state / "scheduler.json")
    enabled = bool(sched.get("enabled", False)) if keep_schedule else False
    _write(state / "scheduler.json", json.dumps({
        "enabled": enabled,
        "running": False, "last_run": None, "last_ok": None, "step": None,
    }, indent=2) + "\n")

    kept = "kept" if settings is not None else "none found"
    sched_note = "left as-is" if keep_schedule else "forced OFF"
    print(f"    reset approvals.json, alerts.json (notification settings: {kept})")
    print(f"    scheduler.json reset, Auto-generate {sched_note}")


def restart_nginx() -> None:
    print(f"• Restarting {NGINX_SERVICE} container")
    try:
        r = subprocess.run(
            ["docker", "compose", "restart", NGINX_SERVICE],
            cwd=ROOT, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        print("    ⚠ docker not found on PATH — start it and restart the container manually:")
        print(f"      docker compose restart {NGINX_SERVICE}")
        return
    except subprocess.TimeoutExpired:
        print("    ⚠ docker restart timed out — check the container manually.")
        return
    if r.returncode == 0:
        print(f"    ✓ {NGINX_SERVICE} restarted — live WAF is back to CRS-only")
    else:
        print(f"    ⚠ restart failed (exit {r.returncode}):")
        print("   ", (r.stderr or r.stdout).strip().splitlines()[-1] if (r.stderr or r.stdout).strip() else "")


def main() -> int:
    ap = argparse.ArgumentParser(description="Reset XAF to a fresh state.")
    ap.add_argument("-y", "--yes", action="store_true", help="skip the confirmation prompt")
    ap.add_argument("--keep-logs", action="store_true", help="keep modsec-logs/audit.log")
    ap.add_argument("--keep-schedule", action="store_true",
                    help="don't force Auto-generate off (unsafe if the console is running)")
    ap.add_argument("--no-restart", action="store_true", help="do not restart the container")
    args = ap.parse_args()

    print(f"XAF reset — target: {ROOT}\n")
    if not args.yes:
        ans = input("This wipes logs, parse/cluster output, generated + deployed rules,\n"
                    "and operator state, then restarts the WAF. Continue? [y/N] ").strip().lower()
        if ans not in ("y", "yes"):
            print("Aborted.")
            return 1
        print()

    clear_logs(args.keep_logs)
    clear_parse_cluster()
    clear_generate_history()
    clear_rules()
    clear_operator_state(args.keep_schedule)
    if not args.no_restart:
        restart_nginx()

    print("\nDone — system is fresh. Reload the console UI to see empty dashboards.")
    if not args.keep_schedule:
        print("Note: Auto-generate was turned OFF. If the console is open, refresh it,")
        print("      and re-enable Auto-generate from the sidebar when you want it back.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
