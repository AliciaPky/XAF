import json
import os
import re
import urllib.parse

# Enhancements over the original:
#   #1 POST body          - parses application/x-www-form-urlencoded bodies
#   #2 JSON body          - parses application/json bodies (Juice Shop login)
#   #3 ALL parameters     - emits every param value, not just the first
#   #4 normalization      - adds payload_norm (NUM/STR tokens) for CLUSTERING ONLY;
#                           raw payload is kept untouched for rule generation
#   #5 double URL-decode  - defeats double-encoded payloads (%2527 -> ' )
#   #6 noise removal      - already done: payload is the bare value, no param name
#   #7 metadata           - uri, rule_id, rule_msg, timestamp, unique_id,
#                           http_code, and a blocked/bypassed status flag
#
# One row is emitted PER parameter value, so multi-field requests
# (e.g. username=admin&password=' OR 1=1 --) produce one row each.

INPUT_FILE  = "modsec-logs/audit.log"
OUTPUT_FILE = "output/parsed_logs.json"

# Messages emitted by rules WE generate. Excluding them stops the system from
# training on its own output (feedback contamination).
GENERATED_RULE_MSGS = {"AUTO_GENERATED_RULE", "CUSTOM_RULE_TRIGGERED"}

# Response code that means the WAF blocked the request. Tune if your CRS
# blocking action returns something other than 403.
BLOCK_STATUS = 403

# ----------------------------- decoding ------------------------------------
def deep_unquote(value, max_passes=3):
    """URL-decode repeatedly to defeat double/triple encoding (%2527 -> ' )."""
    if value is None:
        return None
    prev = value
    for _ in range(max_passes):
        cur = urllib.parse.unquote_plus(prev)
        if cur == prev:          # nothing changed -> fully decoded
            break
        prev = cur
    return prev


# --------------------------- normalization ---------------------------------
def normalize(payload):
    """Heuristic normalization used ONLY for clustering, never for rule-gen.

    Collapses superficially-different-but-structurally-identical payloads
    so they land in the same cluster:
        ' OR 1=1 --      ->  ' or num=num --
        ' OR 999=999 --  ->  ' or num=num --
        admin' OR '1'='1 ->  admin' or 'str'='num   (quoted -> STR, bare -> NUM)
    """
    if not payload:
        return ""
    norm = payload.lower()
    # quoted string literals -> 'STR' (do this before NUM so '1' becomes 'STR')
    norm = re.sub(r"'[^']*'", "'STR'", norm)
    norm = re.sub(r'"[^"]*"', '"STR"', norm)
    # bare numeric literals -> NUM
    norm = re.sub(r"\b\d+\b", "NUM", norm)
    # collapse whitespace
    norm = re.sub(r"\s+", " ", norm).strip()
    return norm


# --------------------------- value extraction ------------------------------
def values_from_query(uri):
    """Return all decoded query-string parameter values from a URI."""
    if not uri or "?" not in uri:
        return []
    query = urllib.parse.urlparse(uri).query
    params = urllib.parse.parse_qs(query, keep_blank_values=False)
    out = []
    for vals in params.values():          # iterate ALL params
        for v in vals:
            out.append(deep_unquote(v))    # double-decode
    return out


def values_from_body(body, content_type):
    """Return all values from a request body (form-urlencoded or JSON)."""
    if not body:
        return []
    ctype = (content_type or "").lower()

    # JSON body -> pull every leaf string/number value
    if "application/json" in ctype or body.lstrip().startswith(("{", "[")):
        try:
            data = json.loads(body)
            return [deep_unquote(str(v)) for v in _json_leaves(data)]
        except (json.JSONDecodeError, ValueError):
            pass  # fall through to form parsing

    # form-urlencoded body (username=admin&password=' OR 1=1 --)
    params = urllib.parse.parse_qs(body, keep_blank_values=False)
    if params:
        out = []
        for vals in params.values():
            for v in vals:
                out.append(deep_unquote(v))
        return out

    # Unknown body type: treat the whole body as one payload.
    return [deep_unquote(body)]


def _json_leaves(obj):
    """Recursively yield leaf values of a JSON structure."""
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _json_leaves(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _json_leaves(v)
    else:
        if obj is not None and str(obj).strip() != "":
            yield obj


def header_value(headers, name):
    """Case-insensitive header lookup."""
    if not isinstance(headers, dict):
        return None
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


# ------------------------------- main --------------------------------------
def process_audit_log(input_file, output_file):
    parsed_results = []

    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found.")
        return

    with open(input_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                print("Skipping invalid JSON line.")
                continue

            tx       = data.get("transaction", {})
            request  = tx.get("request", {})
            response = tx.get("response", {})
            messages = tx.get("messages", [])

            first_msg = messages[0] if messages else {}
            details   = first_msg.get("details", {})
            rule_msg  = first_msg.get("message")

            # Skip hits from our own generated rules (feedback contamination).
            if rule_msg in GENERATED_RULE_MSGS:
                continue

            # ---- #7 metadata ----
            http_code = response.get("http_code")
            status    = "blocked" if http_code == BLOCK_STATUS else "bypassed"

            # ---- gather candidate payloads (#1 #2 #3) ----
            content_type = header_value(request.get("headers"), "Content-Type")
            payloads = []
            payloads += values_from_query(request.get("uri"))
            payloads += values_from_body(request.get("body"), content_type)

            # one row per non-empty, de-duplicated value
            seen = set()
            for payload in payloads:
                if not payload or not payload.strip():
                    continue
                if payload in seen:
                    continue
                seen.add(payload)

                parsed_results.append({
                    "payload":      payload,            # raw -> rule generation
                    "payload_norm": normalize(payload), # #4 normalized -> clustering
                    "uri":          request.get("uri"),
                    "method":       request.get("method"),
                    "rule_id":      details.get("ruleId"),
                    "rule_msg":     rule_msg,
                    "http_code":    http_code,
                    "status":       status,             # blocked | bypassed
                    "timestamp":    tx.get("time_stamp"),
                    "unique_id":    tx.get("unique_id"),
                })

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as out_f:
        json.dump(parsed_results, out_f, indent=2)

    blocked  = sum(1 for r in parsed_results if r["status"] == "blocked")
    bypassed = len(parsed_results) - blocked
    print(f"Parsed {len(parsed_results)} payload(s) into {output_file}")
    print(f"  blocked:  {blocked}")
    print(f"  bypassed: {bypassed}   <-- feed these to clustering")


if __name__ == "__main__":
    process_audit_log(INPUT_FILE, OUTPUT_FILE)