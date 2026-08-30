import json
import os
import re
import urllib.parse

INPUT_FILE  = "modsec-logs/audit.log"
OUTPUT_FILE = "output/parsed_logs.json"

# Messages emitted by generated rules but excludes them stops the system from
# training on its own output (feedback contamination).
GENERATED_RULE_MSGS = {"AUTO_GENERATED_RULE", "CUSTOM_RULE_TRIGGERED"}

# Response code that means the WAF blocked the request.
BLOCK_STATUS = 403

def deep_unquote(value, max_passes=3):
    # URL-decode repeatedly to defeat double/triple encoding (%2527 -> ' )
    if value is None:
        return None
    prev = value
    for _ in range(max_passes):
        cur = urllib.parse.unquote_plus(prev)
        if cur == prev:
            break
        prev = cur
    return prev


def normalize(payload):
    """Heuristic normalization used ONLY for clustering, never for rule-gen.
    Collapses structurally-identical payloads so they land in the same cluster:
        ' OR 1=1 --      ->  ' or num=num --
        admin' OR '1'='1 ->  admin' or 'str'='num
    """
    if not payload:
        return ""
    norm = payload.lower()
    # quoted string literals -> 'STR' (before NUM so '1' becomes 'STR')
    norm = re.sub(r"'[^']*'", "'STR'", norm)
    norm = re.sub(r'"[^"]*"', '"STR"', norm)
    norm = re.sub(r"\b\d+\b", "NUM", norm)
    norm = re.sub(r"\s+", " ", norm).strip()
    return norm


def values_from_query(uri):
    """Return all decoded query-string parameter values from a URI."""
    if not uri or "?" not in uri:
        return []
    query = urllib.parse.urlparse(uri).query
    params = urllib.parse.parse_qs(query, keep_blank_values=False)
    out = []
    for vals in params.values():
        for v in vals:
            out.append(deep_unquote(v))
    return out


def values_from_body(body, content_type):
    """Return all values from a request body (form-urlencoded or JSON)."""
    if not body:
        return []
    ctype = (content_type or "").lower()

    if "application/json" in ctype or body.lstrip().startswith(("{", "[")):
        try:
            data = json.loads(body)
            return [deep_unquote(str(v)) for v in _json_leaves(data)]
        except (json.JSONDecodeError, ValueError):
            pass  # fall through to form parsing

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


# CRS records the offending value in its "found within COLLECTION:name: <value>"
# trailer (audit part H). For POST bodies not stored as request.body, this is the
# only place the payload survives, so we recover it here.
MATCHED_RE = re.compile(r"found within\s+\S+:\s(.+?)(?=\s*Matched Data:|$)", re.S)
# "(Value: `<full value>' )" holds the COMPLETE value, surviving even when the
# "found within" trailer is truncated ("396 characters omitted"). Prefer it.
MATCH_VALUE_RE = re.compile(r"\(Value:\s*[`'\"]?(.*?)['`\"]?\s*\)\s*$", re.S)


def _looks_truncated(val):
    """An HTML/JS fragment cut mid-token: opens a tag ('<') but never closes it.
    A truncation artifact (e.g. '<img src=x o'), not a real payload."""
    v = val.strip()
    return v.startswith("<") and ">" not in v


def values_from_matched_data(messages):
    """Recover the FULL offending value from CRS message trailers (audit part H).
    Prefer the '(Value: ...)' field; fall back to the 'found within' trailer only
    for values that don't look truncated."""
    out = []
    for m in messages or []:
        det = m.get("details") or {}
        mv = MATCH_VALUE_RE.search(det.get("match") or "")
        if mv and mv.group(1).strip():
            out.append(deep_unquote(mv.group(1).strip()))
            continue
        for fw in MATCHED_RE.finditer(det.get("data") or ""):
            val = fw.group(1).strip()
            if val and not _looks_truncated(val):
                out.append(deep_unquote(val))
    return out


def header_value(headers, name):
    # Case-insensitive header lookup
    if not isinstance(headers, dict):
        return None
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


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

            if rule_msg in GENERATED_RULE_MSGS:
                continue

            http_code = response.get("http_code")
            status    = "blocked" if http_code == BLOCK_STATUS else "bypassed"

            content_type = header_value(request.get("headers"), "Content-Type")
            payloads = []
            payloads += values_from_query(request.get("uri"))
            payloads += values_from_body(request.get("body"), content_type)
            # Fallback only when query+body yielded nothing: recover from the CRS
            # matched-data. It's truncated, so avoid it when the full payload is
            # already available (GET args) to keep fragments out of clustering.
            if not payloads:
                payloads += values_from_matched_data(messages)

            seen = set()
            for payload in payloads:
                if not payload or not payload.strip():
                    continue
                if payload in seen:
                    continue
                seen.add(payload)

                parsed_results.append({
                    "payload":      payload,             # raw -> rule generation
                    "payload_norm": normalize(payload),  # normalized -> clustering
                    "uri":          request.get("uri"),
                    "method":       request.get("method"),
                    "rule_id":      details.get("ruleId"),
                    "rule_msg":     rule_msg,
                    "http_code":    http_code,
                    "status":       status,
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
