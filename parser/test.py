import json

LOG_FILE = "./modsec-logs/audit.log"

with open(LOG_FILE, "r") as f:
	line = f.read().strip()

entry = json.loads(line)

tx = entry.get("transaction", {})
request = tx.get("request", {})
uri = request.get("uri", "")

results = []

for msg in entry.get("messages", []):
        details = msg.get("details", {})
        rule_id = details.get("ruleId")
        rule_msg = msg.get("message")
        payload = details.get("data", "")

        if rule_id:
                results.append({
                        "uri": uri,
                        "payload": payload,
                        "rule_id": rule_id,
                        "rule_msg": rule_msg
                })

print(results)
