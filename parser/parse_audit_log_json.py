import json
import os
import urllib.parse

def process_audit_log(input_file, output_file):
    parsed_results = []

    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found.")
        return

    with open(input_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            try:
                data = json.loads(line)
                
                # Digging into the nested structure
                transaction = data.get("transaction", {})
                request = transaction.get("request", {})
                messages = transaction.get("messages", [])
                
                # Get the first message details if available
                first_msg = messages[0] if messages else {}
                details = first_msg.get("details", {})

                # Construct the flat dictionary
                entry = {
                    "uri": request.get("uri"),
                    "payload": extract_payload(request.get("uri")),
                    "rule_id": details.get("ruleId"),
                    "rule_msg": first_msg.get("message")
                }
                
                parsed_results.append(entry)
            
            except json.JSONDecodeError:
                print(f"Skipping invalid JSON line.")
                continue

    # Write the entire list to the output file
    with open(output_file, 'w') as out_f:
        json.dump(parsed_results, out_f, indent=2)
    
    print(f"Successfully parsed {len(parsed_results)} entries into {output_file}")

def extract_payload(uri):
    if not uri or "?" not in uri:
        return None
    query = urllib.parse.urlparse(uri).query
    params = urllib.parse.parse_qs(query)
    if not params:
        return None
    # take the first query param's value, URL-decoded
    first_value = list(params.values())[0][0]
    return first_value

# Execution
process_audit_log('modsec-logs/audit.log', 'output/parsed_logs.json')
