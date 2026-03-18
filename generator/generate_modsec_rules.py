import os
import re
import urllib.parse

INPUT_FOLDER = "./output"
OUTPUT_FILE = "./rules/custom/auto_generated.conf"

BASE_RULE_ID = 200000

def extract_payload(line):
    parsed = urllib.parse.urlparse(line) #decode by parse_qs
    qs = urllib.parse.parse_qs(parsed.query)
    if "id" in qs and qs["id"]:
        return qs["id"][0]  #decoded by parse_qs
    return None

def escape_regex(payload):
    return re.escape(payload)

def generate_rules():
    rule_id = BASE_RULE_ID
    
    with open(OUTPUT_FILE, "w") as out:
        out.write("# Auto-generated rules\n\n")
        
        for file in os.listdir(INPUT_FOLDER):
            if file.startswith("cluster") and file.endswith("_payloads.txt"):
                
                with open(os.path.join(INPUT_FOLDER, file)) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        
                        payload = extract_payload(line)
                        if not payload:
                            continue
                        
                        regex = escape_regex(payload)
                        
                        rule = f'''SecRule ARGS "@rx {regex}" \\
"id:{rule_id},phase:2,deny,log,auditlog,msg:'AUTO_GENERATED_RULE',severity:CRITICAL"\n\n'''
                        
                        out.write(rule)
                        rule_id += 1

if __name__ == "__main__":
    generate_rules()