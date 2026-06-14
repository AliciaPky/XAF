import os
import re

INPUT_FOLDER = "./output"
OUTPUT_FILE = "./rules/custom/auto_generated.conf"

BASE_RULE_ID = 200000

def escape_regex(payload):
    return re.escape(payload)

def generate_rules():
    rule_id = BASE_RULE_ID

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    with open(OUTPUT_FILE, "w") as out:
        out.write("# Auto-generated rules\n\n")

        for file in sorted(os.listdir(INPUT_FOLDER)):
            if file.startswith("cluster") and file.endswith("_payloads.txt"):

                with open(os.path.join(INPUT_FOLDER, file)) as f:
                    for line in f:
                        # Each line is already the decoded attack payload.
                        payload = line.strip()
                        if not payload:
                            continue

                        regex = escape_regex(payload)

                        rule = f'''SecRule ARGS "@rx {regex}" \\
"id:{rule_id},phase:2,deny,log,auditlog,msg:'AUTO_GENERATED_RULE',severity:CRITICAL"\n\n'''

                        out.write(rule)
                        rule_id += 1

if __name__ == "__main__":
    generate_rules()