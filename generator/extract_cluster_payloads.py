import pandas as pd

INPUT = "./output/clustered_attacks.csv"
OUTPUT = "./output/cluster0_payloads.txt"

df = pd.read_csv(INPUT)

cluster0 = df[df["cluster"] == 0]

payloads = cluster0["payload"].dropna().unique()

with open(OUTPUT, "w") as f:
    for p in payloads[:10]:  # limit for prompt clarity
        f.write(p + "\n")

print(f"[+] Extracted {len(payloads)} payloads from cluster 0")
