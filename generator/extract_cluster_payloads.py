import pandas as pd
import os

INPUT_FILE = "./output/clustered_attacks.csv"
OUTPUT_DIR = "./output"

df = pd.read_csv(INPUT_FILE)

# Use the decoded attack payload (same column clustering ran on), not the raw URI.
df["payload"] = df["payload"].fillna("").astype(str)
df = df[df["payload"].str.strip() != ""]

# Get all unique cluster labels
clusters = df["cluster"].unique()

for cluster_id in clusters:
    if int(cluster_id) == -1:   # skip DBSCAN noise; lone payloads can't generalize
        continue

    cluster_df = df[df["cluster"] == cluster_id]

    filename = f"cluster{cluster_id}_payloads.txt"
    filepath = os.path.join(OUTPUT_DIR, filename)

    with open(filepath, "w") as f:
        for payload in sorted(set(cluster_df["payload"])):  # dedupe within cluster
            f.write(payload + "\n")

print("Cluster payload files generated.")