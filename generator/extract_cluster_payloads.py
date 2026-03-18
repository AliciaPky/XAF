import pandas as pd
import os

INPUT_FILE = "./output/clustered_attacks.csv"
OUTPUT_DIR = "./output"

df = pd.read_csv(INPUT_FILE)

# Ensure payload column is clean
df["payload"] = df["uri"].fillna("").astype(str)
df = df[df["payload"].str.strip() != ""]

# Get all unique cluster labels
clusters = df["cluster"].unique()

for cluster_id in clusters:
    cluster_df = df[df["cluster"] == cluster_id]
    
    filename = f"cluster{cluster_id}_payloads.txt"
    filepath = os.path.join(OUTPUT_DIR, filename)
    
    with open(filepath, "w") as f:
        for payload in cluster_df["uri"]: #choose which column to extract
            f.write(payload + "\n")

print("Cluster payload files generated.")