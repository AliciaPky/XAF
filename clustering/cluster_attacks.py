import json
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN

INPUT_FILE = "./output/parsed_logs.json"
OUTPUT_FILE = "./output/clustered_attacks.csv"

# Train only on attacks that slipped past CRS (status == "bypassed").
BYPASSED_ONLY = False

with open(INPUT_FILE, "r") as f:
    data = json.load(f)

df = pd.DataFrame(data)

# --- sanity: we always need the raw payload ---
if "payload" not in df.columns:
    raise ValueError("parsed_logs.json must contain a 'payload' column.")

# --- pick the column to CLUSTER on (normalized if available) ---
if "payload_norm" in df.columns:
    cluster_col = "payload_norm"
else:
    cluster_col = "payload"
    print("[!] No 'payload_norm' column found; clustering on raw 'payload'. "
          "Re-run the upgraded parser to enable normalization.")

# --- optional: keep only requests that bypassed the WAF ---
if BYPASSED_ONLY and "status" in df.columns:
    bypassed = df[df["status"] == "bypassed"]
    if len(bypassed) == 0:
        print("[!] BYPASSED_ONLY is set but no bypassed rows exist; "
              "using all rows so clustering isn't empty.")
    else:
        df = bypassed

# --- drop obvious noise ---
df = df[~df["payload"].str.contains("socket.io", na=False)]

# --- clean both columns so the vectorizer never sees NaN ---
df["payload"]   = df["payload"].fillna("").astype(str)
df[cluster_col] = df[cluster_col].fillna("").astype(str)
df = df[df["payload"].str.strip() != ""]

# Dedupe on the RAW payload (keep distinct attack strings so the generator
# sees variety), then cluster those rows by their normalized form.
df = df.drop_duplicates(subset="payload").reset_index(drop=True)

if df.empty:
    print("No payloads to cluster.")
    raise SystemExit

# Character n-grams: the default word tokenizer drops punctuation/short tokens
# (quotes, =, --, NUM=NUM) that carry the attack signal. char_wb keeps them.
vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=1000)
X = vectorizer.fit_transform(df[cluster_col])   # <-- cluster on normalized form

dbscan = DBSCAN(
    eps=0.65,        # cosine distance on char n-grams; groups the OR-based SQLi family
    min_samples=2,
    metric="cosine",
)

df["cluster"] = dbscan.fit_predict(X)

# CSV keeps raw payload (for rule-gen) + payload_norm + metadata + cluster.
df.to_csv(OUTPUT_FILE, index=False)

print(df["cluster"].value_counts())
print(f"\nClustered on '{cluster_col}'. Raw 'payload' preserved for rule generation.")