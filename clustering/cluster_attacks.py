import json
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN

INPUT_FILE = "./output/parsed_logs.json"
OUTPUT_FILE = "./output/clustered_attacks.csv"

# Only learn from attacks that bypassed CRS; falls back to all rows if none did.
BYPASSED_ONLY = False

FAMILY_SIGNATURES = {
    "ssti": ("{{", "}}", "{%", "%}", "__class__", "__mro__", "__globals__", "7*7",
             "popen(", "lipsum", "request.application", "self.__", "${", "<%="),
    "xss": ("<script", "onerror", "onload", "onfocus", "ontoggle", "<svg",
            "<img", "<iframe", "<body", "<video", "<details", "javascript:",
            "alert(", "onmouseover", "fromcharcode"),
    "sqli": ("union", "select ", " or 1", "1=1", "'='", "sleep(", "waitfor",
             "extractvalue", "updatexml", "information_schema", "benchmark(",
             "' or ", "' and ", "--", "/**/", "concat("),
}


def classify_family(payload):
    """Return 'sqli' | 'xss' | 'ssti', or None for benign/unclassified.
    SSTI/XSS are checked before SQLi so mixed payloads aren't mislabelled."""
    s = (payload or "").lower()
    for family in ("ssti", "xss", "sqli"):
        if any(tok in s for tok in FAMILY_SIGNATURES[family]):
            return family
    return None


with open(INPUT_FILE, "r") as f:
    data = json.load(f)

df = pd.DataFrame(data)

if "payload" not in df.columns:
    raise ValueError("parsed_logs.json must contain a 'payload' column.")

# Cluster on the normalized payload when available, else the raw payload.
if "payload_norm" in df.columns:
    cluster_col = "payload_norm"
else:
    cluster_col = "payload"
    print("[!] No 'payload_norm' column found; clustering on raw 'payload'. "
          "Re-run the upgraded parser to enable normalization.")

if BYPASSED_ONLY and "status" in df.columns:
    bypassed = df[df["status"] == "bypassed"]
    if len(bypassed) == 0:
        print("[!] BYPASSED_ONLY is set but no bypassed rows exist; "
              "using all rows so clustering isn't empty.")
    else:
        df = bypassed

df = df[~df["payload"].str.contains("socket.io", na=False)]

df["payload"]   = df["payload"].fillna("").astype(str)
df[cluster_col] = df[cluster_col].fillna("").astype(str)
df = df[df["payload"].str.strip() != ""]

# Dedupe on raw payload; keep="last" refreshes re-fired attacks to their latest row.
df = df.drop_duplicates(subset="payload", keep="last").reset_index(drop=True)

if df.empty:
    print("No payloads to cluster.")
    raise SystemExit

df["family"] = df["payload"].map(classify_family)
n_benign = int(df["family"].isna().sum())
df = df[df["family"].notna()].reset_index(drop=True)
print(f"[i] dropped {n_benign} benign/unclassified payload(s); "
      f"kept {len(df)} attack payload(s) across {df['family'].nunique()} famil(ies).")

if df.empty:
    print("No attack payloads to cluster after benign filtering.")
    raise SystemExit

# Cluster each family separately; offset labels so cluster ids stay globally unique.
labels = pd.Series(-1, index=df.index, dtype=int)
next_base = 0
for family, group in df.groupby("family"):
    if len(group) < 2:
        continue
    vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5),
                                 max_features=1000)
    X = vectorizer.fit_transform(group[cluster_col])
    sub = DBSCAN(eps=0.65, min_samples=2, metric="cosine").fit_predict(X)
    for idx, lab in zip(group.index, sub):
        labels.loc[idx] = -1 if lab == -1 else next_base + int(lab)
    n_clusters = (sub.max() + 1) if sub.max() >= 0 else 0
    next_base += n_clusters
    print(f"    {family:<5}: {len(group):>3} payloads -> {n_clusters} cluster(s)")

df["cluster"] = labels

df.to_csv(OUTPUT_FILE, index=False)

print("\nCluster sizes (family / cluster):")
print(df.groupby(["family", "cluster"]).size())
print(f"\nClustered on '{cluster_col}' per family. "
      f"Raw 'payload' preserved for rule generation.")
