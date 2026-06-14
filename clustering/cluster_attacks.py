import json
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN

INPUT_FILE = "./output/parsed_logs.json"

with open(INPUT_FILE, "r") as f:
    data = json.load(f)

df = pd.DataFrame(data)

# Sanity check
required = {"payload"}
missing = required - set(df.columns)
if missing:
    raise ValueError(f"Missing columns: {missing}")

# Drop noise (socket.io)
df = df[~df["payload"].str.contains("socket.io", na=False)]

# Clean payload column (avoid NaN crashing vectorizer)
df["payload"] = df["payload"].fillna("").astype(str)
df = df[df["payload"].str.strip() != ""]

# Cluster on DISTINCT payloads so exact duplicates don't dominate a cluster.
df = df.drop_duplicates(subset="payload").reset_index(drop=True)

# Character n-grams: the default word tokenizer drops punctuation/short tokens
# (quotes, =, --, 1=1) that carry the attack signal. char_wb keeps them.
vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=1000)
X = vectorizer.fit_transform(df["payload"]) #choose which column to extract

dbscan = DBSCAN(
    eps=0.65,        # cosine distance on char n-grams; groups the OR-based SQLi family
    min_samples=2,
    metric="cosine"
)

df["cluster"] = dbscan.fit_predict(X)

df.to_csv("./output/clustered_attacks.csv", index=False)

print(df["cluster"].value_counts())
