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

vectorizer = TfidfVectorizer(max_features=1000)
# Clean payload column (avoid NaN crashing vectorizer)
df["payload"] = df["payload"].fillna("").astype(str)
df = df[df["payload"].str.strip() != ""]
X = vectorizer.fit_transform(df["uri"]) #choose which column to extract

dbscan = DBSCAN(
    eps=0.4,
    min_samples=2,
    metric="cosine"
)

df["cluster"] = dbscan.fit_predict(X)

df.to_csv("./output/clustered_attacks.csv", index=False)

print(df["cluster"].value_counts())
