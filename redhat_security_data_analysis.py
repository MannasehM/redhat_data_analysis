import requests
from bs4 import BeautifulSoup
import os
from datetime import datetime
import json
import pandas as pd
from pandas import json_normalize
import glob
import matplotlib.pyplot as plt
from collections import Counter
import re
import nltk
from nltk.corpus import stopwords

BASE_URL = "https://security.access.redhat.com/data/csaf/v2/vex/2025/"
SAVE_DIR = "data/sep2025/"
os.makedirs(SAVE_DIR, exist_ok=True)

resp = requests.get(BASE_URL)
soup = BeautifulSoup(resp.text, "html.parser")

download_count = 0
MAX_DOWNLOADS = 100

for row in soup.select("tbody tr"):
    name_cell = row.find("td", class_="indexcolname")
    date_cell = row.find("td", class_="indexcollastmod")

    if not name_cell or not date_cell:
        continue

    href = name_cell.a.get("href") if name_cell.a else None
    lastmod_text = date_cell.get_text(strip=True)

    try:
        lastmod_dt = datetime.strptime(lastmod_text, "%a, %d %b %Y %H:%M:%S %z")
    except ValueError:
        continue

    # only keep September 2025
    if href and href.endswith(".json") and lastmod_dt.year == 2025 and lastmod_dt.month == 9:
        file_url = BASE_URL + href
        file_path = os.path.join(SAVE_DIR, href)

        r = requests.get(file_url)
        if r.status_code == 200:
            with open(file_path, "wb") as f:
                f.write(r.content)
            print(f"Saved {file_path}")
        else:
            print(f"Failed to download {href}")

        download_count += 1
        if download_count >= MAX_DOWNLOADS:
            print(f"Reached limit of {MAX_DOWNLOADS} downloads, stopping.")
            break



json_files = glob.glob("data/sep2025/*.json")

rows = []

for file in json_files:
    with open(file, "r") as f:
        data = json.load(f)

        # metadata
        tracking = data.get("document", {}).get("tracking", {})
        cve_id = tracking.get("id")
        published = tracking.get("initial_release_date")
        modified = tracking.get("current_release_date")
        status = tracking.get("status")

        description = None
        for vuln in data.get("vulnerabilities", []):
            for note in vuln.get("notes", []):
                if note.get("category") == "description":
                    description = note.get("text")

            release_date = vuln.get("release_date")

            product_status = vuln.get("product_status", {})
            known_not_affected = product_status.get("known_not_affected", [])
            known_affected = product_status.get("known_affected", [])

            for product in known_not_affected:
                rows.append({
                    "CVE_ID": cve_id,
                    "Published": published,
                    "Modified": modified,
                    "Status": status,
                    "Release_Date": release_date,
                    "Product": product,
                    "Affected": False,
                    "Description": description
                })
            for product in known_affected:
                rows.append({
                    "CVE_ID": cve_id,
                    "Published": published,
                    "Modified": modified,
                    "Status": status,
                    "Release_Date": release_date,
                    "Product": product,
                    "Affected": True,
                    "Description": description
                })

df = pd.DataFrame(rows)
df.to_csv("data/sep2025.csv", index=False)
print(df.head())
#print(df.info())

top_products = (
    df.groupby("Product")["CVE_ID"]
      .nunique()
      .sort_values(ascending=False)
      .head(50)
)
print(top_products)



top_products.plot(
    kind="barh",
    figsize=(12,10),
    title="Top 50 Products with Most Unique CVEs (Sep 2025)"
)
plt.xlabel("Unique CVE Count")
plt.ylabel("Product")
plt.gca().invert_yaxis()
plt.tight_layout()
plt.show()



nltk.download("stopwords")
stop_words = set(stopwords.words("english"))

words = []
for desc in df["Description"].dropna():
    for w in re.findall(r"\b[a-zA-Z]{5,}\b", desc.lower()):
        if w not in stop_words:
            words.append(w)

common_words = Counter(words).most_common(50)
print(common_words)

words_df = pd.DataFrame(common_words, columns=["Word", "Frequency"])
words_df.set_index("Word").plot(
    kind="barh",
    figsize=(12,10),
    legend=False,
    title="Top 50 Most Common Words in Vulnerability Descriptions (Sep 2025)"
)
plt.xlabel("Frequency")
plt.ylabel("Word")
plt.gca().invert_yaxis()
plt.tight_layout()
plt.show()