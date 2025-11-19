import csv
import json
import os
import time
import requests
from typing import List

# === API key setup ===
API_KEY = "bf72aeb621a9e8af0e18bedc1e00c8c1aa17a02c14bd22a770bd98f6bb7ece86"
headers = {"x-apikey": API_KEY}

# === Read hashes from CSV ===
def read_hash_file(file_name: str, hash_col: str = "hash") -> List[str]:
    hashes = []
    with open(file_name, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            raise ValueError("CSV file appears to have no header row.")
        if hash_col not in reader.fieldnames:
            raise ValueError(f"Column '{hash_col}' not found in CSV header: {reader.fieldnames}")

        for row in reader:
            raw = row.get(hash_col, "")
            if raw:
                hashes.append(raw.strip().lower())
    return hashes


# === Fetch behaviour summary for each hash and save individually ===
def fetch_and_save_hash_data( hash_vals: List[str], output_folder: str = "output_json"):
    # Create output folder if not exists
    os.makedirs(output_folder, exist_ok=True)

    for hash_val in hash_vals:
        url = f"https://www.virustotal.com/api/v3/files/{hash_val}/behaviour_summary"
        try:
            response = requests.get(url, headers=headers)
            data = response.json()

            # Save individual file named after hash
            file_path = os.path.join(output_folder, f"{hash_val}.json")
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

            print(f"✅ Saved {file_path}")
        except Exception as e:
            print(f"❌ Error fetching {hash_val}: {e}")

        # VirusTotal has rate limits (4/min for free keys) → wait before next request
        time.sleep(16)


# === Run script ===
if __name__ == "__main__":
    print("🔍 Reading hashes...")
    hash_values = read_hash_file("output/aj_all.csv")  # change filename as needed
    print(f"Found {len(hash_values)} hashes.")

    fetch_and_save_hash_data(hash_values)
