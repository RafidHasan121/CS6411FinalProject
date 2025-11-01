import requests
import pandas as pd
import csv
from typing import List
import time

# replace API with from VT
# AJ - API KEY
API_KEY = 'bf72aeb621a9e8af0e18bedc1e00c8c1aa17a02c14bd22a770bd98f6bb7ece86'

# Edihe API KEY
# API_KEY = '94ea76985c5d2d8c8f56804d762285b085a75833c0f48ce06d787333b8a86c19'

API_SECRET = 'aaa9121164520836db909b63715d334d7642175f320dd435'

headers = {"x-apikey": API_KEY}

def read_hash_file(file_name: str, hash_col: str = "hash") -> List[str]:
    hashes = []
    with open(file_name, newline='', encoding='utf-8') as fh:
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

def get_sample_data(hash_vals: List[str]):
    results = []
    for hash_val in hash_vals:
        url = f"https://www.virustotal.com/api/v3/files/{hash_val}/behaviour_summary"
        response = requests.get(url, headers=headers)

        #if response.status_code == 200:
        data = response.json()
        results.append(data)
        print(f"Fetched data for {hash_val}")
        #else:
        #print(f"Error {response.status_code} for {hash_val}")

        time.sleep(16)

    # Save all results after loop
    df = pd.DataFrame(results)

    # 1. CREATE A JSON FILE
    df.to_json("aj_all.json", orient="records", indent=2)
    print(f"Fetched sample data for {hash_vals}")

print("Sample Query.")


# 2. create a new file with your name in the output folder
hash_values = read_hash_file("./output/aj_all.csv")
print(f"{len(hash_values)} hashes found")
get_sample_data(hash_values)