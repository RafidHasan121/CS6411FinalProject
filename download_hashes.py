import json
import csv
import os

def get_hash_and_signature(json_file, output_csv):
    # Read JSON file
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    file_exists = os.path.exists(output_csv)

    # Check if 'data' key exists
    if 'data' not in data:
        raise ValueError("Invalid JSON structure. Expected a top-level 'data' key.")

    # Prepare CSV file
    with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['family', 'hash']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        if not file_exists:
            writer.writeheader()

        # Loop through the list of records
        for item in data['data']:
        #for item in data['data'][:11]:
            sha256 = item.get('sha256_hash', '')
            signature = item.get('signature', '')
            writer.writerow( {'family': signature,'hash':sha256})


    print(f"file reading finished...")


# Example usage:
get_hash_and_signature('./hash-data/all_7_families.json', './output/hash_signature_output.csv')
