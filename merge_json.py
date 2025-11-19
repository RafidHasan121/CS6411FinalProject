import json
import glob

merged = {"data": []}

# Loop through all JSON files in the folder
for filename in glob.glob("vt_reports_copy/*.json"):  # adjust folder name if needed
    try:
        with open(filename, "r", encoding="utf-8") as f:
            json.load(f)
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON in: {filename}")
        print(f"   → {e}")

# Save the combined JSON
with open("merged.json", "w", encoding="utf-8") as f:
    json.dump(merged, f, indent=2)

print(" Merged all JSON files into merged.json")
