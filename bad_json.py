import json

with open("vt_reports/aj_all.json", "r", encoding="utf-8") as f:
    content = f.read().strip()

# Split by lines, parse each JSON object
parts = [json.loads(line) for line in content.splitlines() if line.strip()]

merged = {"data": [p["data"] for p in parts if "data" in p]}

with open("vt_reports/fixed_file.json", "w", encoding="utf-8") as f:
    json.dump(merged, f, indent=2)
