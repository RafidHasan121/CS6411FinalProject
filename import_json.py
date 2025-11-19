import json
import csv
import os
import pandas as pd

# -------------------------------
# CONFIGURATION
# -------------------------------
# Directory containing VirusTotal JSON reports
input_dir = "output_json/"
output_csv = "malware_behavior_data.csv"

# Helper: Safely extract nested JSON fields
def safe_get(data, keys, default=""):
    for key in keys:
        data = data.get(key, {})
    return data if data else default

# List to hold parsed rows
records = []

# Loop through each JSON report
for filename in os.listdir(input_dir):
    if not filename.endswith(".json"):
        continue

    with open(os.path.join(input_dir, filename), "r", encoding="utf-8") as f:
        report = json.load(f)

    # -------------------------------
    # EXTRACT CORE METADATA
    # -------------------------------
    sample_hash = report.get("data", {}).get("id", "")
    attributes = report.get("data", {}).get("attributes", {})
    sandbox_reports = attributes.get("sandbox_verdicts", {})
    behavior_data = attributes.get("behavior", {})

    # Sandbox details (first vendor if multiple)
    sandbox_vendor = list(sandbox_reports.keys())[0] if sandbox_reports else ""
    sandbox_info = sandbox_reports.get(sandbox_vendor, {})

    # -------------------------------
    # EXTRACT BEHAVIORAL INDICATORS
    # -------------------------------
    network_activity = behavior_data.get("network", {})
    processes = behavior_data.get("processes", [])
    files = behavior_data.get("files", [])
    registry = behavior_data.get("registry_keys", [])

    # Extract typical fields
    record = {
        "sample_hash": sample_hash,
        "malware_family": attributes.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
        "submission_date": attributes.get("first_submission_date", ""),
        "sandbox_vendor": sandbox_vendor,
        "process_executed": ", ".join([p.get("name", "") for p in processes[:5]]),
        "command_line_args": ", ".join([p.get("command_line", "") for p in processes[:3]]),
        "file_operations": ", ".join([f.get("path", "") for f in files[:5]]),
        "registry_modifications": ", ".join(registry[:5]) if isinstance(registry, list) else "",
        "network_activity": ", ".join([n.get("domain", "") for n in network_activity.get("domains", [])]),
        "protocol_used": ", ".join(network_activity.keys()),
        "mutex_created": ", ".join(behavior_data.get("mutexes", [])[:3]),
        "scheduled_tasks": str("task" in json.dumps(behavior_data).lower()),
        "persistence_mechanisms": "",
        "privilege_escalation": "",
        "defense_evasion": "",
        "data_exfiltration": "",
        "c2_servers": ", ".join([ip.get("ip", "") for ip in network_activity.get("hosts", [])]),
        "observed_behaviors": sandbox_info.get("malware_classification", ""),
        "mapped_attack_techniques": "",
        "technique_names": "",
        "tactic_category": "",
        "data_source": "VirusTotal",
        "confidence_score": "",
        "comments": ""
    }

    records.append(record)

# -------------------------------
# SAVE TO CSV
# -------------------------------
df = pd.DataFrame(records)
df.to_csv(output_csv, index=False, encoding="utf-8")
print(f"✅ Data successfully saved to: {output_csv}")
print(f"Total samples processed: {len(df)}")
