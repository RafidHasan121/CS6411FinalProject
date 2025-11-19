"""
generate_navigator_layer.py

Scans JSON files in an input folder, finds MITRE technique IDs (Txxxx or Txxxx.yyy),
aggregates counts, and writes a MITRE ATT&CK Navigator layer JSON file.
"""

import json
import glob
import os
import re
from collections import Counter, defaultdict
from typing import Any, Dict, List
import matplotlib.pyplot as plt

INPUT_GLOB = "output_json/*.json"   # adjust to your folder
OUTPUT_FILE = "navigator_layer.json"
DOMAIN = "enterprise-attack"        # change to 'mobile-attack' or 'ics-attack' if needed
LAYER_NAME = "Generated Layer Output"
LAYER_DESCRIPTION = "Auto-generated layer from scanned JSON outputs (technique IDs extracted by regex)."
AUTHOR = "Alieu Samateh"

# regex catches T1003 or T1021.001 style
TECH_REGEX = re.compile(r"\bT\d{4}(?:\.\d{1,3})?\b", flags=re.IGNORECASE)

def find_techniques_in_obj(obj: Any) -> List[str]:
    """
    Recursively search for technique IDs anywhere inside obj.
    Returns a list (may contain duplicates).
    """
    found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            # check keys and values
            if isinstance(k, str):
                found += TECH_REGEX.findall(k)
            found += find_techniques_in_obj(v)
    elif isinstance(obj, list):
        for item in obj:
            found += find_techniques_in_obj(item)
    elif isinstance(obj, str):
        found += TECH_REGEX.findall(obj)
    # other primitive types ignored (ints etc)
    return [t.upper() for t in found]

def scan_files(glob_pattern: str) -> Dict[str, List[str]]:
    """
    Returns mapping filename -> list of found technique IDs.
    """
    results = {}

    for path in glob.glob(glob_pattern):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError:
            # try fallback: treat file as line-delimited JSON and scan lines
            found = []
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    found += TECH_REGEX.findall(line)
            results[path] = [t.upper() for t in found]
            continue

        found = find_techniques_in_obj(data)
        results[path] = found



    return results



def build_layer(tech_counter: Counter, file_map: Dict[str, List[str]], domain=DOMAIN, name=LAYER_NAME, description=LAYER_DESCRIPTION, author=AUTHOR):
    """
    Build a Navigator layer dict from aggregated technique counts.
    Score scaling: counts -> 0..100 linearly (max count => 100).
    """


    if not tech_counter:
        raise ValueError("No techniques found. Aborting layer creation.")

    max_count = max(tech_counter.values())
    def scale(count):
        # avoid division by zero
        return int(round((count / max_count) * 100)) if max_count > 0 else 0

    techniques = []



    for tech, cnt in tech_counter.most_common():
        #comment_lines = [f"Count: {cnt}"]
        comment_lines = []
        # list a few filenames where this technique was found (limit)
        #files = [os.path.basename(p) for p, techs in file_map.items() if tech in techs]
        files = [p for p, techs in file_map.items() if tech in techs]
        if files:
            for f in files:
                with open(f) as fh:
                    j = json.load(fh)
                    sigma_results = j.get("data", {}).get("sigma_analysis_results", [])
                    if sigma_results:
                        descriptions = [r.get("rule_description", "No description") for r in sigma_results]
                        #comment_lines = j["data"]["sigma_analysis_results"].get("rule_description", "No description")


            #comment_lines.append("Found in files: " + ", ".join(files[:8]))
        comment = " | ".join(descriptions)

        techniques.append({
            "techniqueID": tech,
            "score": cnt,
            "comment": comment,
            #"color": "#ff0000",   # color is optional — Navigator will recolor via gradient if desired
            "enabled": True,
            "metadata": [],
            "showSubtechniques": True
        })



    layer = {
        "version": "4.5",
        "name": name,
        "description": description,
        "domain": domain,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#ff0000"],
            "minValue": 0,
            "maxValue": 100
        },
        "legendItems": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#e0e0e0",
        "selectTechniquesAcrossTactics": True,
        "sorting": 0,
        "viewMode": 0,
        "hideDisabled": False,
        "techniqueLayout": "side",
        "filters": {
            "platforms": [],
            "stages": []
        },
        "metadata": [
            {"name": "Author", "value": author},
            {"name": "Generated", "value": ""}
        ]
    }

    return layer

def main():
    file_map = scan_files(INPUT_GLOB)
    # aggregate counts
    counter = Counter()
    for path, techs in file_map.items():
        counter.update(techs)

    if not counter:
        print("No technique IDs found in any files. Exiting.")
        return

    layer = build_layer(counter, file_map)

    # optional: attach generation time
    import datetime
    layer["metadata"].append({"name": "Generated At"})

    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        json.dump(layer, out, indent=2)

    print(f"Navigator layer written to {OUTPUT_FILE}")
    print(f"Techniques found: {len(layer['techniques'])}")
    print("Top techniques (by count):")
    attack_technique = []
    technique_frequency = []
    for tech, cnt in counter.most_common()[:10]:
        print(f"  {tech} — {cnt}")
        attack_technique.append(tech)
        technique_frequency.append(cnt)

    plt.bar(attack_technique, technique_frequency)
    plt.xlabel('attack_technique')
    plt.ylabel('technique_frequency')
    plt.title('Attack technique frequency vs technique counts')
    plt.show()


if __name__ == "__main__":
    main()
