# Copyright © 2025 by Paul Watters. This software is licensed under CC BY-NC 4.0. To view a copy of this license, visit https://creativecommons.org/licenses/by-nc/4.0/
# Use is permitted for **non-commercial, educational, and research purposes only**. Any commercial use, distribution, or adaptation is strictly prohibited without prior written permission.
# This script connects to the VirusTotal API. You must supply your own API key and comply with VirusTotal’s Terms of Service:
# https://support.virustotal.com/hc/en-us/articles/115002168385-Terms-of-Service

import sys
import json
import os

def summary_from_vt_json(json_file):
    with open(json_file, "r") as f:
        vt = json.load(f)
    sha256 = os.path.basename(json_file).split(".")[0]

    # 1. AV engines reporting MALICIOUS/SUSPICIOUS
    engines = []
    try:
        av_results = vt["file_report"]["data"]["attributes"]["last_analysis_results"]
        for eng, info in av_results.items():
            if info.get("category") in ("malicious", "suspicious") and info.get("result"):
                engines.append((eng, info.get("result")))
    except Exception:
        pass

    # 2. Contacted IPs/domains that are NOT harmless/undetected
    bad_ips = []
    for ip in vt.get("contacted_ips", []):
        stats = ip.get("attributes", {}).get("last_analysis_stats", {})
        if stats.get("malicious", 0) or stats.get("suspicious", 0):
            bad_ips.append(ip["id"])

    bad_domains = []
    for dom in vt.get("contacted_domains", []):
        stats = dom.get("attributes", {}).get("last_analysis_stats", {})
        if stats.get("malicious", 0) or stats.get("suspicious", 0):
            bad_domains.append(dom["id"])

    # 3. Sandbox verdicts
    verdicts = []
    try:
        verdicts = [
            (name, v.get("category"), v.get("malware_classification"))
            for name, v in vt["file_report"]["data"]["attributes"]["sandbox_verdicts"].items()
            if v.get("category") not in ("harmless", "undetected")
        ]
    except Exception:
        pass

    # 4. Crowdsourced IDS/YARA hits that are not info/low
    ids_hits = []
    try:
        for rule in vt["file_report"]["data"]["attributes"]["crowdsourced_ids_results"]:
            sev = rule.get("alert_severity", "info")
            if sev not in ("info", "low"):
                ids_hits.append(rule)
    except Exception:
        pass

    # Print summary
    print("="*60)
    print(f"Malicious Activity Summary for: {sha256}")
    print("="*60)
    print("\nAV Engines Detected Malicious/Suspicious:")
    if engines:
        for eng, result in engines:
            print(f"- {eng}: {result}")
    else:
        print("None detected as malicious/suspicious.")

    print("\nContacted IPs flagged as malicious/suspicious:")
    if bad_ips:
        for ip in bad_ips:
            print(f"- {ip}")
    else:
        print("None.")

    print("\nContacted Domains flagged as malicious/suspicious:")
    if bad_domains:
        for dom in bad_domains:
            print(f"- {dom}")
    else:
        print("None.")

    print("\nSandbox verdicts (excluding harmless/undetected):")
    if verdicts:
        for name, cat, mclass in verdicts:
            print(f"- {name}: {cat} ({mclass})")
    else:
        print("All verdicts harmless/undetected.")

    print("\nCrowdsourced IDS/YARA hits of concern (medium/high):")
    if ids_hits:
        for rule in ids_hits:
            print(f"- {rule.get('rule_msg', 'No description')} (Severity: {rule.get('alert_severity')})")
    else:
        print("None.")
    print("="*60)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <vt_full.json>")
        sys.exit(1)
    summary_from_vt_json(sys.argv[1])

