# Copyright © 2025 by Paul Watters. This software is licensed under CC BY-NC 4.0. To view a copy of this license, visit https://creativecommons.org/licenses/by-nc/4.0/
# Use is permitted for **non-commercial, educational, and research purposes only**. Any commercial use, distribution, or adaptation is strictly prohibited without prior written permission.
# This script connects to the VirusTotal API. You must supply your own API key and comply with VirusTotal’s Terms of Service:
# https://support.virustotal.com/hc/en-us/articles/115002168385-Terms-of-Service


import requests
import sys
import json

def vt_api_get(url, api_key):
    headers = {'x-apikey': api_key}
    results = []
    while url:
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            # If 'data' is a list, it's a paginated endpoint
            if isinstance(data.get('data'), list):
                results.extend(data['data'])
                url = data.get('links', {}).get('next')
            else:
                return data
        else:
            print(f"API error at {url}: {resp.status_code} {resp.text}")
            break
    return results

def main(sha256, api_key):
    # All outputs will be written here
    out = {}

    # File main report
    print("Fetching main file report...")
    file_url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    out['file_report'] = vt_api_get(file_url, api_key)

    # List of all relationships to extract
    rels = [
        'contacted_ips', 'contacted_domains', 'contacted_urls',
        'downloaded_files', 'bundled_files', 'communicating_files',
        'compressed_parents', 'execution_parents', 'dropped_files',
        'sigma_analysis_results', 'votes', 'comments', 'behaviours'
    ]

    # Fetch and store each relationship (with pagination!)
    for rel in rels:
        print(f"Fetching {rel}...")
        rel_url = f"https://www.virustotal.com/api/v3/files/{sha256}/{rel}"
        out[rel] = vt_api_get(rel_url, api_key)

    # Also fetch relationships exposed under /relationships endpoint (lists what's available)
    print("Fetching available relationships...")
    rels_url = f"https://www.virustotal.com/api/v3/files/{sha256}/relationships"
    out['relationships_list'] = vt_api_get(rels_url, api_key)

    # Save all info to a single JSON file
    out_file = f"{sha256}.vt_full.json"
    with open(out_file, "w") as f:
        json.dump(out, f, indent=2)

    print(f"\nAll available VirusTotal info has been saved to: {out_file}")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <SHA256_HASH> <VT_API_KEY>")
        sys.exit(1)
    sha256 = sys.argv[1]
    api_key = sys.argv[2]
    main(sha256, api_key)

