# Copyright © 2025 by Paul Watters. This software is licensed under CC BY-NC 4.0. To view a copy of this license, visit https://creativecommons.org/licenses/by-nc/4.0/
# Use is permitted for **non-commercial, educational, and research purposes only**. Any commercial use, distribution, or adaptation is strictly prohibited without prior written permission.
# This script connects to the VirusTotal API. You must supply your own API key and comply with VirusTotal’s Terms of Service:
# https://support.virustotal.com/hc/en-us/articles/115002168385-Terms-of-Service

import sys
import json
import html
import os

def dict_to_html(data, depth=0):
    if isinstance(data, dict):
        items = []
        for k, v in data.items():
            items.append(f"<div class='kv'><span class='key'>{html.escape(str(k))}:</span> {dict_to_html(v, depth+1)}</div>")
        return "<div class='dict'>" + "".join(items) + "</div>"
    elif isinstance(data, list):
        if len(data) == 0:
            return "<span class='empty'>[empty]</span>"
        items = []
        for v in data:
            items.append(f"<li>{dict_to_html(v, depth+1)}</li>")
        return "<ul>" + "".join(items) + "</ul>"
    else:
        return f"<span class='value'>{html.escape(str(data))}</span>"

def html_report(sha256, out):
    html_sections = []
    html_sections.append(f"<h1>VirusTotal Report for {sha256}</h1>")
    # Main file info
    html_sections.append("<h2>Main File Report</h2>")
    html_sections.append("<details open><summary>File Summary</summary>")
    html_sections.append(dict_to_html(out.get('file_report')))
    html_sections.append("</details>")
    # Relationships
    for key in out:
        if key in ['file_report', 'relationships_list']:
            continue
        html_sections.append(f"<h2>{key.replace('_',' ').title()}</h2>")
        html_sections.append(f"<details><summary>View {key}</summary>")
        html_sections.append(dict_to_html(out[key]))
        html_sections.append("</details>")
    # Relationships available
    html_sections.append("<h2>Available Relationships</h2>")
    html_sections.append("<details><summary>View Relationship List</summary>")
    html_sections.append(dict_to_html(out.get('relationships_list')))
    html_sections.append("</details>")
    # Basic styling and collapsible blocks
    style = """
    <style>
    body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f9f9f9; }
    h1 { color: #003366; }
    h2 { color: #225588; margin-top: 32px; }
    .dict { margin-left: 18px; }
    .kv { margin: 3px 0; }
    .key { font-weight: bold; color: #114477; }
    .value { color: #222; }
    ul { margin-left: 20px; }
    details { margin-bottom: 16px; }
    .empty { color: #aaa; font-style: italic; }
    summary { cursor: pointer; font-weight: bold; color: #444; font-size: 1.05em;}
    </style>
    """
    html_out = f"<html><head><meta charset='UTF-8'><title>VirusTotal Report: {sha256}</title>{style}</head><body>{''.join(html_sections)}</body></html>"
    return html_out

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <vt_full.json>")
        sys.exit(1)
    json_file = sys.argv[1]
    if not os.path.isfile(json_file):
        print(f"File not found: {json_file}")
        sys.exit(1)
    # Guess the hash from the filename (assumes [hash].vt_full.json)
    sha256 = os.path.basename(json_file).split(".")[0]
    with open(json_file, "r") as f:
        out = json.load(f)
    html_file = f"{sha256}.vt_full.html"
    html_content = html_report(sha256, out)
    with open(html_file, "w") as f:
        f.write(html_content)
    print(f"HTML report saved to: {html_file}")

