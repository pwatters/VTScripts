# VTScripts
A collection of scripts to automate the analysis of threat intelligence from VirusTotal.
Usage example (assuming MacOS):
$ shasum -a 256 test.file        /* Replace test.file to generate hash */
$ python vt_fullreport.py hash api.key /* Replace hash with the SHA256 and api.key with your API key obtained from VirusTotal */
$ python vt_json_to_html.py test.json /* Replace test.json with the JSON file generated from the previous step, if you want a HTML report */
$ python vt_malicious_summary.py test.json /* Replace test.json with the JSON file generated from the previous step, if you want a summary of malicious activity */
Output for the summary will be something like this:
Sample 2 - XXXXXX.apk 

============================================================

Malicious Activity Summary for: XXXXXXXX

============================================================

AV Engines Detected Malicious/Suspicious:

- Zillya: Trojan.Ewind.Android.3395

- SymantecMobileInsight: AppRisk:Generisk

- ESET-NOD32: a variant of Android/Packed.Jiagu.D potentially unsafe

- Kingsoft: Win32.Troj.Undef.a

- Fortinet: Riskware/Application

Contacted IPs flagged as malicious/suspicious:

- X.X.X.X

- Y.Y.Y.Y
Contacted Domains flagged as malicious/suspicious:
- ww.ZZZZ435435.com

Crowdsourced IDS/YARA hits of concern (medium/high):

- (port_scan) TCP filtered portsweep (Severity: medium)

============================================================

Copyright © 2025 by Paul Watters. This software is licensed under CC BY-NC 4.0. To view a copy of this license, visit https://creativecommons.org/licenses/by-nc/4.0/

Use is permitted for **non-commercial, educational, and research purposes only**. Any commercial use, distribution, or adaptation is strictly prohibited without prior written permission.

This script connects to the VirusTotal API. You must supply your own API key and comply with VirusTotal’s Terms of Service:
https://support.virustotal.com/hc/en-us/articles/115002168385-Terms-of-Service

THE CODE IS PROVIDED "AS IS", WITHOUT WARRANTIES OR GUARANTEES. THE AUTHOR DISCLAIMS ALL LIABILITY FOR DAMAGES ARISING FROM ITS USE.


