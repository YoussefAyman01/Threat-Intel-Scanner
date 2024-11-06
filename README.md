# IP Malicious Checker

This script checks a list of IP addresses for malicious activity using the VirusTotal API. It determines whether an IP is clean or has been flagged as malicious by multiple security solutions. Results are saved in two separate files: one for malicious IPs and one for clean (whitelisted) IPs.

## Features

- Checks IP addresses against VirusTotal's database.
- Classifies IPs as malicious or clean.
- Logs results in two output files:
  - `malicious_ip.txt` - IPs that are flagged as malicious.
  - `whitelisted_ips.txt` - IPs that are clean with no malicious flags.
  
## Prerequisites

Before using this script, make sure you have:

- A **VirusTotal API key**. You can get it by creating a free account on [VirusTotal](https://www.virustotal.com/).
- The following Python libraries installed:
  - `requests` - Used for making HTTP requests to the VirusTotal API.

You can install the required dependencies using pip:

```bash
pip install requests

To Run The Code
>> python code1.py
