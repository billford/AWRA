# Autonomous Web‑Presence Risk Management Agent

This repository contains a Python script (`risk_management_agent.py`) that implements a passive reconnaissance agent for assessing the public security posture of a domain.  The agent uses only openly accessible data sources (DNS APIs, certificate transparency logs, and HTTP requests) and does **not** perform any intrusive or active scanning.

## Features

- **DNS Inspection** – Queries Google’s DNS‑over‑HTTPS API and, if available, `dnspython` to retrieve A, AAAA, NS, MX, TXT, and CAA records for a domain.
- **Subdomain Discovery** – Uses [crt.sh](https://crt.sh/) to enumerate subdomains via certificate transparency logs.
- **Email Authentication Checks** – Looks for SPF, DMARC, and common DKIM selectors to assess email‐spoofing protections.
- **HTTP Security Headers** – Fetches the homepage over HTTPS and checks for best‑practice security headers (Content‑Security‑Policy, HSTS, X‑Frame‑Options, etc.).
- **TLS Certificate Inspection** – Retrieves and reports on the TLS certificate’s subject, issuer and validity period.
- **Recommendations** – Generates simple remediation suggestions based on missing headers and absent email‑authentication records.

## Requirements

This script is intended to be run on a machine with internet access.  It depends on the following Python libraries:

```bash
pip install requests dnspython
```
If dnspython is not installed, the script will still work, but some DNS lookups (e.g., SPF/DMARC/DKIM checks) will be skipped.

Usage
Clone or download this repository, open a terminal, and run:

```
python risk_management_agent.py <domain>
For example:


python risk_management_agent.py curiousai.us
The script outputs:

A list of discovered subdomains (from crt.sh)

DNS record values for the specified record types

SPF, DMARC, and DKIM records (if present)

Presence/absence of common HTTP security headers

TLS certificate subject/issuer and validity dates

A list of simple recommendations based on what was detected ```

Notes
Passive Reconnaissance – The agent only uses publicly available data sources and does not port‑scan, brute‑force or otherwise probe the target. It is therefore suitable for running without prior authorization when evaluating your own domains. Always obtain permission before running any form of security testing on systems you do not own.

Limitations – The script provides a basic overview and does not substitute for professional penetration testing or comprehensive External Attack Surface Management (EASM) platforms. You can extend it by incorporating additional OSINT sources, vulnerability scanning with tools like Subfinder, Amass or Nuclei, and by integrating with ticketing systems for automated remediation workflows.

License
This project is provided as‑is for educational purposes. You may adapt and use it within your own organization, but no warranty is provided.
