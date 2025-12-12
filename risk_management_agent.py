"""
Autonomous Web‑Presence Risk Management Agent
------------------------------------------------

This script implements a simplified version of the risk management agent
described in the accompanying research report.  It uses only public
information (passive reconnaissance) and does not perform any intrusive
actions.  The intent is that you can run this script on your own
machine (with Internet access) to evaluate the public security posture
of a given domain.

Key Features
------------
* **DNS record inspection** via Google's DNS‑over‑HTTPS API
* **Subdomain discovery** using certificate transparency logs (crt.sh)
* **Email authentication checks** for SPF, DKIM and DMARC records
* **HTTP security header analysis**
* **TLS certificate inspection**

Dependencies
------------
The script requires the following Python packages:

* `requests`  – for making HTTP requests
* `dnspython` – for DNS lookups (to install: `pip install dnspython`)

If `dnspython` is not installed, DNS queries will be skipped.  The
script will still attempt to query DNS via Google's DNS API.

Usage
-----
Run the script from the command line and provide the target domain
as an argument:

```
python risk_management_agent.py curiousai.us
```

The script will print a summary of findings, including discovered
subdomains, DNS records, email authentication status, security header
assessment, TLS certificate details and high‑level recommendations.

This is intended as an illustrative example.  In a production
environment you would likely expand it with additional data sources,
caching, concurrency and structured reporting (JSON/YAML outputs).
"""

import argparse
import json
import re
import ssl
import socket
import sys
from datetime import datetime
from typing import Dict, List, Optional

try:
    import requests
except ImportError as e:
    print("The 'requests' library is required to run this script. Please install it with 'pip install requests'.")
    sys.exit(1)

# Try to import dnspython. If unavailable we'll skip certain checks.
try:
    import dns.resolver
    import dns.exception
except ImportError:
    dns = None  # type: ignore


def get_dns_google(domain: str, record_type: str) -> List[Dict[str, str]]:
    """Retrieve DNS records using Google's DNS‑over‑HTTPS API.

    Args:
        domain: The domain to query.
        record_type: One of "A", "AAAA", "NS", "MX", "TXT", "CAA", etc.
    Returns:
        A list of record dictionaries from the API response. If the
        request fails, an empty list is returned.
    """
    url = f"https://dns.google/resolve?name={domain}&type={record_type}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data.get("Answer", [])
    except Exception as e:
        print(f"[*] Google DNS query for {record_type} failed: {e}")
        return []


def get_dns_dnspython(domain: str, record_type: str) -> List[str]:
    """Retrieve DNS records using dnspython if available.

    This function attempts to be compatible with different dnspython
    versions.  In dnspython < 2.0 the `resolve` method may not exist,
    so we fall back to `query` if necessary.

    Args:
        domain: The domain to query.
        record_type: DNS record type (e.g., 'MX', 'TXT').
    Returns:
        A list of record strings. Empty if not available or an error occurs.
    """
    if dns is None:
        return []
    try:
        # Try using the modern API first
        if hasattr(dns.resolver, "resolve"):
            answers = dns.resolver.resolve(domain, record_type)
        else:
            # Older dnspython versions use query()
            answers = dns.resolver.query(domain, record_type)
        return [str(rdata.to_text()) for rdata in answers]
    except Exception:
        return []


def discover_subdomains(domain: str) -> List[str]:
    """Discover subdomains using certificate transparency logs from crt.sh.

    Args:
        domain: The domain to search for.
    Returns:
        A list of unique subdomains (including wildcard entries).  If
        crt.sh is unreachable, returns an empty list.
    """
    query_url = f"https://crt.sh/?q={domain}&output=json"
    try:
        resp = requests.get(query_url, timeout=15)
        resp.raise_for_status()
        entries = resp.json()
        subdomains = set()
        for entry in entries:
            name_value = entry.get("name_value", "")
            for sub in name_value.split("\n"):
                sub = sub.strip().lower().rstrip('.')
                if sub.endswith(domain):
                    subdomains.add(sub)
        return sorted(subdomains)
    except Exception as e:
        print(f"[*] Error querying crt.sh: {e}")
        return []


def check_spf(domain: str) -> Optional[str]:
    """Retrieve the SPF record for a domain using dnspython if available.

    Returns:
        The SPF string if present, otherwise None.
    """
    txt_records = get_dns_dnspython(domain, "TXT")
    for rec in txt_records:
        if rec.strip().startswith("v=spf1"):
            return rec.strip()
    return None


def check_dmarc(domain: str) -> Optional[str]:
    """Retrieve the DMARC record for a domain using dnspython.
    Returns:
        The DMARC record string if present.
    """
    dmarc_domain = f"_dmarc.{domain}"
    txt_records = get_dns_dnspython(dmarc_domain, "TXT")
    for rec in txt_records:
        if rec.strip().startswith("v=DMARC1"):
            return rec.strip()
    return None


def check_dkim(domain: str) -> List[str]:
    """Attempt to retrieve DKIM selectors via heuristic patterns.

    Note: DKIM selectors are specific to mail providers and often need
    knowledge of the selector used.  This function attempts some
    common selectors (e.g. default, mail) and returns any found keys.
    """
    selectors = ["default", "mail", "selector1", "google", "mx"]
    keys = []
    for selector in selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        txt_records = get_dns_dnspython(dkim_domain, "TXT")
        for rec in txt_records:
            if rec.strip().startswith("v=DKIM1"):
                keys.append(f"{selector}: {rec.strip()}")
    return keys


def get_http_security_headers(url: str) -> Dict[str, bool]:
    """Check for the presence of important HTTP security headers.

    Args:
        url: The full URL (scheme+hostname) to query.
    Returns:
        A dictionary mapping header names to True/False depending on whether
        they are present.
    """
    required_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]
    presence = {h: False for h in required_headers}
    try:
        resp = requests.get(url, timeout=10)
        for header in presence.keys():
            if header in resp.headers:
                presence[header] = True
        return presence
    except Exception as e:
        print(f"[*] Error fetching {url}: {e}")
        return presence


def get_tls_certificate(hostname: str) -> Optional[Dict[str, str]]:
    """Retrieve the TLS certificate details for a host.

    Args:
        hostname: The domain or subdomain to connect to.
    Returns:
        A dictionary containing subject, issuer and validity period, or None
        if retrieval fails.
    """
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as sock:
        try:
            sock.settimeout(10)
            sock.connect((hostname, 443))
            cert = sock.getpeercert()
            return {
                "subject": str(cert.get("subject")),
                "issuer": str(cert.get("issuer")),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
            }
        except Exception as e:
            print(f"[*] Error retrieving TLS certificate: {e}")
            return None


def generate_recommendations(headers_presence: Dict[str, bool], spf: Optional[str], dmarc: Optional[str], dkim_keys: List[str]) -> List[str]:
    """Generate remediation recommendations based on findings.

    Args:
        headers_presence: Mapping of header names to booleans.
        spf: SPF record string or None.
        dmarc: DMARC record string or None.
        dkim_keys: List of DKIM keys found.
    Returns:
        A list of recommendation strings.
    """
    recs = []
    # HTTP security headers
    for header, present in headers_presence.items():
        if not present:
            recs.append(f"Add missing HTTP header: {header}")
    # SPF/DMARC
    if spf is None:
        recs.append("Publish an SPF record to define authorized mail senders.")
    if dmarc is None:
        recs.append("Publish a DMARC record (v=DMARC1) with a monitoring policy.")
    else:
        # Encourage moving to enforce mode if using p=none
        if re.search(r"p=none", dmarc, re.IGNORECASE):
            recs.append("Consider moving your DMARC policy from 'none' to 'quarantine' or 'reject' once alignment is confirmed.")
    if not dkim_keys:
        recs.append("Ensure DKIM selectors are configured and published.")
    return recs


def summarise_findings(domain: str) -> None:
    """Collect and print a summary of security findings for a domain."""
    print(f"\n=== Risk Management Report for {domain} ===")
    print(f"Generated: {datetime.utcnow().isoformat()}Z\n")
    # Discover subdomains
    subdomains = discover_subdomains(domain)
    print(f"Found {len(subdomains)} subdomains via crt.sh (may include duplicates):")
    for sd in subdomains[:20]:
        print(f"  - {sd}")
    if len(subdomains) > 20:
        print("  ... (additional subdomains omitted)")
    # DNS records
    record_types = ["A", "AAAA", "NS", "MX", "TXT", "CAA"]
    for rtype in record_types:
        records = get_dns_google(domain, rtype)
        if records:
            print(f"\n{rtype} records:")
            for rec in records:
                # present result succinctly
                data = rec.get("data")
                print(f"  {data}")
    # Email authentication
    spf = check_spf(domain)
    dmarc = check_dmarc(domain)
    dkim_keys = check_dkim(domain)
    print("\nEmail authentication:")
    print(f"  SPF:   {spf or 'not found'}")
    print(f"  DMARC: {dmarc or 'not found'}")
    if dkim_keys:
        for key in dkim_keys:
            print(f"  DKIM:  {key}")
    else:
        print("  DKIM:  no keys found in common selectors")
    # HTTP security headers
    url = f"https://{domain}"
    headers_presence = get_http_security_headers(url)
    print("\nHTTP security headers:")
    for header, present in headers_presence.items():
        print(f"  {header}: {'present' if present else 'missing'}")
    # TLS certificate
    cert_info = get_tls_certificate(domain)
    print("\nTLS certificate:")
    if cert_info:
        print(f"  Subject: {cert_info['subject']}")
        print(f"  Issuer:  {cert_info['issuer']}")
        print(f"  Valid from {cert_info['not_before']} to {cert_info['not_after']}")
    else:
        print("  Unable to retrieve certificate details.")
    # Recommendations
    recs = generate_recommendations(headers_presence, spf, dmarc, dkim_keys)
    print("\nRecommendations:")
    if recs:
        for rec in recs:
            print(f"  - {rec}")
    else:
        print("  No immediate recommendations; configuration appears robust.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Autonomous Web‑Presence Risk Management Agent")
    parser.add_argument("domain", help="Target domain to analyze (e.g., example.com)")
    args = parser.parse_args()
    summarise_findings(args.domain)


if __name__ == "__main__":
    main()
