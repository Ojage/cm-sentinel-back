import os
import re
import time
import json
from typing import Any, Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

# --- bootstrap ---
load_dotenv()
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})  # adjust origins for prod

REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "6"))
IP2WHOIS_API_KEY = os.getenv("IP2WHOIS_API_KEY", "").strip()
GOOGLE_DNS = "https://dns.google/resolve"

# -------- utils --------
_cm_label = re.compile(r"^[a-z0-9-]{1,63}$", re.IGNORECASE)

def normalize_domain(raw: str) -> str:
    v = raw.strip().lower()
    # strip scheme, path, query, fragments if pasted as URL
    v = re.sub(r"^[a-z]+://", "", v)
    v = re.split(r"[/?#]", v, 1)[0]
    return v.rstrip(".")

def is_valid_cm_domain(raw: str) -> bool:
    host = normalize_domain(raw)
    if not host.endswith(".cm"):
        return False
    labels = host.split(".")
    if len(labels) < 2:
        return False
    for lb in labels:
        if not _cm_label.match(lb):
            return False
        if lb.startswith("-") or lb.endswith("-"):
            return False
    return True

def http_get(url: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        r = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
        if r.ok:
            return r.json()
    except requests.RequestException:
        return None
    return None

# -------- external lookups --------
def dns_query(name: str, rtype: str) -> List[Dict[str, Any]]:
    """Query Google DNS-over-HTTPS. Returns RRset list (empty if none)."""
    data = http_get(GOOGLE_DNS, {"name": name, "type": rtype})
    if not data or "Answer" not in data:
        return []
    answers = data.get("Answer", [])
    # Normalize a bit
    out = []
    for a in answers:
        out.append({
            "recordType": rtype,
            "value": a.get("data", ""),
            "ttl": a.get("TTL", 0),
        })
    return out

def get_dns_bundle(domain: str) -> List[Dict[str, Any]]:
    records = []
    for rtype in ("A", "AAAA", "NS", "MX", "TXT", "CNAME"):
        records.extend(dns_query(domain, rtype))
    return records


def whois_lookup(domain: str) -> Optional[Dict[str, Any]]:
    """Use WhoisXMLAPI with proper handling of XML/JSON responses."""
    if not IP2WHOIS_API_KEY:
        return None

    url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"

    # Try POST method first with JSON output format specified
    payload = {
        "domainName": domain,
        "apiKey": IP2WHOIS_API_KEY,
        "outputFormat": "JSON"  # Request JSON format explicitly
    }

    headers = {
        "Content-Type": "application/json"
    }

    try:
        print(f"Making WHOIS request for domain: {domain}")

        response = requests.post(url, json=payload, headers=headers, timeout=30)

        print(f"Response status: {response.status_code}")
        print(f"Response content-type: {response.headers.get('content-type', 'unknown')}")
        print(f"Raw response (first 500 chars): {response.text[:500]}...")

        response.raise_for_status()

        if not response.text.strip():
            print("API returned empty response")
            return None

        # Check if response is XML or JSON
        content_type = response.headers.get('content-type', '').lower()
        response_text = response.text.strip()

        # Determine format by content
        is_xml = (response_text.startswith('<?xml') or
                  response_text.startswith('<WhoisRecord') or
                  'xml' in content_type)

        if is_xml:
            print("Processing XML response...")
            return parse_whois_xml(response_text, domain)
        else:
            print("Processing JSON response...")
            try:
                data = response.json()
                return parse_whois_json(data, domain)
            except json.JSONDecodeError as e:
                print(f"JSON decode error: {e}")
                return None

    except requests.exceptions.HTTPError as e:
        print(f"HTTP error {response.status_code}: {response.text}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"WHOIS API request failed: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error in WHOIS lookup: {e}")
        return None


def parse_whois_xml(xml_text: str, domain: str) -> Optional[Dict[str, Any]]:
    """Parse XML response from WhoisXMLAPI."""
    try:
        # Remove XML declaration and parse
        if xml_text.startswith('<?xml'):
            xml_text = xml_text.split('?>', 1)[1] if '?>' in xml_text else xml_text

        root = ET.fromstring(xml_text)

        # Handle both direct WhoisRecord and nested structure
        whois_record = root if root.tag == 'WhoisRecord' else root.find('WhoisRecord')
        if whois_record is None:
            print("No WhoisRecord found in XML")
            return None

        # Extract basic info - prioritize registryData if available
        registry_data = whois_record.find('registryData')
        data_source = registry_data if registry_data is not None else whois_record

        # Get domain name
        domain_name_elem = data_source.find('domainName')
        domain_name = domain_name_elem.text if domain_name_elem is not None else domain

        # Get registrar
        registrar_name_elem = data_source.find('registrarName')
        registrar = registrar_name_elem.text if registrar_name_elem is not None else None

        # Get dates
        created_date_elem = data_source.find('createdDate')
        created_date = created_date_elem.text if created_date_elem is not None else None

        expires_date_elem = data_source.find('expiresDate')
        expires_date = expires_date_elem.text if expires_date_elem is not None else None

        # Get status
        status_elem = data_source.find('status')
        status = None
        if status_elem is not None and status_elem.text:
            # Status might be space-separated, take first one
            status = status_elem.text.split()[0] if status_elem.text.strip() else None

        # Get name servers
        nameservers = []
        nameservers_elem = data_source.find('nameServers')
        if nameservers_elem is not None:
            # Try hostNames first
            hostnames_elem = nameservers_elem.find('hostNames')
            if hostnames_elem is not None:
                for address in hostnames_elem.findall('Address'):
                    if address.text and address.text.strip():
                        nameservers.append(address.text.strip())

            # Fallback to rawText if no hostNames found
            if not nameservers:
                rawtext_elem = nameservers_elem.find('rawText')
                if rawtext_elem is not None and rawtext_elem.text:
                    # Parse nameservers from raw text
                    lines = rawtext_elem.text.strip().split('\n')
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith('Name Server:'):
                            nameservers.append(line)

        # Try to get registrant info (often not available in public WHOIS)
        registrant = "Private Registration"  # Default

        # Look for contact email as fallback for registrant
        contact_email_elem = whois_record.find('contactEmail')
        if contact_email_elem is not None and contact_email_elem.text:
            registrant = contact_email_elem.text

        result = {
            "domain": domain_name,
            "registrar": registrar,
            "registrant": registrant,
            "registrationDate": created_date,
            "expirationDate": expires_date,
            "status": status,
            "nameServers": nameservers,
        }

        print(f"Parsed WHOIS data: {json.dumps(result, indent=2)}")
        return result

    except ET.ParseError as e:
        print(f"XML parsing error: {e}")
        print(f"Problematic XML: {xml_text[:1000]}")
        return None
    except Exception as e:
        print(f"Error parsing XML response: {e}")
        return None


def parse_whois_json(data: Dict[str, Any], domain: str) -> Optional[Dict[str, Any]]:
    """Parse JSON response from WhoisXMLAPI."""
    try:
        whois_record = data.get("WhoisRecord", {})
        if not whois_record:
            print("No WhoisRecord found in JSON")
            return None

        # Prioritize registryData if available
        registry_data = whois_record.get("registryData", {})
        data_source = registry_data if registry_data else whois_record

        # Extract registrar information
        registrar_info = data_source.get("registrar") or data_source.get("registrarName")
        registrar_name = None
        if isinstance(registrar_info, dict):
            registrar_name = registrar_info.get("name") or registrar_info.get("registrarName")
        elif isinstance(registrar_info, str):
            registrar_name = registrar_info

        # Extract registrant information
        registrant_info = data_source.get("registrant", {})
        registrant_name = "Private Registration"  # Default
        if isinstance(registrant_info, dict):
            registrant_name = (
                    registrant_info.get("name") or
                    registrant_info.get("organization") or
                    registrant_name
            )

        # Extract status information
        status_info = data_source.get("status")
        status = None
        if isinstance(status_info, list) and status_info:
            first_status = status_info[0]
            if isinstance(first_status, dict):
                status = first_status.get("status") or first_status.get("name")
            else:
                status = str(first_status)
        elif isinstance(status_info, str):
            status = status_info.split()[0].strip()

        # Extract name servers
        nameservers_info = data_source.get("nameServers", {})
        nameservers = []

        if isinstance(nameservers_info, dict):
            hostnames = nameservers_info.get("hostNames", [])
            if isinstance(hostnames, list):
                nameservers = [ns for ns in hostnames if ns and isinstance(ns, str)]
        elif isinstance(nameservers_info, list):
            for ns in nameservers_info:
                if isinstance(ns, dict):
                    name = ns.get("name") or ns.get("hostName")
                    if name:
                        nameservers.append(name)
                elif isinstance(ns, str):
                    nameservers.append(ns)

        return {
            "domain": data_source.get("domainName", domain),
            "registrar": registrar_name,
            "registrant": registrant_name,
            "registrationDate": data_source.get("createdDate"),
            "expirationDate": data_source.get("expiresDate"),
            "status": status,
            "nameServers": nameservers,
        }

    except Exception as e:
        print(f"Error parsing JSON response: {e}")
        return None


# Alternative using GET method (some APIs prefer this)
def whois_lookup_get_method(domain: str) -> Optional[Dict[str, Any]]:
    """Alternative WHOIS lookup using GET method."""
    if not IP2WHOIS_API_KEY:
        return None

    url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"

    params = {
        "domainName": domain,
        "apiKey": IP2WHOIS_API_KEY,
        "outputFormat": "JSON"
    }

    try:
        print(f"Making WHOIS GET request for domain: {domain}")
        response = requests.get(url, params=params, timeout=30)

        print(f"Response status: {response.status_code}")
        print(f"Response content-type: {response.headers.get('content-type', 'unknown')}")

        response.raise_for_status()

        if not response.text.strip():
            return None

        # Handle both XML and JSON responses
        response_text = response.text.strip()
        is_xml = (response_text.startswith('<?xml') or
                  response_text.startswith('<WhoisRecord'))

        if is_xml:
            return parse_whois_xml(response_text, domain)
        else:
            try:
                data = response.json()
                return parse_whois_json(data, domain)
            except json.JSONDecodeError:
                return None

    except Exception as e:
        print(f"GET method failed: {e}")
        return None


# Test function
def test_whois_api(domain: str = "google.com") -> bool:
    """Test WHOIS API with both methods."""
    if not IP2WHOIS_API_KEY:
        print("No API key configured")
        return False

    print(f"Testing WHOIS API with domain: {domain}")

    print("\n=== Testing POST method ===")
    result_post = whois_lookup(domain)

    print("\n=== Testing GET method ===")
    result_get = whois_lookup_get_method(domain)

    success = result_post is not None or result_get is not None
    print(f"\nAPI Test Result: {'PASS' if success else 'FAIL'}")

    if result_post:
        print("POST method successful!")
    if result_get:
        print("GET method successful!")

    return success


# Helper function for your existing codebase
def http_post_xml_json(url: str, json_data: Dict[str, Any], timeout: int = 30) -> Optional[str]:
    """Helper function that returns raw response text for XML/JSON handling."""
    try:
        headers = {"Content-Type": "application/json"}
        response = requests.post(url, json=json_data, headers=headers, timeout=timeout)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"HTTP POST request failed: {e}")
        return None
# -------- typosquatting helpers --------
NEARBY = {
    "a": ["q", "w", "s", "z"],
    "e": ["w", "r", "s", "d"],
    "i": ["u", "o", "k", "j"],
    "o": ["i", "p", "k", "l"],
    "m": ["n"],
    "c": ["x", "v"],
}

def generate_variants(domain: str) -> List[str]:
    """Simple, deterministic variant set: tld swaps, char ops, subdomain."""
    parts = domain.split(".")
    tld = parts[-1]
    sld = ".".join(parts[:-1])

    variants = set()
    # TLD confusion
    for swap in ("com", "co", "cn"):
        variants.add(f"{sld}.{swap}")
    # Subdomain prepends
    variants.add(f"www.{domain}")

    # Single-character ops on SLD (delete/duplicate/replace/adjacent swap)
    base = sld
    for i, ch in enumerate(base):
        # delete
        variants.add(f"{base[:i]}{base[i+1:]}.{tld}")
        # duplicate
        variants.add(f"{base[:i+1]}{ch}{base[i+1:]}.{tld}")
        # replace (nearby keyboard)
        for k in NEARBY.get(ch, []):
            variants.add(f"{base[:i]}{k}{base[i+1:]}.{tld}")
        # adjacent swap
        if i < len(base) - 1:
            swapped = list(base)
            swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
            variants.add(f"{''.join(swapped)}.{tld}")

    # A simple "-admin" variant
    if len(parts) >= 2:
        variants.add(f"{sld}-admin.{tld}")

    variants.discard(domain)
    return sorted(v for v in variants if v)

def is_registered(name: str) -> Tuple[bool, Optional[str]]:
    """Heuristic: if A or NS exists, consider registered; return registrar if WHOIS available."""
    # Quick DNS check
    if dns_query(name, "A") or dns_query(name, "NS"):
        registrar = None
        # Optional: WHOIS (costly) only if we have a key
        if IP2WHOIS_API_KEY:
            w = whois_lookup(name)
            registrar = w.get("registrar") if w else None
        return True, registrar
    return False, None

def risk_level(variant: str, original: str) -> str:
    # naive heuristic: .com swap or "-admin" → high; others medium/low
    if variant.endswith(".com") or variant.endswith("-admin.cm"):
        return "high"
    if variant.endswith(".co") or variant.endswith(".cn") or variant.startswith("www."):
        return "medium"
    return "low"

# -------- API route --------
@app.post("/api/inspect")
def inspect():
    """
    Request body: { "domain": "example.cm" }
    Response (subset aligned to your TS types):
    {
      "success": true,
      "data": {
        "domain": "...",
        "whois": {...} | null,
        "dns": [{recordType, value, ttl}],
        "typosquattingVariants": [{variant, type, riskLevel, registered, registrar?}],
        "timestamp": "ISO"
      }
    }
    """
    payload = request.get_json(silent=True) or {}
    domain = payload.get("domain", "")
    domain = normalize_domain(domain)

    if not domain or not is_valid_cm_domain(domain):
        return jsonify({
            "success": False,
            "error": {"message": "Invalid .cm domain", "code": "INVALID_INPUT"}
        }), 400

    started = time.time()

    # DNS
    dns_records = get_dns_bundle(domain)

    # WHOIS (optional)
    print(IP2WHOIS_API_KEY)
    whois = whois_lookup(domain) if IP2WHOIS_API_KEY else None

    # Variants + registration probe
    out_variants = []
    for v in generate_variants(domain):
        reg, registrar = is_registered(v)
        out_variants.append({
            "variant": v,
            "type": "tld-swap" if v.endswith((".com", ".co", ".cn")) else ("subdomain" if v.startswith("www.") else "typo"),
            "riskLevel": risk_level(v, domain),
            "registered": reg,
            **({"registrar": registrar} if registrar else {})
        })

    resp = {
        "domain": domain,
        "whois": whois,
        "dns": dns_records,
        "typosquattingVariants": out_variants,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsedMs": int((time.time() - started) * 1000),
    }

    return jsonify({"success": True, "data": resp}), 200


@app.get("/")
def root():
    return {
        "ok": True,
        "service": "cm-sentinel-api",
        "version": "1.0.0"
    }

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5001"))
    app.run(host="0.0.0.0", port=port, debug=True)
