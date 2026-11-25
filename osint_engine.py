from datetime import datetime, timezone
import json
import dns.exception
import dns.resolver
import requests


def normalize_subdomains(raw_entries, root_domain):
    cleaned = set()
    root_domain = root_domain.lower().strip()
    for entry in raw_entries:
        for line in entry.splitlines():
            host = line.strip().lower().lstrip("*.")
            if host == root_domain or host.endswith(f".{root_domain}"):
                cleaned.add(host)
    return sorted(cleaned)


def fetch_ct_subdomains(domain, timeout=25):
    headers = {"User-Agent": "SubReconX-Academic-OSINT/1.0"}
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        raw_names = [item.get("name_value", "") for item in data if item.get("name_value")]
        return normalize_subdomains(raw_names, domain)
    except (requests.exceptions.RequestException, ValueError):
        fallback_url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = requests.get(fallback_url, headers=headers, timeout=timeout)
        resp.raise_for_status()
        raw_names = [line.split(",")[0] for line in resp.text.splitlines() if "," in line]
        return normalize_subdomains(raw_names, domain)


def resolve_dns_records(subdomain, timeout=5):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.lifetime = timeout
    records = {"A": [], "AAAA": [], "CNAME": []}
    for rtype in records:
        try:
            answers = resolver.resolve(subdomain, rtype)
            records[rtype] = [rdata.to_text() for rdata in answers]
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            continue
    return records


def run_recon(domain, timeout=15, resolve=False, dry_run=False):
    result = {
        "target": domain,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "dry_run": dry_run,
        "subdomains": [],
        "errors": [],
    }
    if dry_run:
        result["planned_queries"] = [
            f"GET https://crt.sh/?q=%25.{domain}&output=json (fallback: hackertarget)",
            "DNS A/AAAA/CNAME via 1.1.1.1, 8.8.8.8" if resolve else "DNS resolution disabled",
        ]
        return result

    try:
        subdomains = fetch_ct_subdomains(domain, timeout=timeout)
        for sub in subdomains:
            entry = {"hostname": sub}
            if resolve:
                entry["dns"] = resolve_dns_records(sub, timeout=min(timeout, 5))
            result["subdomains"].append(entry)
    except requests.exceptions.Timeout:
        result["errors"].append(f"Passive OSINT lookup timed out after {timeout}s.")
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        result["errors"].append(f"HTTP error from passive OSINT source: {status}")
    except (requests.exceptions.RequestException, json.JSONDecodeError) as exc:
        result["errors"].append(f"Passive lookup error: {exc}")
    return result


if __name__ == "__main__":
    print("=== Test 1: Dry-Run Mode ===")
    print(json.dumps(run_recon("example.com", resolve=True, dry_run=True), indent=2))
    print("\n=== Test 2: Graceful Timeout Handling ===")
    print(json.dumps(run_recon("example.com", timeout=0.001, resolve=False), indent=2))