#!/usr/bin/env python3
"""
bulk_rdap.py  –  Resolve a list of IPs to ASN, Org, Country concurrently with caching.

    python bulk_rdap.py ips.txt rdap.csv --workers 50 --cache-db rdap_cache.db
"""
from __future__ import annotations
import csv, sys, argparse, concurrent.futures, sqlite3, time
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional
from ipwhois import IPWhois, exceptions as ipw_exc
from rich.progress import Progress, BarColumn, TimeElapsedColumn
import ipaddress

class RDAPCache:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_db()
        
    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rdap_cache (
                    ip TEXT PRIMARY KEY,
                    asn TEXT,
                    asn_desc TEXT,
                    country TEXT,
                    cidr TEXT,
                    org_name TEXT,
                    last_updated TIMESTAMP
                )
            """)
    
    def get(self, ip: str) -> Optional[dict]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT * FROM rdap_cache WHERE ip = ?", (ip,)
            )
            row = cursor.fetchone()
            if row:
                return {
                    "ip": row[0],
                    "asn": row[1],
                    "asn_desc": row[2],
                    "country": row[3],
                    "cidr": row[4],
                    "org_name": row[5],
                    "last_updated": row[6]
                }
        return None
    
    def set(self, data: dict):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO rdap_cache 
                (ip, asn, asn_desc, country, cidr, org_name, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                data["ip"],
                data["asn"],
                data["asn_desc"],
                data["country"],
                data["cidr"],
                data.get("org_name", ""),
                datetime.now().isoformat()
            ))

class RateLimiter:
    def __init__(self, requests_per_second: float = 1.0):
        self.requests_per_second = requests_per_second
        self.last_request = 0.0
        
    def wait(self):
        now = time.time()
        time_since_last = now - self.last_request
        if time_since_last < (1.0 / self.requests_per_second):
            time.sleep((1.0 / self.requests_per_second) - time_since_last)
        self.last_request = time.time()

def get_asn_prefixes(asn: str) -> list[str]:
    """Get all prefixes for a given ASN."""
    try:
        obj = IPWhois("1.1.1.1")  # Dummy IP
        data = obj.lookup_rdap(depth=1, asn=asn)
        return [net["cidr"] for net in data.get("network", {}).get("prefixes", [])]
    except Exception:
        return []

def rdap_lookup(ip: str, cache: RDAPCache, rate_limiter: RateLimiter) -> dict[str, str] | None:
    """
    Look up *ip* via RDAP with caching and rate limiting.
    Returns dict with enriched fields or None on error.
    """
    # Check cache first
    cached = cache.get(ip)
    if cached:
        return cached

    try:
        rate_limiter.wait()
        data = IPWhois(ip).lookup_rdap(depth=1)
        result = {
            "ip": ip,
            "asn": data["asn"],
            "asn_desc": data["asn_description"],
            "country": data["asn_country_code"],
            "cidr": data["network"]["cidr"],
            "org_name": data.get("objects", {}).get(data["asn"], {}).get("contact", {}).get("name", ""),
            "last_updated": datetime.now().isoformat()
        }
        cache.set(result)
        return result
    except (ipw_exc.IPDefinedError, ipw_exc.HTTPLookupError):
        return None

def main(inp: Path, out: Path, cache_db: Path, workers: int = 30, rate_limit: float = 1.0) -> None:
    cache = RDAPCache(cache_db)
    rate_limiter = RateLimiter(rate_limit)
    
    ips = [line.strip() for line in inp.read_text().splitlines() if line.strip()]
    with Progress("[progress.description]{task.description}",
                  BarColumn(), "[magenta]{task.completed}/{task.total}",
                  TimeElapsedColumn()) as bar:
        task = bar.add_task("[cyan]RDAP", total=len(ips))
        results: list[dict[str, str]] = []
        asn_prefixes: dict[str, list[str]] = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = []
            for ip in ips:
                futures.append(pool.submit(rdap_lookup, ip, cache, rate_limiter))
            
            for future in concurrent.futures.as_completed(futures):
                bar.advance(task)
                res = future.result()
                if res:
                    results.append(res)
                    # Collect ASN prefixes
                    if res["asn"] not in asn_prefixes:
                        asn_prefixes[res["asn"]] = get_asn_prefixes(res["asn"])

    # Write main CSV
    with out.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    # Write ASN prefixes CSV
    prefix_out = out.with_suffix('.prefixes.csv')
    with prefix_out.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["asn", "asn_desc", "prefix"])
        for asn, prefixes in asn_prefixes.items():
            asn_desc = next((r["asn_desc"] for r in results if r["asn"] == asn), "")
            for prefix in prefixes:
                writer.writerow([asn, asn_desc, prefix])

    print(f"[+] Saved {len(results)} enriched rows → {out}")
    print(f"[+] Saved {sum(len(p) for p in asn_prefixes.values())} ASN prefixes → {prefix_out}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("infile", type=Path)
    ap.add_argument("outfile", type=Path)
    ap.add_argument("--workers", "-w", type=int, default=30)
    ap.add_argument("--cache-db", type=Path, default=Path("rdap_cache.db"))
    ap.add_argument("--rate-limit", type=float, default=1.0,
                   help="Maximum requests per second")
    args = ap.parse_args()
    try:
        main(args.infile, args.outfile, args.cache_db, args.workers, args.rate_limit)
    except KeyboardInterrupt:
        sys.exit(1)
