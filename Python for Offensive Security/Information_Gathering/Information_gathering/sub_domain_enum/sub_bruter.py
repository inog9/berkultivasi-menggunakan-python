#!/usr/bin/env python3
"""
sub_bruter.py  –  Asynchronous DNS brute-forcer with wildcard filtering.

Usage:
  python sub_bruter.py example.com subdomains.txt -c 800
"""

import asyncio, socket, argparse, sys
from pathlib import Path
import aiodns

resolver = aiodns.DNSResolver()

# ──────────────────────────────────────────────────────────────
async def resolve(name: str) -> list[str]:
    """Return list of IPv4 addresses for *name* or empty list if NXDOMAIN."""
    try:
        # Query A records; other types can be added if needed
        response = await resolver.gethostbyname(name, socket.AF_INET)
        return [r.host for r in response]
    except aiodns.error.DNSError:
        return []

# ──────────────────────────────────────────────────────────────
async def worker(q: asyncio.Queue, root: str, wildcard_ips: set[str]) -> None:
    """
    Consumer coroutine:
      1. Pull sub-domain from queue
      2. Resolve FQDN
      3. Print only non-wildcard results
    """
    while True:
        sub = await q.get()
        fqdn = f"{sub}.{root}"
        ips  = await resolve(fqdn)

        # Print when resolution succeeded *and* IPs differ from wildcard set
        if ips and set(ips) != wildcard_ips:
            print(f"{fqdn:<40} {', '.join(ips)}")

        q.task_done()

# ──────────────────────────────────────────────────────────────
async def main(wordlist: Path, root: str, concurrency: int) -> None:
    """Set up the queue, spawn workers and wait for completion."""
    # Test for wildcard DNS once and reuse result
    wildcard_present, wildcard_ips = await is_wildcard(root)
    if wildcard_present:
        print(f"[!] Wildcard detected → {', '.join(wildcard_ips)}")

    queue = asyncio.Queue()

    # Pre-load queue with every sub-label from wordlist
    for sub in wordlist.read_text().splitlines():
        await queue.put(sub.strip())

    # Spawn worker coroutines
    tasks = [asyncio.create_task(worker(queue, root, wildcard_ips))
             for _ in range(concurrency)]

    # Wait until queue fully processed
    await queue.join()

    # Gracefully cancel workers (otherwise they await forever)
    for t in tasks:
        t.cancel()

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("domain")
    ap.add_argument("wordlist", type=Path)
    ap.add_argument("-c", "--concurrency", type=int, default=500,
                    help="number of simultaneous DNS queries")
    args = ap.parse_args()

    try:
        asyncio.run(main(args.wordlist, args.domain, args.concurrency))
    except KeyboardInterrupt:
        sys.exit(1)
