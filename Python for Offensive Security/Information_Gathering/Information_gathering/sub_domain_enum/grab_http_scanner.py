#!/usr/bin/env python3
"""
scanner.py  –  Enumerate banners for IP:port lines.

input.txt  -> 192.0.2.1:22
              203.0.113.10:443
"""
import asyncio, json, random
from pathlib import Path
from grab_core import tcp_banner, tls_hello, http_head, Banner

PORT_HINTS = {
    22:  ("ssh",  b"\r\n"),
    25:  ("smtp", b"EHLO example.com\r\n"),
    21:  ("ftp",  b"\r\n"),
    80:  ("http", b"HEAD / HTTP/1.0\r\n\r\n"),
    443: ("https", b"HEAD / HTTP/1.0\r\n\r\n"),
}

async def fingerprint(ip: str, port: int) -> Banner | None:
    """Dispatch correct grab method based on port hint table."""
    if port in (80,):
        return await http_head(ip, port, tls=False)
    if port in (443,):
        # Try HTTPS; also capture JA3 + CN
        http_banner = await http_head(ip, port, tls=True)
        xtra = await tls_hello(ip, port)
        if http_banner and xtra:
            http_banner.extra["ja3"], http_banner.extra["cn"] = xtra
        return http_banner
    # Fallback raw TCP
    proto, pay = PORT_HINTS.get(port, ("tcp", b"\r\n"))
    data = await tcp_banner(ip, port, pay)
    if data:
        try:
            banner = data.decode(errors="replace").strip()
        except UnicodeDecodeError:
            banner = repr(data[:30])
        return Banner(ip, port, proto, banner, {})
    return None

async def run(file: Path, out: Path, concurrency: int = 500):
    lines = [l.strip() for l in file.read_text().splitlines() if l.strip()]
    q     = asyncio.Queue()
    for line in lines:
        ip, p = line.split(":")
        await q.put((ip, int(p)))

    results = []

    async def worker():
        while True:
            ip, port = await q.get()
            res = await fingerprint(ip, port)
            if res:
                print(f"{res.ip}:{res.port:<5} {res.proto:<5} {res.banner[:60]}")
                results.append(res._asdict())
            # jitter to evade IDS thresholds
            await asyncio.sleep(random.uniform(0.02, 0.08))
            q.task_done()

    tasks = [asyncio.create_task(worker()) for _ in range(concurrency)]
    await q.join()
    for t in tasks: t.cancel()

    out.write_text(json.dumps(results, indent=2))
    print(f"[+] Saved {len(results)} banners → {out}")

if __name__ == "__main__":
    import argparse, sys
    ap = argparse.ArgumentParser()
    ap.add_argument("infile", type=Path)
    ap.add_argument("outfile", type=Path)
    ap.add_argument("-c", "--concurrency", type=int, default=400)
    args = ap.parse_args()
    try:
        asyncio.run(run(args.infile, args.outfile, args.concurrency))
    except KeyboardInterrupt:
        sys.exit(0)
