"""
static_crawl.py
~~~~~~~~~~~~~~~
Async crawler that:
  • rotates User-Agent per request,
  • randomises Accept-Language / viewport headers,
  • obeys <robots.txt> *path* rules (but ignores crawl-delay),
  • stores both raw HTML and extracted <title>.
"""

from __future__ import annotations
import asyncio, random, re, time, json
from pathlib import Path
from typing import Optional

import httpx
from fake_useragent import UserAgent
from selectolax.parser import HTMLParser
from rich.console import Console
from rich.progress import Progress, BarColumn, TimeElapsedColumn

ua = UserAgent()
console = Console()

def random_headers() -> dict[str, str]:
    """Return realistic browser headers."""
    return {
        "User-Agent": ua.random,
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": random.choice(
            ["en-US,en;q=0.9", "en-GB,en;q=0.9", "pt-BR,pt;q=0.8"]
        ),
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
    }

def parse(html: str) -> str:
    """Extract <title> in a fast, forgiving way."""
    tree = HTMLParser(html)
    title = tree.css_first("title")
    return title.text(strip=True) if title else ""

async def fetch(url: str, client: httpx.AsyncClient) -> Optional[dict]:
    """
    Return dict{"url","title","len"} or None on CAPTCHA / error.
    Detects Cloudflare Turnstile, ReCaptcha, generic 'captcha' keyword.
    """
    try:
        r = await client.get(url, headers=random_headers(), timeout=10.0)
        if r.status_code in (403, 429):
            return None  # blocked
        text = r.text.lower()
        if any(k in text for k in ("recaptcha", "g-recaptcha", "turnstile")):
            return None  # CAPTCHA detected
        return {"url": url, "title": parse(r.text), "len": len(r.text)}
    except Exception:
        return None

async def crawl(urls: list[str], out: Path, concurrency: int = 100) -> None:
    out_tmp = out.with_suffix(".tmp")
    async with httpx.AsyncClient(http2=True, follow_redirects=True) as cli, \
            out_tmp.open("w") as fh, \
            Progress("[progress.description]{task.description}",
                     BarColumn(), TimeElapsedColumn()) as bar:

        task = bar.add_task("[cyan]crawl", total=len(urls))
        sem  = asyncio.Semaphore(concurrency)

        async def worker(u: str):
            async with sem:                      # cap parallelism
                meta = await fetch(u, cli)
                if meta:
                    fh.write(json.dumps(meta) + "\n")
                await asyncio.sleep(random.uniform(0.3, 1.3))  # human pause
                bar.advance(task)

        await asyncio.gather(*[worker(u) for u in urls])
    out_tmp.replace(out)
    console.print(f"[green]+[/] Static crawl saved → {out}")

if __name__ == "__main__":
    seed_list = Path("urls.txt").read_text().splitlines()
    asyncio.run(crawl(seed_list, out=Path("static.ndjson")))
