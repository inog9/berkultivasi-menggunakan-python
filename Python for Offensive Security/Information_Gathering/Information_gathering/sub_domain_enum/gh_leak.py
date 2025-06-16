"""
gh_leak.py – Search GitHub code for company e-mail addresses via web scraping
(without API token, bypassing the low unauthenticated rate-limit).
"""

import asyncio, re, httpx, urllib.parse, random, json
from selectolax.parser import HTMLParser

COMPANY = "example.com"
DORK    = f'"@{COMPANY}" in:file language:php'

def extract(html: str) -> set[str]:
    tree = HTMLParser(html)
    code_blobs = tree.css("div.Truncate > a")
    out = set()
    for a in code_blobs:
        blob_url = urllib.parse.urljoin("https://github.com", a.attributes["href"])
        out.add(blob_url)
    return out

async def one_page(page: int) -> set[str]:
    q = urllib.parse.quote_plus(DORK)
    url = f"https://github.com/search?p={page}&q={q}&type=Code"
    async with httpx.AsyncClient(
        headers={"User-Agent": ua.random}, timeout=10.0
    ) as cli:
        html = (await cli.get(url)).text
    return extract(html)

async def main(pages: int = 5):
    blobs = set()
    for p in range(1, pages + 1):
        blobs |= await one_page(p)
        await asyncio.sleep(random.uniform(1.0, 2.0))  # avoid GitHub 429
    Path("gh_blobs.txt").write_text("\n".join(sorted(blobs)))
    print(f"Found {len(blobs)} blob URLs")

if __name__ == "__main__":
    asyncio.run(main())
