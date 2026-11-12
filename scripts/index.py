#!/usr/bin/env python3
"""Rebuild INDEX.md from the frontmatter of every writeup README.md."""
import pathlib
from collections import Counter

root = pathlib.Path(__file__).resolve().parent.parent

def meta(path):
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.startswith("---"):
        return None
    out = {}
    for line in text.split("---", 2)[1].strip().splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip().strip("[]")
    return out

rows = []
for base in ("platforms", "events", "labs"):
    for readme in (root / base).rglob("README.md"):
        m = meta(readme)
        if m and m.get("title"):
            rows.append((m, readme.parent.relative_to(root)))

rows.sort(key=lambda r: (r[0].get("platform", ""), r[0].get("category", ""), r[0]["title"].lower()))
count = Counter(m.get("category", "?") for m, _ in rows)
out = ["# Index", "",
       f"**{len(rows)} writeups** | " + ", ".join(f"{c}: {n}" for c, n in sorted(count.items())), "",
       "| Challenge | Platform | Category | Difficulty | Date | Tags |",
       "|---|---|---|---|---|---|"]
for m, p in rows:
    out.append(f"| [{m['title']}]({p.as_posix()}/) | {m.get('platform','')} | "
               f"{m.get('category','')} | {m.get('difficulty','')} | {m.get('date','')} | {m.get('tags','')} |")
(root / "INDEX.md").write_text("\n".join(out) + "\n", encoding="utf-8")
print(f"{len(rows)} writeups indexed")
