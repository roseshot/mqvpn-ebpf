#!/usr/bin/env python3
"""Check relative Markdown links and GitHub-style heading fragments, offline.

Run from any working directory: python3 scripts/check-doc-links.py
No dependency, network request, or GitHub token required.
"""
from pathlib import Path
from urllib.parse import unquote, urlsplit
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
FILES = [*ROOT.glob("README*.md"), *ROOT.glob("docs/**/*.md")]
LINK = re.compile(r'!?\[[^\]]+\]\(\s*<?([^\s)>]+)>?(?:\s+"[^"]*")?\s*\)')
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$")
FENCE = re.compile(r"^\s*(`{3,}|~{3,})")


def github_slug(heading):
    heading = re.sub(r"!\[([^\]]+)\]\([^)]+\)", r"\1", heading)
    heading = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", heading)
    heading = re.sub(r"<[^>]+>", "", heading)
    heading = heading.replace(chr(96), "").strip().lower()
    heading = "".join(c for c in heading if c.isalnum() or c in " _-")
    return heading.replace(" ", "-")


def anchors(path):
    found = set()
    count = {}
    inside = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if FENCE.match(line):
            inside = not inside
            continue
        if inside:
            continue
        match = HEADING.match(line)
        if not match:
            continue
        slug = github_slug(match.group(1))
        seen = count.get(slug, 0)
        found.add(f"{slug}-{seen}" if seen else slug)
        count[slug] = seen + 1
    return found


def check():
    failures = []
    for doc in FILES:
        inside = False
        for lineno, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
            if FENCE.match(line):
                inside = not inside
                continue
            if inside or line.startswith("    "):
                continue
            for match in LINK.finditer(line):
                url = match.group(1)
                parsed = urlsplit(url)
                if parsed.scheme or parsed.netloc or url.startswith("//"):
                    continue
                pathpart = unquote(parsed.path)
                if pathpart.startswith("/"):
                    # Absolute website paths are not repository-local files.
                    continue
                target = (doc.parent / pathpart).resolve() if pathpart else doc
                try:
                    target.relative_to(ROOT)
                except ValueError:
                    failures.append(f"{doc.relative_to(ROOT)}:{lineno}: link escapes repository: {url}")
                    continue
                if not target.exists():
                    failures.append(f"{doc.relative_to(ROOT)}:{lineno}: missing local target: {url}")
                elif parsed.fragment and target.suffix.lower() == ".md":
                    anchor = unquote(parsed.fragment).lower()
                    if anchor not in anchors(target):
                        failures.append(f"{doc.relative_to(ROOT)}:{lineno}: missing heading #{anchor} in {target.relative_to(ROOT)}")
    return failures


if __name__ == "__main__":
    errors = check()
    if errors:
        print("\n".join(errors), file=sys.stderr)
        print(f"{len(errors)} Markdown link error(s)", file=sys.stderr)
        raise SystemExit(1)
    print(f"PASS Markdown relative links and heading fragments in {len(FILES)} files")
