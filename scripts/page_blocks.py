#!/usr/bin/env python3
"""Print one ```bash block of a Markdown page, so CI can run a page's commands as written.

    python3 scripts/page_blocks.py docs/send-us-the-result.md 1    the first bash block
    python3 scripts/page_blocks.py docs/send-us-the-result.md --count

Blocks are numbered from 1 in the order they appear; only blocks fenced as ```bash count.
Uses only the standard library (CI runs it with the runner's own python3).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

BLOCK = re.compile(r"^```bash\n(.*?)^```$", re.S | re.M)


def blocks(text: str) -> list[str]:
    return BLOCK.findall(text)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    found = blocks(Path(argv[0]).read_text(encoding="utf-8"))
    if argv[1] == "--count":
        print(len(found))
        return 0
    try:
        n = int(argv[1])
    except ValueError:
        n = 0
    if not 1 <= n <= len(found):
        print(f"error: {argv[0]} has {len(found)} bash block(s); there is no block {argv[1]}", file=sys.stderr)
        return 2
    sys.stdout.write(found[n - 1])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
