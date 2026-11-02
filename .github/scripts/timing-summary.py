#!/usr/bin/env python3
"""Prints echalote timing lines from test logs / JUnit XML reports.

Usage: timing-summary.py OUT.txt INPUT... (files or directories; XML system-out is read too)

Writes every `echalote.<area>.timing` line and every `live ... tor` result line to OUT.txt,
and prints them plus the slowest stages to stdout so they show up in the CI job log.
"""
import html
import os
import re
import sys

LINE = re.compile(r"(echalote\.[A-Za-z0-9_-]+\.timing [^\r\n<]*|live direct[-a-z]* tor [^\r\n<]*|inflate consensus [^\r\n<]*|ios (?:rsa|ecdh)[^\r\n<]*)")


def files(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                for n in sorted(names):
                    if n.endswith((".xml", ".log", ".txt")):
                        yield os.path.join(root, n)
        elif os.path.isfile(p):
            yield p


def main():
    out, inputs = sys.argv[1], sys.argv[2:]
    seen, lines = set(), []
    for f in files(inputs):
        with open(f, encoding="utf-8", errors="replace") as fh:
            text = html.unescape(fh.read())
        for m in LINE.finditer(text):
            line = m.group(1).strip()
            if line not in seen:
                seen.add(line)
                lines.append(line)
    with open(out, "w") as fh:
        fh.write("\n".join(lines) + ("\n" if lines else ""))
    print(f"::group::echalote timing lines ({len(lines)})")
    for line in lines:
        print(line)
    print("::endgroup::")
    stages = []
    for line in lines:
        m = re.search(r"echalote\.(\S+)\.timing .*?stage=(\S+) ms=([0-9.]+)(.*)", line)
        if m:
            stages.append((float(m.group(3)), m.group(1), m.group(2), m.group(4).strip()))
    stages.sort(reverse=True)
    print("Slowest stages:")
    for ms, area, stage, extra in stages[:25]:
        print(f"  {ms:9.1f} ms  {area}/{stage}  {extra[:120]}")
    for line in lines:
        if line.startswith("live "):
            print(line)


if __name__ == "__main__":
    main()
