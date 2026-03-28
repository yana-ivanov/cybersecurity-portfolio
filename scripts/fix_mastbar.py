#!/usr/bin/env python3
"""
fix_mastbar.py
Fixes two issues across all analysis HTML files:
1. mast-bar CSS stuck inside a media query — moves it to top level
2. Adds white-space:nowrap;overflow:hidden to prevent text wrapping
3. Removes extra <span> wrapper in water_infrastructure_analysis.html
Run from anywhere — uses absolute paths.
"""

import os
import re

PORTFOLIO = os.path.expanduser("~/Work/security/cybersecurity-portfolio/analysis")

# The correct top-level mast-bar CSS (what every file should have)
CORRECT_MASTBAR = ".mast-bar{background:#ef4444;margin-top:0;padding:.6rem 3rem;font-family:var(--mono);font-size:.72rem;letter-spacing:.08em;color:#fff;display:flex;align-items:center;gap:2rem;white-space:nowrap;overflow:hidden}"
CORRECT_MASTDOT = ".mast-bar-dot{width:8px;height:8px;border-radius:50%;background:#fff;animation:blink 1.5s ease-in-out infinite}"

files = sorted([
    os.path.join(PORTFOLIO, f)
    for f in os.listdir(PORTFOLIO)
    if f.endswith(".html")
])

print("── Fixing mast-bar across all analysis files ───────────────────────────")

for filepath in files:
    filename = os.path.basename(filepath)

    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    original = content

    # ── Fix 1: Remove any mast-bar rule that's inside a media query ──────────
    # Pattern: indented .mast-bar{...} inside @media block (has leading spaces)
    content = re.sub(
        r'\n\s{2,}\.mast-bar\{background:#ef4444[^}]*\}',
        '',
        content
    )

    # ── Fix 2: Replace top-level mast-bar with correct version (adds nowrap) ──
    content = re.sub(
        r'\.mast-bar\{background:#ef4444[^}]*\}',
        CORRECT_MASTBAR,
        content
    )

    # ── Fix 3: Ensure mast-bar-dot is correct ────────────────────────────────
    content = re.sub(
        r'\.mast-bar-dot\{[^}]*\}',
        CORRECT_MASTDOT,
        content
    )

    # ── Fix 4: Remove <span> wrapper inside mast-bar (water file) ────────────
    content = re.sub(
        r'(<div class="mast-bar">\s*<div class="mast-bar-dot"></div>\s*)<span>(.*?)</span>(\s*</div>)',
        r'\1\2\3',
        content,
        flags=re.DOTALL
    )

    if content != original:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  FIXED:  {filename}")
    else:
        print(f"  OK:     {filename}")

print()
print("── Verify with:")
print(f'   grep -n "mast-bar{{" {PORTFOLIO}/*.html')
