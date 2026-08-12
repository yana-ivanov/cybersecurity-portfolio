#!/usr/bin/env python3
"""
fix_mobile_notice.py
Inserts mobile-notice div in correct position (after back-nav, before masthead)
for the 6 analysis files missing it.
Run from: ~/Work/security/cybersecurity-portfolio
"""
import os

PORTFOLIO = os.path.expanduser("~/Work/security/cybersecurity-portfolio/analysis")
NOTICE = '<div class="mobile-notice"><strong>Intentionally desktop-first</strong> — best experienced on a workstation</div>\n'

TARGETS = [
    "CMMC_Supply_Chain.html",
    "data-breach-exposure-analysis.html",
    "stryker_threat_analysis.html",
    "The_Cascade_Analysis.html",
    "Volt_Typhoon_Analysis.html",
    "water_infrastructure_analysis.html"
]

for filename in TARGETS:
    filepath = os.path.join(PORTFOLIO, filename)
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    if 'class="mobile-notice"' in content:
        print(f"  SKIP (already has it): {filename}")
        continue

    # Insert before <div class="masthead"> or <header class="masthead">
    for tag in ['<div class="masthead">', '<header class="masthead">']:
        if tag in content:
            content = content.replace(tag, NOTICE + tag, 1)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"  FIXED: {filename}")
            break
    else:
        print(f"  WARN - no masthead tag found: {filename}")
