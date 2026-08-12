#!/usr/bin/env python3
"""
fix_mastbar_text.py
Converts all-caps mast-bar ticker text to clean sentence case.
Run from: ~/Work/security/cybersecurity-portfolio
"""
import os

PORTFOLIO = os.path.expanduser("~/Work/security/cybersecurity-portfolio/analysis")

FIXES = {
    "CMMC_Supply_Chain.html": (
        "CMMC PHASE 1 IN EFFECT SINCE NOV 2025 &nbsp;·&nbsp; PHASE 2 MANDATORY C3PAO CERTIFICATION NOV 10, 2026 &nbsp;·&nbsp; 8 MONTHS REMAINING &nbsp;·&nbsp; 99% OF CONTRACTORS NOT AUDIT-READY",
        "CMMC Phase 1 in effect since Nov 2025 &nbsp;·&nbsp; Phase 2 mandatory C3PAO certification: Nov 10, 2026 &nbsp;·&nbsp; 8 months remaining &nbsp;·&nbsp; 99% of contractors not audit-ready"
    ),
    "glassworm_analysis.html": (
        "ACTIVE CAMPAIGN &nbsp;·&nbsp; 151+ GITHUB REPOS COMPROMISED &nbsp;·&nbsp; MARCH 2026 &nbsp;·&nbsp; DEFENSE SUPPLY CHAIN RISK",
        "Active campaign &nbsp;·&nbsp; 151+ GitHub repos compromised &nbsp;·&nbsp; March 2026 &nbsp;·&nbsp; Defense supply chain risk"
    ),
    "hiring_trap_analysis.html": (
        "500K+ JOB SEEKERS INSTALLED THIS EXTENSION &nbsp;·&nbsp; MANIFEST GRANTS ACCESS TO EVERY WEBSITE YOU VISIT &nbsp;·&nbsp; THREE SCRIPTS RUN ON ALL URLs",
        "500K+ job seekers installed this extension &nbsp;·&nbsp; Manifest grants access to every website you visit &nbsp;·&nbsp; Three content scripts run on all URLs"
    ),
    "homoglyph_bec_analysis.html": (
        "$2.8 BILLION LOST IN 2024 ALONE &nbsp;·&nbsp; 21,442 COMPLAINTS TO FBI IC3 &nbsp;·&nbsp; 63% OF ORGANIZATIONS HIT IN 2025",
        "$2.8 billion lost to BEC in 2024 &nbsp;·&nbsp; 21,442 complaints to FBI IC3 &nbsp;·&nbsp; 63% of organizations targeted in 2025"
    ),
    "linkedin_open_door.html": (
        "NO TAX ID REQUIRED TO POST JOBS &nbsp;·&nbsp; 80.6M FAKE ACCOUNTS REMOVED IN 6 MONTHS &nbsp;·&nbsp; $501M IN JOB SCAM LOSSES 2024 &nbsp;·&nbsp; ACTIVE DOD TARGETING DOCUMENTED BY US AIR FORCE",
        "No tax ID required to post jobs &nbsp;·&nbsp; 80.6M fake accounts removed in 6 months &nbsp;·&nbsp; $501M in job scam losses in 2024 &nbsp;·&nbsp; Active DoD targeting documented by US Air Force"
    ),
    "signal_whatsapp_analysis.html": (
        "ACTIVE CAMPAIGN &nbsp;·&nbsp; DUTCH INTELLIGENCE CONFIRMED &nbsp;·&nbsp; GOVERNMENT EMPLOYEES COMPROMISED &nbsp;·&nbsp; DEFENSE CONTRACTORS AT RISK &nbsp;·&nbsp; MARCH 16 2026",
        "Active campaign &nbsp;·&nbsp; Dutch intelligence confirmed &nbsp;·&nbsp; Government employees compromised &nbsp;·&nbsp; Defense contractors at risk &nbsp;·&nbsp; March 16, 2026"
    ),
    "stryker_threat_analysis.html": (
        "ACTIVE INCIDENT &nbsp;·&nbsp; INVESTIGATION ONGOING &nbsp;·&nbsp; ALL FINDINGS BASED ON PUBLIC REPORTING &nbsp;·&nbsp; ANALYSIS CURRENT AS OF MARCH 14 2026",
        "Active incident &nbsp;·&nbsp; Investigation ongoing &nbsp;·&nbsp; All findings based on public reporting &nbsp;·&nbsp; Analysis current as of March 14, 2026"
    ),
    "Volt_Typhoon_Analysis.html": (
        "ONGOING OPERATION &nbsp;·&nbsp; CRITICAL INFRASTRUCTURE COMPROMISED &nbsp;·&nbsp; SOME FOOTHOLDS WILL NEVER BE FOUND &nbsp;·&nbsp; ANALYSIS CURRENT AS OF MARCH 14 2026",
        "Ongoing operation &nbsp;·&nbsp; Critical infrastructure compromised &nbsp;·&nbsp; Some footholds will never be found &nbsp;·&nbsp; Analysis current as of March 14, 2026"
    ),
    "water_infrastructure_analysis.html": (
        "EPA HAS NO STATUTORY AUTHORITY TO MANDATE WATER CYBERSECURITY &nbsp;·&nbsp; 70% OF UTILITIES FAILED BASIC STANDARDS &nbsp;·&nbsp; 9 MILLION PEOPLE SERVED BY A SINGLE UNFILTERED SYSTEM &nbsp;·&nbsp; MARCH 2026",
        "EPA has no statutory authority to mandate water cybersecurity &nbsp;·&nbsp; 70% of utilities failed basic standards &nbsp;·&nbsp; 9 million people served by a single unfiltered system &nbsp;·&nbsp; March 2026"
    ),
}

print("── Fixing mast-bar ticker text ─────────────────────────────────────────")
for filename, (old, new) in FIXES.items():
    filepath = os.path.join(PORTFOLIO, filename)
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    if old in content:
        content = content.replace(old, new)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  FIXED: {filename}")
    elif new in content:
        print(f"  SKIP (already fixed): {filename}")
    else:
        print(f"  WARN - text not found: {filename}")

print()
print("── Verify with:")
print("   grep -A1 'mast-bar-dot' ~/Work/security/cybersecurity-portfolio/analysis/*.html")
