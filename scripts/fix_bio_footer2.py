#!/usr/bin/env python3
"""
fix_bio_footer2.py
Replaces bio+footer section in broken analysis files with the exact
pattern from data-breach-exposure-analysis.html (the reference file).
Each file keeps its own footer text.
Run from: ~/Work/security/cybersecurity-portfolio
"""
import os, re

PORTFOLIO = os.path.expanduser("~/Work/security/cybersecurity-portfolio/analysis")

# The correct bio block (same for all files)
BIO_BLOCK = '''<div class="wrap">
</div></div>

<div class="bio">
  <div class="bio-avatar">YI</div>
  <div>
    <div class="bio-name">Yana Ivanov</div>
    <div class="bio-title">Security Analyst &nbsp;·&nbsp; CMMC Compliance Analyst &nbsp;·&nbsp; SiteWave Studio</div>
    <p class="bio-text">Yana Ivanov is a security analyst and CMMC compliance consultant based in Connecticut, specializing in cybersecurity risk assessment for defense contractors in the Connecticut defense industrial base. With 15 years of enterprise technology experience and an MS in Information Systems, she brings a practitioner perspective to threat intelligence analysis. She is currently pursuing CompTIA Security+ and CMMC Registered Practitioner certification, with a focus on helping defense supply chain companies achieve genuine — not checkbox — security compliance. This analysis was produced independently as a contribution to the security community's understanding of active threats against US defense infrastructure.</p>
    <p class="bio-text" style="margin-top:.75rem"><a href="../index.html" class="back-nav-link">Portfolio</a></p>
  </div>
</div>'''

# Footer text per file (unique to each report)
FOOTER_TEXT = {
    "The_Cascade_Analysis.html": (
        "The Cascade — Infrastructure Analysis &nbsp;·&nbsp; Yana Ivanov &nbsp;·&nbsp; March 15, 2026",
        "Hypothetical scenario &nbsp;·&nbsp; Based on public reporting &nbsp;·&nbsp; For educational use &nbsp;·&nbsp; Independent analysis"
    ),
    "Volt_Typhoon_Analysis.html": (
        "Volt Typhoon — Silent War &nbsp;·&nbsp; Yana Ivanov &nbsp;·&nbsp; March 14, 2026",
        "Based on public reporting &nbsp;·&nbsp; For educational use &nbsp;·&nbsp; Independent analysis"
    ),
    "stryker_threat_analysis.html": (
        "The Stryker Attack &nbsp;·&nbsp; Yana Ivanov &nbsp;·&nbsp; March 14, 2026",
        "Based on public reporting &nbsp;·&nbsp; For educational use &nbsp;·&nbsp; Independent analysis"
    ),
    "homoglyph_bec_analysis.html": (
        "The Identical Lie &nbsp;·&nbsp; Yana Ivanov &nbsp;·&nbsp; March 2026",
        "Based on public reporting &nbsp;·&nbsp; For educational use &nbsp;·&nbsp; Independent analysis"
    ),
    "glassworm_analysis.html": (
        "The Invisible Threat &nbsp;·&nbsp; Yana Ivanov &nbsp;·&nbsp; March 2026",
        "Based on public reporting &nbsp;·&nbsp; For educational use &nbsp;·&nbsp; Independent analysis"
    ),
    "hiring_trap_analysis.html": (
        "The Hiring Trap &nbsp;·&nbsp; Yana Ivanov &nbsp;·&nbsp; March 2026",
        "Based on public reporting &nbsp;·&nbsp; For educational use &nbsp;·&nbsp; Independent analysis"
    ),
    "CMMC_Supply_Chain.html": (
        "The Weakest Link — CMMC Supply Chain &nbsp;·&nbsp; Yana Ivanov &nbsp;·&nbsp; March 2026",
        "Based on public reporting &nbsp;·&nbsp; For educational use &nbsp;·&nbsp; Independent analysis"
    ),
}

for filename, (footer_line1, footer_line2) in FOOTER_TEXT.items():
    filepath = os.path.join(PORTFOLIO, filename)
    with open(filepath) as f:
        content = f.read()

    # Find everything from last section content end to </body>
    # Strategy: find the existing bio/footer block and replace it entirely
    # Look for the start of the bio area (various patterns used across files)
    
    # Find <script> or </body> to know where bio+footer ends
    script_pos = content.rfind('\n<script>')
    if script_pos == -1:
        script_pos = content.rfind('</body>')
    
    # Find start of bio section - look backwards from script for <div class="wrap"> or bio comment
    bio_area_start = -1
    
    # Try various patterns that appear before bio in these files
    patterns = [
        '\n<!-- ══ BIO ══ -->\n',
        '\n<!-- ── AUTHOR BIO ── -->\n',
        '\n\n<!-- ── AUTHOR BIO ── -->\n',
    ]
    
    for pattern in patterns:
        pos = content.rfind(pattern, 0, script_pos)
        if pos != -1:
            bio_area_start = pos
            break
    
    if bio_area_start == -1:
        # Fall back: find last </div></div> before script
        pos = content.rfind('</div></div>', 0, script_pos)
        if pos != -1:
            bio_area_start = pos
    
    if bio_area_start == -1:
        print(f"  WARN - could not find bio start: {filename}")
        continue

    # Build the new footer
    new_footer = f'''
<footer>
  <span>{footer_line1}</span>
  <span>{footer_line2}</span>
</footer>
'''

    # Replace everything from bio_area_start to script_pos
    new_content = content[:bio_area_start] + '\n\n' + BIO_BLOCK + '\n' + new_footer + content[script_pos:]

    with open(filepath, 'w') as f:
        f.write(new_content)
    print(f"  FIXED: {filename}")

print("\nDone. Open locally to verify before committing.")
