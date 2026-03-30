#!/usr/bin/env python3
"""
fix_bio_footer.py
Run from the root of cybersecurity-portfolio repo.
Fixes the bio + footer on all analysis reports (not labs or tools).
"""

import os, re

# ── Canonical bio/footer snippet ──────────────────────────────────────────────
BIO_FOOTER = '''
<div class="bio">
  <div class="bio-avatar">YI</div>
  <div>
    <div class="bio-name">Yana Ivanov</div>
    <div class="bio-title">Security Analyst &nbsp;·&nbsp; CMMC Compliance Analyst &nbsp;·&nbsp; SiteWave Studio</div>
    <p class="bio-text">Yana Ivanov is a security analyst and CMMC consultant based in Connecticut, specializing in cybersecurity risk assessment for defense contractors in the Connecticut defense industrial base. With 15 years of enterprise technology experience and an MS in Information Systems, she brings a practitioner perspective to threat intelligence analysis. She is currently pursuing CompTIA Security+ and CMMC Registered Practitioner certification, with a focus on helping defense supply chain companies achieve genuine — not checkbox — security compliance. This analysis was produced independently as a contribution to the security community's understanding of active threats against US defense infrastructure.</p>
    <p class="bio-text" style="margin-top:.75rem"><a href="../index.html" class="back-nav-link">Portfolio</a></p>
  </div>
</div>

'''

# ── CSS to ensure .back-nav-link works inside bio ─────────────────────────────
BACK_NAV_LINK_CSS = '''
/* back-nav-link inside bio */
.back-nav-link{font-family:var(--mono);font-size:.65rem;letter-spacing:.12em;color:#4a9eff;text-decoration:none;text-transform:uppercase;display:inline-flex;align-items:center;gap:.5rem;transition:color .2s}
.back-nav-link:hover{color:#93c5fd}
.back-nav-link::before{content:'←';font-size:.75rem}
'''

# ── Folders to process (not labs, not tools) ──────────────────────────────────
TARGET_FOLDERS = ['analysis', 'training', 'writing']

def get_report_title(html):
    m = re.search(r'<title>([^<]+)</title>', html)
    return m.group(1).split('|')[0].strip().split('—')[0].strip() if m else 'Report'

def get_report_date(html):
    # Try to find Published date in meta grid
    m = re.search(r'Published.*?<div class="value">([^<]+)</div>', html, re.DOTALL)
    return m.group(1).strip() if m else 'March 2026'

def fix_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        html = f.read()

    # Skip if no bio class found — not a report
    if 'class="bio"' not in html and 'class="bio ' not in html:
        print(f'  SKIP (no bio): {filepath}')
        return

    title = get_report_title(html)
    date  = get_report_date(html)

    footer_content = f'{title} · Yana Ivanov · {date}'

    new_footer = f'<footer>\n  <span>{footer_content}</span>\n  <span>Based on public reporting · For educational use · Independent analysis</span>\n</footer>'

    # 1. Add back-nav-link CSS if missing
    if '.back-nav-link' not in html:
        html = html.replace('</style>', BACK_NAV_LINK_CSS + '</style>', 1)

    # 2. Replace everything from the last </div></div> before bio to </html>
    #    Pattern: find the bio block and footer, replace entirely
    pattern = re.compile(
        r'(<\/div>\s*<\/div>\s*)?'       # closing wrap+content divs (optional)
        r'<div class="bio">.*?<\/div>\s*'  # existing bio
        r'(<\/div>\s*)?'                   # extra closing div sometimes present
        r'<footer>.*?<\/footer>',          # existing footer
        re.DOTALL
    )

    replacement = '</div></div>\n' + BIO_FOOTER + new_footer

    if pattern.search(html):
        html = pattern.sub(replacement, html, count=1)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f'  FIXED: {filepath}')
    else:
        print(f'  WARN (pattern not matched): {filepath}')

def main():
    repo_root = os.path.dirname(os.path.abspath(__file__))
    print(f'Running from: {repo_root}\n')

    for folder in TARGET_FOLDERS:
        folder_path = os.path.join(repo_root, folder)
        if not os.path.isdir(folder_path):
            print(f'Folder not found, skipping: {folder}')
            continue
        for fname in sorted(os.listdir(folder_path)):
            if fname.endswith('.html'):
                fix_file(os.path.join(folder_path, fname))

    print('\nDone. Review changes with: git diff')

if __name__ == '__main__':
    main()
