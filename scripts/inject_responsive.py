#!/usr/bin/env python3
"""
inject_responsive.py
Injects responsive CSS + mobile notice into analysis, labs, and writing pages.
Run from: ~/Work/security/cybersecurity-portfolio
"""

import os
import glob
import sys

PORTFOLIO = os.path.expanduser("~/Work/security/cybersecurity-portfolio")

RESPONSIVE_CSS = """
/* ── RESPONSIVE — CONTENT PAGES ─────────────────────────────────────────────
   480px  small phones | 680px  large phones | 768px  tablet portrait
   1024px tablet landscape → desktop layout
   ─────────────────────────────────────────────────────────────────────────── */
.mobile-notice{display:none;background:#1e2d45;border-bottom:1px solid rgba(255,255,255,.08);padding:.55rem 1.5rem;font-family:var(--mono);font-size:.62rem;letter-spacing:.06em;color:#94a3b8;text-align:center}
.mobile-notice strong{color:#60a5fa}
@media(max-width:1024px){.mobile-notice{display:block}}
@media(max-width:768px){
  .wrap,.mast-inner,.back-nav{padding-left:1.75rem;padding-right:1.75rem}
  .mast-meta{grid-template-columns:1fr 1fr}
  .stat-num-grid{grid-template-columns:1fr 1fr}
  .split-visual{grid-template-columns:1fr}
  .attack-flow{grid-template-columns:1fr 1fr;gap:.5rem}
  .flow-step::after{display:none}
  .figure-body{padding:1.25rem 1rem}
  .tbl-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
  table{font-size:.78rem}
  th,td{padding:.55rem .75rem}
  .bio{grid-template-columns:1fr;padding:2rem 1.75rem}
  footer{flex-direction:column;text-align:center;padding:1.5rem}
  .timeline{padding-left:1.5rem}
  .step-item{grid-template-columns:2rem 1fr;gap:.75rem}
  .perm-card{grid-template-columns:auto 1fr}
  .verify-grid{grid-template-columns:1fr}
  .stat-row{grid-template-columns:1fr 1fr}
  .kill-chain .kc-step{grid-template-columns:36px 1fr}
  h2{font-size:1.55rem}
  h3{font-size:1.1rem}
}
@media(max-width:680px){
  .wrap,.mast-inner,.back-nav{padding-left:1.5rem;padding-right:1.5rem}
  .mast-meta{grid-template-columns:1fr}
  .stat-num-grid{grid-template-columns:1fr 1fr}
  .attack-flow{grid-template-columns:1fr}
  .split-visual{grid-template-columns:1fr}
  .flow-step::after{display:none}
  .stat-row{grid-template-columns:1fr}
  .figure-body{padding:1rem .85rem}
  .bio{grid-template-columns:1fr;padding:2rem 1.5rem}
  footer{flex-direction:column;text-align:center;padding:1.5rem}
  h1.title{font-size:1.65rem}
  h2{font-size:1.35rem}
  .layer{grid-template-columns:24px 1fr;gap:.65rem}
  .kc-step{grid-template-columns:32px 1fr;gap:.65rem}
}
@media(max-width:480px){
  html{font-size:17px}
  .wrap,.mast-inner{padding-left:1.1rem;padding-right:1.1rem}
  .back-nav{padding:.55rem 1.1rem}
  .mast-meta{grid-template-columns:1fr}
  .stat-num-grid{grid-template-columns:1fr 1fr}
  .stat-num{font-size:1.8rem}
  .attack-flow{grid-template-columns:1fr}
  .split-visual{grid-template-columns:1fr}
  .figure-body{padding:.85rem .75rem}
  .figure-title{padding:.55rem .85rem;font-size:.58rem}
  table{font-size:.72rem}
  th,td{padding:.45rem .55rem}
  .mast-bar{padding:.55rem 1.1rem;font-size:.62rem}
  h1.title{font-size:1.45rem}
  h2{font-size:1.2rem}
  h3{font-size:1rem}
  .bio{padding:1.5rem 1.1rem}
  footer{padding:1.25rem 1.1rem}
  .layer{grid-template-columns:20px 1fr;gap:.5rem}
  .perm-badge{display:none}
}
@media(min-width:768px) and (orientation:landscape){
  .mobile-notice{display:none}
  .mast-meta{grid-template-columns:1fr 1fr 1fr}
  .stat-num-grid{grid-template-columns:repeat(4,1fr)}
  .split-visual{grid-template-columns:1fr 1fr}
  .attack-flow{grid-template-columns:repeat(5,1fr)}
  .flow-step::after{display:block}
  h2{font-size:1.9rem}
  h3{font-size:1.25rem}
}"""

MOBILE_NOTICE = '<div class="mobile-notice"><strong>Intentionally desktop-first</strong> — best experienced on a workstation</div>'

# Target directories
TARGET_GLOBS = [
    os.path.join(PORTFOLIO, "analysis", "*.html"),
    os.path.join(PORTFOLIO, "labs", "*.html"),
    os.path.join(PORTFOLIO, "writing", "*.html"),
]

files = []
for pattern in TARGET_GLOBS:
    files.extend(sorted(glob.glob(pattern)))

print("── Injecting responsive CSS and mobile notice ──────────────────────────")
patched = 0
skipped = 0

for filepath in files:
    filename = os.path.basename(filepath)

    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # Skip if already patched
    if "RESPONSIVE — CONTENT PAGES" in content:
        print(f"  SKIP (already patched): {filename}")
        skipped += 1
        continue

    # 1. Inject CSS before </style>
    if "</style>" not in content:
        print(f"  WARN (no </style> found): {filename}")
        continue
    content = content.replace("</style>", RESPONSIVE_CSS + "\n</style>", 1)

    # 2. Inject mobile notice after <body>
    if "<body>" in content:
        content = content.replace("<body>", f"<body>\n{MOBILE_NOTICE}", 1)
    else:
        print(f"  WARN (no <body> tag found): {filename}")

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"  PATCHED: {filename}")
    patched += 1

print()
print(f"── Complete: {patched} patched, {skipped} skipped ──────────────────────────────")
print()
print("── Verify with:")
print(f'   grep -l "mobile-notice" {PORTFOLIO}/analysis/*.html')
print(f'   grep -l "mobile-notice" {PORTFOLIO}/labs/*.html')
print(f'   grep -l "mobile-notice" {PORTFOLIO}/writing/*.html')
