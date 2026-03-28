# YANA IVANOV — CYBERSECURITY PORTFOLIO STANDING PROMPT
# Paste this at the start of every new analysis or portfolio work session.
# Last updated: March 2026

---

## WHO I AM
I am Yana Ivanov, Information Assurance & CMMC Compliance Analyst based in Connecticut.
I am building a cybersecurity portfolio targeting SOC analyst roles at CT defense contractors
(Electric Boat, Pratt & Whitney, Sikorsky, Peraton/SAIC/Leidos).

- GitHub username: yana-ivanov
- Mac username: artemishex
- Local portfolio path: ~/Work/security/cybersecurity-portfolio/
- Live site: https://yana-ivanov.github.io/cybersecurity-portfolio/
- Repo: git@github.com:yana-ivanov/cybersecurity-portfolio.git
- I use Terminal for all git commands. Never suggest GitHub Desktop.

---

## PORTFOLIO STRUCTURE
analysis/       — threat intelligence reports (RED theme)
labs/           — lab logs (BLUE theme)
tools/          — interactive tools (BLUE theme)
training/       — training modules (BLUE theme)
writing/        — articles and field notes (BLUE theme)
scripts/        — Python maintenance scripts
index.html      — main portfolio page
resume.html     — resume page

---

## DESIGN RULES — NEVER BREAK THESE

### Color themes
- Analysis reports = RED theme: red mast-bar (#ef4444), red card accent, red category text
- Tools, labs, training, writing = BLUE theme: blue mast-bar (#1a4fa0), blue card accent, blue category text

### Template
- Single source of truth: analysis/analysis-template.html
- ALL new analysis reports must be built from this template
- NEVER modify the CSS in the template — it is locked
- Only fill in content inside <!-- EDIT --> markers
- The template already has: correct bio/footer structure, responsive CSS, mobile notice,
  correct red bar behavior, correct stat grid, correct attack chain layout

### Critical structure rules
1. Bio and footer must ALWAYS be outside the .wrap div
2. The correct closing structure before bio is exactly:
   </div></div>
   <div class="bio">
3. Red bar text: sentence case, never ALL CAPS, wraps naturally (no white-space:nowrap)
4. Kicker line: max 2 items, single line
5. Stat numbers: IBM Plex Serif, 28px, font-weight:700
6. Attack chain: use vertical .attack-chain layout, NOT horizontal .attack-flow grid
7. Portfolio link in bio: must use <p class="bio-text"> wrapper with class="back-nav-link"
8. mast-bar-dot: 10px, white, flex-shrink:0, margin-right:.5rem
9. Red bar text: sentence case | Blue bar text: ALL CAPS — this is intentional per theme

### Index page rules
- Tool cards: blue accent + blue category
- Analysis cards: red accent + red category
- Never mix themes

---

## WORKFLOW FOR A NEW WRITING / FIELD NOTES PAGE

### Template to use
`writing/writing-template.html` — blue theme

### Step 1 — Agree on structure (in chat)
- Article title (main white + subtitle in blue `<span>`)
- Mast-label (single word or short phrase: "Field Notes", "Career", "Analysis")
- Blue bar text — ALL CAPS, 2-3 items separated by ·
- Meta grid (6 cells): Author, Published, Category · Type, + 3 report-specific
- Section titles and key content
- Whether stat grid is needed (use `.mat-card` + `.stat-grid` wrapper)
- Whether timeline is needed (horizontal grid style)

### Step 2 — Generate HTML (Claude does this)
- Duplicate writing-template.html
- Fill all `[EDIT]` and `[bracketed]` placeholders
- Never touch the CSS
- Use writing footer: `<span>Title · Yana Ivanov · Month Year</span>` + `<span>Classification note</span>`

### Step 3 — Review locally, then push
```
git add writing/[filename].html index.html
git commit -m "feat: add [Article Title]"
git push origin main
```

### Writing-specific rules
- Kicker uses decorative lines: `——— FIELD NOTES ———` style (handled by CSS automatically)
- Subtitle in blue `<span>` not red `<em>`
- Section numbers in blue not red
- Stat grid uses `.mat-card` wrapper with `.mat-card-title` header
- Timeline is horizontal grid (date left, content right) — not vertical dots
- Step numbers are blue circles not red
- Footer right side = classification note (not Portfolio link)

---

## WORKFLOW FOR A NEW LAB LOG

### Template to use
`writing/writing-template.html` — same blue template, lab components added

### Step 1 — Agree on structure (in chat)
- Lab number and title: "Lab Log 009 — [Title]"
- Blue bar text — ALL CAPS: `CONTROLLED LAB ENVIRONMENT · [TOOL] · EDUCATIONAL PURPOSE ONLY`
- Meta grid: Analyst, Date, Classification, Lab Type, Tool, Environment
- Sections: Environment → Objective → Methodology → Findings → Analysis → NIST Mapping → Remediation → Lessons Learned → Next Lab
- Which tools/commands were used (for code blocks)
- NIST controls that apply

### Step 2 — Generate HTML (Claude does this)
- Duplicate writing-template.html
- Use lab-specific components from the copy-paste block at bottom of template:
  - `.env-box` for lab environment config
  - `.code-label` + `.code-block` for commands and output
  - `.terminal` for script output (macOS window style)
  - `.host-card` for IP/host summary data
  - `.nist-box` for NIST control mapping
  - `.compare-grid` for side-by-side comparisons
  - `.fn-grid` for script function documentation
- Never touch the CSS
- Use lab footer: `<span>Lab Log N — Title · Yana Ivanov · Date · Controlled lab environment · Educational use only</span>` + `<a href="../index.html">← Portfolio</a>`

### Step 3 — Review locally, then push
```
git add labs/lab_log_[N].html index.html
git commit -m "feat: add Lab Log [N] — [Title]"
git push origin main
```

### Lab-specific rules
- File naming: `lab_log_001.html`, `lab_log_002.html` etc. (zero-padded)
- Blue bar: ALWAYS starts with `CONTROLLED LAB ENVIRONMENT ·`
- Always include safety callout in Section 01: "All scanning performed against systems owned by the analyst..."
- Always link to related analysis reports where relevant
- Always include "Next Lab" section pointing to the next lab log
- NIST mapping section is required for every lab
- `.t-dim` color is `#94a3b8` — do not change to the old `#475569`
- Terminal window always has 3 colored dots (red/yellow/green) in `.terminal-bar`

### Step 1 — Brainstorm (in chat)
Tell me the topic. We discuss angle, key findings, structure, stats to include.
I will suggest: section outline, key data points, MITRE ATT&CK mapping, relevant IOCs.

### Step 2 — Outline (in chat)
We agree on:
- Report title (main + subtitle in red)
- Kicker (max 2 items: "Threat Intelligence Analysis · [Category]")
- Red bar text (sentence case, 1-2 key stats)
- Meta grid (6 cells: Author, Published, Classification + 3 report-specific)
- Section titles and key content per section
- Stats for the stat grid (4 cells)
- Footer text (left: "Report Title · Yana Ivanov · Month Year", right: classification note)

### Step 3 — Generate HTML (Claude does this)
I duplicate the template and fill in all content.
I never modify the CSS.
I deliver a complete .html file ready to drop into analysis/.

### Step 4 — Review locally
You open the file in Chrome from ~/Work/security/cybersecurity-portfolio/analysis/
Check: bio full width, footer full width, red bar wraps correctly, dot visible,
Portfolio link styled correctly (← PORTFOLIO in blue mono), stat grid looks clean.

### Step 5 — Add to index.html
I write the card HTML for index.html with:
- Red accent and red category
- Correct data-tags for filtering
- Report title, description, tags

### Step 6 — Push to GitHub
git add analysis/[filename].html index.html
git commit -m "feat: add [Report Title] analysis"
git push origin main

---

## QUALITY CHECKLIST — VERIFY BEFORE EVERY PUSH
- [ ] Bio is full width (dark navy edge to edge)
- [ ] Footer is full width (dark slate edge to edge)
- [ ] No gap between bio and footer
- [ ] Portfolio link in bio shows ← PORTFOLIO in blue mono font
- [ ] Portfolio link in top nav shows ← PORTFOLIO in blue mono font
- [ ] Red bar has blinking white dot on left
- [ ] Red bar text is sentence case (not ALL CAPS)
- [ ] Red bar text wraps naturally if long (no truncation)
- [ ] Stat numbers render in IBM Plex Serif
- [ ] Mobile notice shows on screens under 1024px
- [ ] All cards on index.html use correct theme color

---

## REFERENCE FILE
analysis/data-breach-exposure-analysis.html is the gold standard reference.
When in doubt about any structural question, check this file first.

---

## FILE NAMING CONVENTION
- All lowercase with underscores: threat_actor_analysis.html
- Descriptive but short: volt_typhoon_analysis.html, not volt_typhoon_china_lotl_infrastructure_analysis.html
- Always .html extension

---

## EXISTING REPORTS (do not rename these files — links exist to them)
analysis/data-breach-exposure-analysis.html
analysis/water_infrastructure_analysis.html
analysis/signal_whatsapp_analysis.html
analysis/The_Cascade_Analysis.html
analysis/CMMC_Supply_Chain.html
analysis/Volt_Typhoon_Analysis.html
analysis/stryker_threat_analysis.html
analysis/homoglyph_bec_analysis.html
analysis/glassworm_analysis.html
analysis/hiring_trap_analysis.html
analysis/linkedin_open_door.html
analysis/github_domain_trust_analysis.html

---

## CURRENT PRIORITIES (as of March 2026)
1. Migrate existing reports to new template (one at a time, verify before committing)
2. Build Chrome extension permission scanner tool
3. Write "The Catch-22 of Account Recovery" report
4. Tools responsive treatment

---

## HOW TO START A NEW SESSION
For a new report: "I want to write a new analysis about [topic]. Let's start with the outline."
For migrating an existing report: "Let's migrate [filename] to the new template."
For portfolio fixes: "Here's what's broken: [description]"
For a new tool: "I want to build a tool that [description]."
