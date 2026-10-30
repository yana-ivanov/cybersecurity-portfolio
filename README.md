# Yana Ivanov — Cybersecurity Portfolio

Threat intelligence research, detection engineering, and browser-based security tools. Built by a senior UX/product designer pivoting into cybersecurity — 15 years designing enterprise software, now writing detection rules and analyzing threat actor behavior.

Contributor to [Sublime Security's open-source email detection ruleset](https://github.com/sublime-security/sublime-rules) and to [SigmaHQ](https://github.com/SigmaHQ/sigma). I also maintain my own Sublime rule feed at [custom-sublime-rules](https://github.com/yana-ivanov/custom-sublime-rules).

**Portfolio:** [yanaivanov.com](https://yanaivanov.com)  
**GitHub:** [@yana-ivanov](https://github.com/yana-ivanov)  
**X:** [@ArtemisHex_](https://x.com/ArtemisHex_)  
**Discord:** ArtemisHex

---

## Browser-Based Security Tools

All tools run entirely in the browser. No data leaves your machine. No backend required.

### [Email Threat Analyzer](https://yanaivanov.com/tools/email-threat-analyzer.html)
AI-powered email security analysis with MITRE ATT&CK mapping, VirusTotal integration, and local detection modules for CSS injection, Glassworm invisible Unicode, and Figma platform phishing. Supports Gmail live scanning, file upload, and raw paste. Includes 12 interactive demo scenarios covering BEC, ransomware, credential phishing, era-pair comparisons, and CSS injection attacks.

### [pkpass Analyzer](https://yanaivanov.com/tools/pkpass_analyzer.html)
Drop an Apple Wallet `.pkpass` file and get a full security report — suspicious `webServiceURL`, embedded URLs, archive contents, and field anomalies. Built on original research into pkpass abuse as a phishing delivery mechanism. Summary and findings surfaced first, raw fields below.

### [AES-256 File Encryption Tool](https://yanaivanov.com/tools/aes_tool.html)
Browser-based AES-256-GCM file encryption using the Web Crypto API. True randomness from your OS entropy source. Files never leave your browser. Includes educational documentation explaining why GCM mode matters over CBC and why key management is the real security decision.

### [CVSS Calculator](https://yanaivanov.com/tools/cvss_calculator.html)
Common Vulnerability Scoring System calculator for quickly assessing vulnerability severity.

### [AlertDesk — SOC Triage Tool](https://yanaivanov.com/tools/alertdesk.html)
Upload a CSV export from any SIEM (Splunk, Microsoft Sentinel, Elastic) and run AI classification on every alert — Phishing, Ransomware, Lateral Movement, C2, False Positive. Mark each alert as Escalate, Investigate, or Close. Generates a triage report. Designed for small defense contractors without a dedicated SOC team.

### [ClickFix Simulator](https://yanaivanov.com/tools/clickfix_simulator.html)
Interactive demonstration of the ClickFix social engineering technique — shows how attackers use JavaScript to silently replace clipboard contents, causing users to unknowingly execute malicious commands. Built for security awareness training.

### [Glassworm Detector](https://yanaivanov.com/tools/glassworm_detector.html)
Scans text and code for invisible Unicode characters used in supply chain attacks — the technique documented in the Glassworm VS Code extension campaign. Highlights invisible codepoints that are literally invisible to the naked eye.

### [Zeek Triage Tool](https://yanaivanov.com/tools/zeek_triage_tool.html)
Upload a `.pcap` file and get an automated IOC threat report. Built with Python and Zeek for network traffic analysis.

---

## Detection Rules

### Sublime Security — upstream

Submitted to [Sublime Security's production ruleset](https://github.com/sublime-security/sublime-rules).

| Rule | Status | Analysis |
|------|--------|----------|
| Homoglyph confusable character coverage | ✅ Merged — [#4596](https://github.com/sublime-security/sublime-rules/pull/4596) | [The Identical Lie](https://yanaivanov.com/analysis/homoglyph_bec_analysis.html) |
| ClickFix clipboard hijack lure | ✅ Merged — [#4921](https://github.com/sublime-security/sublime-rules/pull/4921) | [Between Copy and Paste](https://yanaivanov.com/writing/clickfix_field_note.html) |
| RoundPress XSS webmail exploit | 🔄 In review — [#4981](https://github.com/sublime-security/sublime-rules/pull/4981) | [The Pattern Held](https://yanaivanov.com/analysis/roundpress_part3.html) |
| Suspicious download file types — msi, hta, ps1 | 🔄 In review — [#5622](https://github.com/sublime-security/sublime-rules/pull/5622) | — |
| pkpass Apple Wallet phishing | ⏸ Closed — [#5120](https://github.com/sublime-security/sublime-rules/pull/5120) | [The Trusted Pass](https://yanaivanov.com/analysis/pkpass_analysis.html) |
| Homoglyph BEC and Glassworm invisible Unicode | ⏸ Closed — [#4267](https://github.com/sublime-security/sublime-rules/pull/4267) | [The Invisible Threat](https://yanaivanov.com/analysis/glassworm_analysis.html) |

The pkpass rule was closed as, in the reviewer's words, "successful research but not a great fit for our core feed," to be picked back up if the technique starts appearing in the wild. It stays in my own feed in the meantime. #4267 bundled a homoglyph BEC rule with invisible-Unicode detection. The invisible-Unicode half was withdrawn for Sublime to research internally. The homoglyph half went into their test telemetry and returned 72 matches with roughly 69 false positives: matching any Cyrillic or Greek character catches people who legitimately write in those scripts, rather than the mixed-script substitution that signals the attack. The PR closed, but it surfaced a real gap in two existing rules, and I carried that work into them at #4596.

### SigmaHQ — upstream

Submitted to [SigmaHQ](https://github.com/SigmaHQ/sigma). All four awaiting review.

| Rule | Status |
|------|--------|
| macOS browser credential and cookie store access | 🔄 [#6449](https://github.com/SigmaHQ/sigma/pull/6449) |
| macOS keychain credential access coverage | 🔄 [#6450](https://github.com/SigmaHQ/sigma/pull/6450) |
| macOS encoded payload piped to shell | 🔄 [#6451](https://github.com/SigmaHQ/sigma/pull/6451) |
| Azazel ransom note creation — Linux | 🔄 [#6452](https://github.com/SigmaHQ/sigma/pull/6452) |

### Custom rule feed

[**custom-sublime-rules**](https://github.com/yana-ivanov/custom-sublime-rules) — 25 MQL rules maintained as a subscribable Sublime feed. Broadly applicable rules go upstream; this feed keeps the narrower lures, the specific brand impersonations, and the detections still collecting evidence.

Every rule in it has been run against a live mailbox: 4,033 inbound messages across 30 days, one hunt per rule. The results, including the false positives, are published in the repo README and written up in [Twenty-Five Rules I Had Never Run](https://yanaivanov.com/writing/rule_feed_field_note.html).

| Rule | Analysis |
|------|----------|
| CSS injection webmail sanitizer bypass | [The Style That Steals](https://yanaivanov.com/writing/css_field_note.html) |
| CaptiveCrunch M365 doppelganger — Storm-2945 | [Four Layers](https://yanaivanov.com/writing/captivecrunch_field_note.html) |
| PDF job offer lure and dangerous action keys — Operation Dream Job | — |
| ScreenConnect cloud C2 subdomain | [ScreenConnect RMM Abuse](https://yanaivanov.com/analysis/screenconnect_analysis.html) |
| India tax authority impersonation — ITR/GST | — |
| ZIP with LNK and GitHub Raw link — Operation GitPower | [Operation GitPower](https://yanaivanov.com/analysis/kimsuky_gitpower_analysis.html) |
| PDF with AI-generated metadata — Kimsuky pattern | [Operation GitPower](https://yanaivanov.com/analysis/kimsuky_gitpower_analysis.html) |
| Framer-hosted credential phishing | — |
| Figma first-contact invite abuse | [The App I Trust Most](https://yanaivanov.com/writing/figma_field_note.html) |
| OWAReaper onload XSS delivery | [The Pattern Held](https://yanaivanov.com/analysis/roundpress_part3.html) |
| ShinyHunters .claims TLD IT impersonation | [Operational Lifecycle](https://yanaivanov.com/analysis/shinyhunters-operational-lifecycle.html) |
| EvilTokens device code body lure | — |
| Jira Service Management PaaP phishing lure | [The Platform Is the Weapon](https://yanaivanov.com/writing/paap_field_note.html) |
| Hugging Face model share — AI supply chain delivery | [The Watering Hole](https://yanaivanov.com/analysis/huggingface_watering_hole.html) |
| Azure Blob Storage credential phishing | — |
| Script file direct delivery — double extension lure | — |
| Cloud storage malware delivery | — |
| N-able N-central RMM brand impersonation | — |
| Amazon/AWS typosquat domain — Coruna campaign | — |
| GoToResolve RMM brand impersonation | — |
| Unicode homoglyph attachment filename | [The Identical Lie](https://yanaivanov.com/analysis/homoglyph_bec_analysis.html) |
| BeaverTail developer recruitment lure | [The Open Door](https://yanaivanov.com/analysis/linkedin_open_door.html) |
| Real estate wire fraud — closing impersonation | [The Closing Table](https://yanaivanov.com/analysis/rewf_analysis.html) |
| pkpass Apple Wallet pass from unsolicited sender | [The Trusted Pass](https://yanaivanov.com/analysis/pkpass_analysis.html) |
| RoundPress and ZimReaper @import tag-splitting XSS | [The Pattern Held](https://yanaivanov.com/analysis/roundpress_part3.html) |

---

## Threat Research & Analysis

Selected analyses, published at [yanaivanov.com](https://yanaivanov.com):

- **[Eight Random Letters — How a GitHub Account Factory Signs Its Own Work](https://yanaivanov.com/analysis/eight_random_letters_analysis.html)** — Account lifecycle measured across a random sample: an eight-character marker repository on registration day, weeks of dormancy, then batch activation. 834 release assets carrying 134,146 recorded downloads
- **[Open by Default — Why Self-Hosted AI Tools Ship Without Authentication and End Up Exposed](https://yanaivanov.com/analysis/ai_exposure_analysis.html)** — The shared-responsibility gap in self-hosted AI infrastructure, with NVD and CISA KEV counts
- **[The Trust Tax — How Attackers Stopped Building Infrastructure and Started Borrowing Ours](https://yanaivanov.com/analysis/trust_tax_analysis.html)**
- **[The Shai-Hulud Cascade — Six Weeks of a Supply Chain Worm](https://yanaivanov.com/analysis/shai-hulud-cascade.html)**
- **[ShinyHunters Operational Lifecycle — A Threat Actor as a Process](https://yanaivanov.com/analysis/shinyhunters-operational-lifecycle.html)**
- **[Operation GitPower — Kimsuky's AI Lab, the Russia Alliance, and the Detection Gap Nobody Is Talking About](https://yanaivanov.com/analysis/kimsuky_gitpower_analysis.html)**
- **[The Watering Hole — How Hugging Face Became the Most Trusted Attack Surface in AI](https://yanaivanov.com/analysis/huggingface_watering_hole.html)**
- **[The Invisible Threat — Glassworm Unicode Supply Chain Attack](https://yanaivanov.com/analysis/glassworm_analysis.html)**
- **[The Open Door — LinkedIn's Verification Gap and the National Security Cost of Profit Over Trust](https://yanaivanov.com/analysis/linkedin_open_door.html)**
- **[The Closing Table — Real Estate Wire Fraud and the BEC Attack That Targets the Most Trusted Email in a Transaction](https://yanaivanov.com/analysis/rewf_analysis.html)**
- **[Volt Typhoon — Investigative Analysis](https://yanaivanov.com/analysis/Volt_Typhoon_Analysis.html)**
- **[The New Recruit — How Criminal Networks Build Their Next Generation of Attackers](https://yanaivanov.com/analysis/telnyx_new_recruit.html)**

---

## Field Notes

- **[Twenty-Five Rules I Had Never Run](https://yanaivanov.com/writing/rule_feed_field_note.html)** — Publishing a rule feed, then testing all 25 rules against 4,033 real messages for the first time
- **[The Only Thing macOS Detection Watches](https://yanaivanov.com/writing/macos_coverage_field_note.html)** — SigmaHQ carries 2,878 Windows rules and 76 for macOS, and 71 of the 76 watch the same event
- **[I Thought Attacks Were Up](https://yanaivanov.com/writing/kev_surge_field_note.html)** — A 60% rise in confirmed exploitation, and the reporter bias that looked like confirmation
- **[Rated, Triaged, Attached to Nothing](https://yanaivanov.com/writing/nvd_cpe_field_note.html)** — What deferred CPE status means for anyone matching CVEs to products
- **[The Reply You Trusted — How DarkGate Weaponizes Your Email History](https://yanaivanov.com/writing/darkgate_field_note.html)**
- **[Between Copy and Paste](https://yanaivanov.com/writing/clickfix_field_note.html)** — ClickFix clipboard hijacking and the ScreenConnect delivery chain
- **[The Style That Steals — CSS as a Weapon Inside Your Inbox](https://yanaivanov.com/writing/css_field_note.html)**
- **[The Platform Is the Weapon — How Attackers Use GitHub, Jira, and Slack Against You](https://yanaivanov.com/writing/paap_field_note.html)**
- **[The App I Trust Most — What I Found When I Started Looking at Figma Like an Attacker](https://yanaivanov.com/writing/figma_field_note.html)**
- **[裁员名单: The Document No One Was Supposed to See](https://yanaivanov.com/writing/valleyrat_field_note.html)**
- **[Four Layers — CaptiveCrunch and the Traveler's Complete Attack Surface](https://yanaivanov.com/writing/captivecrunch_field_note.html)**
- **[Building ArgusX — Field Notes](https://yanaivanov.com/writing/argusx-field-notes.html)**

---

## About

I am a security researcher and detection engineer in Connecticut. Before security I spent 15 years as a senior UX/product designer. I co-founded [ArgusX](https://yanaivanov.com/writing/argusx-field-notes.html), a live threat intelligence platform. Security+ in progress.

Everything here is independent research shared as a contribution to the security community.
