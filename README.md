# Yana Ivanov — Cybersecurity Portfolio

Threat intelligence research, detection engineering, and browser-based security tools. Built by a senior UX/product designer pivoting into cybersecurity — 15 years designing enterprise software, now writing detection rules and analyzing threat actor behavior.

Active contributor to [Sublime Security's open-source email detection ruleset](https://github.com/sublime-security/sublime-rules).

**Portfolio:** [yanaivanov.com](https://yanaivanov.com)  
**GitHub:** [@yana-ivanov](https://github.com/yana-ivanov)  
**X:** [@ArtemisHex_](https://x.com/ArtemisHex_)

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

Open-source detection rules contributed to [Sublime Security's production ruleset](https://github.com/sublime-security/sublime-rules). All rules target email-layer detection.

| Rule | Gist | Status |
|------|------|--------|
| ClickFix clipboard hijack lure | [gist](https://gist.github.com/yana-ivanov/7dcd7bdb7c321f3b42117e6104603ee7) | PR merged |
| pkpass Apple Wallet phishing | [gist](https://gist.github.com/yana-ivanov/b3e4ee146561d05f63e71618a6ba366e) | PR open |
| RoundPress XSS webmail exploit | [gist](https://gist.github.com/yana-ivanov/7edf45c26bacf957dfaf5d6ba96df5eb) | PR open |
| CSS injection webmail sanitizer bypass | [gist](https://gist.github.com/yana-ivanov/8bf1e78d3f6f3166521403acb0447e48) | In pipeline |
| CaptiveCrunch M365 doppelganger — Storm-2945 | [gist](https://gist.github.com/yana-ivanov/8b4770f07ab638cec1cf49bb276bd2b6) | In pipeline |
| PDF job offer lure + YARA — Operation Dream Job | [gist](https://gist.github.com/yana-ivanov/678d779716643c68cbc2fee789e42f07) | In pipeline |
| ScreenConnect cloud C2 subdomain | [gist](https://gist.github.com/yana-ivanov/cba5b9561d05f14d0dbefb56e2558484) | In pipeline |
| India tax authority impersonation — ITR/GST | [gist](https://gist.github.com/yana-ivanov/e7a0e6898b1bd64e5b41dd9b5da90cd1) | In pipeline |
| ZIP+LNK with GitHub Raw C2 — Operation GitPower | [gist](https://gist.github.com/yana-ivanov/567ddfffe0aa5a345786db0ae735e97e) | In pipeline |
| PDF with AI-generated metadata — Kimsuky pattern | [gist](https://gist.github.com/yana-ivanov/4ebb6f4b726c8a7b6a73e04e29e65952) | In pipeline |
| Framer-hosted credential phishing | [gist](https://gist.github.com/yana-ivanov/a2a8eac912af67bf84bebba54442a86f) | In pipeline |
| Figma first-contact invite abuse | [gist](https://gist.github.com/yana-ivanov/3fc9d818d29e7227e959a4803ef7765f) | In pipeline |
| OWAReaper onload= XSS delivery | [gist](https://gist.github.com/yana-ivanov/4f14e4f7163b53f00853066965221b6c) | In pipeline |
| ShinyHunters .claims TLD IT impersonation | [gist](https://gist.github.com/yana-ivanov/78f5e40ab19842b0d760e00bf8945f42) | In pipeline |
| EvilTokens device code body lure | [gist](https://gist.github.com/yana-ivanov/30916df7e16a170f4b689bcd4b07bac0) | In pipeline |
| Jira Service Management PaaP phishing lure | [gist](https://gist.github.com/yana-ivanov/499ad4d3ff401488ee4414b9243046c8) | In pipeline |

---

## Threat Research & Analysis

Published analyses at [yanaivanov.com](https://yanaivanov.com):

- **[ScreenConnect RMM Abuse and the Email Delivery Gap](https://yanaivanov.com/analysis/screenconnect_analysis.html)** — Active campaign analysis with live URLhaus IOCs, three documented email delivery vectors, and detection gap in existing coverage
- **[Glassworm — Invisible Unicode Supply Chain Attack](https://yanaivanov.com/analysis/glassworm_analysis.html)** — 433+ component supply chain campaign, Solana+BitTorrent C2, NK/PolinRider attribution
- **[pkpass Phishing — Apple Wallet as an Attack Surface](https://yanaivanov.com/analysis/pkpass_analysis.html)** — Original research into `.pkpass` abuse for travel brand impersonation
- **[The New Recruit — Gaming Platforms as Criminal Recruitment Infrastructure](https://yanaivanov.com/analysis/telnyx_new_recruit.html)** — How criminal networks recruit minors through gaming platforms and the home network as corporate perimeter gap

---

## Field Notes

- [ClickFix — Clipboard Hijack Lure with ScreenConnect Delivery Chain](https://yanaivanov.com/writing/clickfix_field_note.html)
- [CSS Injection — The Bomb Inside Your Inbox](https://yanaivanov.com/writing/css_field_note.html)
- [Framer as a Phishing Platform](https://yanaivanov.com/writing/framer_field_note.html)
- [Platform as Proxy — GitHub, Jira, Slack as Phishing Infrastructure](https://yanaivanov.com/writing/paap_field_note.html)
- [Figma — Email Infrastructure Abuse and Invite Phishing](https://yanaivanov.com/writing/figma_field_note.html)

---

## About

I am a security researcher and detection engineer in Connecticut. Before security I spent 15 years as a senior UX/product designer. I co-founded [ArgusX](https://yanaivanov.com), a live threat intelligence platform. Security+ in progress.

Everything here is independent research shared as a contribution to the security community.
