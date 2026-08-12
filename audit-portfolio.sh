#!/bin/bash
# ════════════════════════════════════════════════════════════════════
# Portfolio Audit Script
# Yana Ivanov — Cybersecurity Portfolio
# ════════════════════════════════════════════════════════════════════
#
# Scans all HTML files for:
#   1. Threat-level color inconsistencies (CRITICAL/HIGH/MEDIUM/LOW chips)
#   2. Broken or missing Portfolio links (nav, bio, footer)
#
# CANONICAL ARGUSX THREAT COLORS (must use these hex codes):
#   Critical = #dc2626  (red)
#   High     = #ea580c  (orange)
#   Medium   = #d97706  (amber)
#   Low      = #16a34a  (green)
#
# USAGE:
#   cd ~/Desktop/cybersecurity-portfolio    # or wherever your repo is
#   bash audit-portfolio.sh
#
# ════════════════════════════════════════════════════════════════════

# Colors for terminal output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Counters
TOTAL_FILES=0
ISSUES_FOUND=0
FILES_WITH_ISSUES=0

echo ""
echo -e "${BOLD}════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  PORTFOLIO AUDIT — Threat Colors & Portfolio Links${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════════════════${NC}"
echo ""

# Find all HTML files
HTML_FILES=$(find . -name "*.html" -type f -not -path "./node_modules/*" -not -path "./.git/*" 2>/dev/null)

if [ -z "$HTML_FILES" ]; then
    echo -e "${RED}No HTML files found. Are you in the portfolio directory?${NC}"
    exit 1
fi

# Process each file
for FILE in $HTML_FILES; do
    TOTAL_FILES=$((TOTAL_FILES + 1))
    FILE_ISSUES=0
    FILE_REPORT=""

    # ────────────────────────────────────────────────────────────
    # CHECK 1: Threat-level color consistency
    # ────────────────────────────────────────────────────────────
    
    # Does this file have any threat severity chips?
    HAS_SEVERITY=$(grep -iE "CRITICAL|MEDIUM|HIGH|LOW" "$FILE" | grep -iE "finding-tag|severity|chip|tag" 2>/dev/null)
    
    if [ ! -z "$HAS_SEVERITY" ]; then
        
        # Check for MEDIUM with blue color (the common bug)
        MEDIUM_BLUE=$(grep -nE "fn-medium|medium" "$FILE" | grep -iE "blue|#1a4fa0|#1e40af|var\(--blue\)" 2>/dev/null)
        if [ ! -z "$MEDIUM_BLUE" ]; then
            FILE_REPORT="${FILE_REPORT}\n  ${YELLOW}⚠${NC}  MEDIUM appears to use BLUE coloring (should be amber #d97706)"
            FILE_REPORT="${FILE_REPORT}\n      Lines: $(echo "$MEDIUM_BLUE" | head -3 | cut -d: -f1 | tr '\n' ',' | sed 's/,$//')"
            FILE_ISSUES=$((FILE_ISSUES + 1))
        fi
        
        # Check for non-canonical critical color
        WRONG_CRITICAL=$(grep -nE "critical" "$FILE" | grep -iE "#c0392b|#b91c1c|#991b1b" 2>/dev/null | grep -v "rgba")
        if [ ! -z "$WRONG_CRITICAL" ]; then
            FILE_REPORT="${FILE_REPORT}\n  ${YELLOW}⚠${NC}  CRITICAL uses non-canonical red (should be #dc2626)"
            FILE_REPORT="${FILE_REPORT}\n      Lines: $(echo "$WRONG_CRITICAL" | head -3 | cut -d: -f1 | tr '\n' ',' | sed 's/,$//')"
            FILE_ISSUES=$((FILE_ISSUES + 1))
        fi
        
        # Check for non-canonical high color
        WRONG_HIGH=$(grep -nE "fn-high|high-severity" "$FILE" | grep -iE "#b45309|#92400e|#78350f" 2>/dev/null | grep -v "rgba")
        if [ ! -z "$WRONG_HIGH" ]; then
            FILE_REPORT="${FILE_REPORT}\n  ${YELLOW}⚠${NC}  HIGH may use non-canonical orange (should be #ea580c)"
            FILE_REPORT="${FILE_REPORT}\n      Lines: $(echo "$WRONG_HIGH" | head -3 | cut -d: -f1 | tr '\n' ',' | sed 's/,$//')"
            FILE_ISSUES=$((FILE_ISSUES + 1))
        fi
    fi
    
    # ────────────────────────────────────────────────────────────
    # CHECK 2: Portfolio link consistency
    # ────────────────────────────────────────────────────────────
    
    # Find all hrefs that contain "Portfolio" link text nearby
    # Pattern: <a href="..."...>Portfolio</a> or similar
    
    # Extract Portfolio link URLs (anchor tags with "Portfolio" as text)
    PORTFOLIO_LINKS=$(grep -nE 'href="[^"]*"[^>]*>[^<]*[Pp]ortfolio' "$FILE" 2>/dev/null)
    PORTFOLIO_LINKS_ALT=$(grep -nE '>[Pp]ortfolio</a>' "$FILE" 2>/dev/null)
    
    # Also check back-nav-link class (often used for footer/bio portfolio links)
    BACK_NAV_LINKS=$(grep -nE 'back-nav-link|back-nav' "$FILE" 2>/dev/null | grep -i href)
    
    # Look for broken patterns
    if [ ! -z "$PORTFOLIO_LINKS" ] || [ ! -z "$PORTFOLIO_LINKS_ALT" ]; then
        
        # Pattern 1: href="#" or href="" (empty links)
        EMPTY_LINKS=$(grep -nE 'href="#?"[^>]*>[^<]*[Pp]ortfolio' "$FILE" 2>/dev/null)
        if [ ! -z "$EMPTY_LINKS" ]; then
            FILE_REPORT="${FILE_REPORT}\n  ${RED}✗${NC}  Portfolio link is EMPTY (href=\"\" or href=\"#\")"
            FILE_REPORT="${FILE_REPORT}\n      Lines: $(echo "$EMPTY_LINKS" | cut -d: -f1 | tr '\n' ',' | sed 's/,$//')"
            FILE_ISSUES=$((FILE_ISSUES + 1))
        fi
        
        # Pattern 2: href="javascript:..." or similar  
        BAD_LINKS=$(grep -nE 'href="(javascript:|mailto:|tel:)[^"]*"[^>]*>[^<]*[Pp]ortfolio' "$FILE" 2>/dev/null)
        if [ ! -z "$BAD_LINKS" ]; then
            FILE_REPORT="${FILE_REPORT}\n  ${RED}✗${NC}  Portfolio link has wrong protocol (javascript:/mailto:/tel:)"
            FILE_REPORT="${FILE_REPORT}\n      Lines: $(echo "$BAD_LINKS" | cut -d: -f1 | tr '\n' ',' | sed 's/,$//')"
            FILE_ISSUES=$((FILE_ISSUES + 1))
        fi
        
        # Pattern 3: Check that the link points to index.html or root
        # Get all Portfolio anchor hrefs
        WRONG_TARGET=$(grep -oE 'href="[^"]*"[^>]*>[^<]*[Pp]ortfolio' "$FILE" 2>/dev/null | \
                       grep -vE 'href="\.\./index\.html|href="/index\.html|href="index\.html|href="https://yanaivanov\.com/index\.html|href="https://yanaivanov\.com/"|href="\.\./"|href="/"|href="\./"')
        if [ ! -z "$WRONG_TARGET" ]; then
            FILE_REPORT="${FILE_REPORT}\n  ${RED}✗${NC}  Portfolio link points to WRONG target"
            FILE_REPORT="${FILE_REPORT}\n      Found: $(echo "$WRONG_TARGET" | head -3 | sed 's/^/        /')"
            FILE_ISSUES=$((FILE_ISSUES + 1))
        fi
        
        # Count how many Portfolio links exist (should typically be 2-3: top nav, bio, footer)
        PORTFOLIO_COUNT=$(grep -cE '>[Pp]ortfolio</a>' "$FILE" 2>/dev/null)
        if [ "$PORTFOLIO_COUNT" -eq "0" ]; then
            FILE_REPORT="${FILE_REPORT}\n  ${YELLOW}⚠${NC}  NO Portfolio links found in file"
            FILE_ISSUES=$((FILE_ISSUES + 1))
        elif [ "$PORTFOLIO_COUNT" -eq "1" ]; then
            FILE_REPORT="${FILE_REPORT}\n  ${BLUE}ⓘ${NC}  Only 1 Portfolio link (consider adding to bio and footer)"
        fi
    fi
    
    # ────────────────────────────────────────────────────────────
    # Print report for this file (only if issues)
    # ────────────────────────────────────────────────────────────
    if [ $FILE_ISSUES -gt 0 ]; then
        FILES_WITH_ISSUES=$((FILES_WITH_ISSUES + 1))
        ISSUES_FOUND=$((ISSUES_FOUND + FILE_ISSUES))
        echo -e "${BOLD}${FILE}${NC}"
        echo -e "$FILE_REPORT"
        echo ""
    fi
done

# ════════════════════════════════════════════════════════════════════
# Summary
# ════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  SUMMARY${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Files scanned:        ${BOLD}${TOTAL_FILES}${NC}"
echo -e "  Files with issues:    ${BOLD}${FILES_WITH_ISSUES}${NC}"
echo -e "  Total issues found:   ${BOLD}${ISSUES_FOUND}${NC}"
echo ""

if [ $ISSUES_FOUND -eq 0 ]; then
    echo -e "${GREEN}  ✓ Portfolio is clean!${NC}"
else
    echo -e "${YELLOW}  Review the issues above and patch each file.${NC}"
fi
echo ""

# ════════════════════════════════════════════════════════════════════
# Reference: Canonical color codes
# ════════════════════════════════════════════════════════════════════
echo -e "${BOLD}REFERENCE — Canonical ArgusX threat colors:${NC}"
echo -e "  Critical: ${BOLD}#dc2626${NC}  (red)"
echo -e "  High:     ${BOLD}#ea580c${NC}  (orange)"
echo -e "  Medium:   ${BOLD}#d97706${NC}  (amber)"
echo -e "  Low:      ${BOLD}#16a34a${NC}  (green)"
echo ""
