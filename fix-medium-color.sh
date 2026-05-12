#!/bin/bash
# ════════════════════════════════════════════════════════════════════
# Script 2: Fix MEDIUM Severity Chip Color (blue → amber)
# ════════════════════════════════════════════════════════════════════
#
# Path A: Minimum viable fix.
# Only changes .fn-medium severity chips from blue to amber.
# Does NOT touch:
#   - .callout-blue (informational callouts stay blue)
#   - .stat-blue (informational stats stay blue)
#   - Hyperlinks (stay blue)
#   - code blocks (stay blue)
#   - .fn-critical (already correct)
#   - .fn-high (already amber, unchanged)
#
# WHAT CHANGES (per file):
#   .fn-medium .finding-num{background:var(--blue)...}
#     → .fn-medium .finding-num{background:var(--amber)...}
#
#   .fn-medium .finding-tag{background:var(--blue-dim);color:var(--blue)}
#     → .fn-medium .finding-tag{background:var(--amber-dim);color:var(--amber)}
#
# SAFETY:
#   - Dry-run mode by default
#   - Creates .bak backup before any write
#   - Run with --apply to make real changes
#
# USAGE:
#   bash fix-medium-color.sh           # dry-run
#   bash fix-medium-color.sh --apply   # apply changes
#
# ════════════════════════════════════════════════════════════════════

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

APPLY=false
if [ "$1" == "--apply" ]; then
    APPLY=true
fi

echo ""
echo -e "${BOLD}════════════════════════════════════════════════════════════════════${NC}"
if [ "$APPLY" = true ]; then
    echo -e "${BOLD}  Fix MEDIUM Color — ${RED}APPLY MODE${NC}${BOLD} (writing changes)${NC}"
else
    echo -e "${BOLD}  Fix MEDIUM Color — ${GREEN}DRY RUN${NC}${BOLD} (no changes written)${NC}"
fi
echo -e "${BOLD}════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BOLD}What this does:${NC}"
echo -e "  Changes ${YELLOW}.fn-medium${NC} chips from BLUE to AMBER"
echo -e "  Leaves all other blue usage alone (links, callouts, stats, code)"
echo ""

# ────────────────────────────────────────────────────────────────────
# Files with MEDIUM blue (from audit)
# ────────────────────────────────────────────────────────────────────
declare -a FILES=(
    "./tools/alertdesk.html"
    "./analysis/github_domain_trust_analysis.html"
    "./analysis/analysis-template.html"
    "./analysis/data-breach-exposure-analysis.html"
    "./analysis/telnyx_new_recruit.html"
    "./analysis/homoglyph_bec_analysis.html"
    "./analysis/glassworm_analysis.html"
    "./analysis/stryker_threat_analysis.html"
    "./analysis/sixty_seconds.html"
    "./analysis/apple_watch_threat_analysis.html"
)

TOTAL_FILES=0
TOTAL_REPLACEMENTS=0
FILES_CHANGED=0

# ────────────────────────────────────────────────────────────────────
# Process each file
# ────────────────────────────────────────────────────────────────────
for FILE in "${FILES[@]}"; do
    TOTAL_FILES=$((TOTAL_FILES + 1))
    
    if [ ! -f "$FILE" ]; then
        echo -e "${RED}✗ NOT FOUND:${NC} $FILE"
        echo ""
        continue
    fi
    
    echo -e "${BOLD}File:${NC} $FILE"
    
    # Look for the two specific patterns that need fixing
    # Pattern 1: .fn-medium .finding-num with --blue background
    PATTERN1=$(grep -nE '\.fn-medium .finding-num\{background:var\(--blue\)' "$FILE" 2>/dev/null)
    
    # Pattern 2: .fn-medium .finding-tag with --blue colors
    PATTERN2=$(grep -nE '\.fn-medium .finding-tag\{background:var\(--blue-dim\);color:var\(--blue\)' "$FILE" 2>/dev/null)
    
    MATCHES=0
    if [ ! -z "$PATTERN1" ]; then MATCHES=$((MATCHES + 1)); fi
    if [ ! -z "$PATTERN2" ]; then MATCHES=$((MATCHES + 1)); fi
    
    if [ "$MATCHES" -eq "0" ]; then
        echo -e "  ${GREEN}✓ No fn-medium blue patterns found (already clean or different format)${NC}"
        echo ""
        continue
    fi
    
    echo -e "  Found ${YELLOW}${MATCHES}${NC} pattern(s) to fix"
    
    if [ ! -z "$PATTERN1" ]; then
        LINE1=$(echo "$PATTERN1" | head -1 | cut -d: -f1)
        echo -e "    ${BLUE}L${LINE1}${NC} — .fn-medium .finding-num (number circle)"
    fi
    if [ ! -z "$PATTERN2" ]; then
        LINE2=$(echo "$PATTERN2" | head -1 | cut -d: -f1)
        echo -e "    ${BLUE}L${LINE2}${NC} — .fn-medium .finding-tag (severity chip)"
    fi
    
    if [ "$APPLY" = true ]; then
        # Backup
        cp "$FILE" "${FILE}.bak"
        
        # Fix Pattern 1: finding-num background
        # Match: .fn-medium .finding-num{background:var(--blue);color:#fff}
        # Replace --blue with --amber
        sed -i.tmp 's|\(\.fn-medium .finding-num{background:\)var(--blue)|\1var(--amber)|g' "$FILE"
        
        # Fix Pattern 2: finding-tag background and color
        # Match: .fn-medium .finding-tag{background:var(--blue-dim);color:var(--blue)}
        # Replace both --blue-dim and --blue with amber equivalents
        sed -i.tmp 's|\(\.fn-medium .finding-tag{background:\)var(--blue-dim);color:var(--blue)|\1var(--amber-dim);color:var(--amber)|g' "$FILE"
        
        rm -f "${FILE}.tmp"
        
        # Verify the change worked
        REMAINING1=$(grep -cE '\.fn-medium .finding-num\{background:var\(--blue\)' "$FILE" 2>/dev/null)
        REMAINING2=$(grep -cE '\.fn-medium .finding-tag\{background:var\(--blue-dim\);color:var\(--blue\)' "$FILE" 2>/dev/null)
        REMAINING=$((REMAINING1 + REMAINING2))
        
        if [ "$REMAINING" -eq "0" ]; then
            echo -e "  ${GREEN}✓ Fixed — patterns replaced with amber${NC}"
            echo -e "  ${BLUE}  Backup: ${FILE}.bak${NC}"
            TOTAL_REPLACEMENTS=$((TOTAL_REPLACEMENTS + MATCHES))
            FILES_CHANGED=$((FILES_CHANGED + 1))
        else
            echo -e "  ${RED}⚠ WARNING: ${REMAINING} pattern(s) still match${NC}"
            echo -e "  ${YELLOW}  Restore: cp ${FILE}.bak ${FILE}${NC}"
        fi
    else
        echo -e "  ${YELLOW}(dry-run — not changed)${NC}"
        TOTAL_REPLACEMENTS=$((TOTAL_REPLACEMENTS + MATCHES))
    fi
    
    echo ""
done

# ────────────────────────────────────────────────────────────────────
# Summary
# ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  SUMMARY${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Files inspected:      ${BOLD}${TOTAL_FILES}${NC}"

if [ "$APPLY" = true ]; then
    echo -e "  Files changed:        ${BOLD}${FILES_CHANGED}${NC}"
    echo -e "  CSS rules updated:    ${BOLD}${TOTAL_REPLACEMENTS}${NC}"
    echo ""
    echo -e "  ${GREEN}✓ Backups saved with .bak extension${NC}"
    echo ""
    echo -e "  ${BOLD}Verify in browser, then clean up:${NC}"
    echo -e "       ${BOLD}find . -name '*.html.bak' -delete${NC}"
else
    echo -e "  Would update:         ${BOLD}${TOTAL_REPLACEMENTS}${NC} CSS rule(s)"
    echo ""
    echo -e "  ${YELLOW}This was a DRY RUN — nothing was changed.${NC}"
    echo -e "  ${BOLD}To apply:${NC}"
    echo -e "       ${BOLD}bash fix-medium-color.sh --apply${NC}"
fi
echo ""
