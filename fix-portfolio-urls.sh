#!/bin/bash
# ════════════════════════════════════════════════════════════════════
# Script 1: Fix Stale GitHub Pages Portfolio URLs (v2 — Global Swap)
# ════════════════════════════════════════════════════════════════════
#
# Replaces all references to the old GitHub Pages hosting URL:
#   https://yana-ivanov.github.io/cybersecurity-portfolio/
#
# With your current production domain:
#   https://yanaivanov.com/
#
# Same path preserved — so ../tools/X.html stays X.html, etc.
#
# WHY GLOBAL SWAP INSTEAD OF RELATIVE PATHS:
# The dry-run revealed these files contain MIXED link types:
#   - Portfolio nav links
#   - Privacy Policy links
#   - Internal tool/analysis links
#   - Plain-text references
# A single global swap fixes ALL of them safely. Every link continues
# to point to the same logical destination, just on the live domain.
#
# SAFETY:
#   - Dry-run mode by default
#   - Creates .bak backup before any write
#   - Run with --apply to make real changes
#
# USAGE:
#   bash fix-portfolio-urls.sh           # dry-run
#   bash fix-portfolio-urls.sh --apply   # apply changes
#
# ════════════════════════════════════════════════════════════════════

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Check for --apply flag
APPLY=false
if [ "$1" == "--apply" ]; then
    APPLY=true
fi

echo ""
echo -e "${BOLD}════════════════════════════════════════════════════════════════════${NC}"
if [ "$APPLY" = true ]; then
    echo -e "${BOLD}  Fix Portfolio URLs v2 — ${RED}APPLY MODE${NC}${BOLD} (writing changes)${NC}"
else
    echo -e "${BOLD}  Fix Portfolio URLs v2 — ${GREEN}DRY RUN${NC}${BOLD} (no changes written)${NC}"
fi
echo -e "${BOLD}════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BOLD}Replacement rule:${NC}"
echo -e "  OLD: ${YELLOW}https://yana-ivanov.github.io/cybersecurity-portfolio/${NC}"
echo -e "  NEW: ${GREEN}https://yanaivanov.com/${NC}"
echo ""
echo -e "${BOLD}Also replacing bare domain references:${NC}"
echo -e "  OLD: ${YELLOW}yana-ivanov.github.io/cybersecurity-portfolio${NC} (plain text)"
echo -e "  NEW: ${GREEN}yanaivanov.com${NC}"
echo ""

# ────────────────────────────────────────────────────────────────────
# Files that need fixing (from audit script results)
# ────────────────────────────────────────────────────────────────────
declare -a FILES=(
    "./tools/email-threat-analyzer.html"
    "./tools/alertdesk.html"
    "./tools/youtube-purge.html"
    "./privacy.html"
    "./writing/email-threat-analyzer-field-notes.html"
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
    
    # Count occurrences of stale URLs
    OLD_COUNT=$(grep -cE 'yana-ivanov\.github\.io/cybersecurity-portfolio' "$FILE" 2>/dev/null)
    
    if [ "$OLD_COUNT" -eq "0" ]; then
        echo -e "  ${GREEN}✓ Already clean${NC}"
        echo ""
        continue
    fi
    
    echo -e "  Found ${YELLOW}${OLD_COUNT}${NC} stale reference(s)"
    
    # Show preview of changes
    echo -e "  ${BOLD}Changes preview:${NC}"
    grep -nE 'yana-ivanov\.github\.io/cybersecurity-portfolio' "$FILE" | head -3 | while IFS= read -r LINE; do
        LINENUM=$(echo "$LINE" | cut -d: -f1)
        # Show what the line looks like AFTER replacement
        AFTER=$(echo "$LINE" | cut -d: -f2- | \
                sed 's|https://yana-ivanov\.github\.io/cybersecurity-portfolio|https://yanaivanov.com|g' | \
                sed 's|yana-ivanov\.github\.io/cybersecurity-portfolio|yanaivanov.com|g' | \
                cut -c1-150)
        echo -e "    ${BLUE}L${LINENUM} →${NC} ${AFTER}..."
    done
    
    if [ "$OLD_COUNT" -gt 3 ]; then
        echo -e "    ${BLUE}(+ $(($OLD_COUNT - 3)) more)${NC}"
    fi
    
    if [ "$APPLY" = true ]; then
        # Create backup
        cp "$FILE" "${FILE}.bak"
        
        # Replacement 1: Full URL with protocol
        # Pattern: https://yana-ivanov.github.io/cybersecurity-portfolio
        # Replace: https://yanaivanov.com
        sed -i.tmp 's|https://yana-ivanov\.github\.io/cybersecurity-portfolio|https://yanaivanov.com|g' "$FILE"
        
        # Replacement 2: Bare domain (plain text references)
        # Pattern: yana-ivanov.github.io/cybersecurity-portfolio
        # Replace: yanaivanov.com
        # (This runs after the http:// replacement, so it only catches plain-text refs)
        sed -i.tmp 's|yana-ivanov\.github\.io/cybersecurity-portfolio|yanaivanov.com|g' "$FILE"
        
        # Remove the .tmp file sed creates on macOS
        rm -f "${FILE}.tmp"
        
        # Verify
        REMAINING=$(grep -cE 'yana-ivanov\.github\.io/cybersecurity-portfolio' "$FILE" 2>/dev/null)
        if [ "$REMAINING" -eq "0" ]; then
            echo -e "  ${GREEN}✓ Fixed — all ${OLD_COUNT} reference(s) replaced${NC}"
            echo -e "  ${BLUE}  Backup: ${FILE}.bak${NC}"
            TOTAL_REPLACEMENTS=$((TOTAL_REPLACEMENTS + OLD_COUNT))
            FILES_CHANGED=$((FILES_CHANGED + 1))
        else
            echo -e "  ${RED}⚠ WARNING: ${REMAINING} reference(s) still remain${NC}"
            echo -e "  ${YELLOW}  Restore: cp ${FILE}.bak ${FILE}${NC}"
        fi
    else
        echo -e "  ${YELLOW}(dry-run — not changed)${NC}"
        TOTAL_REPLACEMENTS=$((TOTAL_REPLACEMENTS + OLD_COUNT))
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
    echo -e "  Total replacements:   ${BOLD}${TOTAL_REPLACEMENTS}${NC}"
    echo ""
    echo -e "  ${GREEN}✓ Backups saved with .bak extension${NC}"
    echo ""
    echo -e "  ${BOLD}Verify in browser, then clean up backups:${NC}"
    echo -e "       ${BOLD}find . -name '*.html.bak' -delete${NC}"
else
    echo -e "  Would replace:        ${BOLD}${TOTAL_REPLACEMENTS}${NC} reference(s)"
    echo ""
    echo -e "  ${YELLOW}This was a DRY RUN — nothing was changed.${NC}"
    echo -e "  ${BOLD}To apply:${NC}"
    echo -e "       ${BOLD}bash fix-portfolio-urls.sh --apply${NC}"
fi
echo ""
