#!/bin/bash

# add_plausible.sh
# Adds Plausible Analytics snippet to all HTML files in the portfolio
# Skips Google verification files and files that already have Plausible
#
# Usage:
#   bash add_plausible.sh          # Dry run (shows what would change, no changes made)
#   bash add_plausible.sh false    # Live run (actually modifies files)

# Configuration
PORTFOLIO_DIR="$HOME/cybersecurity-portfolio"
DRY_RUN=${1:-true}  # Default to dry run

# Files to skip (Google verification files)
SKIP_FILES=(
    "google1234abcd.html"
    "google2ac7614618ac6355.html"
)

# The Plausible snippet to insert
PLAUSIBLE_SNIPPET='    <!-- Privacy-friendly analytics by Plausible -->
    <script async src="https://plausible.io/js/pa-NXVpsfumVAR2LJELxP_So.js"></script>
    <script>
      window.plausible=window.plausible||function(){(plausible.q=plausible.q||[]).push(arguments)},plausible.init=plausible.init||function(i){plausible.o=i||{}};
      plausible.init()
    </script>'

# Counters
TOTAL=0
ADDED=0
SKIPPED_ALREADY=0
SKIPPED_GOOGLE=0
ERRORS=0

echo "================================================"
if [ "$DRY_RUN" = "true" ]; then
    echo "DRY RUN MODE - no files will be modified"
else
    echo "LIVE MODE - files will be modified"
fi
echo "Portfolio directory: $PORTFOLIO_DIR"
echo "================================================"
echo ""

# Verify portfolio directory exists
if [ ! -d "$PORTFOLIO_DIR" ]; then
    echo "ERROR: Portfolio directory not found: $PORTFOLIO_DIR"
    echo "Edit the PORTFOLIO_DIR variable at the top of this script if needed."
    exit 1
fi

# Find all HTML files
while IFS= read -r file; do
    TOTAL=$((TOTAL + 1))
    filename=$(basename "$file")
    
    # Skip Google verification files
    skip=false
    for skip_file in "${SKIP_FILES[@]}"; do
        if [ "$filename" = "$skip_file" ]; then
            skip=true
            break
        fi
    done
    
    if [ "$skip" = true ]; then
        echo "SKIP (Google verification): $file"
        SKIPPED_GOOGLE=$((SKIPPED_GOOGLE + 1))
        continue
    fi
    
    # Check if Plausible is already in the file
    if grep -q "plausible.io" "$file"; then
        echo "ALREADY HAS PLAUSIBLE: $file"
        SKIPPED_ALREADY=$((SKIPPED_ALREADY + 1))
        continue
    fi
    
    # Check if file has </head> tag
    if ! grep -q "</head>" "$file"; then
        echo "ERROR - No </head> tag found in: $file"
        ERRORS=$((ERRORS + 1))
        continue
    fi
    
    # Do the insert (or simulate it)
    if [ "$DRY_RUN" = "true" ]; then
        echo "WOULD ADD to: $file"
        ADDED=$((ADDED + 1))
    else
        # Create a temporary file with snippet inserted before </head>
        awk -v snippet="$PLAUSIBLE_SNIPPET" '
            /<\/head>/ && !found {
                print snippet
                found = 1
            }
            { print }
        ' "$file" > "$file.tmp"
        
        if [ $? -eq 0 ] && [ -s "$file.tmp" ]; then
            mv "$file.tmp" "$file"
            echo "ADDED to: $file"
            ADDED=$((ADDED + 1))
        else
            rm -f "$file.tmp"
            echo "ERROR adding to: $file"
            ERRORS=$((ERRORS + 1))
        fi
    fi
    
done < <(find "$PORTFOLIO_DIR" -name "*.html" -not -path "*/node_modules/*" 2>/dev/null)

echo ""
echo "================================================"
echo "Summary:"
echo "  Total HTML files found: $TOTAL"
if [ "$DRY_RUN" = "true" ]; then
    echo "  Would add to: $ADDED"
else
    echo "  Successfully added to: $ADDED"
fi
echo "  Already had Plausible: $SKIPPED_ALREADY"
echo "  Skipped (Google verify): $SKIPPED_GOOGLE"
echo "  Errors: $ERRORS"
echo "================================================"

if [ "$DRY_RUN" = "true" ]; then
    echo ""
    echo "To run for real (modify files):"
    echo "  bash $0 false"
fi
