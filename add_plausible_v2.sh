#!/bin/bash

# add_plausible.sh (v2 - macOS compatible)
# Adds Plausible Analytics snippet to all HTML files in the portfolio
# Skips Google verification files and files that already have Plausible
#
# Usage:
#   bash add_plausible.sh          # Dry run (shows what would change, no changes made)
#   bash add_plausible.sh false    # Live run (actually modifies files)

# Configuration
PORTFOLIO_DIR="$HOME/cybersecurity-portfolio"
DRY_RUN=${1:-true}

# Files to skip (Google verification files)
SKIP_FILES=(
    "google1234abcd.html"
    "google2ac7614618ac6355.html"
)

# Write the snippet to a temp file so we can read it cleanly
SNIPPET_FILE=$(mktemp)
cat > "$SNIPPET_FILE" << 'SNIPPET_EOF'
    <!-- Privacy-friendly analytics by Plausible -->
    <script async src="https://plausible.io/js/pa-NXVpsfumVAR2LJELxP_So.js"></script>
    <script>
      window.plausible=window.plausible||function(){(plausible.q=plausible.q||[]).push(arguments)},plausible.init=plausible.init||function(i){plausible.o=i||{}};
      plausible.init()
    </script>
SNIPPET_EOF

# Cleanup snippet file on exit
trap "rm -f $SNIPPET_FILE" EXIT

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
    
    if [ "$DRY_RUN" = "true" ]; then
        echo "WOULD ADD to: $file"
        ADDED=$((ADDED + 1))
    else
        # Use sed to insert the snippet before </head>
        # The trick: read snippet from file, escape it for sed, insert
        TMP_FILE="${file}.plausible.tmp"
        
        # Use Python for safe insertion - works regardless of file content
        python3 - "$file" "$SNIPPET_FILE" "$TMP_FILE" << 'PYEOF'
import sys

source_file = sys.argv[1]
snippet_file = sys.argv[2]
output_file = sys.argv[3]

with open(snippet_file, 'r') as f:
    snippet = f.read()

with open(source_file, 'r', encoding='utf-8') as f:
    content = f.read()

# Insert snippet just before first </head>
if '</head>' in content:
    new_content = content.replace('</head>', snippet + '</head>', 1)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(new_content)
    sys.exit(0)
else:
    sys.exit(1)
PYEOF
        
        if [ $? -eq 0 ] && [ -s "$TMP_FILE" ]; then
            mv "$TMP_FILE" "$file"
            echo "ADDED to: $file"
            ADDED=$((ADDED + 1))
        else
            rm -f "$TMP_FILE"
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
