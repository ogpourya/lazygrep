#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "🔨 Building lazygrep..."
if ! go build -o lazygrep lazygrep.go; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

# Setup isolated test directory
TEST_DIR="test_env"
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR/subdir"
mkdir -p "$TEST_DIR/node_modules"

# Move binary to test dir
mv lazygrep "$TEST_DIR/"
cd "$TEST_DIR"

# --- Create Test Data ---
echo "📝 Creating test files..."

# 1. Regular text file with multiple matches
cat <<EOF > data.txt
Here is some random text.
Valid email: test@example.com
Another one: admin@corp.net
A URL here: https://www.google.com
An IP address: 192.168.1.100
EOF

# 2. File in a subdirectory
echo "sub@example.com" > subdir/nested.txt

# 3. File in an ignored directory (node_modules)
echo "ignore_me@example.com" > node_modules/trash.txt

# 4. Binary file (contains null byte)
printf "some_text_before\x00ignore_this_binary@example.com" > binary.bin

# 5. Advanced Validation Data (Credit Cards & UUIDs)
# 4532... is a valid Visa (Luhn check passes)
# 4532...1 is invalid (Luhn check fails)
cat <<EOF > advanced.txt
Valid Card: 4532015112830366
Invalid Card: 4532015112830361
UUID 1: 123e4567-e89b-12d3-a456-426614174000
UUID 2: 987f6543-e21b-12d3-a456-426614174000
Mac Address: 00:1A:2B:3C:4D:5E
Mixed Line: test1@example.com and test2@example.com on the same line
EOF

# --- Run Tests ---

# TEST 1: File Walking (Emails)
echo -n "🧪 Test 1: File Walking (Emails)... "
OUTPUT=$(./lazygrep emails)

if echo "$OUTPUT" | grep -q "test@example.com" && \
   echo "$OUTPUT" | grep -q "admin@corp.net" && \
   echo "$OUTPUT" | grep -q "sub@example.com"; then
    
    # Check for IGNORED emails
    if echo "$OUTPUT" | grep -q "ignore_me@example.com"; then
         echo -e "${RED}FAIL${NC}"
         echo "❌ Found email in 'node_modules' which should be ignored."
         exit 1
    fi
    # Check for BINARY file matches
    if echo "$OUTPUT" | grep -q "ignore_this_binary"; then
         echo -e "${RED}FAIL${NC}"
         echo "❌ Scanned a binary file which should have been skipped."
         exit 1
    fi
    # Check for Mixed Line matches (should find both)
    if ! echo "$OUTPUT" | grep -q "test1@example.com" || ! echo "$OUTPUT" | grep -q "test2@example.com"; then
         echo -e "${RED}FAIL${NC}"
         echo "❌ Failed to find multiple emails on a single line."
         exit 1
    fi
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
    echo "❌ Failed to find expected emails."
    exit 1
fi

# TEST 2: Stdin Piping (URLs)
echo -n "🧪 Test 2: Stdin Pipe Support (URLs)... "
PIPE_OUT=$(cat data.txt | ./lazygrep urls)

if echo "$PIPE_OUT" | grep -q "https://www.google.com"; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
    echo "❌ Failed to find URL from stdin pipe."
    exit 1
fi

# TEST 3: Specific Mode (IPv4)
echo -n "🧪 Test 3: IPv4 Extraction... "
IP_OUT=$(./lazygrep ipv4)
if echo "$IP_OUT" | grep -q "192.168.1.100"; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
    echo "❌ Failed to extract IPv4 address."
    exit 1
fi

# TEST 4: Credit Card Validation (Luhn Check)
echo -n "🧪 Test 4: Credit Card Validation... "
CC_OUT=$(./lazygrep credit-cards)

# Should find the valid card
if ! echo "$CC_OUT" | grep -q "4532015112830366"; then
    echo -e "${RED}FAIL${NC}"
    echo "❌ Failed to find valid credit card number."
    exit 1
fi

# Should NOT find the invalid card (regex matches, but validator should reject it)
if echo "$CC_OUT" | grep -q "4532015112830361"; then
    echo -e "${RED}FAIL${NC}"
    echo "❌ Validation failed: Invalid credit card was reported as valid."
    exit 1
fi
echo -e "${GREEN}PASS${NC}"

# TEST 5: UUID Extraction
echo -n "🧪 Test 5: UUID Extraction... "
UUID_OUT=$(./lazygrep uuids)
COUNT=$(echo "$UUID_OUT" | grep -cE "[0-9a-fA-F-]{36}")
if [ "$COUNT" -eq "2" ]; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
    echo "❌ Expected 2 UUIDs, found $COUNT."
    exit 1
fi

# Cleanup
cd ..
rm -rf "$TEST_DIR"

echo ""
echo -e "${GREEN}🎉 All tests passed successfully!${NC}"
