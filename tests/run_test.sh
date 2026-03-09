#!/bin/bash
# Quick test script — run inside Docker container
#
# Usage:
#   docker exec -it aasa bash
#   bash tests/run_test.sh
#
# Or from outside:
#   docker exec aasa bash tests/run_test.sh

set -e

echo "=== AASA Rule Learning Test ==="
echo ""

# 1. Start the test fixture server in background
echo "[1/5] Starting test fixture server on :9999..."
python tests/test_server.py &
SERVER_PID=$!
sleep 1

# 2. Scan the poisoned website (with LLM judge)
echo ""
echo "[2/5] Scanning poisoned website (http://localhost:9999) ..."
SCAN_RESP=$(curl -s -X POST http://localhost:6001/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"http://localhost:9999","max_depth":0,"max_pages":5,"enable_llm_judge":true}')
SCAN_ID=$(echo "$SCAN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['scan_id'])")
echo "  Scan ID: $SCAN_ID"

# Poll until done
while true; do
  STATUS=$(curl -s http://localhost:6001/api/v1/scan/$SCAN_ID | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
  echo "  Status: $STATUS"
  if [[ "$STATUS" == "completed" ]] || [[ "$STATUS" == failed* ]]; then
    break
  fi
  sleep 3
done

# 3. Scan the poisoned PDF (with LLM judge)
echo ""
echo "[3/5] Scanning poisoned PDF (http://localhost:9999/poisoned.pdf) ..."
PDF_RESP=$(curl -s -X POST http://localhost:6001/api/v1/scan/pdf \
  -H "Content-Type: application/json" \
  -d '{"url":"http://localhost:9999/poisoned.pdf","enable_llm_judge":true}')
PDF_ID=$(echo "$PDF_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['scan_id'])")
echo "  Scan ID: $PDF_ID"

while true; do
  STATUS=$(curl -s http://localhost:6001/api/v1/scan/$PDF_ID | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
  echo "  Status: $STATUS"
  if [[ "$STATUS" == "completed" ]] || [[ "$STATUS" == failed* ]]; then
    break
  fi
  sleep 3
done

# 4. Check learned rules
echo ""
echo "[4/5] Checking learned rules..."
RULES=$(curl -s http://localhost:6001/api/v1/rules)
echo "$RULES" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data.get('rules', [])
print(f'  Total rules extracted: {len(rules)}')
for r in rules:
    print(f'  [{r[\"state\"]:10s}] {r[\"title\"][:60]:60s} conf={r[\"confidence_score\"]:.0%}  regex={r[\"regex_pattern\"][:50]}')
"

# 5. Check usage
echo ""
echo "[5/5] LLM usage summary..."
curl -s http://localhost:6001/api/v1/usage | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(f'  API calls:    {data[\"total_calls\"]}')
print(f'  Total tokens: {data[\"total_tokens\"]:,}')
print(f'  Total cost:   \${data[\"total_cost_usd\"]:.4f}')
for p, v in data.get('by_purpose', {}).items():
    print(f'    {p:25s}  {v[\"calls\"]} calls  {v[\"input_tokens\"]+v[\"output_tokens\"]:>8,} tokens  \${v[\"cost_usd\"]:.4f}')
"

# Cleanup
kill $SERVER_PID 2>/dev/null || true
echo ""
echo "=== Done! Check the Web UI: Learned Rules tab ==="
