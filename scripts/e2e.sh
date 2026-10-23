#!/usr/bin/env bash
# Reproducible end-to-end: create a scoped project, run an assessment against the
# authorized OWASP Juice Shop lab target, and print the report + audit trail.
set -euo pipefail
API=${API:-http://localhost:8000}
USE_LLM=${USE_LLM:-true}

JS_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' juiceshop)
echo "Authorized lab target: $JS_IP:3000"

PID=$(curl -s -X POST "$API/projects" -H 'content-type: application/json' -d "{
  \"name\":\"Juice Shop Lab\",\"autonomy_level\":3,
  \"scopes\":[{\"kind\":\"cidr\",\"value\":\"172.18.0.0/16\",\"is_lab_env\":true}]
}" | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")
echo "project=$PID"

RID=$(curl -s -X POST "$API/projects/$PID/runs" -H 'content-type: application/json' -d "{
  \"objective\":\"Assess the authorized Juice Shop lab target\",
  \"target\":\"http://$JS_IP:3000\",\"use_llm\":$USE_LLM
}" | python3 -c "import sys,json;print(json.load(sys.stdin)['run_id'])")
echo "run=$RID"

until [ "$(curl -s "$API/runs/$RID" | python3 -c 'import sys,json;print(json.load(sys.stdin)["state"])')" != "running" ]; do
  sleep 3
done

echo "=== REPORT ==="
curl -s "$API/runs/$RID/report" | python3 -m json.tool
echo "=== AUDIT ==="
curl -s "$API/projects/$PID/audit" | python3 -m json.tool
