#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
TMP=$(mktemp -d)
PIDS=
trap 'kill $PIDS 2>/dev/null || true; rm -rf "$TMP"' EXIT

mkdir -p "$TMP/api/v1" "$TMP/metrics"
printf '%s\n' '{
  "slots": 3,
  "acquisitions": 4
}' >"$TMP/api/v1/stats"
printf '%s\n' '{
  "count": 0,
  "entries": []
}' >"$TMP/api/v1/entries"
printf '%s\n' '{
  "countries": [
    {
      "country": "jp",
      "acquisitions": 3
    },
    {
      "country": "us",
      "acquisitions": 1
    }
  ]
}' >"$TMP/api/v1/country-acquisitions"
printf '%s\n' \
  '# HELP global_egress_request_results_total Completed proxy requests by result, selected country, and entry.' \
  '# TYPE global_egress_request_results_total counter' \
  'global_egress_request_results_total{result="success",country="jp",entry="entry-jp"} 3' \
  '# HELP global_egress_request_duration_seconds Request setup duration until upstream readiness.' \
  '# TYPE global_egress_request_duration_seconds histogram' \
  'global_egress_request_duration_seconds_bucket{result="success",country="jp",entry="entry-jp",le="0.25"} 3' \
  'global_egress_request_duration_seconds_bucket{result="success",country="jp",entry="entry-jp",le="+Inf"} 3' \
  'global_egress_request_duration_seconds_sum{result="success",country="jp",entry="entry-jp"} 0.375' \
  'global_egress_request_duration_seconds_count{result="success",country="jp",entry="entry-jp"} 3' \
  'global_egress_requested_country_total{country="jp"} 3' \
  'global_egress_selected_country_total{country="jp"} 3' \
  'global_egress_country_fallback_total{requested="us",selected="jp"} 1' \
  'global_egress_payload_bytes_total{direction="sent",country="jp",entry="entry-jp"} 128' \
  'global_egress_tunnel_opens_total{role="entry",result="success"} 1' \
  >"$TMP/api/v1/metrics"

CONTROL="file://$TMP/api" OUT_DIR="$TMP/metrics" \
  sh "$ROOT/deploy/collector/global-egress-collector" once

METRICS="$TMP/metrics/global_egress.prom"
grep -Fx 'global_egress_country_acquisitions_total{country="jp"} 3' "$METRICS"
grep -Fx 'global_egress_country_acquisitions_total{country="us"} 1' "$METRICS"
grep -Fx 'global_egress_request_results_total{result="success",country="jp",entry="entry-jp"} 3' "$METRICS"
grep -Fx 'global_egress_request_duration_seconds_count{result="success",country="jp",entry="entry-jp"} 3' "$METRICS"
grep -Fx 'global_egress_requested_country_total{country="jp"} 3' "$METRICS"
grep -Fx 'global_egress_selected_country_total{country="jp"} 3' "$METRICS"
grep -Fx 'global_egress_country_fallback_total{requested="us",selected="jp"} 1' "$METRICS"
grep -Fx 'global_egress_payload_bytes_total{direction="sent",country="jp",entry="entry-jp"} 128' "$METRICS"
grep -Fx 'global_egress_tunnel_opens_total{role="entry",result="success"} 1' "$METRICS"

mkfifo "$TMP/server-port"
python3 - "$TMP/server-port" <<'PY' &
import http.server
import sys

port_file = sys.argv[1]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/v1/metrics":
            body = b'{"error":"not found"}\n'
            self.send_response(404)
        elif self.path == "/v1/stats":
            body = b'{"slots": 1}\n'
            self.send_response(200)
        elif self.path == "/v1/entries":
            body = b'{"count": 0, "entries": []}\n'
            self.send_response(200)
        else:
            body = b'{"countries": []}\n'
            self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass

server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
with open(port_file, "w", encoding="utf-8") as output:
    output.write(f"{server.server_port}\n")
server.serve_forever()
PY
SERVER_PID=$!
PIDS="$SERVER_PID"
read -r SERVER_PORT <"$TMP/server-port"
mkdir "$TMP/error-metrics"
CONTROL="http://127.0.0.1:$SERVER_PORT" OUT_DIR="$TMP/error-metrics" \
  sh "$ROOT/deploy/collector/global-egress-collector" once
grep -Fx '# global-egress extended metrics unavailable' "$TMP/error-metrics/global_egress.prom"
if grep -Fq '{"error":"not found"}' "$TMP/error-metrics/global_egress.prom"; then
  echo "HTTP error body leaked into Prometheus output" >&2
  exit 1
fi

jq -e '
  .panels[]
  | select(.id == 23)
  | .targets[0].expr == "topk(8, sum by (country) (global_egress_selected_country_total{job=\"$job\"}))"
' "$ROOT/deploy/grafana/global-egress.json"

jq -e '
  .version == 20
  and (.panels | length) == 27
  and ([.panels[] | select(.type == "row") | .title] == [
    "Overview",
    "Traffic & routing",
    "Distribution & inventory",
    "Workload & host"
  ])
  and ([.panels[] | select(.id >= 1 and .id <= 5) | .title] == [
    "Status",
    "Success rate",
    "p95 setup latency",
    "Entry health",
    "Connections"
  ])
  and ([.panels[] | select(.id >= 1 and .id <= 5) | .gridPos] == [
    {"h":5,"w":8,"x":0,"y":1},
    {"h":5,"w":8,"x":8,"y":1},
    {"h":5,"w":8,"x":16,"y":1},
    {"h":5,"w":8,"x":0,"y":6},
    {"h":5,"w":8,"x":8,"y":6}
  ])
  and (.panels[] | select(.id == 40) | .title == "Tunnel budget" and .gridPos == {"h":5,"w":8,"x":16,"y":6})
  and ([.panels[] | select(.type == "row") | .gridPos.y] == [0, 11, 33, 49])
  and (.panels[] | select(.id == 2) | .targets[0].expr | contains("global_egress_request_results_total"))
  and (.panels[] | select(.id == 2) | .targets[0].expr | contains("increase(") | not)
  and (.panels[] | select(.id == 2) | .fieldConfig.defaults.thresholds.steps[1].value == 90)
  and (.panels[] | select(.id == 2) | .fieldConfig.defaults.thresholds.steps[2].value == 99)
  and (.panels[] | select(.id == 1) | .targets[0].expr | contains("global_egress_request_results_total"))
  and (.panels[] | select(.id == 1) | .targets[0].expr | contains("increase(") | not)
  and (.panels[] | select(.id == 1) | .targets[0].expr | contains("rate(") | not)
  and (.panels[] | select(.id == 1) | .targets[0].expr | contains("< bool 90"))
  and (.panels[] | select(.id == 1) | .targets[0].expr | contains("> bool 2.5"))
  and (.panels[] | select(.id == 1) | .description | contains("90%"))
  and (.panels[] | select(.id == 1) | .description | contains("process-lifetime"))
  and (.panels[] | select(.id == 1) | .description | contains("2.5 seconds"))
  and (.panels[] | select(.id == 1) | .fieldConfig.defaults.mappings[2].options["2"].text == "DEGRADED")
  and (.panels[] | select(.id == 3) | .targets[0].expr | contains("global_egress_request_duration_seconds_bucket"))
  and (.panels[] | select(.id == 3) | .targets[0].expr | contains("rate(") | not)
  and (.panels[] | select(.id == 3) | .fieldConfig.defaults.thresholds.steps[-1].value == 2.5)
  and (.panels[] | select(.id == 6) | .type == "state-timeline")
  and (.panels[] | select(.id == 6) | .targets[0].legendFormat == "{{entry}}")
  and (.panels[] | select(.id == 6) | .targets[0].expr | contains("entry=~\".*[A-Za-z0-9].*\""))
  and ([.panels[] | select(.id == 22) | .targets[].expr] | all(contains("entry=~\".*[A-Za-z0-9].*\"")))
  and (.panels[] | select(.id == 8) | .type == "bargauge")
  and (.panels[] | select(.id == 12) | .type == "state-timeline")
  and ([.panels[] | select(.id == 12) | .targets[].legendFormat] == ["node scrape", "control API"])
  and (.panels[] | select(.id == 23) | .type == "bargauge")
  and (.panels[] | select(.id == 42) | .targets[0].expr | contains("global_egress_requested_country_total"))
  and (.panels[] | select(.id == 43) | .targets[0].expr | contains("global_egress_country_fallback_total"))
  and (.panels[] | select(.id == 43) | .targets[0].expr | contains("or vector(0)"))
  and (.panels[] | select(.id == 43) | .targets[0].expr | contains("country!~\"any|multiple\""))
  and (.panels[] | select(.id == 44) | .targets[0].expr | contains("global_egress_request_results_total"))
  and (.panels[] | select(.id == 45) | .targets[0].expr | contains("global_egress_request_duration_seconds_bucket"))
  and (.panels[] | select(.id == 45) | .targets[0].expr | contains("rate(") | not)
  and (.panels[] | select(.id == 45) | .fieldConfig.defaults.color.mode == "thresholds")
  and (.panels[] | select(.id == 45) | .fieldConfig.defaults.thresholds.steps[-1].value == 2.5)
  and (.panels[] | select(.id == 47) | .targets[0].expr | contains("global_egress_tunnel_open_duration_seconds_bucket"))
  and (.panels[] | select(.id == 47) | .targets[0].expr | contains("rate(") | not)
  and (.panels[] | select(.id == 46) | .title == "Memory usage")
  and (.panels[] | select(.id == 9) | .title == "Session state")
  and (.panels[] | select(.id == 10) | .title == "CPU usage")
  and (.panels[] | select(.id == 11) | .title == "Network I/O")
' "$ROOT/deploy/grafana/global-egress.json"

# Record curl argv so a bearer token cannot hide on the command line.
mkdir -p "$TMP/bin"
export REAL_CURL
REAL_CURL=$(command -v curl)
cat >"$TMP/bin/curl" <<'WRAP'
#!/bin/sh
{
  printf 'argc=%s\n' "$#"
  i=1
  for arg in "$@"; do
    printf 'arg%d=%s\n' "$i" "$arg"
    i=$((i + 1))
  done
} >>"$CURL_ARGV_LOG"
exec "$REAL_CURL" "$@"
WRAP
chmod 0755 "$TMP/bin/curl"

start_control_stub() {
  require_token=$1
  log=$2
  ready=$3
  mkfifo "$ready"
  python3 - "$require_token" "$log" "$ready" <<'PY' &
import http.server
import sys

require_token, log_path, ready = sys.argv[1], sys.argv[2], sys.argv[3]

FIXTURES = {
    "/v1/stats": b'{"slots": 1}\n',
    "/v1/entries": b'{"count": 0, "entries": []}\n',
    "/v1/country-acquisitions": b'{"countries": []}\n',
    "/v1/metrics": (
        b"# TYPE global_egress_request_results_total counter\n"
        b'global_egress_request_results_total{result="success",country="jp",entry="entry-jp"} 1\n'
    ),
}

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        auth = self.headers.get("Authorization") or ""
        with open(log_path, "a", encoding="utf-8") as output:
            output.write(f"{self.path}\t{auth}\n")
        if require_token and auth != f"Bearer {require_token}":
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Bearer realm="global-egress"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = FIXTURES.get(self.path, b'{"ok":true}\n')
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass

server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
with open(ready, "w", encoding="utf-8") as output:
    output.write(f"{server.server_port}\n")
server.serve_forever()
PY
  STUB_PID=$!
  PIDS="$PIDS $STUB_PID"
  read -r STUB_PORT <"$ready"
}

assert_paths() {
  log=$1
  want_auth=$2
  for path in /v1/stats /v1/country-acquisitions /v1/metrics /v1/entries; do
    grep -Fqx "$path	$want_auth" "$log" || {
      echo "missing control request $path with expected Authorization" >&2
      echo "recorded:" >&2
      cat "$log" >&2
      exit 1
    }
  done
  extra=$(awk -F '\t' -v want="$want_auth" '$2 != want { print }' "$log" || true)
  if [ -n "$extra" ]; then
    echo "control request with unexpected Authorization:" >&2
    printf '%s\n' "$extra" >&2
    exit 1
  fi
}

assert_no_token_leak() {
  token=$1
  shift
  for path in "$@"; do
    if grep -Fq "$token" "$path"; then
      echo "token leaked into $path" >&2
      exit 1
    fi
  done
}

TOKEN=g2-collector-token-ulw
printf '%s\n' "$TOKEN" >"$TMP/control-token"
chmod 0600 "$TMP/control-token"

# Unset token: legacy collector must not send Authorization on any control GET.
: >"$TMP/unauth-log"
start_control_stub "" "$TMP/unauth-log" "$TMP/unauth-port"
UNAUTH_PID=$STUB_PID
UNAUTH_PORT=$STUB_PORT
mkdir "$TMP/unauth-metrics"
: >"$TMP/unauth-argv"
CURL_ARGV_LOG="$TMP/unauth-argv" PATH="$TMP/bin:$PATH" CONTROL="http://127.0.0.1:$UNAUTH_PORT" \
  OUT_DIR="$TMP/unauth-metrics" env -u CONTROL_TOKEN_FILE -u CONTROL_TOKEN \
  sh "$ROOT/deploy/collector/global-egress-collector" once
kill "$UNAUTH_PID" 2>/dev/null || true
grep -Fx 'global_egress_up 1' "$TMP/unauth-metrics/global_egress.prom"
assert_paths "$TMP/unauth-log" ""
if grep -Fi 'authorization' "$TMP/unauth-argv"; then
  echo "Authorization header sent while token was unset" >&2
  exit 1
fi

# Configured token file: every control GET must carry Bearer, never argv/metrics.
: >"$TMP/auth-log"
start_control_stub "$TOKEN" "$TMP/auth-log" "$TMP/auth-port"
AUTH_PID=$STUB_PID
AUTH_PORT=$STUB_PORT
mkdir "$TMP/auth-metrics"
: >"$TMP/auth-argv"
CURL_ARGV_LOG="$TMP/auth-argv" PATH="$TMP/bin:$PATH" CONTROL="http://127.0.0.1:$AUTH_PORT" \
  OUT_DIR="$TMP/auth-metrics" CONTROL_TOKEN_FILE="$TMP/control-token" \
  env -u CONTROL_TOKEN sh "$ROOT/deploy/collector/global-egress-collector" once
kill "$AUTH_PID" 2>/dev/null || true
grep -Fx 'global_egress_up 1' "$TMP/auth-metrics/global_egress.prom"
assert_paths "$TMP/auth-log" "Bearer $TOKEN"
assert_no_token_leak "$TOKEN" \
  "$TMP/auth-metrics/global_egress.prom" \
  "$TMP/auth-argv"
