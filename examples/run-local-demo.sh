#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
canary_bin=${CANARY_BIN:-"$project_root/build/canary"}
fixture_bin=${FIXTURE_BIN:-"$project_root/build/local_server"}
demo_tmp=$(mktemp -d "${TMPDIR:-/tmp}/canary-demo.XXXXXX")
server_pid=

cleanup() {
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$demo_tmp"
}
trap cleanup EXIT HUP INT TERM

if [ ! -x "$canary_bin" ]; then
  nim c --nimcache:"$project_root/build/nimcache-demo-canary" \
    -o:"$canary_bin" "$project_root/src/canary.nim"
fi
if [ ! -x "$fixture_bin" ]; then
  nim c --nimcache:"$project_root/build/nimcache-demo-fixture" \
    -o:"$fixture_bin" "$project_root/tests/fixtures/local_server.nim"
fi

start_server() {
  mode=$1
  shift
  port_file="$demo_tmp/$mode.port"
  error_file="$demo_tmp/$mode.err"
  "$fixture_bin" "$mode" "$@" >"$port_file" 2>"$error_file" &
  server_pid=$!

  attempts=0
  while [ ! -s "$port_file" ]; do
    if ! kill -0 "$server_pid" 2>/dev/null; then
      wait "$server_pid" || true
      sed -n '1,20p' "$error_file" >&2
      return 1
    fi
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 100 ]; then
      echo "local fixture did not announce a port" >&2
      return 1
    fi
    sleep 0.02
  done
  IFS= read -r server_port <"$port_file"
}

finish_server() {
  wait "$server_pid"
  server_pid=
}

start_server http-ok
"$canary_bin" http "http://127.0.0.1:$server_port/health" \
  --search fixture-ok --timeout 2000
finish_server

start_server tcp-request --expected-request=PING --response=PONG
"$canary_bin" tcp 127.0.0.1 --port "$server_port" \
  --request PING --expected PONG --timeout 2000
finish_server

start_server udp-echo --response=pong
"$canary_bin" udp 127.0.0.1 --port "$server_port" \
  --payload ping --expected pong --timeout 2000
finish_server

start_server webhook-ok
"$canary_bin" notify test webhook \
  --notify "http://127.0.0.1:$server_port/canary-demo"
finish_server

echo "Local Canary demo completed successfully."
