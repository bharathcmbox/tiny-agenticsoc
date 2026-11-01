#!/usr/bin/env bash
# Run an atomic test plan against the lab victims and record precise time windows.
#   usage: lab/atomics/run-plan.sh lab/atomics/phase2-plan.tsv [results_dir]
# Each test: get prereqs -> run -> settle -> cleanup. Windows over SSH (OpenSSH, PowerShell shell),
# Linux over SSH with sudo pwsh. Output: <results_dir>/runs.jsonl + per-step logs.
set -uo pipefail
PLAN="${1:?plan.tsv}"
OUT="${2:-results/atomics/$(date -u +%Y%m%dT%H%M%SZ)}"
K="${LAB_SSH_KEY:-$HOME/.ssh/tiny-soc_ed25519}"
SETTLE="${SETTLE:-10}"   # seconds between run and cleanup
GAP="${GAP:-45}"         # seconds between tests so windows don't overlap
SKIP="${SKIP:-}"         # space-separated test ids to skip (e.g. already run)
mkdir -p "$OUT"
# -n: never read stdin, or ssh would swallow the rest of the plan inside the while-read loop
SSH=(ssh -n -i "$K" -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR)

art()    { # host, powershell-command
  case "$1" in
    win) "${SSH[@]}" Administrator@10.10.10.20 "$2" ;;
    lin) "${SSH[@]}" soc@10.10.10.21 "sudo pwsh -NonInteractive -Command \"$2\"" ;;
  esac
}
manual() { # host, command
  case "$1" in
    win) "${SSH[@]}" Administrator@10.10.10.20 "$2" ;;
    lin) "${SSH[@]}" soc@10.10.10.21 "sudo bash -c '$2'" ;;
  esac
}
now() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }

grep -v '^#' "$PLAN" | while IFS=$'\t' read -r id host tech num cmd; do
  [[ -z "$id" ]] && continue
  [[ " $SKIP " == *" $id "* ]] && { echo "skip $id"; continue; }
  echo "[$(date +%T)] $id $host $tech-$num ${cmd:+(manual: $cmd)}"
  if [[ -z "${cmd:-}" ]]; then
    art "$host" "Invoke-AtomicTest $tech -TestNumbers $num -GetPrereqs" > "$OUT/$id.prereq.log" 2>&1
  fi
  start=$(now)
  if [[ -n "${cmd:-}" ]]; then
    manual "$host" "$cmd" > "$OUT/$id.run.log" 2>&1; rc=$?
  else
    art "$host" "Invoke-AtomicTest $tech -TestNumbers $num" > "$OUT/$id.run.log" 2>&1; rc=$?
  fi
  sleep "$SETTLE"
  end=$(now)
  if [[ -z "${cmd:-}" ]]; then
    art "$host" "Invoke-AtomicTest $tech -TestNumbers $num -Cleanup" > "$OUT/$id.cleanup.log" 2>&1
  fi
  name=$(grep -m1 -oE "Executing test: .*" "$OUT/$id.run.log" | sed 's/Executing test: //' | tr -d '\r"')
  printf '{"id":"%s","host":"%s","technique":"%s","test":%s,"name":"%s","manual":"%s","start":"%s","end":"%s","exit":%s}\n' \
    "$id" "$host" "$tech" "$num" "${name:-$cmd}" "${cmd:-}" "$start" "$end" "$rc" >> "$OUT/runs.jsonl"
  sleep "$GAP"
done
echo "done -> $OUT/runs.jsonl"
