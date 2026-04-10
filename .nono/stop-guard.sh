#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="$ROOT_DIR/.nono/guard-commands.json"

if [[ ! -f "$CONFIG_PATH" ]]; then
  exit 0
fi

mapfile -t COMMANDS < <(
  jq -r '.commands[]? | "\(.kind)\t\(.command)"' "$CONFIG_PATH"
)

if [[ "${#COMMANDS[@]}" -eq 0 ]]; then
  exit 0
fi

failures=()
run_cmd() {
  local label="$1"
  local command="$2"
  if command -v devenv >/dev/null 2>&1 && [[ -f "$ROOT_DIR/devenv.nix" ]]; then
    if ! (cd "$ROOT_DIR" && devenv shell --no-tui --no-reload -- bash -lc "$command"); then
      failures+=("$label: $command")
    fi
  else
    if ! (cd "$ROOT_DIR" && bash -lc "$command"); then
      failures+=("$label: $command")
    fi
  fi
}

for entry in "${COMMANDS[@]}"; do
  kind="${entry%%$'\t'*}"
  command="${entry#*$'\t'}"
  run_cmd "$kind" "$command"
done

if [[ "${#failures[@]}" -gt 0 ]]; then
  {
    echo "Stop blocked because the project checks are failing:"
    printf ' - %s\n' "${failures[@]}"
    echo
    echo "Fix the failing lint/build/test command or update .nono/guard-commands.json before stopping."
  } >&2
  exit 2
fi
