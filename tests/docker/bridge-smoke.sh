#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${RIFT_DOCKER_BRIDGE_VM:-}" != "1" ]]; then
  echo "Set RIFT_DOCKER_BRIDGE_VM=1 only on a disposable Linux VM with Docker Engine." >&2
  exit 2
fi
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This smoke test requires Linux Docker Engine." >&2
  exit 2
fi
command -v docker >/dev/null || { echo "docker is required" >&2; exit 2; }
exec python3 "$(dirname "$0")/bridge-smoke.py"
