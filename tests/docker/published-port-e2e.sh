#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${RIFT_DOCKER_PUBLISHED_VM:-}" != "1" || "$(uname -s)" != "Linux" ]]; then
  echo "Run only on a disposable Linux Docker VM with RIFT_DOCKER_PUBLISHED_VM=1." >&2
  exit 2
fi
exec python3 "$(dirname "$0")/published-port-e2e.py"
