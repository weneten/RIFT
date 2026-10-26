#!/bin/sh
set -eu
python3 /usr/local/libexec/rift-echo.py &
exec /usr/local/bin/rift "$@"
