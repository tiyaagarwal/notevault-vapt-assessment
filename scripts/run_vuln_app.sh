#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../app"
[ -d node_modules ] || npm install
PORT="${PORT:-4001}" node server.js
