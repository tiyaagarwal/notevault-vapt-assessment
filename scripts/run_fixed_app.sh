#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../fixed"
[ -d node_modules ] || npm install
if [ -z "${JWT_SECRET:-}" ]; then
  echo "JWT_SECRET not set — generating a random one for this run only." >&2
  export JWT_SECRET
  JWT_SECRET="$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")"
fi
PORT="${PORT:-4002}" node server.js
