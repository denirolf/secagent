#!/usr/bin/env bash
# Ensure a cloud session can run the test suite and (optionally) the e2e.
set -e
pip install -q -r requirements.txt || true
# Start the Docker daemon if it is installed but not running (needed for the e2e).
if command -v docker >/dev/null 2>&1 && ! docker info >/dev/null 2>&1; then
  (sudo -n dockerd >/tmp/dockerd.log 2>&1 &) || true
  for i in $(seq 1 10); do docker info >/dev/null 2>&1 && break; sleep 1; done
fi
echo "secagent-platform session ready: run 'pytest -q' for unit tests."
