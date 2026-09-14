#!/usr/bin/env bash
# resume-test.sh — cross-restart file-transfer resume regression (TT_BOT_RESUME).
#
# Phase 1 (partial): the initiator sends the 8 MiB test file and cancels
#   mid-transfer; the responder persists a resumable partial (its .rsum
#   sidecar records the file_id + path + byte offset). Both exit cleanly.
# Phase 2 (resume): BOTH peers restart with the SAME profiles (so the
#   responder reloads its .rsum index) and the initiator re-sends the SAME
#   file (same content -> same file_id). The responder must auto-resume
#   from the partial (log "auto-resuming") and complete with matching
#   content — no accept dialog, no re-download of the prefix.
#
# PASS = phase 1 leaves a partial + .rsum, phase 2 logs "auto-resuming"
#        AND the received file matches the full 8 MiB pattern.
# Usage: bash resume-test.sh
set -u

cd "$(dirname "$0")" || exit 1

BIN=build/TkTox

# Shared build/run env: computes the multiarch triplet and sets
# PKG_CONFIG_PATH + LD_LIBRARY_PATH for the vendored .deps tree.
. "$(dirname "$0")/env.sh"

if [ ! -x "$BIN" ]; then
    echo "building..." >&2
    cmake --build build --target TkTox -j4 || exit 1
fi

# Fresh profiles each run (fresh salt -> fresh key), so no stale .rsum.
rm -f build/rs-a.tox build/rs-a.tox.oq build/rs-a.tox.ses build/rs-a.tox.rsum \
      build/rs-b.tox build/rs-b.tox.oq build/rs-b.tox.ses build/rs-b.tox.rsum \
      /tmp/TkTox-testfile-big.bin /tmp/TkTox-testfile-rx.bin
: > build/rs-a.log
: > build/rs-b.log

# Mandatory at-rest encryption: the engine refuses to start without a
# passphrase on a non-tty. Tests run unattended, so supply one via env.
export TT_PASSPHRASE=resume-test-passphrase

# ---- Phase 1: partial transfer (initiator cancels mid-flight) ----
echo "=== phase 1: partial transfer ==="
env TT_BOT_RESUME=1 "$BIN" --bot build/rs-a.tox >build/rs-a.log 2>&1 &
APID=$!
trap 'kill $APID $BPID 2>/dev/null; wait 2>/dev/null' EXIT
BPID=""

AID=""
for _ in $(seq 1 60); do
    AID=$(grep -o '[a-fA-F0-9]\{76\}' build/rs-a.log | head -1)
    if [ -n "$AID" ] && grep -q 'self connection: 2' build/rs-a.log; then
        break
    fi
    sleep 1
done
if [ -z "$AID" ]; then
    echo "FAIL: responder never came online, see build/rs-a.log"
    exit 1
fi

env TT_BOT_RESUME=1 "$BIN" --bot build/rs-b.tox "$AID" >build/rs-b.log 2>&1 &
BPID=$!

wait $APID; ARC=$?
wait $BPID; BRC=$?
trap - EXIT

echo "phase 1: responder rc=$ARC, initiator rc=$BRC"
if [ "$ARC" != 0 ] || [ "$BRC" != 0 ]; then
    echo "FAIL: phase 1 did not exit cleanly"
    echo "--- responder log ---"; grep -E 'resume|file|FAILED' build/rs-a.log || true
    echo "--- initiator log ---"; grep -E 'resume|file|FAILED' build/rs-b.log || true
    exit 1
fi

# The responder must have persisted a resumable partial + .rsum sidecar.
if [ ! -f build/rs-a.tox.rsum ]; then
    echo "FAIL: no .rsum sidecar after phase 1"
    exit 1
fi
if [ ! -f /tmp/TkTox-testfile-rx.bin ]; then
    echo "FAIL: no partial file after phase 1"
    exit 1
fi
PARTIAL=$(stat -c %s /tmp/TkTox-testfile-rx.bin 2>/dev/null || echo 0)
echo "phase 1: partial size = $PARTIAL bytes (of 8388608)"
if [ "$PARTIAL" -eq 0 ] || [ "$PARTIAL" -ge 8388608 ]; then
    echo "FAIL: partial size $PARTIAL not in (0, 8MiB)"
    exit 1
fi

# ---- Phase 2: restart both with the SAME profiles, re-send the SAME file ----
echo "=== phase 2: auto-resume ==="
: > build/rs-a.log
: > build/rs-b.log

env TT_BOT_RESUME=2 "$BIN" --bot build/rs-a.tox >build/rs-a.log 2>&1 &
APID=$!
trap 'kill $APID $BPID 2>/dev/null; wait 2>/dev/null' EXIT
BPID=""

AID=""
for _ in $(seq 1 60); do
    AID=$(grep -o '[a-fA-F0-9]\{76\}' build/rs-a.log | head -1)
    if [ -n "$AID" ] && grep -q 'self connection: 2' build/rs-a.log; then
        break
    fi
    sleep 1
done
if [ -z "$AID" ]; then
    echo "FAIL: responder never came online in phase 2, see build/rs-a.log"
    exit 1
fi

env TT_BOT_RESUME=2 "$BIN" --bot build/rs-b.tox "$AID" >build/rs-b.log 2>&1 &
BPID=$!

wait $APID; ARC=$?
wait $BPID; BRC=$?
trap - EXIT

echo "phase 2: responder rc=$ARC, initiator rc=$BRC"
if [ "$ARC" != 0 ] || [ "$BRC" != 0 ]; then
    echo "FAIL: phase 2 did not exit cleanly"
    echo "--- responder log ---"; grep -E 'resume|file|auto-resum' build/rs-a.log || true
    echo "--- initiator log ---"; grep -E 'resume|file|auto-resum' build/rs-b.log || true
    exit 1
fi

# The responder must have auto-resumed (log "auto-resuming") and the
# received file must match the full 8 MiB pattern.
if ! grep -q 'auto-resuming' build/rs-a.log; then
    echo "FAIL: responder never auto-resumed (no 'auto-resuming' in log)"
    grep -E 'file offer|resume' build/rs-a.log || true
    exit 1
fi
if ! grep -q 'content matches pattern' build/rs-a.log; then
    echo "FAIL: received file content does not match the 8 MiB pattern"
    grep 'file done' build/rs-a.log || true
    exit 1
fi
FINAL=$(stat -c %s /tmp/TkTox-testfile-rx.bin 2>/dev/null || echo 0)
echo "phase 2: final size = $FINAL bytes"
if [ "$FINAL" != 8388608 ]; then
    echo "FAIL: final file size $FINAL != 8388608"
    exit 1
fi

echo "resume PASS (phase 1 partial=$PARTIAL bytes -> phase 2 auto-resumed to full 8 MiB, content matches)"
