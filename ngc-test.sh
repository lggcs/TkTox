#!/usr/bin/env bash
# ngc-test.sh — full two-bot regression on the current binary:
# --bot responder (avatar, file offer, auto-accept) + --bot initiator
# (ping/pong, file roundtrip, NGC private-group roundtrip incl. promote,
# topic, kick). Fresh identities every run. rc=0 from both = PASS.
# Usage: bash ngc-test.sh full
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

rm -f build/ngc-a.tox build/ngc-a.tox.oq build/ngc-a.tox.ses build/ngc-a.tox.rsum \
      build/ngc-b.tox build/ngc-b.tox.oq build/ngc-b.tox.ses build/ngc-b.tox.rsum
: > build/ngc-a.log
: > build/ngc-b.log

# Mandatory at-rest encryption: the engine refuses to start without a
# passphrase on a non-tty. Tests run unattended, so supply one via env.
export TT_PASSPHRASE=ngc-test-passphrase

"$BIN" --bot build/ngc-a.tox >build/ngc-a.log 2>&1 &
APID=$!
trap 'kill $APID $BPID 2>/dev/null; wait 2>/dev/null' EXIT
BPID=""

# gate on the responder being DHT-online before launching the initiator
AID=""
for _ in $(seq 1 60); do
    AID=$(grep -o '[a-fA-F0-9]\{76\}' build/ngc-a.log | head -1)
    if [ -n "$AID" ] && grep -q 'self connection: 2' build/ngc-a.log; then
        break
    fi
    sleep 1
done
if [ -z "$AID" ]; then
    echo "FAIL: responder never came online, see build/ngc-a.log"
    exit 1
fi

"$BIN" --bot build/ngc-b.tox "$AID" >build/ngc-b.log 2>&1 &
BPID=$!

wait $APID; ARC=$?
wait $BPID; BRC=$?
trap - EXIT

echo "responder rc=$ARC (build/ngc-a.log)"
echo "initiator rc=$BRC (build/ngc-b.log)"
if [ "$ARC" = 0 ] && [ "$BRC" = 0 ]; then
    echo "PASS"
    exit 0
fi
echo "FAIL"
exit 1