#!/usr/bin/env bash
# e2ee-test.sh — M3/M4 encrypted-layer regression (TT_BOT_E2EE, run with
# TT_E2EE=1 so the layer is on): the engine handshakes when the friend
# comes online, the initiator's ping stashes until the session is live,
# then flows as an encrypted DATA frame; the pong returns the same way.
# PASS = both instances rc=0 AND both logged the SAME 32-hex verify code
# (TT_EV_E2EE_STATE) AND the initiator got a read receipt for its
# encrypted ping.
#
# M4 harness modes (optional, run after the base roundtrip):
#   reorder  — the initiator delivers DATA frames seq 3,2,4 out of order;
#              the responder must recover 2 and 3 via the skipped-key store
#              and echo all three back (reorder_rx=3 / reorder_echo=3).
#   replay   — the initiator re-injects the last incoming DATA frame into
#              its own session; the engine must log a TT_E2EE_REPLAY reject
#              (never crash, never consume chain state).
# Usage: bash e2ee-test.sh [reorder|replay]
set -u

cd "$(dirname "$0")" || exit 1

MODE="${1:-}"
BIN=build/TkTox

# Shared build/run env: computes the multiarch triplet and sets
# PKG_CONFIG_PATH + LD_LIBRARY_PATH for the vendored .deps tree.
. "$(dirname "$0")/env.sh"

if [ ! -x "$BIN" ]; then
    echo "building..." >&2
    cmake --build build --target TkTox -j4 || exit 1
fi

rm -f build/e2ee-a.tox build/e2ee-a.tox.oq build/e2ee-a.tox.ses build/e2ee-a.tox.rsum \
      build/e2ee-b.tox build/e2ee-b.tox.oq build/e2ee-b.tox.ses build/e2ee-b.tox.rsum
: > build/e2ee-a.log
: > build/e2ee-b.log

# Mandatory at-rest encryption: the engine refuses to start without a
# passphrase on a non-tty. Tests run unattended, so supply one via env.
export TT_PASSPHRASE=e2ee-test-passphrase

# M4 harness env: the initiator drives the ratchet edge case after the
# session establishes (reorder/replay). Both peers need the mode flag so
# each counts its own side (responder: recovered frames; initiator: echoes).
EXTRA_A=""
EXTRA_B=""
case "$MODE" in
    reorder) EXTRA_A="TT_BOT_E2EE_REORDER=1"; EXTRA_B="TT_BOT_E2EE_REORDER=1" ;;
    replay)  EXTRA_A="TT_BOT_E2EE_REPLAY=1"; EXTRA_B="TT_BOT_E2EE_REPLAY=1" ;;
    "") ;;
    *) echo "unknown mode '$MODE' (expected reorder|replay|'')" >&2; exit 2 ;;
esac

# responder first; gate on DHT-online before launching the initiator
env TT_E2EE=1 TT_BOT_E2EE=1 $EXTRA_B "$BIN" --bot build/e2ee-a.tox >build/e2ee-a.log 2>&1 &
APID=$!
trap 'kill $APID $BPID 2>/dev/null; wait 2>/dev/null' EXIT
BPID=""

AID=""
for _ in $(seq 1 60); do
    AID=$(grep -o '[a-fA-F0-9]\{76\}' build/e2ee-a.log | head -1)
    if [ -n "$AID" ] && grep -q 'self connection: 2' build/e2ee-a.log; then
        break
    fi
    sleep 1
done
if [ -z "$AID" ]; then
    echo "FAIL: responder never came online, see build/e2ee-a.log"
    exit 1
fi

env TT_E2EE=1 TT_BOT_E2EE=1 $EXTRA_A "$BIN" --bot build/e2ee-b.tox "$AID" >build/e2ee-b.log 2>&1 &
BPID=$!

wait $APID; ARC=$?
wait $BPID; BRC=$?
trap - EXIT

echo "responder rc=$ARC (build/e2ee-a.log)"
echo "initiator rc=$BRC (build/e2ee-b.log)"
if [ "$ARC" != 0 ] || [ "$BRC" != 0 ]; then
    echo "FAIL"
    exit 1
fi

# both peers must report the SAME 32-hex verification code
ACODE=$(grep -o 'e2ee state friend 0: 1 code=[0-9a-f]\{32\}' build/e2ee-a.log \
    | head -1 | cut -d= -f2)
BCODE=$(grep -o 'e2ee state friend 0: 1 code=[0-9a-f]\{32\}' build/e2ee-b.log \
    | head -1 | cut -d= -f2)
if [ -z "$ACODE" ] || [ "$ACODE" != "$BCODE" ]; then
    echo "FAIL: verify codes differ or missing (a='$ACODE' b='$BCODE')"
    exit 1
fi

# initiator must hold a read receipt for its encrypted ping
if ! grep -q 'receipt matches sent message id' build/e2ee-b.log; then
    echo "FAIL: no read receipt for the encrypted ping"
    exit 1
fi

echo "verify code: $ACODE"
echo "e2ee PASS (handshake + encrypted roundtrip + receipt, codes match)"

# M4 harness assertions
case "$MODE" in
    reorder)
        # responder recovered all three out-of-order frames (rx=3, echo=0);
        # initiator got all three echoes back (rx=0, echo=3)
        if ! grep -q 'M4 reorder: rx=3 echo=0' build/e2ee-a.log; then
            echo "FAIL: responder did not recover all reorder frames"
            grep 'M4 reorder' build/e2ee-a.log || true
            exit 1
        fi
        if ! grep -q 'M4 reorder: rx=0 echo=3' build/e2ee-b.log; then
            echo "FAIL: initiator did not get all reorder echoes"
            grep 'M4 reorder' build/e2ee-b.log || true
            exit 1
        fi
        echo "e2ee reorder PASS (out-of-order frames recovered via skipped-key store)"
        ;;
    replay)
        # the re-inject must have been posted and rejected as TT_E2EE_REPLAY
        if ! grep -q 'replay: re-inject -> -6 (expect -6)' build/e2ee-b.log; then
            echo "FAIL: replay re-inject was not rejected as TT_E2EE_REPLAY"
            grep 'replay:' build/e2ee-b.log || true
            exit 1
        fi
        echo "e2ee replay PASS (re-injected frame rejected as TT_E2EE_REPLAY)"
        ;;
esac
