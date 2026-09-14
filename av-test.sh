#!/usr/bin/env bash
# av-test.sh — focused M-AV2/M-AV4 call regression (TT_BOT_CALL_SOLO):
# audio call -> peer auto-answers -> ACTIVE states both sides -> hangup ->
# FINISHED/ENDED observed on BOTH sides (rx side asserted at exit).
# TT_BOT_CALL_VTEST=1: the call also negotiates video (2500 kbps); the
# initiator pumps synthetic frames, the callee echoes its own back, and
# both sides must receive TT_EV_AV_FRAME events (M-AV4 wire proof).
# Tier B additions:
#   TT_BOT_CALL_PAUSE=1: mid-call pause/resume cycle (state 0 both ends,
#     then the pre-pause states restored; the callee hangs up afterwards).
#   TT_BOT_CALL_DECLINE=1: the peer CANCELs on arrival; the caller must
#     observe FINISHED + ENDED and never an ACTIVE state.
#   TT_BOT_CALL_OFFLINE=1: single instance calls an unreachable friend
#     (valid-checksum ToxID nobody owns); toxav must reject the call
#     (TOXAV_ERR_CALL_FRIEND_NOT_CONNECTED = error 4), no crash.
# Skips the file/group phases entirely. rc=0 both = PASS.
# Usage: bash av-test.sh [TT_BOT_CALL_VTEST=1|TT_BOT_CALL_PAUSE=1|TT_BOT_CALL_DECLINE=1|TT_BOT_CALL_OFFLINE=1]
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

rm -f build/av-a.tox build/av-a.tox.oq build/av-a.tox.ses build/av-a.tox.rsum \
      build/av-b.tox build/av-b.tox.oq build/av-b.tox.ses build/av-b.tox.rsum
: > build/av-a.log
: > build/av-b.log

# Mandatory at-rest encryption: the engine refuses to start without a
# passphrase on a non-tty. Tests run unattended, so supply one via env.
export TT_PASSPHRASE=av-test-passphrase

VTEST_ENV=()
[ -n "${TT_BOT_CALL_VTEST:-}" ] && VTEST_ENV=(TT_BOT_CALL_VTEST=1)
PAUSE_ENV=()
[ -n "${TT_BOT_CALL_PAUSE:-}" ] && PAUSE_ENV=(TT_BOT_CALL_PAUSE=1)
DECLINE_ENV=()
[ -n "${TT_BOT_CALL_DECLINE:-}" ] && DECLINE_ENV=(TT_BOT_CALL_DECLINE=1)
OFFLINE_ENV=()
[ -n "${TT_BOT_CALL_OFFLINE:-}" ] && OFFLINE_ENV=(TT_BOT_CALL_OFFLINE=1)
NEG_MODE=0
[ -n "${TT_BOT_CALL_DECLINE:-}" ] || [ -n "${TT_BOT_CALL_OFFLINE:-}" ] && NEG_MODE=1
if [ "$NEG_MODE" = 0 ]; then
    env TT_BOT_CALL=1 TT_BOT_CALL_SOLO=1 "${VTEST_ENV[@]}" "${PAUSE_ENV[@]}" "$BIN" --bot build/av-a.tox >build/av-a.log 2>&1 &
    APID=$!
    trap 'kill $APID $BPID 2>/dev/null; wait 2>/dev/null' EXIT
    BPID=""

    # gate on the responder being DHT-online before launching the initiator
    AID=""
    for _ in $(seq 1 60); do
        AID=$(grep -o '[a-fA-F0-9]\{76\}' build/av-a.log | head -1)
        if [ -n "$AID" ] && grep -q 'self connection: 2' build/av-a.log; then
            break
        fi
        sleep 1
    done
    if [ -z "$AID" ]; then
        echo "FAIL: responder never came online, see build/av-a.log"
        exit 1
    fi

    env TT_BOT_CALL=1 TT_BOT_CALL_SOLO=1 "${VTEST_ENV[@]}" "${PAUSE_ENV[@]}" "$BIN" --bot build/av-b.tox "$AID" >build/av-b.log 2>&1 &
    BPID=$!

    wait $APID; ARC=$?
    wait $BPID; BRC=$?
    trap - EXIT

    echo "responder rc=$ARC (build/av-a.log)"
    echo "initiator rc=$BRC (build/av-b.log)"
    if [ "$ARC" = 0 ] && [ "$BRC" = 0 ]; then
        echo "PASS"
        exit 0
    fi
    echo "FAIL"
    exit 1
fi

# ---- tier B negative modes (single initiator instance) ----
if [ -n "${TT_BOT_CALL_DECLINE:-}" ]; then
    # decline needs a live peer that refuses the call
    env TT_BOT_CALL=1 TT_BOT_CALL_SOLO=1 TT_BOT_CALL_DECLINE=1 "$BIN" --bot build/av-a.tox >build/av-a.log 2>&1 &
    APID=$!
    trap 'kill $APID $BPID 2>/dev/null; wait 2>/dev/null' EXIT
    BPID=""
    AID=""
    for _ in $(seq 1 60); do
        AID=$(grep -o '[a-fA-F0-9]\{76\}' build/av-a.log | head -1)
        if [ -n "$AID" ] && grep -q 'self connection: 2' build/av-a.log; then
            break
        fi
        sleep 1
    done
    if [ -z "$AID" ]; then
        echo "FAIL: responder never came online, see build/av-a.log"
        exit 1
    fi
    env TT_BOT_CALL=1 TT_BOT_CALL_SOLO=1 TT_BOT_CALL_DECLINE=1 "$BIN" --bot build/av-b.tox "$AID" >build/av-b.log 2>&1 &
    BPID=$!
    wait $APID; ARC=$?
    wait $BPID; BRC=$?
    trap - EXIT
else
    # offline: one initiator-role instance (dummy peer arg, no real add),
    # no live peer at all
    env TT_BOT_CALL=1 TT_BOT_CALL_OFFLINE=1 "$BIN" --bot build/av-a.tox x >build/av-a.log 2>&1 &
    APID=$!
    trap 'kill $APID 2>/dev/null; wait 2>/dev/null' EXIT
    wait $APID; ARC=$?
    trap - EXIT
    BRC=0
    BPID=""
fi

# shared negative-mode verdicts
if [ "$ARC" != 0 ]; then
    echo "FAIL: negative-path instance rc=$ARC"
    exit 1
fi
if [ -n "${TT_BOT_CALL_OFFLINE:-}" ]; then
    if ! grep -q 'call(0, a=32 v=0): 4' build/av-a.log; then
        echo "FAIL: offline call was not rejected with NOT_CONNECTED(4)"
        grep 'call(' build/av-a.log || true
        exit 1
    fi
    echo "offline call rejected with NOT_CONNECTED(4), no crash — PASS"
    exit 0
fi
if ! grep -q 'decline: finished_rx=1 ended_ok=1 active_state=0' build/av-b.log; then
    echo "FAIL: decline caller did not see FINISHED+ENDED without an ACTIVE state"
    grep 'decline' build/av-b.log || true
    exit 1
fi
echo "responder rc=$ARC (build/av-a.log)"
echo "initiator rc=$BRC (build/av-b.log)"
echo "decline PASS (FINISHED + ENDED, no ACTIVE state)"