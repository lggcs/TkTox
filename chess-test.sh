#!/usr/bin/env bash
# chess-test.sh — chess interop regression (TT_BOT_CHESS): two bot instances
# play a scripted scholar's mate over the real lossless-packet wire using
# toxic's game_chess.c framing (type 160 invite / 161 data, u32 BE game id,
# 4-char algebraic moves). The responder auto-accepts the invite; both sides
# play their colour's moves from the verified sequence; the game must end in
# checkmate with the white side winning.
#
# PASS = both instances rc=0 AND both logged the game start AND the game end
# AND the winner is the white side (we_won == we_white on both peers).
# Usage: bash chess-test.sh
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

rm -f build/chess-a.tox build/chess-a.tox.oq build/chess-a.tox.ses build/chess-a.tox.rsum \
      build/chess-b.tox build/chess-b.tox.oq build/chess-b.tox.ses build/chess-b.tox.rsum
: > build/chess-a.log
: > build/chess-b.log

# Mandatory at-rest encryption: the engine refuses to start without a
# passphrase on a non-tty. Tests run unattended, so supply one via env.
export TT_PASSPHRASE=chess-test-passphrase

# responder first; gate on DHT-online before launching the initiator
env TT_BOT_CHESS=1 "$BIN" --bot build/chess-a.tox >build/chess-a.log 2>&1 &
APID=$!
trap 'kill $APID $BPID 2>/dev/null; wait 2>/dev/null' EXIT
BPID=""

AID=""
for _ in $(seq 1 60); do
    AID=$(grep -o '[a-fA-F0-9]\{76\}' build/chess-a.log | head -1)
    if [ -n "$AID" ] && grep -q 'self connection: 2' build/chess-a.log; then
        break
    fi
    sleep 1
done
if [ -z "$AID" ]; then
    echo "FAIL: responder never came online, see build/chess-a.log"
    exit 1
fi

env TT_BOT_CHESS=1 "$BIN" --bot build/chess-b.tox "$AID" >build/chess-b.log 2>&1 &
BPID=$!

wait $APID; ARC=$?
wait $BPID; BRC=$?
trap - EXIT

echo "responder rc=$ARC (build/chess-a.log)"
echo "initiator rc=$BRC (build/chess-b.log)"
if [ "$ARC" != 0 ] || [ "$BRC" != 0 ]; then
    echo "FAIL"
    exit 1
fi

# both peers must have started and ended the game. The scholar's mate is
# delivered by white, so on each peer the winner must be the white side
# (we_won == we_white). Across the two logs exactly one side is white.
WHITE_COUNT=0
for LOG in build/chess-a.log build/chess-b.log; do
    if ! grep -q 'chess: game started' "$LOG"; then
        echo "FAIL: $LOG never started the game"
        grep 'chess:' "$LOG" || true
        exit 1
    fi
    if ! grep -q 'chess: game over' "$LOG"; then
        echo "FAIL: $LOG never ended the game"
        grep 'chess:' "$LOG" || true
        exit 1
    fi
    # the winner must be the white side (we_won == we_white)
    if ! grep -q 'chess: started=1 ended=1 we_white=1 we_won=1' "$LOG" &&
       ! grep -q 'chess: started=1 ended=1 we_white=0 we_won=0' "$LOG"; then
        echo "FAIL: $LOG did not report the white side winning (we_won != we_white)"
        grep 'chess: started' "$LOG" || true
        exit 1
    fi
    if grep -q 'chess: started=1 ended=1 we_white=1 we_won=1' "$LOG"; then
        WHITE_COUNT=$((WHITE_COUNT + 1))
    fi
done
if [ "$WHITE_COUNT" != 1 ]; then
    echo "FAIL: expected exactly one white side, found $WHITE_COUNT"
    exit 1
fi

echo "chess PASS (invite -> accept -> scholar's mate over lossless packets, white wins)"
