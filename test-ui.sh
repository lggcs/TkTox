#!/usr/bin/env bash
# test-ui.sh — run the Tk UI with a long-lived echo bot alongside for
# manual testing. The bot runs in --echo mode: it NEVER self-exits
# (the old --bot responder quit after 20s of group idle / 180s total,
# which looked like the UI "going offline" mid-session — round 21).
# Usage: ./test-ui.sh [ui args...]   (e.g. ./test-ui.sh myprofile.tox)
set -u

cd "$(dirname "$0")" || exit 1

BIN=build/TkTox
BOT_PROFILE=build/test-bot.tox
UI_LOG=build/test-ui.log
BOT_LOG=build/test-bot.log

# Shared build/run env: computes the multiarch triplet and sets
# PKG_CONFIG_PATH + LD_LIBRARY_PATH for the vendored .deps tree.
. "$(dirname "$0")/env.sh"

if [ ! -x "$BIN" ]; then
    echo "building..." >&2
    cmake --build build --target TkTox -j4 || exit 1
fi

: > "$BOT_LOG"
# Mandatory at-rest encryption: the engine refuses to start without a
# passphrase on a non-tty. The bot runs unattended, so supply one via env.
export TT_PASSPHRASE=test-ui-bot-passphrase
"$BIN" --echo "$BOT_PROFILE" >"$BOT_LOG" 2>&1 &
BOT=$!
trap 'kill "$BOT" 2>/dev/null; wait "$BOT" 2>/dev/null' EXIT

TOXID=""
for _ in $(seq 1 60); do
    TOXID=$(grep -o '[0-9a-fA-F]\{76\}' "$BOT_LOG" | head -1)
    [ -n "$TOXID" ] && break
    sleep 1
done

echo "=================================================="
if [ -n "$TOXID" ]; then
    echo " bot ToxID (paste into the sidebar search bar):"
    echo "   $TOXID"
else
    echo " warning: bot did not report a ToxID, see $BOT_LOG"
fi
echo " bot pid: $BOT   log: $BOT_LOG (never self-exits; Ctrl-C stops both)"
echo " the bot auto-accepts requests + group invites, echoes messages."
echo " starting UI... (UI log: $UI_LOG)"
echo "=================================================="

"$BIN" "$@" >"$UI_LOG" 2>&1
rc=$?
echo "UI exited (rc=$rc). Last bot activity:"
tail -5 "$BOT_LOG"