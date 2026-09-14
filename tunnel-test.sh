#!/usr/bin/env bash
# tunnel-test.sh — UDP-over-Tox tunnel regression: a fake UDP game server
# and a fake TCP echo server, a host tunnel relaying to both, and a client
# tunnel. A UDP datagram sent to the client's local port must reach the game
# server (and the reply come back); a TCP connection to the client's local
# port must reach the TCP server (and the echo come back). This proves both
# the lossy (UDP) and lossless (TCP) channels end to end.
#
# Both instances start FRESH (like chess-test.sh / Echo Bot): the host comes
# online first, its ToxID is grepped from the log, and the client is launched
# with it. No profile pre-generation, so there is no stale DHT state to make
# the friend request flaky. The host runs with --tunnel-trust-all so the
# client is auto-allowlisted on connect (opt-in test flag; the default
# remains an explicit allowlist).
#
# PASS = UDP round-trip AND TCP round-trip both succeed.
# Usage: bash tunnel-test.sh
set -u

cd "$(dirname "$0")" || exit 1

BIN=build-dyn/TkTox

. "$(dirname "$0")/env.sh"

if [ ! -x "$BIN" ]; then
    echo "building..." >&2
    cmake --build build-dyn --target TkTox -j4 || exit 1
fi

rm -f build-dyn/th.tox build-dyn/th.tox.oq build-dyn/th.tox.ses build-dyn/th.tox.rsum \
      build-dyn/tc.tox build-dyn/tc.tox.oq build-dyn/tc.tox.ses build-dyn/tc.tox.rsum \
      build-dyn/server-got.txt build-dyn/client-got.txt \
      build-dyn/tcp-server-got.txt build-dyn/tcp-client-got.txt
: > build-dyn/th.log
: > build-dyn/tc.log

export TT_PASSPHRASE=tunnel-test-passphrase

# Kill any leftover tunnel processes from a prior interrupted run and wait
# for the test ports to free (consecutive runs otherwise collide on 30010).
pkill -f 'TkTox --tunnel' 2>/dev/null
for _ in $(seq 1 20); do
    if ! ss -uln 2>/dev/null | grep -qE ':3001[02] '; then
        break
    fi
    sleep 1
done

# Fake UDP game server: echoes back any datagram it receives, and records
# the first one. Runs on 127.0.0.1:30010 (the SECOND disjoint range the host
# shares, proving multi-range forwarding).
python3 - <<'PY' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 30010))
s.settimeout(120)
try:
    data, addr = s.recvfrom(2048)
    with open("build-dyn/server-got.txt", "w") as f:
        f.write(data.decode("utf-8", "replace"))
    s.sendto(b"server-reply", addr)
except Exception as e:
    with open("build-dyn/server-err.txt", "w") as f:
        f.write(str(e))
PY
SPID=$!

# Fake TCP echo server: accepts one connection, echoes back what it reads.
# Runs on 127.0.0.1:30012 (the SECOND disjoint TCP range).
python3 - <<'PY' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 30012))
s.listen(1)
s.settimeout(120)
try:
    conn, _ = s.accept()
    conn.settimeout(120)
    data = conn.recv(2048)
    with open("build-dyn/tcp-server-got.txt", "w") as f:
        f.write(data.decode("utf-8", "replace"))
    conn.sendall(b"tcp-server-reply")
    conn.close()
except Exception as e:
    with open("build-dyn/tcp-server-err.txt", "w") as f:
        f.write(str(e))
PY
TPID=$!
trap 'kill $SPID $TPID $HPID $CPID 2>/dev/null; wait 2>/dev/null' EXIT
HPID=""
CPID=""

# host tunnel: relay UDP to 30000-30001,30010 and TCP to 30002-30003,30012
# (two DISJOINT ranges per protocol, like a game needing several scattered
# ports). --tunnel-trust-all auto-allowlists the client when it connects,
# so no pre-seeding is needed.
"$BIN" --tunnel-host build-dyn/th.tox 127.0.0.1 30000-30001,30010 30002-30003,30012 --tunnel-trust-all \
    >build-dyn/th.log 2>&1 &
HPID=$!

HID=""
for _ in $(seq 1 60); do
    HID=$(grep -o '[a-fA-F0-9]\{76\}' build-dyn/th.log | head -1)
    if [ -n "$HID" ] && grep -q 'self connection: 2' build-dyn/th.log; then
        break
    fi
    sleep 1
done
if [ -z "$HID" ]; then
    echo "FAIL: host never came online, see build-dyn/th.log"
    exit 1
fi

# client tunnel: add the host. The client binds the SAME range list as the
# host (so port_idx aligns), but shifts the second disjoint range to free
# local ports (30010->30011, 30012->30013) to avoid colliding with the fake
# servers on this host. Index 2 still maps to server 30010/30012, proving
# the second disjoint range forwards end to end. The client auto-assigns a
# loopback IP (127.0.0.x) so simultaneous tunnels don't collide on ports.
"$BIN" --tunnel-client build-dyn/tc.tox "$HID" 30000-30001,30011 30002-30003,30013 >build-dyn/tc.log 2>&1 &
CPID=$!

# wait for the two to connect (host logs friend connection)
CONN=0
for _ in $(seq 1 90); do
    if grep -q 'host: friend 0 connection: 2' build-dyn/th.log; then
        CONN=1
        break
    fi
    sleep 1
done
if [ "$CONN" != 1 ]; then
    echo "FAIL: host and client never connected"
    echo "--- host log ---"; tail -20 build-dyn/th.log
    echo "--- client log ---"; tail -20 build-dyn/tc.log
    exit 1
fi

# The client auto-assigns a loopback octet (127.0.0.2, .3, ...). Read it from
# the log so the test works even when run back-to-back with the multi-tunnel
# test (which may have left .2/.3 briefly occupied, pushing this client to a
# higher octet).
CIP=$(grep -o '127\.0\.0\.[0-9]*' build-dyn/tc.log | head -1)
if [ -z "$CIP" ]; then
    echo "FAIL: could not read client loopback IP from log"
    exit 1
fi
echo "client loopback: $CIP"

# UDP: send a datagram to the client's local port; it must reach the game
# server. Lossy packets can drop, so retry a few times.
python3 - "$CIP" <<'PY'
import socket, time, sys
ip = sys.argv[1]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(10)
ok = False
for _ in range(5):
    s.sendto(b"hello-tunnel", (ip, 30011))
    try:
        data, _ = s.recvfrom(2048)
        with open("build-dyn/client-got.txt", "w") as f:
            f.write(data.decode("utf-8", "replace"))
        ok = True
        break
    except socket.timeout:
        time.sleep(1)
if not ok:
    with open("build-dyn/client-err.txt", "w") as f:
        f.write("no reply after retries")
PY

# TCP: connect to the client's local port; the echo must come back
python3 - "$CIP" <<'PY'
import socket, sys
ip = sys.argv[1]
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(10)
try:
    s.connect((ip, 30013))
    s.sendall(b"hello-tcp-tunnel")
    data = s.recv(2048)
    with open("build-dyn/tcp-client-got.txt", "w") as f:
        f.write(data.decode("utf-8", "replace"))
    s.close()
except Exception as e:
    with open("build-dyn/tcp-client-err.txt", "w") as f:
        f.write(str(e))
PY

wait $SPID; SRC=$?
wait $TPID; TRC=$?
# stop the tunnel processes before clearing the trap, so they don't leak
# into the next run and collide on the test ports
kill $HPID $CPID 2>/dev/null
wait $HPID $CPID 2>/dev/null
trap - EXIT

echo "udp server rc=$SRC, tcp server rc=$TRC"
echo "--- host log ---"; grep 'tunnel' build-dyn/th.log
echo "--- client log ---"; grep 'tunnel' build-dyn/tc.log

# UDP assertions
if [ ! -f build-dyn/server-got.txt ]; then
    echo "FAIL: game server never received the client datagram"
    [ -f build-dyn/server-err.txt ] && cat build-dyn/server-err.txt
    exit 1
fi
if [ "$(cat build-dyn/server-got.txt)" != "hello-tunnel" ]; then
    echo "FAIL: server got wrong payload: $(cat build-dyn/server-got.txt)"
    exit 1
fi
if [ ! -f build-dyn/client-got.txt ]; then
    echo "FAIL: client never received the server reply"
    [ -f build-dyn/client-err.txt ] && cat build-dyn/client-err.txt
    exit 1
fi
if [ "$(cat build-dyn/client-got.txt)" != "server-reply" ]; then
    echo "FAIL: client got wrong reply: $(cat build-dyn/client-got.txt)"
    exit 1
fi

# TCP assertions
if [ ! -f build-dyn/tcp-server-got.txt ]; then
    echo "FAIL: TCP server never received the client's data"
    [ -f build-dyn/tcp-server-err.txt ] && cat build-dyn/tcp-server-err.txt
    exit 1
fi
if [ "$(cat build-dyn/tcp-server-got.txt)" != "hello-tcp-tunnel" ]; then
    echo "FAIL: TCP server got wrong payload: $(cat build-dyn/tcp-server-got.txt)"
    exit 1
fi
if [ ! -f build-dyn/tcp-client-got.txt ]; then
    echo "FAIL: TCP client never received the server echo"
    [ -f build-dyn/tcp-client-err.txt ] && cat build-dyn/tcp-client-err.txt
    exit 1
fi
if [ "$(cat build-dyn/tcp-client-got.txt)" != "tcp-server-reply" ]; then
    echo "FAIL: TCP client got wrong echo: $(cat build-dyn/tcp-client-got.txt)"
    exit 1
fi

echo "tunnel PASS (UDP lossy + TCP lossless round-trips over Tox)"
