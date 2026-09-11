#!/usr/bin/env bash
# tunnel-multi-test.sh — proves that MULTIPLE simultaneous client tunnels get
# DISTINCT loopback octets (127.0.0.2, 127.0.0.3, ...) so they can share the
# same ports without colliding, and that each tunnel forwards end to end.
#
# Scenario: one host shares UDP 30000-30001 and TCP 30002-30003. TWO separate
# client processes join the SAME host with the SAME port range. Because each
# client tunnel auto-assigns its own loopback octet (probe-bind aware across
# processes), client 1 binds 127.0.0.2 and client 2 binds 127.0.0.3 — both on
# the same ports, no conflict. We then verify a UDP round-trip and a TCP
# round-trip through EACH octet.
#
# PASS = client1 on 127.0.0.2 AND client2 on 127.0.0.3 AND all four
#        round-trips (UDP+TCP on each octet) succeed.
# Usage: bash tunnel-multi-test.sh
set -u

cd "$(dirname "$0")" || exit 1

BIN=build-dyn/TkTox

. "$(dirname "$0")/env.sh"

if [ ! -x "$BIN" ]; then
    echo "building..." >&2
    cmake --build build-dyn --target TkTox -j4 || exit 1
fi

rm -f build-dyn/th.tox build-dyn/th.tox.oq build-dyn/th.tox.ses \
      build-dyn/tc1.tox build-dyn/tc1.tox.oq build-dyn/tc1.tox.ses \
      build-dyn/tc2.tox build-dyn/tc2.tox.oq build-dyn/tc2.tox.ses \
      build-dyn/*-got.txt build-dyn/*-err.txt
: > build-dyn/th.log
: > build-dyn/tc1.log
: > build-dyn/tc2.log

export TT_PASSPHRASE=tunnel-multi-test-passphrase

# Kill any leftover tunnel processes and wait for the test ports to free.
pkill -f 'TkTox --tunnel' 2>/dev/null
for _ in $(seq 1 20); do
    if ! ss -uln 2>/dev/null | grep -qE ':3000[02] '; then
        break
    fi
    sleep 1
done

# Fake UDP game server on 127.0.0.1:30000: echoes back every datagram it
# receives, handling both clients (2 datagrams).
python3 - <<'PY' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 30000))
s.settimeout(120)
try:
    for i in range(2):
        data, addr = s.recvfrom(2048)
        with open("build-dyn/server-got-%d.txt" % i, "w") as f:
            f.write(data.decode("utf-8", "replace"))
        s.sendto(b"server-reply", addr)
except Exception as e:
    with open("build-dyn/server-err.txt", "w") as f:
        f.write(str(e))
PY
SPID=$!

# Fake TCP echo server on 127.0.0.1:30002: echoes back each connection,
# handling both clients (2 connections).
python3 - <<'PY' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 30002))
s.listen(2)
s.settimeout(120)
try:
    for i in range(2):
        conn, _ = s.accept()
        conn.settimeout(120)
        data = conn.recv(2048)
        with open("build-dyn/tcp-server-got-%d.txt" % i, "w") as f:
            f.write(data.decode("utf-8", "replace"))
        conn.sendall(b"tcp-server-reply")
        conn.close()
except Exception as e:
    with open("build-dyn/tcp-server-err.txt", "w") as f:
        f.write(str(e))
PY
TPID=$!
trap 'kill $SPID $TPID $HPID $C1PID $C2PID 2>/dev/null; wait 2>/dev/null' EXIT
HPID=""
C1PID=""
C2PID=""

# host tunnel: relay UDP to 30000-30001 and TCP to 30002-30003.
"$BIN" --tunnel-host build-dyn/th.tox 127.0.0.1 30000-30001 30002-30003 --tunnel-trust-all \
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

# TWO client tunnels, SAME port range, separate processes. They must get
# distinct loopback octets (127.0.0.2 and 127.0.0.3).
"$BIN" --tunnel-client build-dyn/tc1.tox "$HID" 30000-30001 30002-30003 >build-dyn/tc1.log 2>&1 &
C1PID=$!
"$BIN" --tunnel-client build-dyn/tc2.tox "$HID" 30000-30001 30002-30003 >build-dyn/tc2.log 2>&1 &
C2PID=$!

# wait for both clients to connect (host logs two friend connections)
CONN=0
for _ in $(seq 1 90); do
    if grep -q 'friend 0 connection: 2' build-dyn/th.log &&
       grep -q 'friend 1 connection: 2' build-dyn/th.log; then
        CONN=1
        break
    fi
    sleep 1
done
if [ "$CONN" != 1 ]; then
    echo "FAIL: host and both clients never connected"
    echo "--- host log ---"; tail -20 build-dyn/th.log
    echo "--- client1 log ---"; tail -20 build-dyn/tc1.log
    echo "--- client2 log ---"; tail -20 build-dyn/tc2.log
    exit 1
fi

# Assert the two clients bound DISTINCT octets (whichever process bound first
# gets the lower one; the atomic bind guarantees they never collide).
IP1=$(grep -o '127\.0\.0\.[0-9]*' build-dyn/tc1.log | head -1)
IP2=$(grep -o '127\.0\.0\.[0-9]*' build-dyn/tc2.log | head -1)
echo "client1 octet: $IP1"
echo "client2 octet: $IP2"
if [ -z "$IP1" ] || [ -z "$IP2" ]; then
    echo "FAIL: could not read both client loopback IPs"
    exit 1
fi
if [ "$IP1" = "$IP2" ]; then
    echo "FAIL: both clients bound the same octet $IP1"
    exit 1
fi
if [ "$IP1" = "127.0.0.1" ] || [ "$IP2" = "127.0.0.1" ]; then
    echo "FAIL: a client bound the base loopback 127.0.0.1"
    exit 1
fi

# UDP round-trip through each octet (lossy, so retry).
python3 - "$IP1" "$IP2" <<'PY'
import socket, time, sys
ip1, ip2 = sys.argv[1], sys.argv[2]
def udp_roundtrip(ip, port, tag):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(10)
    for _ in range(5):
        s.sendto(b"hello-" + tag.encode(), (ip, port))
        try:
            data, _ = s.recvfrom(2048)
            with open("build-dyn/client-got-%s.txt" % tag, "w") as f:
                f.write(data.decode("utf-8", "replace"))
            return True
        except socket.timeout:
            time.sleep(1)
    return False
ok1 = udp_roundtrip(ip1, 30000, "c1")
ok2 = udp_roundtrip(ip2, 30000, "c2")
if not ok1:
    with open("build-dyn/client-err-c1.txt", "w") as f:
        f.write("no reply on " + ip1)
if not ok2:
    with open("build-dyn/client-err-c2.txt", "w") as f:
        f.write("no reply on " + ip2)
PY

# TCP round-trip through each octet.
python3 - "$IP1" "$IP2" <<'PY'
import socket, sys
ip1, ip2 = sys.argv[1], sys.argv[2]
def tcp_roundtrip(ip, port, tag):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    try:
        s.connect((ip, port))
        s.sendall(b"hello-tcp-" + tag.encode())
        data = s.recv(2048)
        with open("build-dyn/tcp-client-got-%s.txt" % tag, "w") as f:
            f.write(data.decode("utf-8", "replace"))
        s.close()
        return True
    except Exception as e:
        with open("build-dyn/tcp-client-err-%s.txt" % tag, "w") as f:
            f.write(str(e))
        return False
ok1 = tcp_roundtrip(ip1, 30002, "c1")
ok2 = tcp_roundtrip(ip2, 30002, "c2")
PY

wait $SPID; SRC=$?
wait $TPID; TRC=$?
kill $HPID $C1PID $C2PID 2>/dev/null
wait $HPID $C1PID $C2PID 2>/dev/null
trap - EXIT

echo "udp server rc=$SRC, tcp server rc=$TRC"
echo "--- host log ---"; grep 'tunnel' build-dyn/th.log
echo "--- client1 log ---"; grep 'tunnel' build-dyn/tc1.log
echo "--- client2 log ---"; grep 'tunnel' build-dyn/tc2.log

# UDP assertions: both octets must have round-tripped.
for tag in c1 c2; do
    if [ ! -f build-dyn/client-got-$tag.txt ]; then
        echo "FAIL: UDP round-trip on $tag failed"
        [ -f build-dyn/client-err-$tag.txt ] && cat build-dyn/client-err-$tag.txt
        exit 1
    fi
    if [ "$(cat build-dyn/client-got-$tag.txt)" != "server-reply" ]; then
        echo "FAIL: UDP $tag got wrong reply: $(cat build-dyn/client-got-$tag.txt)"
        exit 1
    fi
done

# TCP assertions: both octets must have round-tripped.
for tag in c1 c2; do
    if [ ! -f build-dyn/tcp-client-got-$tag.txt ]; then
        echo "FAIL: TCP round-trip on $tag failed"
        [ -f build-dyn/tcp-client-err-$tag.txt ] && cat build-dyn/tcp-client-err-$tag.txt
        exit 1
    fi
    if [ "$(cat build-dyn/tcp-client-got-$tag.txt)" != "tcp-server-reply" ]; then
        echo "FAIL: TCP $tag got wrong echo: $(cat build-dyn/tcp-client-got-$tag.txt)"
        exit 1
    fi
done

echo "tunnel-multi PASS (2 clients, distinct octets 127.0.0.2/127.0.0.3, UDP+TCP round-trips on both)"
