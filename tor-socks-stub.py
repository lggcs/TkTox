#!/usr/bin/env python3
"""socks5 stub for TkTox Tor-mode verification.

Minimal RFC 1928 SOCKS5 server: no-auth greeting, CONNECT to IPv4/IPv6
targets, then a bidirectional relay to the real destination. Enough to
exercise toxcore's TCP_client.c SOCKS5 handshake and prove every outbound
connection of a proxied engine flows through here.

Usage: python3 tor-socks-stub.py [port]   (default 9050, bind 127.0.0.1)
"""
import selectors
import socket
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9050


def pump(sel):
    for key, _ in sel.select():
        if key.data == "listener":
            c, _ = srv.accept()
            c.setblocking(False)
            sel.register(c, selectors.EVENT_READ, "hs")
            continue
        sock = key.fileobj
        mode = key.data
        try:
            if mode == "hs":
                data = sock.recv(64)
                if len(data) < 3 or data[0] != 5:
                    sock.close(); sel.unregister(sock); continue
                n = data[1]
                if len(data) < 2 + n:
                    continue  # partial greeting; poll again
                if 0 not in data[2:2 + n]:
                    sock.sendall(b"\x05\xff"); sock.close(); sel.unregister(sock); continue
                sock.sendall(b"\x05\x00")
                sel.modify(sock, selectors.EVENT_READ, "req")
            elif mode == "req":
                data = sock.recv(512)
                if len(data) < 7:
                    continue
                if data[0] != 5 or data[1] != 1:
                    sock.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
                    sock.close(); sel.unregister(sock); continue
                atyp = data[3]
                if atyp == 1:
                    addr = socket.inet_ntoa(data[4:8]); porto = int.from_bytes(data[8:10], "big"); hdr = 10
                elif atyp == 4:
                    addr = socket.inet_ntop(socket.AF_INET6, data[4:20]); porto = int.from_bytes(data[20:22], "big"); hdr = 22
                else:
                    sock.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
                    sock.close(); sel.unregister(sock); continue
                try:
                    dst = socket.create_connection((addr, porto), timeout=10)
                except OSError:
                    sock.sendall(b"\x05\x01\x00\x01" + b"\x00" * 6)
                    sock.close(); sel.unregister(sock); continue
                dst.setblocking(False)
                sock.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
                pairs[sock] = dst
                pairs[dst] = sock
                sel.unregister(sock)
                sel.register(sock, selectors.EVENT_READ, dst)
                sel.register(dst, selectors.EVENT_READ, sock)
            else:  # relay: data is the peer socket
                peer = key.data
                data = sock.recv(65536)
                if not data:
                    sel.unregister(sock)
                    if sock in pairs:
                        sel.unregister(pairs[sock]); pairs[sock].close(); del pairs[sock]
                    sock.close()
                    continue
                peer.sendall(data)
        except OSError:
            try: sel.unregister(sock)
            except KeyError: pass
            sock.close()


sel = selectors.DefaultSelector()
pairs = {}
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", PORT))
srv.listen(16)
srv.setblocking(False)
sel.register(srv, selectors.EVENT_READ, "listener")
print(f"socks5 stub on 127.0.0.1:{PORT}", flush=True)
while True:
    pump(sel)