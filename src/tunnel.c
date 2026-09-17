#include "tunnel.h"
#include "tox_thread.h"
#include "session.h"
#include "log.h"
#include "platform.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* ---- state ---- */

#define TT_TUNNEL_ALLOW_MAX 64

/* A host invite that the friend never accepts is dropped after this many
   seconds, so the panel doesn't show a zombie "(pending)" row forever. */
#define TT_TUNNEL_PENDING_TIMEOUT 60

/* One allowlist entry: a friend identity (public key) the host will relay.
   fn is resolved lazily (UINT32_MAX = not yet a friend / unresolved) so the
   allowlist can be populated before the friend is added. */
typedef struct TTTunnelAllow {
    bool used;
    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    uint32_t fn; /* resolved friend number, UINT32_MAX = pending */
} TTTunnelAllow;

/* Host mode: one UDP socket per (allowed friend, port) so the game server
   sees a distinct source port per client. */
typedef struct TTTunnelSock {
    bool used;
    uint32_t fn;
    uint16_t port_idx; /* index into the UDP range */
    int sock;
    struct sockaddr_in srv;
} TTTunnelSock;

/* A TCP connection being forwarded. connid is client-assigned and unique
   per friend; it multiplexes multiple connections over one lossless channel.
   On the host, sock is the connection to the server; on the client, sock is
   the accepted local connection. */
typedef struct TTTunnelConn {
    bool used;
    uint32_t fn;      /* friend number (host side) */
    uint16_t port_idx; /* index into the TCP range */
    uint16_t connid;  /* client-assigned id */
    int sock;         /* -1 = none yet (host: connecting) */
    bool connecting;  /* host: non-blocking connect in progress */
    /* Host: data received from the client while the server connect is still
       in progress. Flushed once the connect completes. */
    uint8_t *pend;
    size_t pend_len, pend_cap;
} TTTunnelConn;

struct TTTunnel {
    bool used;
    unsigned id;          /* stable, monotonic */
    bool host;            /* true = host, false = client */
    bool pending;         /* host: invite sent, awaiting accept;
                             client: invite received, awaiting accept/decline */
    time_t pending_since; /* when `pending` was set (host invite), for the
                             never-accepted timeout; 0 = not pending */
    bool e2ee_active;     /* tunnel E2EE session with peer_fn is live (TT_E2EE
                             on and handshake completed); drives the UI badge */
    uint32_t peer_fn;     /* the friend this tunnel is with (host: invited
                             friend; client: the host). UINT32_MAX = unresolved */
    uint8_t peer_pk[TOX_PUBLIC_KEY_SIZE]; /* friend identity (client: host pk) */

    /* host mode */
    char server_host[256];
    TTPortRangeList udp;    /* UDP server ports (empty = disabled) */
    TTPortRangeList tcp;    /* TCP server ports (empty = disabled) */
    TTTunnelAllow allow[TT_TUNNEL_ALLOW_MAX];
    TTTunnelSock socks[TT_MAX_FRIENDS * TT_TUNNEL_MAX_PORTS];
    TTTunnelConn conns[TT_TUNNEL_MAX_CONNS];

    /* client mode */
    uint8_t local_ip;         /* loopback octet: 127.0.0.<local_ip> (2..254) */
    int listen_sock[TT_TUNNEL_MAX_PORTS];   /* UDP: bound 127.0.0.<local_ip>:<udp ports> */
    int tcp_listen_sock[TT_TUNNEL_MAX_PORTS]; /* TCP: bound 127.0.0.<local_ip>:<tcp ports> */
    TTPortRangeList udp_local;   /* actual bound UDP ports */
    TTPortRangeList tcp_local;   /* actual bound TCP ports */
    struct sockaddr_in peer[TT_TUNNEL_MAX_PORTS]; /* local UDP client per port */
    bool peer_set[TT_TUNNEL_MAX_PORTS];
    uint16_t next_connid;         /* TCP: next client-assigned connid */
};

/* ---- helpers ---- */

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool hex_to_pk(const char *hex, uint8_t pk[TOX_PUBLIC_KEY_SIZE]) {
    if (!hex || strlen(hex) != TOX_PUBLIC_KEY_SIZE * 2) return false;
    for (size_t i = 0; i < TOX_PUBLIC_KEY_SIZE; i++) {
        int hi = hexval(hex[i * 2]);
        int lo = hexval(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        pk[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static bool pk_equal(const uint8_t a[TOX_PUBLIC_KEY_SIZE],
                     const uint8_t b[TOX_PUBLIC_KEY_SIZE]) {
    return memcmp(a, b, TOX_PUBLIC_KEY_SIZE) == 0;
}

static int udp_socket(void) {
    int s = tt_socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    tt_nonblock(s);
    return s;
}

static int tcp_socket(void) {
    int s = tt_socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    tt_nonblock(s);
    return s;
}

/* Resolve the server address (IPv4 literal or hostname) into sockaddr_in. */
static bool resolve_addr(const char *host, uint16_t port,
                         struct sockaddr_in *out) {
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &a.sin_addr) == 1) {
        *out = a;
        return true;
    }
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char p[8];
    snprintf(p, sizeof p, "%u", port);
    if (getaddrinfo(host, p, &hints, &res) != 0 || !res) {
        if (res) freeaddrinfo(res);
        return false;
    }
    *out = *(struct sockaddr_in *)res->ai_addr;
    freeaddrinfo(res);
    return true;
}

/* Bind a UDP socket to 127.0.0.<ip>:<port>. Returns the fd, or -1 on failure. */
static int bind_udp_local(uint8_t ip, uint16_t port) {
    int s = udp_socket();
    if (s < 0) return -1;
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl((INADDR_LOOPBACK & 0xffffff00) | ip);
    a.sin_port = htons(port);
    if (tt_bind(s, (struct sockaddr *)&a, sizeof a) < 0) {
        tt_close(s);
        return -1;
    }
    return s;
}

/* Bind + listen a TCP socket on 127.0.0.<ip>:<port>. Returns the fd, or -1. */
static int bind_tcp_local(uint8_t ip, uint16_t port) {
    int s = tcp_socket();
    if (s < 0) return -1;
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl((INADDR_LOOPBACK & 0xffffff00) | ip);
    a.sin_port = htons(port);
    if (tt_bind(s, (struct sockaddr *)&a, sizeof a) < 0 ||
        tt_listen(s, 16) < 0) {
        tt_close(s);
        return -1;
    }
    return s;
}

/* Atomically claim a free loopback octet (127.0.0.2, .3, ...) for a client
   tunnel by binding ALL of its real UDP+TCP sockets on that octet. The real
   bind is the atomic claim: if another process (or another tunnel in this
   process) already holds any of these ports on an octet, the bind fails with
   EADDRINUSE and we close what we bound and try the next octet. This avoids
   the TOCTOU race of a separate probe-then-bind. On success tn->local_ip is
   set and all sockets are bound; returns true. On failure all sockets are
   closed and returns false. */
static bool bind_client_local(TTToxThread *t, struct TTTunnel *tn) {
    unsigned nu = tt_port_list_len(&tn->udp_local);
    unsigned nt = tt_port_list_len(&tn->tcp_local);
    for (uint8_t ip = 2; ip < 255; ip++) {
        bool used = false;
        for (int i = 0; i < TT_TUNNEL_MAX_TUNNELS; i++) {
            struct TTTunnel *o = t->tunnels[i];
            if (o && !o->host && o->local_ip == ip) { used = true; break; }
        }
        if (used) continue;
        /* try to bind all UDP ports on this octet */
        unsigned bound = 0;
        bool ok = true;
        for (unsigned i = 0; i < nu; i++) {
            int s = bind_udp_local(ip, tt_port_list_port(&tn->udp_local, i));
            if (s < 0) { ok = false; break; }
            tn->listen_sock[i] = s;
            bound++;
        }
        if (!ok) {
            for (unsigned i = 0; i < bound; i++) tt_close(tn->listen_sock[i]);
            continue;
        }
        /* try to bind all TCP ports on this octet */
        unsigned tbound = 0;
        for (unsigned i = 0; i < nt; i++) {
            int s = bind_tcp_local(ip, tt_port_list_port(&tn->tcp_local, i));
            if (s < 0) { ok = false; break; }
            tn->tcp_listen_sock[i] = s;
            tbound++;
        }
        if (!ok) {
            for (unsigned i = 0; i < tbound; i++) tt_close(tn->tcp_listen_sock[i]);
            for (unsigned i = 0; i < nu; i++) tt_close(tn->listen_sock[i]);
            continue;
        }
        tn->local_ip = ip;
        return true;
    }
    return false;
}

/* ---- tunnel list management ---- */

static struct TTTunnel *tunnel_find(TTToxThread *t, unsigned id) {
    for (int i = 0; i < TT_TUNNEL_MAX_TUNNELS; i++) {
        struct TTTunnel *tn = t->tunnels[i];
        if (tn && tn->id == id) return tn;
    }
    return NULL;
}

/* Find a tunnel of the given role whose peer is fn. */
static struct TTTunnel *tunnel_by_peer(TTToxThread *t, uint32_t fn, bool host) {
    for (int i = 0; i < TT_TUNNEL_MAX_TUNNELS; i++) {
        struct TTTunnel *tn = t->tunnels[i];
        if (tn && tn->host == host && tn->peer_fn == fn) return tn;
    }
    return NULL;
}

static struct TTTunnel *tunnel_alloc(TTToxThread *t, bool host) {
    for (int i = 0; i < TT_TUNNEL_MAX_TUNNELS; i++) {
        if (t->tunnels[i]) continue;
        struct TTTunnel *tn = calloc(1, sizeof *tn);
        if (!tn) return NULL;
        tn->used = true;
        tn->host = host;
        tn->id = ++t->tunnel_seq;
        if (t->tunnel_seq == 0) t->tunnel_seq = 1;
        tn->peer_fn = UINT32_MAX;
        for (int j = 0; j < TT_TUNNEL_MAX_PORTS; j++) {
            tn->listen_sock[j] = -1;
            tn->tcp_listen_sock[j] = -1;
        }
        for (int j = 0; j < TT_MAX_FRIENDS * TT_TUNNEL_MAX_PORTS; j++)
            tn->socks[j].sock = -1;
        for (int j = 0; j < TT_TUNNEL_MAX_CONNS; j++) tn->conns[j].sock = -1;
        t->tunnels[i] = tn;
        return tn;
    }
    return NULL;
}

static void tunnel_free(TTToxThread *t, struct TTTunnel *tn) {
    if (!tn) return;
    if (tn->host) {
        for (int i = 0; i < TT_MAX_FRIENDS * TT_TUNNEL_MAX_PORTS; i++)
            if (tn->socks[i].used && tn->socks[i].sock >= 0)
                tt_close(tn->socks[i].sock);
        for (int i = 0; i < TT_TUNNEL_MAX_CONNS; i++)
            if (tn->conns[i].used && tn->conns[i].sock >= 0)
                tt_close(tn->conns[i].sock);
    } else {
        for (int i = 0; i < TT_TUNNEL_MAX_PORTS; i++) {
            if (tn->listen_sock[i] >= 0) tt_close(tn->listen_sock[i]);
            if (tn->tcp_listen_sock[i] >= 0) tt_close(tn->tcp_listen_sock[i]);
        }
    }
    for (int i = 0; i < TT_TUNNEL_MAX_TUNNELS; i++)
        if (t->tunnels[i] == tn) t->tunnels[i] = NULL;
    free(tn);
}

/* Resolve a client tunnel's peer friend number from its public key. */
static void tunnel_resolve(TTToxThread *t, struct TTTunnel *tn) {
    if (tn->peer_fn != UINT32_MAX) return;
    Tox_Err_Friend_By_Public_Key err;
    uint32_t fn = tox_friend_by_public_key(t->tox, tn->peer_pk, &err);
    if (err == TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK) {
        tn->peer_fn = fn;
        TT_LOG("tunnel", "client: host is friend %u", fn);
    }
}

/* ---- signaling (invite/accept/decline) ---- */

static void sig_send(TTToxThread *t, uint32_t fn, uint8_t opcode,
                     const uint8_t *payload, size_t plen) {
    /* payload cap sized for the largest signal (INVITE: 200-byte host +
       NUL + two counts + 2 * TT_TUNNEL_MAX_RANGES * 4 range bytes = 269);
       the old 256 cap both overflowed sig_invite's buffer and would have
       silently dropped worst-case invites */
    uint8_t pkt[TT_TUNNEL_SIG_HEADER + 270];
    if (plen > sizeof pkt - TT_TUNNEL_SIG_HEADER) return;
    pkt[0] = TT_TUNNEL_SIG_PACKET_ID;
    pkt[1] = TT_TUNNEL_SIG_VERSION;
    pkt[2] = opcode;
    if (plen) memcpy(pkt + TT_TUNNEL_SIG_HEADER, payload, plen);
    Tox_Err_Friend_Custom_Packet err;
    if (!tox_friend_send_lossless_packet(t->tox, fn, pkt,
                                         TT_TUNNEL_SIG_HEADER + plen, &err))
        TT_LOG("tunnel", "sig send(%u): err %d", fn, (int)err);
}

/* Host -> client: offer a share. Payload:
   server_host\0 + udp_count BE16 + udp_ranges (each: start BE16 + count BE16)
   + tcp_count BE16 + tcp_ranges (each: start BE16 + count BE16) */
static void sig_invite(TTToxThread *t, uint32_t fn, struct TTTunnel *tn) {
    /* worst case: 201 host + 1 + 1 + 8*4 + 1 + 8*4 = 269 bytes */
    uint8_t payload[270];
    size_t hl = strlen(tn->server_host);
    if (hl > 200) hl = 200;
    memcpy(payload, tn->server_host, hl);
    payload[hl] = '\0';
    size_t p = hl + 1;
    payload[p++] = (uint8_t)(tn->udp.count >> 8);
    payload[p++] = (uint8_t)(tn->udp.count & 0xff);
    for (unsigned i = 0; i < tn->udp.count; i++) {
        payload[p++] = (uint8_t)(tn->udp.r[i].start >> 8);
        payload[p++] = (uint8_t)(tn->udp.r[i].start & 0xff);
        payload[p++] = (uint8_t)(tn->udp.r[i].count >> 8);
        payload[p++] = (uint8_t)(tn->udp.r[i].count & 0xff);
    }
    payload[p++] = (uint8_t)(tn->tcp.count >> 8);
    payload[p++] = (uint8_t)(tn->tcp.count & 0xff);
    for (unsigned i = 0; i < tn->tcp.count; i++) {
        payload[p++] = (uint8_t)(tn->tcp.r[i].start >> 8);
        payload[p++] = (uint8_t)(tn->tcp.r[i].start & 0xff);
        payload[p++] = (uint8_t)(tn->tcp.r[i].count >> 8);
        payload[p++] = (uint8_t)(tn->tcp.r[i].count & 0xff);
    }
    sig_send(t, fn, TT_TUN_SIG_INVITE, payload, p);
}

/* Client -> host: accept. Payload: udp_count BE16 + udp_ranges (each:
   start BE16 + count BE16) + tcp_count BE16 + tcp_ranges (each: start BE16
   + count BE16). */
static void sig_accept(TTToxThread *t, uint32_t fn, const TTPortRangeList *udp,
                       const TTPortRangeList *tcp) {
    uint8_t payload[2 + TT_TUNNEL_MAX_RANGES * 4 + 2 + TT_TUNNEL_MAX_RANGES * 4];
    size_t p = 0;
    payload[p++] = (uint8_t)(udp->count >> 8);
    payload[p++] = (uint8_t)(udp->count & 0xff);
    for (unsigned i = 0; i < udp->count; i++) {
        payload[p++] = (uint8_t)(udp->r[i].start >> 8);
        payload[p++] = (uint8_t)(udp->r[i].start & 0xff);
        payload[p++] = (uint8_t)(udp->r[i].count >> 8);
        payload[p++] = (uint8_t)(udp->r[i].count & 0xff);
    }
    payload[p++] = (uint8_t)(tcp->count >> 8);
    payload[p++] = (uint8_t)(tcp->count & 0xff);
    for (unsigned i = 0; i < tcp->count; i++) {
        payload[p++] = (uint8_t)(tcp->r[i].start >> 8);
        payload[p++] = (uint8_t)(tcp->r[i].start & 0xff);
        payload[p++] = (uint8_t)(tcp->r[i].count >> 8);
        payload[p++] = (uint8_t)(tcp->r[i].count & 0xff);
    }
    sig_send(t, fn, TT_TUN_SIG_ACCEPT, payload, p);
}

/* Handle an inbound signaling packet (type 163). */
static void tunnel_sig_rx(TTToxThread *t, uint32_t fn,
                          const uint8_t *data, size_t len) {
    if (len < TT_TUNNEL_SIG_HEADER) return;
    if (data[0] != TT_TUNNEL_SIG_PACKET_ID || data[1] != TT_TUNNEL_SIG_VERSION) return;
    uint8_t opcode = data[2];
    const uint8_t *payload = data + TT_TUNNEL_SIG_HEADER;
    size_t plen = len - TT_TUNNEL_SIG_HEADER;

    switch (opcode) {
    case TT_TUN_SIG_INVITE: {
        /* host invited us to a share. Parse the endpoint + port ranges. */
        if (plen < 3) return;
        size_t hl = strnlen((const char *)payload, plen - 2);
        if (hl == plen - 2) return; /* no NUL terminator */
        char host[256];
        size_t n = hl < sizeof host - 1 ? hl : sizeof host - 1;
        memcpy(host, payload, n);
        host[n] = '\0';
        size_t p = hl + 1;
        TTPortRangeList udp = {0}, tcp = {0};
        udp.count = (uint16_t)((payload[p] << 8) | payload[p + 1]); p += 2;
        if (udp.count > TT_TUNNEL_MAX_RANGES) udp.count = TT_TUNNEL_MAX_RANGES;
        for (unsigned i = 0; i < udp.count; i++) {
            if (p + 4 > plen) return;
            udp.r[i].start = (uint16_t)((payload[p] << 8) | payload[p + 1]);
            udp.r[i].count = (uint16_t)((payload[p + 2] << 8) | payload[p + 3]);
            p += 4;
        }
        if (p + 2 > plen) return;
        tcp.count = (uint16_t)((payload[p] << 8) | payload[p + 1]); p += 2;
        if (tcp.count > TT_TUNNEL_MAX_RANGES) tcp.count = TT_TUNNEL_MAX_RANGES;
        for (unsigned i = 0; i < tcp.count; i++) {
            if (p + 4 > plen) return;
            tcp.r[i].start = (uint16_t)((payload[p] << 8) | payload[p + 1]);
            tcp.r[i].count = (uint16_t)((payload[p + 2] << 8) | payload[p + 3]);
            p += 4;
        }
        /* ignore a second invite from the same friend while one is pending */
        if (tunnel_by_peer(t, fn, false)) return;
        struct TTTunnel *tn = tunnel_alloc(t, false);
        if (!tn) return;
        tn->pending = true;
        tn->peer_fn = fn;
        snprintf(tn->server_host, sizeof tn->server_host, "%s", host);
        tn->udp = udp;
        tn->tcp = tcp;
        char spec[256], spec2[256];
        tt_port_list_to_str(&udp, spec, sizeof spec);
        tt_port_list_to_str(&tcp, spec2, sizeof spec2);
        TTEvent *ev = tt_event_new(TT_EV_TUNNEL_INVITE);
        if (ev) {
            ev->friend_number = fn;
            char *s = malloc(strlen(host) + strlen(spec) + strlen(spec2) + 3);
            if (s) {
                sprintf(s, "%s\n%s\n%s", host, spec, spec2);
                ev->str = s;
                ev->str_len = strlen(s);
            }
            tt_queue_push(&t->out, ev);
        }
        TT_LOG("tunnel", "client: invite from friend %u to share %s udp %s tcp %s",
               fn, host, spec, spec2);
        break;
    }
    case TT_TUN_SIG_ACCEPT: {
        /* client accepted our invite. Find the pending host tunnel for fn. */
        if (plen < 8) return;
        struct TTTunnel *tn = tunnel_by_peer(t, fn, true);
        if (!tn || !tn->pending) return;
        tn->pending = false;
        TTEvent *ev = tt_event_new(TT_EV_TUNNEL_STATE);
        if (ev) {
            ev->friend_number = fn;
            ev->ival = (int)tn->id;
            ev->ival2 = 1; /* live */
            tt_queue_push(&t->out, ev);
        }
        TT_LOG("tunnel", "host: friend %u accepted tunnel %u", fn, tn->id);
        break;
    }
    case TT_TUN_SIG_DECLINE: {
        struct TTTunnel *tn = tunnel_by_peer(t, fn, true);
        if (!tn || !tn->pending) return;
        TTEvent *ev = tt_event_new(TT_EV_TUNNEL_STATE);
        if (ev) {
            ev->friend_number = fn;
            ev->ival = (int)tn->id;
            ev->ival2 = 2; /* declined -> remove */
            tt_queue_push(&t->out, ev);
        }
        tunnel_free(t, tn);
        break;
    }
    default:
        break;
    }
}

/* ---- public API ---- */

unsigned tt_tunnel_start_host(TTToxThread *t, const char *server_host,
                              const TTPortRangeList *udp, const TTPortRangeList *tcp) {
    struct TTTunnel *tn = tunnel_alloc(t, true);
    if (!tn) return 0;
    tn->pending = false;
    snprintf(tn->server_host, sizeof tn->server_host, "%s", server_host);
    tn->udp = udp ? *udp : (TTPortRangeList){0};
    tn->tcp = tcp ? *tcp : (TTPortRangeList){0};
    char us[256], ts[256];
    tt_port_list_to_str(&tn->udp, us, sizeof us);
    tt_port_list_to_str(&tn->tcp, ts, sizeof ts);
    TT_LOG("tunnel", "host mode: UDP->%s:%s TCP->%s:%s", server_host, us,
           server_host, ts);
    return tn->id;
}

unsigned tt_tunnel_start_client(TTToxThread *t, const TTPortRangeList *udp,
                                const TTPortRangeList *tcp, const char *host_pk_hex) {
    struct TTTunnel *tn = tunnel_alloc(t, false);
    if (!tn) return 0;
    tn->pending = false;
    tn->next_connid = 1;
    if (!hex_to_pk(host_pk_hex, tn->peer_pk)) {
        TT_LOG("tunnel", "client: bad host public key");
        tunnel_free(t, tn);
        return 0;
    }
    tn->udp_local = udp ? *udp : (TTPortRangeList){0};
    tn->tcp_local = tcp ? *tcp : (TTPortRangeList){0};

    /* atomically claim a free loopback IP and bind all local sockets */
    if (!bind_client_local(t, tn)) {
        TT_LOG("tunnel", "client: no free loopback IP for ports");
        tunnel_free(t, tn);
        return 0;
    }

    char us[256], ts[256];
    tt_port_list_to_str(&tn->udp_local, us, sizeof us);
    tt_port_list_to_str(&tn->tcp_local, ts, sizeof ts);
    TT_LOG("tunnel", "client mode: UDP 127.0.0.%u:%s TCP 127.0.0.%u:%s",
           tn->local_ip, us, tn->local_ip, ts);
    return tn->id;
}

void tt_tunnel_stop(TTToxThread *t, unsigned id) {
    struct TTTunnel *tn = tunnel_find(t, id);
    if (!tn) return;
    TTEvent *ev = tt_event_new(TT_EV_TUNNEL_REMOVE);
    if (ev) {
        ev->ival = (int)id;
        tt_queue_push(&t->out, ev);
    }
    tunnel_free(t, tn);
    TT_LOG("tunnel", "stopped tunnel %u", id);
}

void tt_tunnel_stop_all(TTToxThread *t) {
    for (int i = 0; i < TT_TUNNEL_MAX_TUNNELS; i++)
        if (t->tunnels[i]) tunnel_free(t, t->tunnels[i]);
}

bool tt_tunnel_active(const TTToxThread *t) {
    for (int i = 0; i < TT_TUNNEL_MAX_TUNNELS; i++)
        if (t->tunnels[i] && t->tunnels[i]->used) return true;
    return false;
}

bool tt_tunnel_allow(TTToxThread *t, unsigned id, const char *pk_hex) {
    struct TTTunnel *tn = tunnel_find(t, id);
    if (!tn || !tn->host) return false;
    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    if (!hex_to_pk(pk_hex, pk)) return false;
    for (int i = 0; i < TT_TUNNEL_ALLOW_MAX; i++) {
        TTTunnelAllow *a = &tn->allow[i];
        if (a->used && pk_equal(a->pk, pk)) return true; /* already allowed */
    }
    for (int i = 0; i < TT_TUNNEL_ALLOW_MAX; i++) {
        TTTunnelAllow *a = &tn->allow[i];
        if (!a->used) {
            a->used = true;
            memcpy(a->pk, pk, TOX_PUBLIC_KEY_SIZE);
            a->fn = UINT32_MAX;
            /* resolve the friend number now if possible */
            Tox_Err_Friend_By_Public_Key err;
            uint32_t fn = tox_friend_by_public_key(t->tox, pk, &err);
            if (err == TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK) a->fn = fn;
            TT_LOG("tunnel", "host: allowlisted %s", pk_hex);
            return true;
        }
    }
    TT_LOG("tunnel", "host: allowlist full");
    return false;
}

void tt_tunnel_allow_all(TTToxThread *t, const char *pk_hex) {
    for (int i = 0; i < TT_TUNNEL_MAX_TUNNELS; i++) {
        struct TTTunnel *tn = t->tunnels[i];
        if (tn && tn->host) tt_tunnel_allow(t, tn->id, pk_hex);
    }
}

bool tt_tunnel_deny(TTToxThread *t, unsigned id, const char *pk_hex) {
    struct TTTunnel *tn = tunnel_find(t, id);
    if (!tn || !tn->host) return false;
    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    if (!hex_to_pk(pk_hex, pk)) return false;
    for (int i = 0; i < TT_TUNNEL_ALLOW_MAX; i++) {
        TTTunnelAllow *a = &tn->allow[i];
        if (!a->used || !pk_equal(a->pk, pk)) continue;
        if (a->fn != UINT32_MAX && a->fn < TT_MAX_FRIENDS) {
            TTTunnelSock *s = &tn->socks[a->fn];
            if (s->used && s->sock >= 0) tt_close(s->sock);
            s->used = false;
            s->sock = -1;
        }
        a->used = false;
        TT_LOG("tunnel", "host: denied %s", pk_hex);
        return true;
    }
    return false;
}

/* ---- UDP forwarding ---- */

/* Host: ensure a UDP socket to the server exists for friend fn + port_idx. */
static int host_sock(struct TTTunnel *tn, uint32_t fn, uint16_t port_idx) {
    if (fn >= TT_MAX_FRIENDS || port_idx >= tt_port_list_len(&tn->udp)) return -1;
    TTTunnelSock *s = &tn->socks[fn * TT_TUNNEL_MAX_PORTS + port_idx];
    if (s->used) return s->sock;
    int fd = udp_socket();
    if (fd < 0) return -1;
    struct sockaddr_in srv;
    if (!resolve_addr(tn->server_host, tt_port_list_port(&tn->udp, port_idx), &srv)) {
        tt_close(fd);
        return -1;
    }
    s->used = true;
    s->fn = fn;
    s->port_idx = port_idx;
    s->sock = fd;
    s->srv = srv;
    return fd;
}

/* Forward a lossy packet from friend fn to the server (host mode). */
static void host_forward(struct TTTunnel *tn, uint32_t fn, uint16_t port_idx,
                         const uint8_t *data, size_t len) {
    if (fn >= TT_MAX_FRIENDS) return;
    /* only allowlisted friends are relayed */
    bool allowed = false;
    for (int i = 0; i < TT_TUNNEL_ALLOW_MAX; i++)
        if (tn->allow[i].used && tn->allow[i].fn == fn) { allowed = true; break; }
    if (!allowed) return;
    int fd = host_sock(tn, fn, port_idx);
    if (fd < 0) return;
    tt_sendto(fd, data, len, 0,
           (struct sockaddr *)&tn->socks[fn * TT_TUNNEL_MAX_PORTS + port_idx].srv,
           sizeof tn->socks[fn * TT_TUNNEL_MAX_PORTS + port_idx].srv);
}

/* Send a datagram to friend fn over a lossy packet, tagged with port_idx. */
static void tunnel_send(TTToxThread *t, uint32_t fn, uint16_t port_idx,
                        const uint8_t *data, size_t len) {
    if (len > TT_TUNNEL_MAX_DATAGRAM) {
        TT_LOG("tunnel", "drop: datagram %zu > %d bytes", len,
               TT_TUNNEL_MAX_DATAGRAM);
        return;
    }
    /* Tunnel E2EE channel (TT_E2EE on): encrypt the WHOLE tunnel packet
       (200 header + payload) as a DATA frame and ride it over a lossy
       type-201 packet, so the receiver's tt_tunnel_rx parses the 200 header
       from the decrypted plaintext (symmetric with the raw path). A
       not-yet-active session drops the datagram (lossy semantics). Drain
       any pending re-key carrier first so the datagram fits a plain DATA
       frame. */
    if (t->tun_e2ee) {
        if (len > TT_TUNNEL_E2EE_MAX_DATAGRAM) {
            TT_LOG("tunnel", "drop: e2ee datagram %zu > %d bytes", len,
                   TT_TUNNEL_E2EE_MAX_DATAGRAM);
            return;
        }
        TTSession *s = &t->tun_e2ee[fn];
        if (!s->active) return; /* lossy: drop until handshake completes */
        uint8_t pkt[TT_TUNNEL_HEADER + TT_TUNNEL_E2EE_MAX_DATAGRAM];
        pkt[0] = TT_TUNNEL_PACKET_ID;
        pkt[1] = TT_TUNNEL_VERSION;
        pkt[2] = (uint8_t)port_idx;
        memcpy(pkt + TT_TUNNEL_HEADER, data, len);
        uint8_t frame[TT_FRAME_MAX];
        /* drain a pending re-key carrier (empty DATA) so the datagram fits */
        if (tt_session_rekey_pending(s)) {
            int rn = tt_session_send_lossy(s, NULL, NULL, 0, frame, sizeof frame);
            if (rn > 0) tt_tunnel_e2ee_send(t, fn, 1, frame, (size_t)rn);
        }
        int n = tt_session_send_lossy(s, NULL, pkt, TT_TUNNEL_HEADER + len,
                                      frame, sizeof frame);
        if (n > 0) tt_tunnel_e2ee_send(t, fn, 1, frame, (size_t)n);
        return;
    }
    uint8_t pkt[TT_TUNNEL_HEADER + TT_TUNNEL_MAX_DATAGRAM];
    pkt[0] = TT_TUNNEL_PACKET_ID;
    pkt[1] = TT_TUNNEL_VERSION;
    pkt[2] = (uint8_t)port_idx;
    memcpy(pkt + TT_TUNNEL_HEADER, data, len);
    Tox_Err_Friend_Custom_Packet err;
    if (!tox_friend_send_lossy_packet(t->tox, fn, pkt, TT_TUNNEL_HEADER + len, &err))
        TT_LOG("tunnel", "lossy send(%u): err %d", fn, (int)err);
}

/* ---- TCP forwarding ---- */

/* Find a conn slot by (fn, connid). */
static TTTunnelConn *conn_find(struct TTTunnel *tn, uint32_t fn, uint16_t connid) {
    for (int i = 0; i < TT_TUNNEL_MAX_CONNS; i++) {
        TTTunnelConn *c = &tn->conns[i];
        if (c->used && c->fn == fn && c->connid == connid) return c;
    }
    return NULL;
}

/* Allocate a free conn slot, or NULL if full. */
static TTTunnelConn *conn_alloc(struct TTTunnel *tn) {
    for (int i = 0; i < TT_TUNNEL_MAX_CONNS; i++) {
        TTTunnelConn *c = &tn->conns[i];
        if (!c->used) {
            c->used = true;
            c->sock = -1;
            c->connecting = false;
            return c;
        }
    }
    return NULL;
}

static void conn_free(struct TTTunnelConn *c) {
    if (c->sock >= 0) tt_close(c->sock);
    free(c->pend);
    c->pend = NULL;
    c->pend_len = c->pend_cap = 0;
    c->used = false;
    c->sock = -1;
    c->connecting = false;
}

/* Append data to a conn's pending buffer (host, while connecting).
   Capped: an authenticated peer can otherwise buffer ~4MB per conn by
   sending TCP_DATA while connect() stalls (64 conns per tunnel). */
#define TT_TUNNEL_PEND_MAX 131072u
static void conn_pend(struct TTTunnelConn *c, const uint8_t *data, size_t len) {
    if (c->pend_len + len > TT_TUNNEL_PEND_MAX) return;
    if (c->pend_len + len > c->pend_cap) {
        size_t ncap = c->pend_cap ? c->pend_cap * 2 : 4096;
        while (ncap < c->pend_len + len) ncap *= 2;
        uint8_t *np = realloc(c->pend, ncap);
        if (!np) return;
        c->pend = np;
        c->pend_cap = ncap;
    }
    memcpy(c->pend + c->pend_len, data, len);
    c->pend_len += len;
}

/* Send a lossless TCP frame to friend fn. */
static void tcp_send(TTToxThread *t, uint32_t fn, uint16_t port_idx,
                     uint16_t connid, uint8_t opcode,
                     const uint8_t *payload, size_t plen) {
    if (plen > TT_TUNNEL_TCP_MAX_PAYLOAD) {
        TT_LOG("tunnel", "tcp: payload %zu > %d bytes", plen,
               TT_TUNNEL_TCP_MAX_PAYLOAD);
        return;
    }
    /* Tunnel E2EE channel (TT_E2EE on): encrypt the whole TCP frame (header
       + payload) as a DATA frame and ride it over a lossless type-165 packet.
       A not-yet-active session drops the frame (lossy semantics — no stash). */
    if (t->tun_e2ee) {
        if (plen > TT_TUNNEL_E2EE_TCP_MAX_PAYLOAD) {
            TT_LOG("tunnel", "tcp: e2ee payload %zu > %d bytes", plen,
                   TT_TUNNEL_E2EE_TCP_MAX_PAYLOAD);
            return;
        }
        TTSession *s = &t->tun_e2ee[fn];
        if (!s->active) return; /* drop until handshake completes */
        uint8_t frame[TT_FRAME_MAX];
        /* drain a pending re-key carrier (empty DATA) so the frame fits */
        if (tt_session_rekey_pending(s)) {
            int rn = tt_session_send_lossy(s, NULL, NULL, 0, frame, sizeof frame);
            if (rn > 0) tt_tunnel_e2ee_send(t, fn, 2, frame, (size_t)rn);
        }
        /* the TCP frame (header + payload) is the plaintext */
        uint8_t tcp[TT_TUNNEL_TCP_HEADER + TT_TUNNEL_E2EE_TCP_MAX_PAYLOAD];
        tcp[0] = TT_TUNNEL_TCP_PACKET_ID;
        tcp[1] = TT_TUNNEL_TCP_VERSION;
        tcp[2] = (uint8_t)port_idx;
        tcp[3] = (uint8_t)(connid >> 8);
        tcp[4] = (uint8_t)(connid & 0xff);
        tcp[5] = opcode;
        if (plen) memcpy(tcp + TT_TUNNEL_TCP_HEADER, payload, plen);
        int n = tt_session_send_lossy(s, NULL, tcp, TT_TUNNEL_TCP_HEADER + plen,
                                      frame, sizeof frame);
        if (n > 0) tt_tunnel_e2ee_send(t, fn, 2, frame, (size_t)n);
        return;
    }
    uint8_t pkt[TT_TUNNEL_TCP_HEADER + TT_TUNNEL_TCP_MAX_PAYLOAD];
    pkt[0] = TT_TUNNEL_TCP_PACKET_ID;
    pkt[1] = TT_TUNNEL_TCP_VERSION;
    pkt[2] = (uint8_t)port_idx;
    pkt[3] = (uint8_t)(connid >> 8);
    pkt[4] = (uint8_t)(connid & 0xff);
    pkt[5] = opcode;
    if (plen) memcpy(pkt + TT_TUNNEL_TCP_HEADER, payload, plen);
    Tox_Err_Friend_Custom_Packet err;
    if (!tox_friend_send_lossless_packet(t->tox, fn, pkt,
                                         TT_TUNNEL_TCP_HEADER + plen, &err))
        TT_LOG("tunnel", "tcp send(%u): err %d", fn, (int)err);
}

/* Host: open a TCP connection to the server for a new conn. */
static void host_open_conn(TTToxThread *t, struct TTTunnel *tn, uint32_t fn,
                           uint16_t port_idx, uint16_t connid) {
    if (conn_find(tn, fn, connid)) return; /* already open */
    TTTunnelConn *c = conn_alloc(tn);
    if (!c) {
        tcp_send(t, fn, port_idx, connid, TT_TCP_OPEN_FAIL, NULL, 0);
        return;
    }
    c->fn = fn;
    c->port_idx = port_idx;
    c->connid = connid;
    c->sock = tcp_socket();
    if (c->sock < 0) {
        conn_free(c);
        tcp_send(t, fn, port_idx, connid, TT_TCP_OPEN_FAIL, NULL, 0);
        return;
    }
    struct sockaddr_in srv;
    if (port_idx >= tt_port_list_len(&tn->tcp) ||
        !resolve_addr(tn->server_host, tt_port_list_port(&tn->tcp, port_idx), &srv)) {
        conn_free(c);
        tcp_send(t, fn, port_idx, connid, TT_TCP_OPEN_FAIL, NULL, 0);
        return;
    }
    int rc = tt_connect(c->sock, (struct sockaddr *)&srv, sizeof srv);
    if (rc == 0) {
        tcp_send(t, fn, port_idx, connid, TT_TCP_OPEN_ACK, NULL, 0);
    } else if (errno == EINPROGRESS) {
        c->connecting = true; /* poll() will finish the connect */
    } else {
        conn_free(c);
        tcp_send(t, fn, port_idx, connid, TT_TCP_OPEN_FAIL, NULL, 0);
    }
}

/* Read available bytes from a conn socket and forward them. Returns false
   if the socket hit EOF/error (caller should close the conn). */
static bool conn_drain(TTToxThread *t, TTTunnelConn *c) {
    uint8_t buf[TT_TUNNEL_TCP_MAX_PAYLOAD];
    for (;;) {
        ssize_t n = tt_recv(c->sock, buf, sizeof buf, 0);
        if (n > 0) {
            tcp_send(t, c->fn, c->port_idx, c->connid, TT_TCP_DATA, buf, (size_t)n);
            continue;
        }
        if (n == 0) return false; /* EOF */
        if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
        return false; /* error */
    }
}

/* ---- poll ---- */

static void tunnel_poll_host(TTToxThread *t, struct TTTunnel *tn) {
    /* UDP: drain each friend's socket to the server */
    for (int i = 0; i < TT_MAX_FRIENDS * TT_TUNNEL_MAX_PORTS; i++) {
        TTTunnelSock *s = &tn->socks[i];
        if (!s->used || s->sock < 0) continue;
        uint8_t buf[TT_TUNNEL_MAX_DATAGRAM];
        ssize_t n = tt_recv(s->sock, buf, sizeof buf, 0);
        if (n > 0) tunnel_send(t, s->fn, s->port_idx, buf, (size_t)n);
    }
    /* TCP: finish pending connects, then drain each conn */
    for (int i = 0; i < TT_TUNNEL_MAX_CONNS; i++) {
        TTTunnelConn *c = &tn->conns[i];
        if (!c->used) continue;
        if (c->connecting) {
            int err = 0;
            socklen_t elen = sizeof err;
            if (getsockopt(c->sock, SOL_SOCKET, SO_ERROR, (char *)&err,
                           &elen) == 0) {
                if (err == 0) {
                    c->connecting = false;
                    tcp_send(t, c->fn, c->port_idx, c->connid, TT_TCP_OPEN_ACK, NULL, 0);
                    /* flush any data buffered while connecting */
                    if (c->pend_len) {
                        tt_send(c->sock, c->pend, c->pend_len, 0);
                        c->pend_len = 0;
                    }
                } else {
                    conn_free(c);
                    tcp_send(t, c->fn, c->port_idx, c->connid, TT_TCP_OPEN_FAIL, NULL, 0);
                    continue;
                }
            }
        }
        if (c->used && c->sock >= 0 && !conn_drain(t, c)) {
            tcp_send(t, c->fn, c->port_idx, c->connid, TT_TCP_FIN, NULL, 0);
            conn_free(c);
        }
    }
}

static void tunnel_poll_client(TTToxThread *t, struct TTTunnel *tn) {
    /* UDP: drain each local client socket to the host */
    if (tn->peer_fn != UINT32_MAX) {
        unsigned n = tt_port_list_len(&tn->udp_local);
        for (unsigned i = 0; i < n; i++) {
            if (tn->listen_sock[i] < 0) continue;
            uint8_t buf[TT_TUNNEL_MAX_DATAGRAM];
            struct sockaddr_in from;
            socklen_t flen = sizeof from;
            ssize_t r = tt_recvfrom(tn->listen_sock[i], buf, sizeof buf, 0,
                                 (struct sockaddr *)&from, &flen);
            if (r > 0) {
                if (!tn->peer_set[i]) {
                    tn->peer[i] = from;
                    tn->peer_set[i] = true;
                }
                tunnel_send(t, tn->peer_fn, (uint16_t)i, buf, (size_t)r);
            }
        }
    }
    /* TCP: accept new local connections on each port, drain existing conns */
    unsigned tn_ = tt_port_list_len(&tn->tcp_local);
    for (unsigned i = 0; i < tn_; i++) {
        if (tn->tcp_listen_sock[i] < 0) continue;
        for (;;) {
            int fd = tt_accept(tn->tcp_listen_sock[i], NULL, NULL);
            if (fd < 0) break;
            tt_nonblock(fd);
            TTTunnelConn *c = conn_alloc(tn);
            if (!c) { tt_close(fd); break; }
            c->fn = tn->peer_fn;
            c->port_idx = (uint16_t)i;
            c->connid = tn->next_connid++;
            if (tn->next_connid == 0) tn->next_connid = 1;
            c->sock = fd;
            tcp_send(t, tn->peer_fn, c->port_idx, c->connid, TT_TCP_OPEN, NULL, 0);
            TT_LOG("tunnel", "client: TCP conn %u on port %u accepted",
                   c->connid, (unsigned)i);
        }
    }
    for (int i = 0; i < TT_TUNNEL_MAX_CONNS; i++) {
        TTTunnelConn *c = &tn->conns[i];
        if (!c->used || c->sock < 0) continue;
        if (!conn_drain(t, c)) {
            tcp_send(t, c->fn, c->port_idx, c->connid, TT_TCP_FIN, NULL, 0);
            conn_free(c);
        }
    }
}

void tt_tunnel_poll(TTToxThread *t) {
    for (int i = 0; i < TT_TUNNEL_MAX_TUNNELS; i++) {
        struct TTTunnel *tn = t->tunnels[i];
        if (!tn || !tn->used) continue;
        /* A pending host invite that the friend never accepted times out. */
        if (tn->pending && tn->host && tn->pending_since &&
            time(NULL) - tn->pending_since >= TT_TUNNEL_PENDING_TIMEOUT) {
            TT_LOG("tunnel", "host: friend %u never accepted tunnel %u — dropping",
                   tn->peer_fn, tn->id);
            TTEvent *ev = tt_event_new(TT_EV_TUNNEL_ERROR);
            if (ev) {
                ev->ival = (int)tn->id;
                ev->str = strdup("The friend never accepted the tunnel invite.");
                tt_queue_push(&t->out, ev);
            }
            tunnel_free(t, tn);
            continue;
        }
        if (tn->pending) continue;
        tunnel_resolve(t, tn);
        /* Tunnel E2EE channel (TT_E2EE on): once the peer is resolved, kick
           the tunnel handshake if it hasn't started yet. Tunnels are
           ephemeral, so a fresh session per tunnel. */
        if (t->tun_e2ee && tn->peer_fn != UINT32_MAX) {
            TTSession *ts = &t->tun_e2ee[tn->peer_fn];
            if (!ts->active && !ts->init_pending && !ts->reply_due)
                tt_tunnel_e2ee_start(t, tn->peer_fn);
            /* surface the live E2EE state to the UI (badge) on change */
            bool live = ts->active;
            if (live != tn->e2ee_active) {
                tn->e2ee_active = live;
                TTEvent *ev = tt_event_new(TT_EV_TUNNEL_E2EE);
                if (ev) {
                    ev->ival = (int)tn->id;
                    ev->ival2 = live ? 1 : 0;
                    tt_queue_push(&t->out, ev);
                }
            }
        }
        if (tn->host) tunnel_poll_host(t, tn);
        else tunnel_poll_client(t, tn);
    }
}

/* ---- rx ---- */

void tt_tunnel_rx(TTToxThread *t, uint32_t fn, const uint8_t *data, size_t len) {
    if (len < TT_TUNNEL_HEADER) return;
    if (data[0] != TT_TUNNEL_PACKET_ID || data[1] != TT_TUNNEL_VERSION) return;
    uint16_t port_idx = data[2];
    const uint8_t *payload = data + TT_TUNNEL_HEADER;
    size_t plen = len - TT_TUNNEL_HEADER;
    for (int i = 0; i < TT_TUNNEL_MAX_TUNNELS; i++) {
        struct TTTunnel *tn = t->tunnels[i];
        if (!tn || !tn->used || tn->pending) continue;
        if (tn->host) {
            host_forward(tn, fn, port_idx, payload, plen);
        } else if (fn == tn->peer_fn && port_idx < tt_port_list_len(&tn->udp_local) &&
                   tn->peer_set[port_idx] && tn->listen_sock[port_idx] >= 0) {
            tt_sendto(tn->listen_sock[port_idx], payload, plen, 0,
                   (struct sockaddr *)&tn->peer[port_idx], sizeof tn->peer[port_idx]);
        }
    }
}

static void tunnel_tcp_rx_host(TTToxThread *t, struct TTTunnel *tn, uint32_t fn,
                               uint16_t port_idx, uint16_t connid, uint8_t opcode,
                               const uint8_t *payload, size_t plen) {
    switch (opcode) {
    case TT_TCP_OPEN:
        host_open_conn(t, tn, fn, port_idx, connid);
        break;
    case TT_TCP_DATA: {
        TTTunnelConn *c = conn_find(tn, fn, connid);
        if (!c) break;
        if (c->connecting) {
            conn_pend(c, payload, plen); /* buffer until connect done */
        } else if (c->sock >= 0) {
            tt_send(c->sock, payload, plen, 0);
        }
        break;
    }
    case TT_TCP_FIN: {
        TTTunnelConn *c = conn_find(tn, fn, connid);
        if (c) conn_free(c);
        break;
    }
    default:
        break;
    }
}

static void tunnel_tcp_rx_client(struct TTTunnel *tn, uint32_t fn,
                                 uint16_t port_idx, uint16_t connid, uint8_t opcode,
                                 const uint8_t *payload, size_t plen) {
    if (port_idx >= tt_port_list_len(&tn->tcp_local)) return;
    switch (opcode) {
    case TT_TCP_OPEN_ACK:
    case TT_TCP_OPEN_FAIL: {
        TTTunnelConn *c = conn_find(tn, fn, connid);
        if (c && opcode == TT_TCP_OPEN_FAIL) conn_free(c);
        break;
    }
    case TT_TCP_DATA: {
        TTTunnelConn *c = conn_find(tn, fn, connid);
        if (c && c->sock >= 0)
            tt_send(c->sock, payload, plen, 0);
        break;
    }
    case TT_TCP_FIN: {
        TTTunnelConn *c = conn_find(tn, fn, connid);
        if (c) conn_free(c);
        break;
    }
    default:
        break;
    }
}

void tt_tunnel_rx_tcp(TTToxThread *t, uint32_t fn, const uint8_t *data, size_t len) {
    if (len < 1) return;
    if (data[0] == TT_TUNNEL_SIG_PACKET_ID) {
        tunnel_sig_rx(t, fn, data, len);
        return;
    }
    if (data[0] != TT_TUNNEL_TCP_PACKET_ID) return;
    if (len < TT_TUNNEL_TCP_HEADER) return;
    if (data[1] != TT_TUNNEL_TCP_VERSION) return;
    uint16_t port_idx = data[2];
    uint16_t connid = (uint16_t)((data[3] << 8) | data[4]);
    uint8_t opcode = data[5];
    const uint8_t *payload = data + TT_TUNNEL_TCP_HEADER;
    size_t plen = len - TT_TUNNEL_TCP_HEADER;
    for (int i = 0; i < TT_TUNNEL_MAX_TUNNELS; i++) {
        struct TTTunnel *tn = t->tunnels[i];
        if (!tn || !tn->used || tn->pending) continue;
        if (tn->host) {
            tunnel_tcp_rx_host(t, tn, fn, port_idx, connid, opcode, payload, plen);
        } else if (fn == tn->peer_fn) {
            tunnel_tcp_rx_client(tn, fn, port_idx, connid, opcode, payload, plen);
        }
    }
}

/* ---- share / accept / decline (UI entry points) ---- */

unsigned tt_tunnel_share(TTToxThread *t, uint32_t fn, const char *server_host,
                         const TTPortRangeList *udp, const TTPortRangeList *tcp) {
    if (fn >= TT_MAX_FRIENDS) return 0;
    struct TTTunnel *tn = tunnel_alloc(t, true);
    if (!tn) return 0;
    tn->pending = true;
    tn->pending_since = time(NULL);
    tn->peer_fn = fn;
    snprintf(tn->server_host, sizeof tn->server_host, "%s", server_host);
    tn->udp = udp ? *udp : (TTPortRangeList){0};
    tn->tcp = tcp ? *tcp : (TTPortRangeList){0};
    /* allowlist the invited friend */
    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    if (tox_friend_get_public_key(t->tox, fn, pk, NULL)) {
        for (int i = 0; i < TT_TUNNEL_ALLOW_MAX; i++) {
            TTTunnelAllow *a = &tn->allow[i];
            if (!a->used) {
                a->used = true;
                memcpy(a->pk, pk, TOX_PUBLIC_KEY_SIZE);
                a->fn = fn;
                break;
            }
        }
    }
    sig_invite(t, fn, tn);
    TTEvent *ev = tt_event_new(TT_EV_TUNNEL_ADD);
    if (ev) {
        ev->friend_number = fn;
        ev->ival = (int)tn->id;
        ev->ival2 = 1; /* host */
        char ep[300];
        char us[256], ts[256];
        tt_port_list_to_str(&tn->udp, us, sizeof us);
        tt_port_list_to_str(&tn->tcp, ts, sizeof ts);
        snprintf(ep, sizeof ep, "%s udp %s tcp %s", server_host, us, ts);
        ev->str = strdup(ep);
        tt_queue_push(&t->out, ev);
    }
    char us[256], ts[256];
    tt_port_list_to_str(&tn->udp, us, sizeof us);
    tt_port_list_to_str(&tn->tcp, ts, sizeof ts);
    TT_LOG("tunnel", "host: invited friend %u to share %s udp %s tcp %s",
           fn, server_host, us, ts);
    return tn->id;
}

unsigned tt_tunnel_accept(TTToxThread *t, uint32_t fn, const TTPortRangeList *udp,
                          const TTPortRangeList *tcp) {
    struct TTTunnel *tn = tunnel_by_peer(t, fn, false);
    if (!tn || !tn->pending) return 0;
    tn->next_connid = 1;
    tn->udp_local = udp ? *udp : (TTPortRangeList){0};
    tn->tcp_local = tcp ? *tcp : (TTPortRangeList){0};

    /* atomically claim a free loopback IP and bind all local sockets */
    if (!bind_client_local(t, tn)) {
        TT_LOG("tunnel", "client: no free loopback IP for ports");
        TTEvent *ev = tt_event_new(TT_EV_TUNNEL_ERROR);
        if (ev) {
            ev->ival = (int)tn->id;
            ev->str = strdup("Could not bind local ports for the tunnel "
                             "(no free loopback IP / ports).");
            tt_queue_push(&t->out, ev);
        }
        tunnel_free(t, tn);
        return 0;
    }

    tn->pending = false;
    sig_accept(t, fn, &tn->udp_local, &tn->tcp_local);
    TTEvent *ev = tt_event_new(TT_EV_TUNNEL_ADD);
    if (ev) {
        ev->friend_number = fn;
        ev->ival = (int)tn->id;
        ev->ival2 = 0; /* client */
        char ep[300];
        char us[256], ts[256];
        tt_port_list_to_str(&tn->udp_local, us, sizeof us);
        tt_port_list_to_str(&tn->tcp_local, ts, sizeof ts);
        snprintf(ep, sizeof ep, "127.0.0.%u udp %s tcp %s", tn->local_ip, us, ts);
        ev->str = strdup(ep);
        tt_queue_push(&t->out, ev);
    }
    char us[256], ts[256];
    tt_port_list_to_str(&tn->udp_local, us, sizeof us);
    tt_port_list_to_str(&tn->tcp_local, ts, sizeof ts);
    TT_LOG("tunnel", "client: accepted share from friend %u on 127.0.0.%u:%s tcp %s",
           fn, tn->local_ip, us, ts);
    return tn->id;
}

void tt_tunnel_decline(TTToxThread *t, uint32_t fn) {
    struct TTTunnel *tn = tunnel_by_peer(t, fn, false);
    if (!tn || !tn->pending) return;
    sig_send(t, fn, TT_TUN_SIG_DECLINE, NULL, 0);
    tunnel_free(t, tn);
    TT_LOG("tunnel", "client: declined share from friend %u", fn);
}
