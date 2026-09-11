#ifndef TT_TUNNEL_H
#define TT_TUNNEL_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tox/tox.h>

/* UDP-over-Tox tunnel (lossy channel) + TCP forwarder (lossless channel).
   The engine lives in the tox thread: every tox_* call and all socket I/O
   run there, so no cross-thread queue is involved (the TTEvent queue is for
   UI events, not high-rate datagrams).

   Multi-tunnel: a process can run several tunnels at once (mesh topology).
   Each tunnel has a stable numeric id (monotonic) and is either a host or a
   client:
     host   — relays allowlisted friends' traffic to one server endpoint.
              UDP: each friend gets its own UDP socket to the server so the
              game can tell clients apart by source port.
              TCP: each friend's TCP connection is forwarded to the server.
     client — binds 127.0.0.1:<port>; the local app connects there and its
              traffic is forwarded to the host.

   Lossy (UDP) framing: [200][version=1][port_idx][datagram...]. Type 200 is
   outside the toxcore AV-reserved lossy range (192-199), so the generic lossy
   callback receives it. port_idx selects which port in the shared port set a
   datagram belongs to (host: which server port; client: which local port).
   The port set is a list of disjoint ranges (e.g. a game needing 2300-2310
   and 80); port_idx indexes into the flattened list of ports. Max datagram =
   1373 - 3 = 1370 bytes; larger datagrams are dropped (fragmentation is a
   follow-up milestone).

   Lossless (TCP) framing: [162][version=1][port_idx][connid BE16][opcode][payload...].
   Type 162 is a lossless custom packet (chess uses 160/161). port_idx selects
   the server/local port; connid is client-assigned and multiplexes multiple
   TCP connections per friend.

   Signaling (lossless, type 163): tunnel invite/accept/decline. The host
   invites a friend to a share; the friend accepts (with chosen local ports)
   or declines. */

#define TT_TUNNEL_PACKET_ID 200
#define TT_TUNNEL_VERSION   1
#define TT_TUNNEL_HEADER    3 /* id + version + port_idx */
#define TT_TUNNEL_MAX_DATAGRAM (TOX_MAX_CUSTOM_PACKET_SIZE - TT_TUNNEL_HEADER)

#define TT_TUNNEL_TCP_PACKET_ID 162
#define TT_TUNNEL_TCP_VERSION   1
#define TT_TUNNEL_TCP_HEADER    6 /* id + version + port_idx + connid(2) + opcode */
#define TT_TUNNEL_TCP_MAX_PAYLOAD (TOX_MAX_CUSTOM_PACKET_SIZE - TT_TUNNEL_TCP_HEADER)

/* Signaling channel (lossless, type 163). */
#define TT_TUNNEL_SIG_PACKET_ID 163
#define TT_TUNNEL_SIG_VERSION   1
#define TT_TUNNEL_SIG_HEADER    3 /* id + version + opcode */

/* Signaling opcodes. */
enum {
    TT_TUN_SIG_INVITE  = 1, /* host->client: share a port range */
    TT_TUN_SIG_ACCEPT  = 2, /* client->host: accept, with chosen local ports */
    TT_TUN_SIG_DECLINE = 3, /* client->host: decline */
};

/* TCP channel opcodes. */
enum {
    TT_TCP_OPEN = 1,      /* client->host: open a connection to the server */
    TT_TCP_OPEN_ACK = 2,  /* host->client: connection established */
    TT_TCP_OPEN_FAIL = 3, /* host->client: connect failed */
    TT_TCP_DATA = 4,      /* bidirectional stream bytes */
    TT_TCP_FIN = 5,       /* bidirectional close */
};

#define TT_TUNNEL_MAX_CONNS 64
#define TT_TUNNEL_MAX_RANGES 8  /* max disjoint ranges per protocol */
#define TT_TUNNEL_MAX_PORTS 32  /* max total ports across all ranges (UDP or TCP) */
/* TT_TUNNEL_MAX_TUNNELS is defined in tox_thread.h (the tunnel list lives
   in TTToxThread). */

/* A contiguous range of ports [start, start+count). count==0 = disabled. */
typedef struct TTPortRange {
    uint16_t start;
    uint16_t count;
} TTPortRange;

/* A set of disjoint port ranges (e.g. a game needing 2300-2310 and 80).
   count = number of ranges; total ports across all ranges <= TT_TUNNEL_MAX_PORTS.
   count==0 = disabled. */
typedef struct TTPortRangeList {
    TTPortRange r[TT_TUNNEL_MAX_RANGES];
    unsigned count;
} TTPortRangeList;

/* Number of ports in a range (0 if disabled). */
static inline unsigned tt_port_range_len(const TTPortRange *r) {
    return r ? r->count : 0;
}

/* Total number of ports across all ranges in a list (0 if empty). */
static inline unsigned tt_port_list_len(const TTPortRangeList *l) {
    if (!l) return 0;
    unsigned n = 0;
    for (unsigned i = 0; i < l->count; i++) n += l->r[i].count;
    return n;
}

/* Map a flattened port index (0..tt_port_list_len-1) to the actual port
   number. Returns 0 if idx is out of range. */
static inline uint16_t tt_port_list_port(const TTPortRangeList *l, unsigned idx) {
    if (!l) return 0;
    for (unsigned i = 0; i < l->count; i++) {
        if (idx < l->r[i].count) return (uint16_t)(l->r[i].start + idx);
        idx -= l->r[i].count;
    }
    return 0;
}

/* True if the list is empty (no ports). */
static inline bool tt_port_list_empty(const TTPortRangeList *l) {
    return !l || l->count == 0 || tt_port_list_len(l) == 0;
}

/* Serialize a range list to a comma-separated string like "2300-2310,80"
   (single ports as "80"). Writes at most cap bytes (incl. NUL). Returns the
   number of bytes written (excluding NUL). */
static inline int tt_port_list_to_str(const TTPortRangeList *l, char *out, size_t cap) {
    if (!out || cap == 0) return 0;
    size_t n = 0;
    out[0] = '\0';
    if (!l) return 0;
    for (unsigned i = 0; i < l->count; i++) {
        if (i) {
            if (n + 1 >= cap) break;
            out[n++] = ',';
        }
        int w;
        if (l->r[i].count > 1)
            w = snprintf(out + n, cap - n, "%u-%u", l->r[i].start,
                         (unsigned)l->r[i].start + l->r[i].count - 1);
        else
            w = snprintf(out + n, cap - n, "%u", l->r[i].start);
        if (w < 0 || (size_t)w >= cap - n) break;
        n += (size_t)w;
    }
    return (int)n;
}

/* Parse a comma-separated range list ("2300-2310,80" or "80") into *out.
   Clamps total ports to TT_TUNNEL_MAX_PORTS and ranges to TT_TUNNEL_MAX_RANGES.
   Returns false on invalid input or an empty result. */
static inline bool tt_port_list_parse(const char *s, TTPortRangeList *out) {
    if (!out) return false;
    out->count = 0;
    if (!s || !*s) return false;
    char buf[256];
    snprintf(buf, sizeof buf, "%s", s);
    unsigned total = 0;
    char *save = NULL;
    for (char *tok = strtok_r(buf, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        if (out->count >= TT_TUNNEL_MAX_RANGES) return false;
        char *dash = strchr(tok, '-');
        int lo, hi;
        if (dash) {
            *dash = '\0';
            lo = atoi(tok);
            hi = atoi(dash + 1);
        } else {
            lo = atoi(tok);
            hi = lo;
        }
        if (lo <= 0 || hi < lo || hi > 65535) return false;
        unsigned cnt = (unsigned)(hi - lo + 1);
        if (total + cnt > TT_TUNNEL_MAX_PORTS) cnt = TT_TUNNEL_MAX_PORTS - total;
        if (cnt == 0) return false;
        out->r[out->count].start = (uint16_t)lo;
        out->r[out->count].count = (uint16_t)cnt;
        out->count++;
        total += cnt;
    }
    return out->count > 0;
}

struct TTToxThread;

/* Start a host tunnel: relay allowlisted friends' UDP to server_host:<udp ports>
   and TCP to server_host:<tcp ports> (empty list = disabled). Returns the
   tunnel id, or 0 on failure. */
unsigned tt_tunnel_start_host(struct TTToxThread *t, const char *server_host,
                              const TTPortRangeList *udp, const TTPortRangeList *tcp);
/* Start a client tunnel: bind 127.0.0.1:<udp ports> (UDP) and
   127.0.0.1:<tcp ports> (TCP) and forward to the friend whose public key
   is host_pk_hex (64 hex chars). Returns the tunnel id, or 0 on failure. */
unsigned tt_tunnel_start_client(struct TTToxThread *t, const TTPortRangeList *udp,
                                const TTPortRangeList *tcp, const char *host_pk_hex);
/* Stop and free a specific tunnel by id (idempotent). */
void tt_tunnel_stop(struct TTToxThread *t, unsigned id);
/* Stop and free all tunnels (shutdown). */
void tt_tunnel_stop_all(struct TTToxThread *t);
/* Poll all tunnels. Called from the tox main loop each iteration; a no-op
   when no tunnel is active. */
void tt_tunnel_poll(struct TTToxThread *t);
/* Handle an incoming lossy packet (from the lossy callback). */
void tt_tunnel_rx(struct TTToxThread *t, uint32_t fn,
                  const uint8_t *data, size_t len);
/* Handle an incoming lossless packet (TCP data + signaling). */
void tt_tunnel_rx_tcp(struct TTToxThread *t, uint32_t fn,
                      const uint8_t *data, size_t len);
/* Runtime allowlist (host tunnel): add/remove a friend public key (64 hex).
   These are live — the tunnel does not need to be torn down to change who
   is relayed. Returns false on invalid input / not a host tunnel. */
bool tt_tunnel_allow(struct TTToxThread *t, unsigned id, const char *pk_hex);
bool tt_tunnel_deny(struct TTToxThread *t, unsigned id, const char *pk_hex);
/* Allow a friend in every host tunnel (trust-all test mode). */
void tt_tunnel_allow_all(struct TTToxThread *t, const char *pk_hex);
/* True if any tunnel is active. */
bool tt_tunnel_active(const struct TTToxThread *t);
/* Host: invite a friend to a share. Creates a host tunnel (server_host,
   udp ports, tcp ports) and sends an invite to fn. Returns the tunnel id,
   or 0 on failure. */
unsigned tt_tunnel_share(struct TTToxThread *t, uint32_t fn,
                         const char *server_host, const TTPortRangeList *udp,
                         const TTPortRangeList *tcp);
/* Client: accept a pending invite from fn, binding the local UDP and TCP
   port sets. Sends accept back to the host. Returns the tunnel id, or 0
   on failure. */
unsigned tt_tunnel_accept(struct TTToxThread *t, uint32_t fn,
                          const TTPortRangeList *udp, const TTPortRangeList *tcp);
/* Client: decline a pending invite from fn. */
void tt_tunnel_decline(struct TTToxThread *t, uint32_t fn);

#endif
