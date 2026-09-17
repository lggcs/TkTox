#ifndef TT_TUNNEL_H
#define TT_TUNNEL_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tox/tox.h>

#include "crypto/crypto.h" /* TT_FRAME_HEAD_MAX, TT_MAC16 (E2EE frame budget) */

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

/* Tunnel E2EE channel (TT_E2EE on): the tunnel's UDP datagrams and TCP
   payloads ride the PQDR ratchet as E2EE frames, wrapped in these custom
   packet types so the receiver routes them to the tunnel session decryptor
   (distinct from the raw 200/162 types used when E2EE is off). The E2EE
   frame (INIT/REPLY/DATA) is the packet payload after the routing header.
   Handshake (INIT/REPLY) rides lossless type 164; UDP data rides lossy
   type 201; TCP data rides lossless type 165. */
#define TT_TUNNEL_E2EE_SIG_PACKET_ID 164
#define TT_TUNNEL_E2EE_TCP_PACKET_ID 165
#define TT_TUNNEL_E2EE_UDP_PACKET_ID 201
#define TT_TUNNEL_E2EE_VERSION 1
/* Tunnel-E2EE wire budget. An E2EE frame rides a custom packet behind a
   2-byte routing header (packet id + version), so the FRAME must fit in
   TOX_MAX_CUSTOM_PACKET_SIZE - 2. This budget is one byte tighter than
   TT_FRAME_MAX, which is sized for the chat path (tox messages, 1372): a
   frame at TT_FRAME_MAX does not fit a custom packet, so tt_tunnel_e2ee_send
   silently discarded it and the stream stalled (see conn_drain). Sizing the
   payload caps from this budget keeps every tunnel frame sendable. */
#define TT_TUNNEL_E2EE_ROUTING_HDR 2 /* packet id + version */
#define TT_TUNNEL_E2EE_FRAME_MAX \
    (TOX_MAX_CUSTOM_PACKET_SIZE - TT_TUNNEL_E2EE_ROUTING_HDR)
/* Max DATA plaintext per E2EE frame, using the largest frame head
   (24-byte nonce; the GCM path is smaller, hence conservative). */
#define TT_TUNNEL_E2EE_DATA_MAX \
    (TT_TUNNEL_E2EE_FRAME_MAX - TT_FRAME_HEAD_MAX - TT_MAC16) /* 1318 */

/* Max UDP datagram payload that fits an E2EE DATA frame: the plaintext is
   the WHOLE tunnel packet (200 header + payload), so the payload is capped
   at the frame data budget minus the 3-byte 200 header. The decrypt buffer
   on the receive side (TT_FRAME_DATA_MAX) must hold the full plaintext. */
#define TT_TUNNEL_E2EE_MAX_DATAGRAM \
    (TT_TUNNEL_E2EE_DATA_MAX - TT_TUNNEL_HEADER)
/* Max TCP payload that fits an E2EE DATA frame: the plaintext is the WHOLE
   TCP frame (162 header + payload), so the payload is capped at the frame
   data budget minus the 6-byte 162 header. The decrypt buffer on the
   receive side (TT_FRAME_DATA_MAX) must hold the full plaintext. */
#define TT_TUNNEL_E2EE_TCP_MAX_PAYLOAD \
    (TT_TUNNEL_E2EE_DATA_MAX - TT_TUNNEL_TCP_HEADER)

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
    TT_TCP_ACK = 6,       /* receiver->sender, 2-byte BE credit: accepted
                             that many DATA frames (flow control; see
                             TT_TUNNEL_TCP_WINDOW) */
};

/* Outgoing TT_TCP_DATA frames a sender may have unacknowledged at once.
   The peer returns credit — a 2-byte BE count of the frames it accepted —
   so at most this many frames sit in toxcore's send queue per connection.

   Without a bound, a fast local read (a large HTTP response) outruns the
   link, toxcore's congestion control trips, and tox_friend_send_lossless_
   packet returns SENDQ — the frame is never buffered and TCP over the
   tunnel has no retransmit, so the stream stalls.

   Credit is returned per frame accepted but SENT BATCHED (see
   TT_TUNNEL_ACK_BATCH): one ACK per data frame would itself saturate the
   return link, and a dropped ACK is unrecoverable — the sender would wait
   for credit forever. */
#define TT_TUNNEL_TCP_WINDOW 16u
/* Frames a receiver may accept before returning credit. Batching keeps the
   ACK channel ~1 frame per this many data frames. */
#define TT_TUNNEL_ACK_BATCH 4u

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

/* ---- tunnel E2EE channel (TT_E2EE on) ----
   A SEPARATE per-friend PQDR session for tunnel datagrams (see
   tox_thread.c). The engine lives in tox_thread.c; tunnel.c calls these to
   encrypt/decrypt datagrams and to kick the handshake. When E2EE is off,
   the tunnel falls back to the raw 200/162 types (plaintext over toxcore's
   transport crypto). */

/* Send one tunnel E2EE frame over a custom packet. kind: 0 = handshake
   (lossless 164), 1 = UDP data (lossy 201), 2 = TCP data (lossless 165).
   Returns 0 when the frame was handed to toxcore, TOX_ERR_FRIEND_CUSTOM_
   PACKET_* when it was not, or -1 for an oversize frame. A lossless caller
   that tracks data must treat SENDQ as backpressure and retry: toxcore drops
   such a packet outright, and TCP over the tunnel cannot retransmit it. */
int tt_tunnel_e2ee_send(struct TTToxThread *t, uint32_t fn, int kind,
                        const uint8_t *frame, size_t len);
/* Start (or restart) the tunnel E2EE session with fn as initiator. */
void tt_tunnel_e2ee_start(struct TTToxThread *t, uint32_t fn);
/* Engine tick: INIT retransmits for every pending tunnel session. */
void tt_tunnel_e2ee_tick(struct TTToxThread *t);
/* Feed one received tunnel E2EE frame. `lossy` marks a datagram (type 201):
   such a frame is dropped on a decode failure instead of being treated as a
   chain desync, since a stale/reordered datagram is the far likelier cause.
   Returns the plaintext length (>0 = DATA to forward), 0 = handshake/control
   frame consumed, or a negative TTE2EEStatus. */
int tt_tunnel_e2ee_rx(struct TTToxThread *t, uint32_t fn,
                      const uint8_t *frame, size_t len,
                      uint8_t *pt, size_t pt_cap, bool lossy);

#endif
