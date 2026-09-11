#ifndef TT_HEADLESS_H
#define TT_HEADLESS_H
#include "tunnel.h"
/* headless.c entry points: --headless test mode, --bot two-instance mode,
   --persist-test group-persistence probe, --offline-test faux offline
   messaging probe, --flap-test invite-to-restored-group repro,
   --soak-test long-lived connectivity watch, and --invrest-test
   invite-into-RESTORED-group repro (the round-21 user trigger). */
int headless_main(const char *profile);
int bot_main(const char *profile, const char *peer_toxid);
int persist_test_main(const char *profile, bool phase_b);
int offline_test_main(const char *profile, const char *peer_toxid, bool phase_b);
int flap_test_main(const char *profile, const char *peer_toxid);
int soak_test_main(const char *profile, int minutes);
int invrest_test_main(const char *profile, const char *peer_toxid, bool phase_b);
int echo_main(const char *profile);
/* UDP-over-Tox tunnel (headless). Host relays allowlisted friends' UDP to a
   local server; client binds local UDP ports and forwards to the host.
   udp/tcp are port-range lists (empty = disabled); tcp adds a lossless TCP
   forwarder for SSH/RDP/Minecraft alongside the UDP channel. */
int tunnel_host_main(const char *profile, const char *server_host,
                     const TTPortRangeList *udp, const TTPortRangeList *tcp,
                     char **allow_toxids, int n_allow, bool trust_all);
int tunnel_client_main(const char *profile, const char *host_toxid,
                       const TTPortRangeList *udp, const TTPortRangeList *tcp);

#endif