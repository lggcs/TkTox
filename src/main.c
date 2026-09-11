#include "tox_thread.h"
#include "headless.h"
#include "ui/ui.h"
#include "tunnel.h"

#include "log.h"
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *profile = NULL;
    const char *peer = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--headless") == 0) {
            profile = (i + 1 < argc) ? argv[i + 1] : "TkTox.tox";
            return headless_main(profile);
        }
        if (strcmp(argv[i], "--bot") == 0) {
            /* --bot <profile> [<peer_toxid>]: responder without peer,
               initiator with one. */
            profile = (i + 1 < argc) ? argv[i + 1] : "TkTox.tox";
            peer = (i + 2 < argc && argv[i + 2][0] != '-') ? argv[i + 2] : NULL;
            return bot_main(profile, peer);
        }
        if (strcmp(argv[i], "--echo") == 0) {
            /* --echo <profile>: long-lived echo responder for manual UI
               testing — never self-exits (unlike the scripted --bot). */
            profile = (i + 1 < argc) ? argv[i + 1] : "TkTox.tox";
            return echo_main(profile);
        }
        if (strcmp(argv[i], "--persist-test") == 0) {
            /* --persist-test <profile> [B]: phase A creates a group and
               exits without leaving; phase B reloads it. */
            profile = (i + 1 < argc) ? argv[i + 1] : "TkTox.tox";
            bool phase_b = (i + 2 < argc && strcmp(argv[i + 2], "B") == 0);
            return persist_test_main(profile, phase_b);
        }
        if (strcmp(argv[i], "--offline-test") == 0) {
            /* --offline-test <profile> <peer_toxid> [B]: phase A queues at
               a dead peer and exits; phase B restores + flushes on reconnect. */
            profile = (i + 1 < argc) ? argv[i + 1] : "TkTox.tox";
            peer = (i + 2 < argc) ? argv[i + 2] : NULL;
            bool phase_b = (i + 3 < argc && strcmp(argv[i + 3], "B") == 0);
            return offline_test_main(profile, peer, phase_b);
        }
        if (strcmp(argv[i], "--flap-test") == 0) {
            /* --flap-test <profile> [<peer_toxid>]: responder without peer,
               initiator with one; two create+invite rounds, rc=3 on drop. */
            profile = (i + 1 < argc) ? argv[i + 1] : "TkTox.tox";
            peer = (i + 2 < argc && argv[i + 2][0] != '-') ? argv[i + 2] : NULL;
            return flap_test_main(profile, peer);
        }
        if (strcmp(argv[i], "--soak-test") == 0) {
            /* --soak-test <profile> [minutes]: hold + log self conn changes. */
            profile = (i + 1 < argc) ? argv[i + 1] : "TkTox.tox";
            int mins = (i + 2 < argc) ? atoi(argv[i + 2]) : 2;
            return soak_test_main(profile, mins);
        }
        if (strcmp(argv[i], "--invrest-test") == 0) {
            /* --invrest-test <profile> <peer_toxid> [B]: phase A creates a
               group, invites the peer, exits without leaving; phase B
               restores the group and re-invites into it (round-21 repro). */
            profile = (i + 1 < argc) ? argv[i + 1] : "TkTox.tox";
            peer = (i + 2 < argc) ? argv[i + 2] : NULL;
            bool phase_b = (i + 3 < argc && strcmp(argv[i + 3], "B") == 0);
            return invrest_test_main(profile, peer, phase_b);
        }
        if (strcmp(argv[i], "--tunnel-host") == 0) {
            /* --tunnel-host <profile> <server_host> <udp_ports> [<tcp_ports>]
               [--tunnel-trust-all] [<friend_toxid>...]:
               relay allowlisted friends' UDP to the local game server, and
               (if TCP ports are given) forward TCP too. Ports are a
               comma-separated list of single numbers or "start-end" ranges
               (e.g. "2300-2310,80"). Trailing ToxIDs seed the allowlist;
               --tunnel-trust-all auto-allowlists any friend that connects
               (opt-in, for testing). */
            profile = (i + 1 < argc) ? argv[i + 1] : "TkTox.tox";
            const char *srv = (i + 2 < argc) ? argv[i + 2] : NULL;
            TTPortRangeList udp = {0}, tcp = {0};
            if (!srv || (i + 3 >= argc) ||
                !tt_port_list_parse(argv[i + 3], &udp)) {
                fprintf(stderr, "usage: --tunnel-host <profile> <server_host> "
                        "<udp_ports> [<tcp_ports>] "
                        "[--tunnel-trust-all] [<friend_toxid>...]\n");
                return 2;
            }
            /* optional TCP server ports: the next arg is a pure number/range
               list (no leading '-') */
            int allow_start = i + 4;
            if (allow_start < argc && argv[allow_start][0] != '-' &&
                (strspn(argv[allow_start], "0123456789-,") == strlen(argv[allow_start]))) {
                tt_port_list_parse(argv[allow_start], &tcp);
                allow_start++;
            }
            /* optional --tunnel-trust-all: auto-allowlist friends on connect */
            bool trust_all = false;
            if (allow_start < argc && strcmp(argv[allow_start], "--tunnel-trust-all") == 0) {
                trust_all = true;
                allow_start++;
            }
            int n_allow = 0;
            for (int k = allow_start; k < argc && argv[k][0] != '-'; k++) n_allow++;
            return tunnel_host_main(profile, srv, &udp, &tcp,
                                    &argv[allow_start], n_allow, trust_all);
        }
        if (strcmp(argv[i], "--tunnel-client") == 0) {
            /* --tunnel-client <profile> <host_toxid> <udp_ports> [<tcp_ports>]:
               add the host, bind 127.0.0.1:<udp_ports> (UDP) and, if given,
               127.0.0.1:<tcp_ports> (TCP). Ports are a comma-separated list
               of single numbers or "start-end" ranges. */
            profile = (i + 1 < argc) ? argv[i + 1] : "TkTox.tox";
            const char *host = (i + 2 < argc) ? argv[i + 2] : NULL;
            TTPortRangeList udp = {0}, tcp = {0};
            if (!host || (i + 3 >= argc) ||
                !tt_port_list_parse(argv[i + 3], &udp)) {
                fprintf(stderr, "usage: --tunnel-client <profile> <host_toxid> "
                        "<udp_ports> [<tcp_ports>]\n");
                return 2;
            }
            if (i + 4 < argc && argv[i + 4][0] != '-' &&
                strspn(argv[i + 4], "0123456789-,") == strlen(argv[i + 4]))
                tt_port_list_parse(argv[i + 4], &tcp);
            return tunnel_client_main(profile, host, &udp, &tcp);
        }
        profile = argv[i];
    }
    if (!profile) profile = "TkTox.tox";

    TTToxThread tt;
    if (!tt_tox_thread_start(&tt, profile, true)) {
        TT_LOG("main", "failed to start tox thread");
        return 1;
    }
    int rc = ui_run(&tt); /* Tk frontend; owns tt_tox_thread_stop */
    return rc;
}