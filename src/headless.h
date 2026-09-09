#ifndef TT_HEADLESS_H
#define TT_HEADLESS_H
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

#endif