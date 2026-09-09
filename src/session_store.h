/* E2EE session persistence (v2): serialize established TTSession state to
   "<profile>.ses" so forward secrecy survives restarts. The sidecar is
   encrypted with a SEPARATE at-rest key derived from the same passphrase
   but a distinct random salt (embedded in the toxencryptsave blob), so a
   leaked profile key cannot decrypt the session keys and vice versa.

   Only ACTIVE sessions are persisted. Pending handshake scratch (eph_a2/a3,
   init_seal, reply_cache, ...) is transient and stale on restart — the
   correct recovery is a fresh handshake, so it is deliberately NOT stored.
   The full M4 ratchet + re-key state IS stored so an established session
   continues folding correctly across a clean restart. */
#ifndef TT_SESSION_STORE_H
#define TT_SESSION_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "session.h"

struct Tox_Pass_Key; /* the SESSION at-rest key (distinct salt), not the profile key */

/* Restore persisted sessions from "<profile>.ses" into e2ee[TT_MAX_FRIENDS]
   (all other entries stay inactive). session_key is the session at-rest
   key. A missing, malformed, or undecryptable file is fine (no sessions
   restored; a plaintext file is accepted for migration). */
void tt_session_store_load(TTSession *e2ee, const char *profile_path,
                           struct Tox_Pass_Key *session_key);

/* Persist every active session atomically (temp + rename), encrypted with
   session_key. When no session is active the sidecar is removed. */
void tt_session_store_save(const TTSession *e2ee, const char *profile_path,
                           struct Tox_Pass_Key *session_key);

#endif
