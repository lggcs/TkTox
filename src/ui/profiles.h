#ifndef TT_PROFILES_H
#define TT_PROFILES_H

/* Multi-profile management: a standalone Tk startup picker that lists the
   profiles in the current directory and lets the user Open / New / Rename /
   Delete one. Runs BEFORE the tox thread starts (no engine state to tear
   down). Returns the chosen profile path (malloc'd, caller frees) or NULL if
   the user cancelled. On success the caller starts the tox thread with it. */
char *tt_profile_picker(void);

#endif
