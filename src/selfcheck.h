#ifndef TT_SELFCHECK_H
#define TT_SELFCHECK_H
/* --selfcheck: verify the platform glue and the bundled runtime resources
   (Tcl/Tk script trees, staging DLLs, crypto, tox engine) without a network,
   a profile, or a display. Entry point for validating a Windows build on a
   real Windows host. Returns 0 when every check passes, 1 otherwise. */
int selfcheck_main(void);
#endif
