#ifndef TT_UI_H
#define TT_UI_H
#include "../tox_thread.h"

/* Run the Tk frontend over the tox thread (Tk 8.6, interp embedded from C,
   no Tcl scripts). Returns the process exit code. */
int ui_run(TTToxThread *tt);

#endif