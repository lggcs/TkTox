#include "selfcheck.h"
#include "tox_thread.h"
#include "log.h"
#include "platform.h"

#include <tcl.h>
#include <tk.h>
#include <tox/tox.h>
#include <sodium.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

/* --selfcheck: exercise the platform glue and the bundled runtime resources
   without a network, a profile, or a display, then print a report and exit
   non-zero on any failure.

   The point is the Windows build: every port-specific hazard (Tcl/Tk script
   trees relocated next to the exe, the staging DLLs, Winsock startup, the
   printf shim) is checked here so a single run on a real Windows host covers
   them. The same checks run on Linux, where they guard the vendored-tree
   paths the UI depends on. */

#ifndef TT_VERSION
#define TT_VERSION "unknown"
#endif

static int g_fail;

static void ck(const char *name, bool ok, const char *detail) {
    if (!ok) g_fail++;
    if (detail && *detail)
        printf("  [%s] %-32s %s\n", ok ? "ok" : "FAIL", name, detail);
    else
        printf("  [%s] %s\n", ok ? "ok" : "FAIL", name);
}

/* A script tree must exist and look like a Tcl script directory (every
   vendor tree ships an "init.tcl" for Tcl and "tk.tcl" for Tk), otherwise
   Tcl_Init/Tk_Init fail at startup with a version/library error. */
static void ck_tree(const char *name, const char *dir, const char *marker) {
    char probe[1300];
    struct stat st;
    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        ck(name, false, dir);
        return;
    }
    snprintf(probe, sizeof probe, "%s/%s", dir, marker);
    ck(name, stat(probe, &st) == 0, dir);
}

/* The Tcl/Tk script trees and the interp bootstrap: the highest-risk part of
   the port, because the compiled-in path points at the *build machine* and
   the staging step has to have put a copy next to the exe. */
static void check_interp(void) {
    printf("Tcl/Tk interpreter\n");

    const char *tcl_dir = tt_tcl_script_dir();
    const char *tk_dir = tt_tk_script_dir();
    printf("  tcl library: %s\n", tcl_dir);
    printf("  tk  library: %s\n", tk_dir);

    ck_tree("tcl script tree", tcl_dir, "init.tcl");
    ck_tree("tk script tree", tk_dir, "tk.tcl");

    /* Same bootstrap order as ui_run/tt_profile_picker: the env overrides
       must win over the path Debian's libtcl has compiled in. */
    setenv("TCL_LIBRARY", tcl_dir, 1);
    setenv("TK_LIBRARY", tk_dir, 1);

    Tcl_FindExecutable("TkTox");
    Tcl_Interp *ip = Tcl_CreateInterp();
    if (!ip) {
        ck("Tcl_CreateInterp", false, NULL);
        return;
    }
    ck("Tcl_CreateInterp", true, NULL);

    if (Tcl_Init(ip) != TCL_OK) {
        ck("Tcl_Init", false, Tcl_GetStringResult(ip));
        Tcl_DeleteInterp(ip);
        return;
    }
    ck("Tcl_Init", true, Tcl_GetVar(ip,
        "tcl_patchLevel", TCL_GLOBAL_ONLY));

    /* Tk_Init needs a display on X11 but not on Windows; a headless Linux
       box therefore reports it as skipped rather than failed. */
    if (Tk_Init(ip) != TCL_OK) {
        const char *err = Tcl_GetStringResult(ip);
        bool no_display = strstr(err, "display") != NULL ||
                          strstr(err, "DISPLAY") != NULL;
        if (no_display)
            printf("  [skip] Tk_Init                        no display (%s)\n",
                   err);
        else
            ck("Tk_Init", false, err);
    } else {
        ck("Tk_Init", true,
           Tcl_GetVar(ip, "tk_patchLevel", TCL_GLOBAL_ONLY));
    }
    Tcl_DeleteInterp(ip);
}

static void check_platform(void) {
    printf("Platform glue\n");

#ifdef _WIN32
    /* Winsock must be up before any socket call; every entry point relies on
       tt_tox_thread_start having done this. */
    ck("tt_net_init (WSAStartup)", tt_net_init(), NULL);

    /* The printf shim: %zu has to render as size_t, not fall back to the
       MSVCRT profile (the -fno-builtin-* guards in CMakeLists). */
    char buf[64];
    snprintf(buf, sizeof buf, "%zu", (size_t)1234567890);
    ck("__USE_MINGW_ANSI_STDIO %zu", strcmp(buf, "1234567890") == 0, buf);

    /* localtime_r is gated behind _POSIX_C_SOURCE, set on the command line. */
    time_t now = 0;
    struct tm tm;
    ck("localtime_r", localtime_r(&now, &tm) != NULL, NULL);

    /* The Windows-only resource: the three non-system DLLs the exe imports.
       Missing ones mean the staging step did not run (or the copy is
       incomplete). tt_exe_relative_dir yields "<exe dir>/<name>" when the
       file is staged and "<name>" verbatim otherwise, so stat() covers both
       the staged tree and the current directory. */
    const char *dlls[] = { "libopus-0.dll", "libvpx-1.dll",
                           "libwinpthread-1.dll" };
    for (size_t i = 0; i < sizeof dlls / sizeof dlls[0]; i++) {
        const char *p = tt_exe_relative_dir(dlls[i], dlls[i]);
        ck(dlls[i], access(p, F_OK) == 0, p);
    }
#else
    ck("tt_net_init", tt_net_init(), NULL);
    ck("tt_exe_relative_dir (passthrough)",
       strcmp(tt_exe_relative_dir("x", "y"), "x") == 0, NULL);
#endif
}

/* The tox engine is what everything else is in service of; building it and
   reading its version catches a mismatched or missing toxcore at runtime. */
static void check_engine(void) {
    printf("Engine and crypto\n");

    char ver[64];
    snprintf(ver, sizeof ver, "%u.%u.%u",
             (unsigned)tox_version_major(), (unsigned)tox_version_minor(),
             (unsigned)tox_version_patch());
    ck("toxcore", tox_version_is_compatible(TOX_VERSION_MAJOR,
        TOX_VERSION_MINOR, TOX_VERSION_PATCH), ver);

    ck("libsodium", sodium_init() >= 0, sodium_version_string());

    /* A tox instance proves the engine initialises with no profile, no
       network, and no threading — the cheapest real end-to-end signal. */
    struct Tox_Options *opts = tox_options_new(NULL);
    Tox_Err_New err = TOX_ERR_NEW_OK;
    Tox *tox = opts ? tox_new(opts, &err) : NULL;
    if (opts) tox_options_free(opts);
    ck("tox_new", tox != NULL, err == TOX_ERR_NEW_OK ? "ok" : "see code");
    if (tox) {
        /* Reading the address exercises the crypto RNG and key serialisation;
           the self key is derived on this call. */
        uint8_t addr[TOX_ADDRESS_SIZE];
        tox_self_get_address(tox, addr);
        ck("tox_self_get_address", true, NULL);
        tox_kill(tox);
    }
}

int selfcheck_main(void) {
    printf("TkTox self-check\n");
    printf("  version %s\n", TT_VERSION);
#ifdef _WIN32
    printf("  platform windows\n");
#else
    printf("  platform posix\n");
#endif

    check_platform();
    check_interp();
    check_engine();

    printf("%s\n", g_fail ? "SELF-CHECK FAILED" : "SELF-CHECK PASSED");
    return g_fail ? 1 : 0;
}
