/* Windows-only shims that need more than a one-liner. Compiled only on
   _WIN32 builds (the CMake list excludes this TU on other platforms). */

#include "platform.h"

#ifdef _WIN32

#include <conio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *tt_getpass(const char *prompt) {
    fputs(prompt, stderr);
    fflush(stderr);
    /* cap mirrors the profile passphrase flows (they never exceed this) */
    static char buf[256];
    size_t n = 0;
    for (;;) {
        int c = _getch();
        if (c == '\r' || c == '\n') { /* Enter */
            break;
        }
        if (c == 3) { /* Ctrl+C */
            buf[0] = '\0';
            fputc('\n', stderr);
            return NULL;
        }
        if (c == '\b' || c == 127) { /* backspace */
            if (n > 0) n--;
            continue;
        }
        if (c >= 32 && c < 127 && n + 1 < sizeof buf)
            buf[n++] = (char)c;
    }
    fputc('\n', stderr);
    buf[n] = '\0';
    return buf;
}

/* Rewrite a script dir to be relative to the running executable.

   CMake bakes the *build machine's* absolute path into TCL_LIBRARY /
   TK_LIBRARY, which breaks the moment TkTox.exe is copied elsewhere (a
   shipped tree, a different install root, a wine prefix). Resolve the exe
   directory at run time instead and append the same tail; fall back to the
   compiled-in path when the relative one does not exist, so a source-tree
   run keeps working unchanged. */
const char *tt_exe_relative_dir(const char *compiled_path, const char *tail) {
    static char buf[1200];
    char exe[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, exe, sizeof exe);
    if (n == 0 || n >= sizeof exe) return compiled_path;
    char *slash = strrchr(exe, '\\');
    if (!slash) slash = strrchr(exe, '/');
    if (!slash) return compiled_path;
    *slash = '\0';
    if (snprintf(buf, sizeof buf, "%s\\%s", exe, tail) >= (int)sizeof buf)
        return compiled_path;
    if (GetFileAttributesA(buf) == INVALID_FILE_ATTRIBUTES)
        return compiled_path;
    return buf;
}

#endif /* _WIN32 */