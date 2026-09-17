#ifndef TT_PLATFORM_H
#define TT_PLATFORM_H

/* Cross-platform shims for the Linux/POSIX-isms the TkTox sources use.
   On non-Windows platforms this header is a pure pass-through: every tt_*
   helper is an inline call to the POSIX function of the same semantics, so
   the Linux build compiles exactly as it did before the port. On Windows
   (mingw-w64) it maps to Winsock/MSVCRT equivalents and supplies the few
   missing pieces (winsock init, errno mapping, portable rename/setenv/
   getpass).

   Windows conventions:
   - tt_socket/tt_recv/... wrappers move the WSAGetLastError code into
     errno, mapped per call to the POSIX constant the caller checks
     (non-blocking connect reports EINPROGRESS, recv/sendto EWOULDBLOCK).
   - Sockets are closed with tt_close() -> closesocket(); plain file fds
     keep using close() directly (only tunnel.c/headless.c/ui_tk.c socket
     paths use tt_close).
   - Winsock init happens once in tt_tox_thread_start (every entry point
     spawns the tox thread before any socket use).
   - rename() on Windows refuses to clobber an existing target; sidecar
     atomic writes go through tt_rename() which removes the target first. */

#if !defined(_WIN32)

/* ---- POSIX pass-through: the includes the sources did before the port ---- */
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h> /* unsetenv/... used by the shims below */

static inline bool tt_net_init(void) { return true; }

static inline int tt_rename(const char *oldpath, const char *newpath) {
    return rename(oldpath, newpath);
}

/* POSIX pass-through socket wrappers (semantics identical to the direct
   calls; they exist so both platforms share one call spelling). */
static inline int tt_socket(int domain, int type, int protocol) {
    return socket(domain, type, protocol);
}
static inline int tt_close(int fd) { return close(fd); }
static inline int tt_bind(int s, const struct sockaddr *a, socklen_t l) {
    return bind(s, a, l);
}
static inline int tt_listen(int s, int backlog) { return listen(s, backlog); }
static inline int tt_accept(int s, struct sockaddr *a, socklen_t *l) {
    return accept(s, a, l);
}
static inline int tt_connect(int s, const struct sockaddr *a, socklen_t l) {
    return connect(s, a, l);
}
static inline ssize_t tt_recv(int s, void *buf, size_t len, int flags) {
    return recv(s, buf, len, flags);
}
static inline ssize_t tt_recvfrom(int s, void *buf, size_t len, int flags,
                                  struct sockaddr *from, socklen_t *fromlen) {
    return recvfrom(s, buf, len, flags, from, fromlen);
}
static inline ssize_t tt_send(int s, const void *buf, size_t len, int flags) {
    return send(s, buf, len, flags);
}
static inline ssize_t tt_sendto(int s, const void *buf, size_t len, int flags,
                                const struct sockaddr *to, socklen_t tolen) {
    return sendto(s, buf, len, flags, to, tolen);
}
static inline int tt_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    return fl;
}

/* 0600-on-create for the private sidecars (keys, history, sessions). */
static inline int tt_fchmod(int fd, int mode) {
    return fchmod(fd, (mode_t)mode);
}

static inline void tt_usleep(unsigned long usec) {
    usleep((useconds_t)usec);
}

static inline int tt_unsetenv(const char *name) {
    return unsetenv(name);
}

/* Vendored script trees are addressed by absolute path on POSIX (the deps
   tree lives beside the source); nothing to relocate. */
static inline const char *tt_exe_relative_dir(const char *compiled_path,
                                              const char *tail) {
    (void)tail;
    return compiled_path;
}

#else /* _WIN32 */

/* NOTE: __USE_MINGW_ANSI_STDIO and _POSIX_C_SOURCE must be defined before
   the first CRT header in the TU; CMake sets both on the command line for
   the Windows build. They are re-set here only as a fallback for direct
   single-TU compiles that include platform.h first. */
#ifndef __USE_MINGW_ANSI_STDIO
#define __USE_MINGW_ANSI_STDIO 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Winsock startup: one-shot per process. Called from tt_tox_thread_start
   (every entry point spawns the tox thread before any socket use). */
static inline bool tt_net_init(void) {
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
}

/* rename(2) on Windows fails when the target exists (POSIX atomically
   replaces it): sidecar writers must remove the target first. */
static inline int tt_rename(const char *oldpath, const char *newpath) {
    _unlink(newpath);
    return MoveFileExA(oldpath, newpath, MOVEFILE_REPLACE_EXISTING) ? 0 : -1;
}

/* Move the WSA error into errno with the POSIX constant the caller checks.
   Raw WSA codes (>= 10000) never compare equal to any E* the code tests,
   so unmapped errors degrade to "fatal" — matching the Linux behavior for
   exotic errors. */
static inline void tt_wsa_to_errno(int wsa) {
    switch (wsa) {
    case 0:                 errno = 0; break;
    case WSAEWOULDBLOCK:    errno = EWOULDBLOCK; break;
    case WSAEINPROGRESS:    errno = EINPROGRESS; break;
    case WSAEADDRINUSE:     errno = EADDRINUSE; break;
    case WSAECONNRESET:     errno = ECONNRESET; break;
    case WSAECONNABORTED:   errno = ECONNABORTED; break;
    case WSAENETDOWN:       errno = ENETDOWN; break;
    case WSAEINTR:          errno = EINTR; break;
    case WSAEACCES:         errno = EACCES; break;
    default:                errno = wsa; break;
    }
}

static inline int tt_socket(int domain, int type, int protocol) {
    int s = (int)socket(domain, type, protocol);
    tt_wsa_to_errno(s < 0 ? WSAGetLastError() : 0);
    return s;
}
/* Sockets must never reach the CRT close(); tt_close is used on every
   descriptor that came from tt_socket(). */
static inline int tt_close(int fd) { return closesocket((SOCKET)fd); }
static inline int tt_bind(int s, const struct sockaddr *a, socklen_t l) {
    int r = bind((SOCKET)s, a, l);
    tt_wsa_to_errno(r < 0 ? WSAGetLastError() : 0);
    return r;
}
static inline int tt_listen(int s, int backlog) {
    int r = listen((SOCKET)s, backlog);
    tt_wsa_to_errno(r < 0 ? WSAGetLastError() : 0);
    return r;
}
static inline int tt_accept(int s, struct sockaddr *a, socklen_t *l) {
    int r = (int)accept((SOCKET)s, a, l);
    tt_wsa_to_errno(r < 0 ? WSAGetLastError() : 0);
    return r;
}
static inline int tt_connect(int s, const struct sockaddr *a, socklen_t l) {
    int r = connect((SOCKET)s, a, l);
    /* A non-blocking connect that is in flight reports WSAEWOULDBLOCK;
       tunnel.c checks EINPROGRESS, so map it in this call's context. */
    int w = WSAGetLastError();
    if (r < 0 && w == WSAEWOULDBLOCK) errno = EINPROGRESS;
    else tt_wsa_to_errno(r < 0 ? w : 0);
    return r;
}
static inline ssize_t tt_recv(int s, void *buf, size_t len, int flags) {
    ssize_t r = (ssize_t)recv((SOCKET)s, buf, (int)len, flags);
    tt_wsa_to_errno(r < 0 ? WSAGetLastError() : 0);
    return r;
}
static inline ssize_t tt_recvfrom(int s, void *buf, size_t len, int flags,
                                  struct sockaddr *from, socklen_t *fromlen) {
    ssize_t r = (ssize_t)recvfrom((SOCKET)s, buf, (int)len, flags,
                                  from, fromlen);
    tt_wsa_to_errno(r < 0 ? WSAGetLastError() : 0);
    return r;
}
static inline ssize_t tt_send(int s, const void *buf, size_t len, int flags) {
    ssize_t r = (ssize_t)send((SOCKET)s, buf, (int)len, flags);
    tt_wsa_to_errno(r < 0 ? WSAGetLastError() : 0);
    return r;
}
static inline ssize_t tt_sendto(int s, const void *buf, size_t len, int flags,
                                const struct sockaddr *to, socklen_t tolen) {
    ssize_t r = (ssize_t)sendto((SOCKET)s, buf, (int)len, flags, to, tolen);
    tt_wsa_to_errno(r < 0 ? WSAGetLastError() : 0);
    return r;
}
static inline void tt_nonblock(int fd) {
    u_long mode = 1;
    ioctlsocket((SOCKET)fd, FIONBIO, &mode);
}

/* POSIX fchmod(2) has no MSVCRT counterpart. The sidecars it protects are
   already created under the user's profile directory (which Windows ACLs
   own); the call is kept as a no-op so the writers need no #ifdef. */
static inline int tt_fchmod(int fd, int mode) {
    (void)fd; (void)mode;
    return 0;
}

/* mingw's unistd.h has no usleep; Sleep() takes milliseconds, so round up
   (never sleep less than asked: polling loops must not spin hot). */
static inline void tt_usleep(unsigned long usec) {
    Sleep((DWORD)((usec + 999) / 1000));
}

/* _putenv("NAME=") removes the variable; there is no unsetenv(3). */
static inline int tt_unsetenv(const char *name) {
    size_t n = strlen(name) + 2;
    char *buf = malloc(n);
    if (!buf) return -1;
    snprintf(buf, n, "%s=", name);
    int rc = _putenv(buf) ? 0 : -1;
    free(buf);
    return rc;
}

/* CRT rename(2) and setenv are not POSIX-complete on Windows; _mkdir takes
   no mode argument; there is no getpass(3). */
#define mkdir(p, m) _mkdir(p)

/* POSIX spellings the sidecar/profile code uses */
#define unlink _unlink
/* mingw's io.h already declares access(3) (CRT _access alias); nothing to
   add. F_OK comes from unistd.h on POSIX; mingw doesn't define it. */
#ifndef F_OK
#define F_OK 0
#endif

static inline int tt_setenv(const char *name, const char *value, int overwrite) {
    if (!overwrite && getenv(name)) return 0;
    size_t n = strlen(name) + strlen(value) + 2;
    char *buf = malloc(n);
    if (!buf) return -1;
    snprintf(buf, n, "%s=%s", name, value);
    int rc = _putenv(buf) ? 0 : -1;
    free(buf);
    return rc;
}
#define setenv tt_setenv

/* Console passphrase prompt; defined in platform_win.c. */
char *tt_getpass(const char *prompt);

/* Resolve a vendored script tree next to the running TkTox.exe (tail is the
   path below the exe dir, e.g. "tcl\\lib\\tcl8.6"); defined in
   platform_win.c. Falls back to compiled_path when it is not there. */
const char *tt_exe_relative_dir(const char *compiled_path, const char *tail);

/* headless.c opens a test file with O_NOFOLLOW; mingw fcntl.h has no such
   flag (Windows has no symlink-follow risk in that path either way). */
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#endif /* _WIN32 */

/* Compiled-in script tree paths, in the platform's own subdirectory layout:
   POSIX addresses the deps tree beside the source; Windows stages a copy
   next to the exe at build time (see the CMakeLists POST_BUILD step) and
   prefers that, so build-win/ stays relocatable. Defined in ui_tk.c; ui_run,
   the profile picker, and --selfcheck all resolve TCL_LIBRARY/TK_LIBRARY
   from these, so the self-check exercises the same path the UI uses. */
const char *tt_tcl_script_dir(void);
const char *tt_tk_script_dir(void);

#endif /* TT_PLATFORM_H */