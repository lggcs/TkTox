#include "profiles.h"

#include "../log.h"
#include <tcl.h>
#include <tk.h>
#include <ctype.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include "platform.h" /* rename/unlink/mkdir shims (POSIX passthrough) */

/* ---- minimal Tcl/Tk bootstrap (mirrors ui_run) ---- */

/* Evaluate a single Tcl command string; log on error. */
static void ev(Tcl_Interp *ip, const char *cmd) {
    if (Tcl_Eval(ip, cmd) != TCL_OK)
        TT_LOG("prof", "tcl: %s", Tcl_GetStringResult(ip));
}

/* ---- profile discovery ---- */

/* A profile is a "<name>.tox" file in the current directory. We list them
   sorted by name. Returns a malloc'd array of malloc'd base names (without
   the .tox suffix), *count set. */
static char **list_profiles(int *count) {
    *count = 0;
    char **out = NULL;
    DIR *d = opendir(".");
    if (!d) return NULL;
    struct dirent *de;
    int cap = 0;
    while ((de = readdir(d)) != NULL) {
        size_t len = strlen(de->d_name);
        if (len <= 4 || strcmp(de->d_name + len - 4, ".tox") != 0) continue;
        /* skip the temp/backup artifacts */
        if (strstr(de->d_name, ".tmp") || strstr(de->d_name, ".new")) continue;
        char *base = malloc(len - 3); /* strip ".tox" */
        if (!base) continue;
        memcpy(base, de->d_name, len - 4);
        base[len - 4] = '\0';
        if (*count >= cap) {
            cap = cap ? cap * 2 : 8;
            char **n = realloc(out, (size_t)cap * sizeof *n);
            if (!n) { free(base); break; }
            out = n;
        }
        out[(*count)++] = base;
    }
    closedir(d);
    /* simple insertion sort by name */
    for (int i = 1; i < *count; i++) {
        char *key = out[i];
        int j = i - 1;
        while (j >= 0 && strcmp(out[j], key) > 0) {
            out[j + 1] = out[j];
            j--;
        }
        out[j + 1] = key;
    }
    return out;
}

static void free_profiles(char **p, int n) {
    for (int i = 0; i < n; i++) free(p[i]);
    free(p);
}

/* ---- picker state ---- */

typedef struct Picker {
    Tcl_Interp *interp;
    char **profiles;
    int count;
    int sel;              /* selected index, -1 = none */
    char *result;         /* chosen "<name>.tox" (malloc'd) or NULL */
    bool done;
    bool new_open;
    bool rename_open;
    bool delete_open;
} Picker;

static Picker g_pk;

static void pk_refresh(Picker *pk) {
    free_profiles(pk->profiles, pk->count);
    pk->profiles = list_profiles(&pk->count);
    pk->sel = -1;
    /* listbox: clear, then insert each profile. A listbox sizes to its
       content, so there is no empty grey area and no scrollbar unless the
       list actually overflows. */
    ev(pk->interp, ".pk.list delete 0 end");
    for (int i = 0; i < pk->count; i++) {
        char cmd[512];
        snprintf(cmd, sizeof cmd, ".pk.list insert end {%s}", pk->profiles[i]);
        ev(pk->interp, cmd);
    }
    ev(pk->interp, ".pk.list selection clear 0 end");
    if (pk->count > 8)
        ev(pk->interp, "grid .pk.listf.sb -row 0 -column 1 -sticky ns");
    else
        ev(pk->interp, "grid remove .pk.listf.sb");
}

/* ---- Tcl command handlers ---- */

static int pk_open(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Picker *pk = cd; (void)ip; (void)objc; (void)objv;
    if (pk->sel < 0 || pk->sel >= pk->count) return TCL_OK;
    size_t n = strlen(pk->profiles[pk->sel]) + 5;
    pk->result = malloc(n);
    if (pk->result)
        snprintf(pk->result, n, "%s.tox", pk->profiles[pk->sel]);
    pk->done = true;
    return TCL_OK;
}

static int pk_cancel(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Picker *pk = cd; (void)ip; (void)objc; (void)objv;
    pk->done = true;
    return TCL_OK;
}

static int pk_select(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Picker *pk = cd; (void)ip; (void)objc; (void)objv;
    /* listbox selection returns the selected index */
    ev(pk->interp, ".pk.list curselection");
    const char *r = Tcl_GetStringResult(pk->interp);
    pk->sel = (r && *r) ? atoi(r) : -1;
    return TCL_OK;
}

static int pk_new_ok(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Picker *pk = cd; (void)ip; (void)objc; (void)objv;
    if (!pk->new_open) return TCL_OK;
    ev(pk->interp, ".pk.new.e get");
    const char *name = Tcl_GetStringResult(pk->interp);
    if (!name || !*name) return TCL_OK;
    /* sanitize: only [A-Za-z0-9._-] survive; reject empty after strip */
    char clean[256];
    size_t j = 0;
    for (const char *p = name; *p && j < sizeof clean - 1; p++) {
        if (isalnum((unsigned char)*p) || *p == '.' || *p == '_' || *p == '-')
            clean[j++] = *p;
    }
    clean[j] = '\0';
    if (!clean[0]) return TCL_OK;
    char path[512];
    snprintf(path, sizeof path, "%s.tox", clean);
    /* refuse to clobber an existing profile */
    if (access(path, F_OK) == 0) {
        ev(pk->interp, "tk_messageBox -icon warning -type ok -title TkTox "
           "-message {A profile with that name already exists.}");
        return TCL_OK;
    }
    pk->result = strdup(path);
    pk->done = true;
    return TCL_OK;
}

static int pk_new_cancel(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Picker *pk = cd; (void)ip; (void)objc; (void)objv;
    pk->new_open = false;
    ev(pk->interp, "destroy .pk.new");
    return TCL_OK;
}

static int pk_new_open(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Picker *pk = cd; (void)ip; (void)objc; (void)objv;
    if (pk->new_open) return TCL_OK;
    pk->new_open = true;
    ev(pk->interp, "toplevel .pk.new -padx 14 -pady 14");
    ev(pk->interp, "wm title .pk.new {New profile}");
    ev(pk->interp, "wm transient .pk.new .");
    ev(pk->interp, "ttk::label .pk.new.l -text {Profile name:}");
    ev(pk->interp, "ttk::entry .pk.new.e -width 30");
    ev(pk->interp, "ttk::frame .pk.new.b");
    ev(pk->interp, "ttk::button .pk.new.b.ok -text Create -command pk_new_ok -style Green.TButton");
    ev(pk->interp, "ttk::button .pk.new.b.no -text Cancel -command pk_new_cancel");
    ev(pk->interp, "pack .pk.new.l -side top -anchor w -pady 2");
    ev(pk->interp, "pack .pk.new.e -side top -fill x -pady 2");
    ev(pk->interp, "pack .pk.new.b.ok -side right -padx 4 -pady 8");
    ev(pk->interp, "pack .pk.new.b.no -side right -pady 8");
    ev(pk->interp, "pack .pk.new.b -side top -anchor e");
    ev(pk->interp, "bind .pk.new.e <Return> pk_new_ok");
    ev(pk->interp, "wm protocol .pk.new WM_DELETE_WINDOW pk_new_cancel");
    ev(pk->interp, "focus .pk.new.e");
    return TCL_OK;
}

static int pk_rename_ok(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Picker *pk = cd; (void)ip; (void)objc; (void)objv;
    if (!pk->rename_open) return TCL_OK;
    if (pk->sel < 0 || pk->sel >= pk->count) return TCL_OK;
    ev(pk->interp, ".pk.ren.e get");
    const char *name = Tcl_GetStringResult(pk->interp);
    if (!name || !*name) return TCL_OK;
    char clean[256];
    size_t j = 0;
    for (const char *p = name; *p && j < sizeof clean - 1; p++) {
        if (isalnum((unsigned char)*p) || *p == '.' || *p == '_' || *p == '-')
            clean[j++] = *p;
    }
    clean[j] = '\0';
    if (!clean[0]) return TCL_OK;
    char oldpath[512], newpath[512];
    snprintf(oldpath, sizeof oldpath, "%s.tox", pk->profiles[pk->sel]);
    snprintf(newpath, sizeof newpath, "%s.tox", clean);
    if (strcmp(oldpath, newpath) == 0) { pk->rename_open = false; ev(pk->interp, "destroy .pk.ren"); return TCL_OK; }
    if (access(newpath, F_OK) == 0) {
        ev(pk->interp, "tk_messageBox -icon warning -type ok -title TkTox "
           "-message {A profile with that name already exists.}");
        return TCL_OK;
    }
    /* rename the profile and all its sidecars */
    static const char *suffixes[] = { "", ".oq", ".tt", ".ses", ".hist", ".ava", ".rsum" };
    for (size_t k = 0; k < sizeof suffixes / sizeof suffixes[0]; k++) {
        char o[600], n[600];
        snprintf(o, sizeof o, "%s%s", oldpath, suffixes[k]);
        snprintf(n, sizeof n, "%s%s", newpath, suffixes[k]);
        if (access(o, F_OK) == 0) tt_rename(o, n);
    }
    pk->rename_open = false;
    ev(pk->interp, "destroy .pk.ren");
    pk_refresh(pk);
    return TCL_OK;
}

static int pk_rename_cancel(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Picker *pk = cd; (void)ip; (void)objc; (void)objv;
    pk->rename_open = false;
    ev(pk->interp, "destroy .pk.ren");
    return TCL_OK;
}

static int pk_rename_open(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Picker *pk = cd; (void)ip; (void)objc; (void)objv;
    if (pk->rename_open) return TCL_OK;
    if (pk->sel < 0 || pk->sel >= pk->count) return TCL_OK;
    pk->rename_open = true;
    ev(pk->interp, "toplevel .pk.ren -padx 14 -pady 14");
    ev(pk->interp, "wm title .pk.ren {Rename profile}");
    ev(pk->interp, "wm transient .pk.ren .");
    ev(pk->interp, "ttk::label .pk.ren.l -text {New name:}");
    ev(pk->interp, "ttk::entry .pk.ren.e -width 30");
    {
        char cmd[512];
        snprintf(cmd, sizeof cmd, ".pk.ren.e insert 0 {%s}", pk->profiles[pk->sel]);
        ev(pk->interp, cmd);
    }
    ev(pk->interp, "ttk::frame .pk.ren.b");
    ev(pk->interp, "ttk::button .pk.ren.b.ok -text Rename -command pk_rename_ok -style Green.TButton");
    ev(pk->interp, "ttk::button .pk.ren.b.no -text Cancel -command pk_rename_cancel");
    ev(pk->interp, "pack .pk.ren.l -side top -anchor w -pady 2");
    ev(pk->interp, "pack .pk.ren.e -side top -fill x -pady 2");
    ev(pk->interp, "pack .pk.ren.b.ok -side right -padx 4 -pady 8");
    ev(pk->interp, "pack .pk.ren.b.no -side right -pady 8");
    ev(pk->interp, "pack .pk.ren.b -side top -anchor e");
    ev(pk->interp, "bind .pk.ren.e <Return> pk_rename_ok");
    ev(pk->interp, "wm protocol .pk.ren WM_DELETE_WINDOW pk_rename_cancel");
    ev(pk->interp, "focus .pk.ren.e");
    return TCL_OK;
}

static int pk_delete_ok(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Picker *pk = cd; (void)ip; (void)objc; (void)objv;
    if (!pk->delete_open) return TCL_OK;
    if (pk->sel < 0 || pk->sel >= pk->count) return TCL_OK;
    char path[512];
    snprintf(path, sizeof path, "%s.tox", pk->profiles[pk->sel]);
    static const char *suffixes[] = { "", ".oq", ".tt", ".ses", ".hist", ".ava", ".rsum" };
    for (size_t k = 0; k < sizeof suffixes / sizeof suffixes[0]; k++) {
        char p[600];
        snprintf(p, sizeof p, "%s%s", path, suffixes[k]);
        unlink(p);
    }
    pk->delete_open = false;
    ev(pk->interp, "destroy .pk.del");
    pk_refresh(pk);
    return TCL_OK;
}

static int pk_delete_cancel(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Picker *pk = cd; (void)ip; (void)objc; (void)objv;
    pk->delete_open = false;
    ev(pk->interp, "destroy .pk.del");
    return TCL_OK;
}

static int pk_delete_open(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Picker *pk = cd; (void)ip; (void)objc; (void)objv;
    if (pk->delete_open) return TCL_OK;
    if (pk->sel < 0 || pk->sel >= pk->count) return TCL_OK;
    pk->delete_open = true;
    ev(pk->interp, "toplevel .pk.del -padx 14 -pady 14");
    ev(pk->interp, "wm title .pk.del {Delete profile}");
    ev(pk->interp, "wm transient .pk.del .");
    {
        char msg[600];
        snprintf(msg, sizeof msg,
                 "Delete profile \"%s\" and all its data? This cannot be undone.",
                 pk->profiles[pk->sel]);
        char cmd[700];
        snprintf(cmd, sizeof cmd, "ttk::label .pk.del.l -text {%s} -wraplength 320", msg);
        ev(pk->interp, cmd);
    }
    ev(pk->interp, "ttk::frame .pk.del.b");
    ev(pk->interp, "ttk::button .pk.del.b.ok -text Delete -command pk_delete_ok -style Danger.TButton");
    ev(pk->interp, "ttk::button .pk.del.b.no -text Cancel -command pk_delete_cancel");
    ev(pk->interp, "pack .pk.del.l -side top -anchor w -pady 2");
    ev(pk->interp, "pack .pk.del.b.ok -side right -padx 4 -pady 8");
    ev(pk->interp, "pack .pk.del.b.no -side right -pady 8");
    ev(pk->interp, "pack .pk.del.b -side top -anchor e");
    ev(pk->interp, "wm protocol .pk.del WM_DELETE_WINDOW pk_delete_cancel");
    return TCL_OK;
}

static int pk_dblclick(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Picker *pk = cd; (void)ip; (void)objc; (void)objv;
    return pk_open(pk, ip, objc, objv);
}

/* ---- main entry ---- */

char *tt_profile_picker(void) {
    memset(&g_pk, 0, sizeof g_pk);
    Picker *pk = &g_pk;

    Tcl_FindExecutable("TkTox");
    setenv("TCL_LIBRARY", tt_tcl_script_dir(), 1);
    setenv("TK_LIBRARY", tt_tk_script_dir(), 1);
    pk->interp = Tcl_CreateInterp();
    if (!pk->interp) { TT_LOG("prof", "Tcl_CreateInterp failed"); return NULL; }
    if (Tcl_Init(pk->interp) != TCL_OK) {
        TT_LOG("prof", "Tcl_Init failed: %s", Tcl_GetStringResult(pk->interp));
        Tcl_DeleteInterp(pk->interp);
        return NULL;
    }
    if (Tk_Init(pk->interp) != TCL_OK) {
        TT_LOG("prof", "Tk_Init failed: %s", Tcl_GetStringResult(pk->interp));
        Tcl_DeleteInterp(pk->interp);
        return NULL;
    }

    Tcl_CreateObjCommand(pk->interp, "pk_open", pk_open, pk, NULL);
    Tcl_CreateObjCommand(pk->interp, "pk_cancel", pk_cancel, pk, NULL);
    Tcl_CreateObjCommand(pk->interp, "pk_select", pk_select, pk, NULL);
    Tcl_CreateObjCommand(pk->interp, "pk_new_open", pk_new_open, pk, NULL);
    Tcl_CreateObjCommand(pk->interp, "pk_new_ok", pk_new_ok, pk, NULL);
    Tcl_CreateObjCommand(pk->interp, "pk_new_cancel", pk_new_cancel, pk, NULL);
    Tcl_CreateObjCommand(pk->interp, "pk_rename_open", pk_rename_open, pk, NULL);
    Tcl_CreateObjCommand(pk->interp, "pk_rename_ok", pk_rename_ok, pk, NULL);
    Tcl_CreateObjCommand(pk->interp, "pk_rename_cancel", pk_rename_cancel, pk, NULL);
    Tcl_CreateObjCommand(pk->interp, "pk_delete_open", pk_delete_open, pk, NULL);
    Tcl_CreateObjCommand(pk->interp, "pk_delete_ok", pk_delete_ok, pk, NULL);
    Tcl_CreateObjCommand(pk->interp, "pk_delete_cancel", pk_delete_cancel, pk, NULL);
    Tcl_CreateObjCommand(pk->interp, "pk_dblclick", pk_dblclick, pk, NULL);

    /* window: the root "." is the toplevel; every widget lives under a
       ".pk" frame that must exist before its children are created. Use
       grid (like the main UI) so the list fills the frame width and the
       title/buttons stay visible without resizing. The list is a listbox
       (not a treeview): it sizes to its content, so there is no empty
       grey area and no vertical text clipping. */
    ev(pk->interp, "wm title . {TkTox — choose a profile}");
    ev(pk->interp, "wm geometry . 460x400");
    ev(pk->interp, "wm minsize . 460 400");
    ev(pk->interp, "ttk::frame .pk -padding 10");
    ev(pk->interp, "grid .pk -sticky nsew");
    ev(pk->interp, "grid columnconfigure . 0 -weight 1");
    ev(pk->interp, "grid rowconfigure . 0 -weight 1");
    ev(pk->interp, "ttk::label .pk.title -text {Choose a profile} -font {TkDefaultFont 12 bold}");
    ev(pk->interp, "ttk::frame .pk.listf");
    /* plain Tk listbox + scrollbar: the vendored ttk tree has no
       listbox.tcl (ttk::listbox needs Tk >= 8.6.10), so use the core
       listbox widget. It sizes to its content — no empty grey area, no
       vertical text clipping. */
    ev(pk->interp, "scrollbar .pk.listf.sb -orient vertical -command {.pk.list yview}");
    ev(pk->interp, "listbox .pk.list -height 8 -width 40 "
                   "-yscrollcommand {.pk.listf.sb set} -selectmode browse "
                   "-exportselection 0 -activestyle none");
    ev(pk->interp, "bind .pk.list <<ListboxSelect>> pk_select");
    ev(pk->interp, "bind .pk.list <Double-Button-1> pk_dblclick");
    ev(pk->interp, "grid .pk.listf.sb -row 0 -column 1 -sticky ns");
    ev(pk->interp, "grid .pk.list -row 0 -column 0 -sticky nsew");
    ev(pk->interp, "grid columnconfigure .pk.listf 0 -weight 1");
    ev(pk->interp, "grid rowconfigure .pk.listf 0 -weight 1");
    ev(pk->interp, "ttk::frame .pk.btns");
    ev(pk->interp, "ttk::button .pk.btns.open -text Open -command pk_open -style Green.TButton");
    ev(pk->interp, "ttk::button .pk.btns.new -text {New...} -command pk_new_open");
    ev(pk->interp, "ttk::button .pk.btns.ren -text {Rename...} -command pk_rename_open");
    ev(pk->interp, "ttk::button .pk.btns.del -text {Delete...} -command pk_delete_open");
    ev(pk->interp, "ttk::button .pk.btns.no -text Cancel -command pk_cancel");
    ev(pk->interp, "grid .pk.title -row 0 -column 0 -sticky ew -pady 6");
    ev(pk->interp, "grid .pk.listf -row 1 -column 0 -sticky nsew -pady 4");
    ev(pk->interp, "grid .pk.btns -row 2 -column 0 -sticky ew");
    ev(pk->interp, "grid rowconfigure .pk 1 -weight 1");
    ev(pk->interp, "grid columnconfigure .pk 0 -weight 1");
    ev(pk->interp, "pack .pk.btns.open -side left -padx 2 -pady 8");
    ev(pk->interp, "pack .pk.btns.new -side left -padx 2 -pady 8");
    ev(pk->interp, "pack .pk.btns.ren -side left -padx 2 -pady 8");
    ev(pk->interp, "pack .pk.btns.del -side left -padx 2 -pady 8");
    ev(pk->interp, "pack .pk.btns.no -side right -padx 2 -pady 8");
    ev(pk->interp, "wm protocol . WM_DELETE_WINDOW pk_cancel");

    pk_refresh(pk);

    /* First run with no profiles: jump straight to the New dialog so the
       user isn't staring at an empty list. */
    if (pk->count == 0)
        pk_new_open(pk, pk->interp, 0, NULL);

    /* run the event loop until a choice is made */
    while (!pk->done) {
        Tcl_DoOneEvent(TCL_ALL_EVENTS);
    }

    char *result = pk->result;
    Tcl_DeleteInterp(pk->interp);
    free_profiles(pk->profiles, pk->count);
    return result;
}
