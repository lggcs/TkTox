#include "app_state.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void app_state_init(AppState *st) {
    memset(st, 0, sizeof *st);
    pthread_mutex_init(&st->lock, NULL);
}

void app_state_destroy(AppState *st) {
    free(st->friends);
    pthread_mutex_destroy(&st->lock);
}

void app_state_set_friend(AppState *st, uint32_t fn, const char *name, int connection) {
    pthread_mutex_lock(&st->lock);
    TTFriend *f = NULL;
    for (size_t i = 0; i < st->friend_count; i++) {
        if (st->friends[i].friend_number == fn) { f = &st->friends[i]; break; }
    }
    if (!f) {
        if (st->friend_count == st->friend_cap) {
            size_t ncap = st->friend_cap ? st->friend_cap * 2 : 8;
            /* checked multiplication: cap counts small structs, but stay disciplined */
            if (ncap > (size_t)-1 / sizeof(TTFriend)) { pthread_mutex_unlock(&st->lock); return; }
            TTFriend *nf = realloc(st->friends, ncap * sizeof(TTFriend));
            if (!nf) { pthread_mutex_unlock(&st->lock); return; }
            st->friends = nf; st->friend_cap = ncap;
        }
        f = &st->friends[st->friend_count++];
        memset(f, 0, sizeof *f);
        f->friend_number = fn;
    }
    if (name && *name) {
        snprintf(f->name, sizeof f->name, "%s", name); /* truncation-safe */
    }
    f->connection = connection;
    pthread_mutex_unlock(&st->lock);
}