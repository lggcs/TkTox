#ifndef TT_APP_STATE_H
#define TT_APP_STATE_H
#include <stdint.h>
#include <pthread.h>

#define TT_TOXID_HEX_SIZE 76 /* 64 hex + nospam(8) + checksum(4) */
#define TT_NAME_MAX 128

typedef struct TTFriend {
    uint32_t friend_number;
    char name[TT_NAME_MAX];
    int connection; /* Tox_Connection value */
} TTFriend;

typedef struct AppState {
    pthread_mutex_t lock;
    char toxid_hex[TT_TOXID_HEX_SIZE];
    int self_connection; /* 0 offline, 1 TCP, 2 UDP */
    TTFriend *friends;
    size_t friend_count, friend_cap;
} AppState;

void app_state_init(AppState *st);
void app_state_destroy(AppState *st);
/* Upsert friend info from a toxcore callback (called on tox thread under lock). */
void app_state_set_friend(AppState *st, uint32_t fn, const char *name, int connection);
#endif