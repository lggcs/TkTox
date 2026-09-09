/* savedata_strip_dht unit test — standalone harness for tox_thread.c's
   savedata rewriter. Compiled separately; links the vendored toxcore only so
   the TU resolves (functions under test are static — #include the source). */
#include "../src/tox_thread.c"

#undef TT_LOG /* harness wants stdout, not the app log */
#define TT_LOG(...) do { } while (0)

static int fails = 0;
#define CHECK(cond) do { if (!(cond)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); ++fails; } } while (0)

static void put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); } /* LE blob */

static void put_section(uint8_t *p, size_t *off, uint16_t type, const uint8_t *payload, uint32_t plen) {
    put32(p + *off, plen);
    put32(p + *off + 4, (0x01ceu << 16) | type);
    if (plen) memcpy(p + *off + 8, payload, plen);
    *off += 8 + plen;
}

static void put_cookie(uint8_t *p) {
    memset(p, 0, 4); /* tox_get_savedata writes a zero u32 first... */
    put32(p + 4, 0x15ed1b1fu); /* ...then STATE_COOKIE_GLOBAL (LE) */
}

int main(void) {
    /* blob layout: cookie(8) + DHT(24) + FRIENDS(3) + DHT(11) + END(0) */
    uint8_t blob[8 + 32 + 11 + 19 + 8];
    memset(blob, 0xA5, sizeof blob);
    put_cookie(blob);
    size_t off = 8;
    uint8_t dummy[24];
    memset(dummy, 0xEE, sizeof dummy);
    put_section(blob, &off, 2, dummy, 24);        /* DHT */
    put_section(blob, &off, 3, (const uint8_t *)"xx", 3);   /* FRIENDS */
    put_section(blob, &off, 2, dummy, 11);        /* second DHT */
    put_section(blob, &off, 255, NULL, 0);        /* END */
    CHECK(off == sizeof blob);

    size_t out_len = 0;
    uint8_t *out = savedata_strip_dht(blob, sizeof blob, &out_len);
    CHECK(out != NULL);
    if (out) {
        CHECK(out_len == 8 + 11 + 8); /* cookie + FRIENDS + END = 27 */
        size_t r = 8;
        uint32_t slen, scook;
        memcpy(&slen, out + r, 4); memcpy(&scook, out + r + 4, 4);
        CHECK((scook & 0xffffu) == 3 && slen == 3);
        r += 8 + slen;
        memcpy(&slen, out + r, 4); memcpy(&scook, out + r + 4, 4);
        CHECK((scook & 0xffffu) == 255 && slen == 0);
        r += 8;
        CHECK(r == out_len);
        free(out);
    }

    /* no DHT section: returns NULL, nothing to do */
    uint8_t nodht[8 + 11 + 8];
    memset(nodht, 0x5A, sizeof nodht);
    put_cookie(nodht);
    off = 8;
    put_section(nodht, &off, 3, (const uint8_t *)"xx", 3);
    put_section(nodht, &off, 255, NULL, 0);
    out = savedata_strip_dht(nodht, sizeof nodht, &out_len);
    CHECK(out == NULL);

    /* DHT-only + END: all that remains is cookie + END (16B) */
    uint8_t only[8 + 32 + 8];
    memset(only, 0x5A, sizeof only);
    put_cookie(only);
    off = 8;
    put_section(only, &off, 2, dummy, 24);
    put_section(only, &off, 255, NULL, 0);
    out = savedata_strip_dht(only, sizeof only, &out_len);
    CHECK(out != NULL);
    if (out) {
        CHECK(out_len == 16);
        uint32_t slen, scook;
        memcpy(&slen, out + 8, 4); memcpy(&scook, out + 12, 4);
        CHECK((scook & 0xffffu) == 255 && slen == 0);
        free(out);
    }

    /* truncated section: fail safe -> NULL */
    out = savedata_strip_dht(blob, 8 + 32 + 5, &out_len); /* cut inside DHT payload */
    CHECK(out == NULL);

    /* bad cookie: NULL */
    uint8_t bad[32];
    memset(bad, 0, sizeof bad);
    out = savedata_strip_dht(bad, sizeof bad, &out_len);
    CHECK(out == NULL);

    /* oversized declared length: NULL */
    uint8_t huge[16];
    memset(huge, 0, 4); /* cookie low word must be zero to reach section parse */
    put32(huge + 4, 0x15ed1b1fu);
    put32(huge + 8, 0xFFFFFFFeu);
    put32(huge + 12, (0x01ceu << 16) | 2);
    out = savedata_strip_dht(huge, sizeof huge, &out_len);
    CHECK(out == NULL);

    if (fails == 0) puts("savedata_strip_dht: ALL PASS");
    return fails ? 1 : 0;
}