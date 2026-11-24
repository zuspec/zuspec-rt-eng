/*
 * zbc_events.c -- the binary trace encoder (see zbc_events.h).
 */
#include <stdlib.h>
#include <string.h>
#include "zbc_events.h"

enum { T_NULL, T_FALSE, T_TRUE, T_INT, T_FLOAT, T_STR, T_STRREF, T_LIST, T_MAP };

static const uint8_t MAGIC[8] = { 'P', 'S', 'T', 'R', 'A', 'C', 'E', 0 };

static void buf_put(zbc_ev_buf_t *b, const void *p, size_t n) {
    if (b->oom) return;
    if (b->len + n > b->cap) {
        size_t cap = b->cap ? b->cap : 256;
        while (cap < b->len + n) cap *= 2;
        uint8_t *q = (uint8_t *)realloc(b->p, cap);
        if (!q) { b->oom = 1; return; }
        b->p = q;
        b->cap = cap;
    }
    memcpy(b->p + b->len, p, n);
    b->len += n;
}

static void buf_byte(zbc_ev_buf_t *b, uint8_t v) { buf_put(b, &v, 1); }

static void buf_uvarint128(zbc_ev_buf_t *b, unsigned __int128 n) {
    for (;;) {
        uint8_t v = (uint8_t)(n & 0x7F);
        n >>= 7;
        if (n) buf_byte(b, v | 0x80);
        else { buf_byte(b, v); return; }
    }
}

static void buf_uvarint(zbc_ev_buf_t *b, uint64_t n) { buf_uvarint128(b, n); }

static uint32_t str_hash(const char *p, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) h = (h ^ (uint8_t)p[i]) * 16777619u;
    return h;
}

/* The id of string p[0..n), or -1 (and interned as the next id). */
static int64_t intern(zbc_ev_sink_t *s, const char *p, size_t n) {
    if ((s->n_strs + 1) * 2 > s->n_slots) {
        uint32_t ns = s->n_slots ? s->n_slots * 2 : 256;
        uint32_t *sl = (uint32_t *)calloc(ns, sizeof(uint32_t));
        if (!sl) { s->rec.oom = 1; return -2; }
        for (uint32_t i = 0; i < s->n_strs; i++) {
            uint32_t h = str_hash(s->strs[i], strlen(s->strs[i])) & (ns - 1);
            while (sl[h]) h = (h + 1) & (ns - 1);
            sl[h] = i + 1;
        }
        free(s->slots);
        s->slots = sl;
        s->n_slots = ns;
    }
    uint32_t h = str_hash(p, n) & (s->n_slots - 1);
    while (s->slots[h]) {
        const char *t = s->strs[s->slots[h] - 1];
        if (strlen(t) == n && memcmp(t, p, n) == 0) return s->slots[h] - 1;
        h = (h + 1) & (s->n_slots - 1);
    }
    if (s->n_strs == s->cap_strs) {
        uint32_t nc = s->cap_strs ? s->cap_strs * 2 : 128;
        char **q = (char **)realloc(s->strs, nc * sizeof(char *));
        if (!q) { s->rec.oom = 1; return -2; }
        s->strs = q;
        s->cap_strs = nc;
    }
    char *c = (char *)malloc(n + 1);
    if (!c) { s->rec.oom = 1; return -2; }
    memcpy(c, p, n);
    c[n] = 0;
    s->strs[s->n_strs] = c;
    s->slots[h] = ++s->n_strs;
    return -1;
}

static void put_str(zbc_ev_sink_t *s, zbc_ev_buf_t *b, const char *p, size_t n) {
    int64_t id = intern(s, p, n);
    if (id == -2) return;
    if (id >= 0) {
        buf_byte(b, T_STRREF);
        buf_uvarint(b, (uint64_t)id);
        return;
    }
    buf_byte(b, T_STR);
    buf_uvarint(b, n);
    buf_put(b, p, n);
}

void zbc_ev_init(zbc_ev_sink_t *s, zbc_ev_out_f out, void *ctx) {
    memset(s, 0, sizeof(*s));
    s->out = out;
    s->ctx = ctx;
    s->prev = -1;
}

void zbc_ev_free(zbc_ev_sink_t *s) {
    for (uint32_t i = 0; i < s->n_strs; i++) free(s->strs[i]);
    free(s->strs);
    free(s->slots);
    free(s->rec.p);
    free(s->frame.p);
    s->strs = NULL;
    s->slots = NULL;
    s->rec.p = s->frame.p = NULL;
    s->n_strs = s->cap_strs = s->n_slots = 0;
    s->rec.len = s->rec.cap = s->frame.len = s->frame.cap = 0;
}

zbc_ev_sink_t *zbc_ev_new(zbc_ev_out_f out, void *ctx) {
    zbc_ev_sink_t *s = (zbc_ev_sink_t *)malloc(sizeof(*s));
    if (s) zbc_ev_init(s, out, ctx);
    return s;
}

void zbc_ev_delete(zbc_ev_sink_t *s) {
    if (!s) return;
    zbc_ev_free(s);
    free(s);
}

int zbc_ev_header(zbc_ev_sink_t *s, const char *const *keys,
                  const char *const *vals, uint32_t n) {
    return zbc_ev_header_int(s, keys, vals, NULL, n);
}

int zbc_ev_header_int(zbc_ev_sink_t *s, const char *const *keys,
                      const char *const *vals, const uint64_t *ints,
                      uint32_t n) {
    if (s->started) return 0;
    s->started = 1;
    zbc_ev_buf_t *b = &s->frame;
    b->len = 0;
    buf_put(b, MAGIC, sizeof(MAGIC));
    buf_uvarint(b, ZBC_TRACE_SCHEMA_VERSION);
    buf_byte(b, T_MAP);
    buf_uvarint(b, n);
    /* keys in sorted order (byte order = Python's for ASCII keys) */
    uint32_t done[64];
    uint32_t m = n < 64 ? n : 64;
    for (uint32_t k = 0; k < m; k++) {
        int best = -1;
        for (uint32_t i = 0; i < m; i++) {
            int used = 0;
            for (uint32_t j = 0; j < k; j++) used |= done[j] == i;
            if (!used && (best < 0 || strcmp(keys[i], keys[best]) < 0)) best = (int)i;
        }
        done[k] = (uint32_t)best;
        put_str(s, b, keys[best], strlen(keys[best]));
        if (vals[best] != NULL) {
            put_str(s, b, vals[best], strlen(vals[best]));
        } else {    /* zigzag, as binary.py: n >= 0 -> 2n */
            buf_byte(b, T_INT);
            buf_uvarint128(b, (unsigned __int128)ints[best] * 2);
        }
    }
    if (b->oom || s->rec.oom) return -1;
    if (s->out) s->out(s->ctx, b->p, b->len);
    return 0;
}

void zbc_ev_watch(zbc_ev_sink_t *s, uint32_t mask, int32_t coro) {
    if (coro < 0) {
        s->mask = mask;
        for (uint32_t i = 0; i < s->n_masks; i++) s->masks[i] = mask;
    } else if ((uint32_t)coro < ZBC_EV_MAX_CORO_MASKS) {
        for (uint32_t i = s->n_masks; i <= (uint32_t)coro; i++) s->masks[i] = s->mask;
        if ((uint32_t)coro >= s->n_masks) s->n_masks = (uint32_t)coro + 1;
        s->masks[coro] = mask;
    }
    uint32_t any = s->mask;
    for (uint32_t i = 0; i < s->n_masks; i++) any |= s->masks[i];
    s->any = any;
}

void zbc_ev_begin(zbc_ev_sink_t *s, const char *kind, uint32_t coro, uint32_t src_ref) {
    if (!s->started) zbc_ev_header(s, NULL, NULL, 0);
    zbc_ev_buf_t *b = &s->rec;
    b->len = 0;
    int64_t d = s->seq - s->prev - 1;
    buf_uvarint(b, d >= 0 ? (uint64_t)d * 2 : (uint64_t)(-d) * 2 - 1);
    s->prev = s->seq++;
    put_str(s, b, kind, strlen(kind));
    buf_uvarint(b, coro);
    buf_uvarint(b, src_ref);
}

void zbc_ev_map(zbc_ev_sink_t *s, uint32_t n) {
    buf_byte(&s->rec, T_MAP);
    buf_uvarint(&s->rec, n);
}

void zbc_ev_list(zbc_ev_sink_t *s, uint32_t n) {
    buf_byte(&s->rec, T_LIST);
    buf_uvarint(&s->rec, n);
}

void zbc_ev_key(zbc_ev_sink_t *s, const char *k) { put_str(s, &s->rec, k, strlen(k)); }

void zbc_ev_str(zbc_ev_sink_t *s, const char *v, size_t len) { put_str(s, &s->rec, v, len); }

void zbc_ev_int(zbc_ev_sink_t *s, int64_t v) {
    buf_byte(&s->rec, T_INT);
    buf_uvarint(&s->rec, v >= 0 ? (uint64_t)v << 1 : (((uint64_t)(-(v + 1))) << 1) | 1);
}

void zbc_ev_uint(zbc_ev_sink_t *s, uint64_t v) {
    buf_byte(&s->rec, T_INT);
    buf_uvarint128(&s->rec, (unsigned __int128)v << 1);
}

void zbc_ev_null(zbc_ev_sink_t *s) { buf_byte(&s->rec, T_NULL); }

void zbc_ev_bool(zbc_ev_sink_t *s, int v) { buf_byte(&s->rec, v ? T_TRUE : T_FALSE); }

void zbc_ev_end(zbc_ev_sink_t *s) {
    zbc_ev_map(s, 0);   /* no extras */
    zbc_ev_buf_t *f = &s->frame;
    f->len = 0;
    buf_uvarint(f, s->rec.len);
    buf_put(f, s->rec.p, s->rec.len);
    if (f->oom || s->rec.oom) return;   /* dropped; seq still counts */
    if (s->out) s->out(s->ctx, f->p, f->len);
}
