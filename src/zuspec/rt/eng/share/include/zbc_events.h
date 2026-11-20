/*
 * zbc_events.h -- debug events from the native engine (P4.4c).
 *
 * The engine raises the same events as the Python VM (be-bc trace/events.py)
 * and writes them in the binary trace form (be-bc docs/spec/trace-schema.md,
 * "Binary form (.pstrace)"): a header (magic, schema version, header map),
 * then one length-prefixed record per event. The sink encodes; the host gets
 * the bytes through `out` (the header first, then each finished record) and
 * writes them to a file or forwards them. Strings are interned per sink, so
 * one sink is one trace file.
 *
 * Which events: a mask of ZBC_EV_* bits per coroutine (zbc_ev_watch). A
 * coroutine raises an event only when its bit is set; a sink with no bits
 * set costs one test per instruction.
 */
#ifndef ZUSPEC_ZBC_EVENTS_H
#define ZUSPEC_ZBC_EVENTS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Bit values: be-bc trace/events.py EV_*. */
enum {
    ZBC_EV_STMT      = 1u << 0,
    ZBC_EV_CALL      = 1u << 1,
    ZBC_EV_TEST      = 1u << 2,
    ZBC_EV_ACCESS    = 1u << 3,
    ZBC_EV_IMPORT    = 1u << 4,
    ZBC_EV_MESSAGE   = 1u << 5,
    ZBC_EV_CHECK     = 1u << 6,
    ZBC_EV_CHAN      = 1u << 7,
    ZBC_EV_NOTIFY    = 1u << 8,
    ZBC_EV_SANITIZER = 1u << 9,
    ZBC_EV_BRANCH    = 1u << 10,
    ZBC_EV_RELOAD    = 1u << 11
};
#define ZBC_EV_ALL 0xFFFu
#define ZBC_TRACE_SCHEMA_VERSION 2

/* The bytes of the trace: called with the header, then once per record. */
typedef void (*zbc_ev_out_f)(void *ctx, const uint8_t *bytes, size_t len);

#define ZBC_EV_MAX_CORO_MASKS 1024   /* coroutines with a mask of their own */

typedef struct {
    uint8_t *p;
    size_t   len, cap;
    int      oom;
} zbc_ev_buf_t;

typedef struct zbc_ev_sink_s {
    zbc_ev_out_f  out;
    void         *ctx;
    /* masks[i]: coroutine i's events (0..n_masks-1); others use `mask`. */
    uint32_t      mask;
    uint32_t      masks[ZBC_EV_MAX_CORO_MASKS];
    uint32_t      n_masks;
    uint32_t      any;        /* OR of every mask (0: no events at all) */
    /* Record state. */
    int64_t       seq;        /* the next record's seq */
    int64_t       prev;       /* the last written seq (-1: none) */
    uint32_t      next_id;    /* frame ids, as the Python VM's scheduler counts them */
    zbc_ev_buf_t  rec;        /* the record being built */
    zbc_ev_buf_t  frame;      /* length prefix + record, handed to `out` */
    /* String interning: open addressing, ids in first-seen order. */
    char        **strs;       /* by id */
    uint32_t      n_strs, cap_strs;
    uint32_t     *slots;      /* hash slots: id + 1, 0 = empty */
    uint32_t      n_slots;
    int           started;    /* the header is written */
} zbc_ev_sink_t;

/* Set up `s` (no events watched yet) and write nothing. */
void zbc_ev_init(zbc_ev_sink_t *s, zbc_ev_out_f out, void *ctx);
/* Release what `s` allocated. */
void zbc_ev_free(zbc_ev_sink_t *s);
/* A sink on the heap (zbc_ev_init'ed), for hosts that cannot size the
 * struct (ctypes, other languages); NULL when out of memory. */
zbc_ev_sink_t *zbc_ev_new(zbc_ev_out_f out, void *ctx);
/* zbc_ev_free and release a sink from zbc_ev_new (NULL: nothing). */
void zbc_ev_delete(zbc_ev_sink_t *s);
/* Write the header: magic, version and a map of `n` string pairs
 * (keys[i] -> vals[i]; keys need not be sorted). Records written before it
 * get an empty header first. Returns 0, or -1 when out of memory. */
int  zbc_ev_header(zbc_ev_sink_t *s, const char *const *keys,
                   const char *const *vals, uint32_t n);
/* Watch `mask` in coroutine `coro`, or in all of them (coro < 0; this also
 * resets the per-coroutine masks). mask 0 turns events off. */
void zbc_ev_watch(zbc_ev_sink_t *s, uint32_t mask, int32_t coro);
/* The mask of coroutine `coro`. */
static inline uint32_t zbc_ev_mask(const zbc_ev_sink_t *s, uint32_t coro) {
    if (!s || !s->any) return 0;
    return coro < s->n_masks ? s->masks[coro] : s->mask;
}

/* Building a record: begin, then the detail map (zbc_ev_map with its pair
 * count, then each key in sorted order and its value), then end. Lists:
 * zbc_ev_list with the count, then the values. end writes an empty extras
 * map, frames the record and hands it to `out`. */
void zbc_ev_begin(zbc_ev_sink_t *s, const char *kind, uint32_t coro, uint32_t src_ref);
void zbc_ev_map(zbc_ev_sink_t *s, uint32_t n);
void zbc_ev_list(zbc_ev_sink_t *s, uint32_t n);
void zbc_ev_key(zbc_ev_sink_t *s, const char *k);
void zbc_ev_str(zbc_ev_sink_t *s, const char *v, size_t len);
void zbc_ev_int(zbc_ev_sink_t *s, int64_t v);
void zbc_ev_uint(zbc_ev_sink_t *s, uint64_t v);
void zbc_ev_bool(zbc_ev_sink_t *s, int v);
void zbc_ev_null(zbc_ev_sink_t *s);
void zbc_ev_end(zbc_ev_sink_t *s);

#ifdef __cplusplus
}
#endif

#endif /* ZUSPEC_ZBC_EVENTS_H */
