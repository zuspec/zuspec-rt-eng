/*
 * pssvm_host.c -- see pssvm.h.
 *
 * An engine owns a copy of the image and the component object, which lives
 * as long as the engine, so component state carries from call to call. Each
 * call owns a timebase that runs the entry's threads; it is dropped at
 * pssvm_call_end.
 */
#include "pssvm.h"
#include "zbc_engine.h"
#include "zbc_events.h"
#include "zbc_ops.h"
#include "zsp_alloc.h"
#include "zsp_timebase.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PSSVM_ERR_MAX 2048

enum { CALL_READY, CALL_DONE, CALL_ERROR };

struct pssvm_s {
    uint8_t     *data;          /* the engine's copy of the image */
    zbc_image_t  img;
    uint32_t     spin_stuck;    /* img.spin_stuck points here */
    uint64_t    *cobj;          /* component object (img.cobj), or NULL */
    int          constructed;
    zbc_host_t  *host;
    uint32_t     verbosity;     /* pssvm_load's `verbosity=N`, with no host */
    uint64_t     step_limit;    /* pssvm_load's `step_limit=N` (zbc_host_t's) */
    uint32_t     seed_keyed;    /* keyed seeds: pssvm_load's `seed_mode` and SEEDKEY (zbc_host_t's) */
    struct zbc_ev_sink_s *events; /* pssvm_set_events, or NULL */
    uint32_t     irq_coro;      /* pssvm_set_irq's handler (0xFFFFFFFF: none) */
    uint8_t     *bound;         /* pssvm_bind's, per coroutine, or NULL */
    uint32_t     n_notes;       /* pssvm_notify's, until the next pssvm_run */
    struct { uint32_t kind, id; uint64_t value; } notes[PSSVM_NOTES_MAX];
    zbc_dbg_t    dbg;           /* pssvm_dbg_*: breakpoints, pause, step */
    int          dbg_on;
    uint64_t     gen;           /* the generation, 1 at load; pssvm_reload adds one */
    zsp_alloc_t  alloc;
    char         err[PSSVM_ERR_MAX];
};

struct pssvm_call_s {
    pssvm_t        *e;
    int             noop;      /* nothing to run: DONE at once ($run_end) */
    uint64_t        seed;
    zsp_timebase_t *tb;
    zbc_result_t    res;
    uint64_t        args[ZBC_CALL_MAX_ARGS];
    uint32_t        pin_slot[ZBC_CALL_MAX_ARGS];   /* an action's arguments (F2.3b) */
    int64_t         pin_val[ZBC_CALL_MAX_ARGS];
    uint32_t        n_pins;
    uint64_t        spawn_budget;
    int             state;
    int             has_ret;
    zbc_host_t      host;       /* the engine's, with imports and memory yielding */
    zbc_yield_t     yield;      /* the pending request, in engine terms */
    pssvm_req_t     req;        /* ... and as pssvm_take / pssvm_request show it */
    uint32_t        next_req;   /* the last req_id given */
    int             taken;      /* the pending request was taken */
    pssvm_req_t     wait_reqs;  /* pssvm_request after a WAIT on REQS */
    int             in_wait_reqs;
    uint8_t         req_args[8 * ZBC_CALL_MAX_ARGS];
    char            call[96];   /* the entry's name, JSON-escaped ("" = the image's) */
    char            err[PSSVM_ERR_MAX];
    zbc_obj_t       obj;        /* the action object (pssvm_call_start_obj) */
    uint64_t       *own_slots;  /* ... when pssvm_call_start allocated it */
    const char     *layout;     /* the action entry's object layout (JSON), or NULL */
};

/* The host a run under `e` uses: the engine's messages, verbosity and import
 * log (pssvm_set_host), with imports and memory answered through `y`. */
static void call_host(pssvm_t *e, zbc_host_t *host, zbc_yield_t *y) {
    memset(host, 0, sizeof(*host));
    if (e->host) {
        host->import_log = e->host->import_log;
        host->message    = e->host->message;
        host->msg_ctx    = e->host->msg_ctx;
        host->verbosity  = e->host->verbosity;
        host->events     = e->host->events;
    } else {
        host->verbosity  = e->verbosity;
    }
    if (e->events) host->events = e->events;
    host->step_limit = e->step_limit;
    host->seed_stream = !e->seed_keyed;
    memset(y, 0, sizeof(*y));
    y->err_coro = 0xFFFFFFFFu;
    y->err_solve = 0xFFFFFFFFu;
    y->err_act = 0xFFFFFFFFu;
    host->yield = y;
    host->bound = e->bound;
    host->dbg = e->dbg_on ? &e->dbg : NULL;
    e->dbg.frames = NULL;   /* the last call's frames are gone */
    e->dbg.pend.n_hits = 0;
}

/* pssvm_error(NULL, NULL): why the last pssvm_load failed. */
static char g_load_err[PSSVM_ERR_MAX];

static const char *zbc_status_name(int st) {
    switch (st) {
    case ZBC_ERR_TOO_SMALL:      return "image too small";
    case ZBC_ERR_BAD_MAGIC:      return "bad magic";
    case ZBC_ERR_BAD_VERSION:    return "bad format version";
    case ZBC_ERR_BAD_ABI:        return "bad ABI id";
    case ZBC_ERR_BAD_SECTIONS:   return "bad section table";
    case ZBC_ERR_NO_CODE:        return "no CODE section";
    case ZBC_ERR_NO_CORO:        return "no CORO section";
    case ZBC_ERR_UNSUPPORTED_OP: return "unsupported operation";
    case ZBC_ERR_BAD_ENTRY:      return "bad entry coroutine";
    case ZBC_ERR_STEP_LIMIT:     return "step limit exhausted";
    case ZBC_ERR_DIV_ZERO:       return "division by zero";
    case ZBC_ERR_SPAWN_LIMIT:    return "spawn limit exhausted";
    case ZBC_ERR_SELECT_NONE:    return "select: no eligible branch";
    case ZBC_ERR_SOLVE_UNSAT:    return "solve: unsatisfiable";
    case ZBC_ERR_SOLVE_FAIL:     return "solve: solver failure";
    case ZBC_ERR_COMP_INIT:      return "component tree not supported";
    case ZBC_ERR_CALL_DEPTH:     return "call depth exceeded";
    case ZBC_ERR_RUNTIME:        return "run-time error";
    case ZBC_ERR_DEADLOCK:       return "deadlock";
    case ZBC_ERR_COMP_UNCHOSEN:
        return "a component attribute is read before the action's solve "
               "chose its component instance (comp, LRM 13.4.5)";
    case ZBC_ERR_OOB_REG:        return "more registers than the engine has (ZBC_MAX_REGS)";
    case ZBC_ERR_OOB_LOCAL:      return "more locals than the engine has (ZBC_MAX_LOCALS)";
    default:                     return "engine error";
    }
}

/* Write the error JSON {"message", "status", "halted_op"} into `buf`.
 * Messages are engine-made and carry no quotes or backslashes, except the
 * entry name, which set_err_name escapes. */
static void set_err(char *buf, int status, int halted_op, const char *fmt, ...) {
    char msg[PSSVM_ERR_MAX / 2];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    snprintf(buf, PSSVM_ERR_MAX, "{\"message\":\"%s\",\"status\":%d,\"halted_op\":%d}",
             msg, status, halted_op);
}

static void json_escape(char *dst, size_t cap, const char *s) {
    size_t n = 0;
    for (; *s && n + 7 < cap; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { dst[n++] = '\\'; dst[n++] = (char)c; }
        else if (c < 0x20) n += (size_t)snprintf(dst + n, cap - n, "\\u%04x", c);
        else dst[n++] = (char)c;
    }
    dst[n] = 0;
}

int pssvm_abi_version(void) { return PSSVM_ABI_VERSION; }

pssvm_t *pssvm_load(const uint8_t *img, size_t len, const char *opts) {
    /* opts: `verbosity=N`, the highest message() level a run with no host
     * (pssvm_set_host) reports (default 0: only NONE); `step_limit=N`, the
     * bytecode steps each frame may run (default ZBC_STEP_LIMIT; 0: no
     * limit, as on the Python VM); `seed_mode=keyed` (the default when the
     * image has SEEDKEY), children's seeds by what they traverse, not their
     * position (F3.9; explicit keyed needs SEEDKEY); `seed_mode=stream`, by
     * position */
    g_load_err[0] = 0;
    if (img == NULL) {
        set_err(g_load_err, PSSVM_E_IMAGE, 0, "no image");
        return NULL;
    }
    pssvm_t *e = (pssvm_t *)calloc(1, sizeof(pssvm_t));
    e->irq_coro = 0xFFFFFFFFu;
    e->gen = 1;
    const char *v = opts ? strstr(opts, "verbosity=") : NULL;
    if (v) e->verbosity = (uint32_t)strtoul(v + 10, NULL, 10);
    const char *sl = opts ? strstr(opts, "step_limit=") : NULL;
    if (sl) {
        uint64_t n = (uint64_t)strtoull(sl + 11, NULL, 10);
        e->step_limit = n ? n : ZBC_STEP_UNLIMITED;
    }
    const char *sm = opts ? strstr(opts, "seed_mode=") : NULL;
    int keyed_asked = sm && strncmp(sm + 10, "keyed", 5) == 0;
    e->seed_keyed = !(sm && strncmp(sm + 10, "stream", 6) == 0);
    e->data = (uint8_t *)malloc(len ? len : 1);
    memcpy(e->data, img, len);
    int rc = zbc_image_open(&e->img, e->data, len);
    if (rc != ZBC_OK) {
        set_err(g_load_err, PSSVM_E_IMAGE, 0, "bad image: %s (%d)", zbc_status_name(rc), rc);
        free(e->data);
        free(e);
        return NULL;
    }
    if (keyed_asked && !e->img.seed_keys) {
        set_err(g_load_err, PSSVM_E_IMAGE, 0,
                "seed_mode=keyed: the image has no seed keys (SEEDKEY)");
        free(e->data);
        free(e);
        return NULL;
    }
    if (!e->img.seed_keys) e->seed_keyed = 0;
    e->img.spin_stuck = &e->spin_stuck;
    zsp_alloc_malloc_init(&e->alloc);
    return e;
}

void pssvm_set_host(pssvm_t *e, zbc_host_t *host) {
    if (e) e->host = host;
}

void pssvm_set_events(pssvm_t *e, struct zbc_ev_sink_s *sink) {
    if (e) e->events = sink;
}

/* zbc_image_check with the engine's host; sets `err` on refusal. */
static int check_image(pssvm_t *e, char *err) {
    int halted = 0;
    zbc_host_t host;
    zbc_yield_t y;
    call_host(e, &host, &y);
    int rc = zbc_image_check(&e->img, &host, &halted);
    if (rc == ZBC_ERR_UNSUPPORTED_OP && halted == ZBC_OP_HEAP) {
        /* heap.md s.9: name what the C engine lacks, not just the opcode. */
        set_err(err, PSSVM_E_IMAGE, halted, "image not runnable: heap ops (strings built at "
                "run time, list/map/set) are not supported by the C engine yet (M14)");
        return PSSVM_E_IMAGE;
    }
    if (rc == ZBC_ERR_UNSUPPORTED_OP && halted == ZBC_HALT_ADDR_CLAIM) {
        set_err(err, PSSVM_E_IMAGE, 0, "image not runnable: address claims (the run's "
                "claim ledger and contiguous placement) are not supported by the C engine yet (M14)");
        return PSSVM_E_IMAGE;
    }
    if (rc != ZBC_OK) {
        set_err(err, PSSVM_E_IMAGE, halted, "image not runnable: %s (%d)",
                zbc_status_name(rc), rc);
        return PSSVM_E_IMAGE;
    }
    return PSSVM_OK;
}

int pssvm_construct(pssvm_t *e, const char *root_type,
                    const uint8_t *args, size_t len) {
    (void)args;
    if (e == NULL) return PSSVM_E_ARGS;
    if (e->constructed) {
        set_err(e->err, PSSVM_E_STATE, 0, "already constructed");
        return PSSVM_E_STATE;
    }
    /* Other roots and constructor arguments come with P4.10 (instances). */
    if ((root_type != NULL && root_type[0] != 0) || len != 0) {
        set_err(e->err, PSSVM_E_ARGS, 0, "only the image's root, without arguments, is supported");
        return PSSVM_E_ARGS;
    }
    int rc = check_image(e, e->err);
    if (rc != PSSVM_OK) return rc;

    const zbc_comp *comp = e->img.comp;
    if (comp) {
        e->cobj = (uint64_t *)calloc(comp->n_slots ? comp->n_slots : 1, sizeof(uint64_t));
        e->img.cobj = e->cobj;
        if (comp->init_coro != 0xFFFFFFFFu) {
            zbc_result_t res = {ZBC_OK, 0, 0, 0};
            uint64_t budget = ZBC_SPAWN_LIMIT;
            zbc_host_t host;
            zbc_yield_t y;
            call_host(e, &host, &y);
            host.dbg = NULL;    /* construction never stops: a pending pause waits for the run */
            zsp_timebase_t *tb = zsp_timebase_create(&e->alloc, ZSP_TIME_PS);
            zsp_timebase_thread_create(
                tb, &zbc_interp_task, ZSP_THREAD_FLAGS_NONE,
                &e->img, (int)comp->init_coro, &res, (zbc_obj_t *)0, (uint32_t)0,
                &budget, &host, (uint64_t)0, (const uint64_t *)0, (uint32_t)0,
                &res, (uint32_t)0, ZBC_FRAME_ROOT);
            int yielded = zbc_drain_until(tb, &e->img, &res, &y);
            zsp_timebase_destroy(tb);
            if (yielded) {
                /* Construction must not need the host: bind handles only. */
                free(e->cobj);
                e->cobj = NULL;
                e->img.cobj = NULL;
                set_err(e->err, PSSVM_ERROR, ZBC_OP_IMPORT,
                        "construct-yield: construction made a bus access or import");
                return -1;
            }
            if (res.status != ZBC_OK) {
                set_err(e->err, PSSVM_ERROR, res.halted_op, "construction failed: %s (%d)",
                        zbc_status_name(res.status), res.status);
                return -1;
            }
        }
    }
    e->constructed = 1;
    return PSSVM_OK;
}

int pssvm_fresh(pssvm_t *e, const char *root_type) {
    if (e == NULL) return PSSVM_E_ARGS;
    free(e->cobj);
    e->cobj = NULL;
    e->img.cobj = NULL;
    e->constructed = 0;
    e->err[0] = 0;
    return pssvm_construct(e, root_type, NULL, 0);
}

const char *pssvm_meta(pssvm_t *e, const char *name) {
    return e ? zbc_image_meta(&e->img, name) : NULL;
}

int pssvm_exec_id(pssvm_t *e, const char *path) {
    if (e == NULL || path == NULL) return -1;
    for (uint32_t i = 0; i < e->img.exec_count; i++) {
        const char *p = zbc_image_str(&e->img, e->img.execs[i].path);
        if (p && !strcmp(p, path)) return (int)i;
    }
    return -1;
}

const char *pssvm_exec_path(pssvm_t *e, uint32_t id) {
    return e && id < e->img.exec_count
           ? zbc_image_str(&e->img, e->img.execs[id].path) : NULL;
}

const char *pssvm_string(pssvm_t *e, uint32_t idx) {
    const zbc_msgtab *mt = e ? e->img.msgtab : NULL;
    return mt && idx < mt->n_model_strings
           ? e->img.msgstrb + e->img.msgstr_off[idx] : NULL;
}

int pssvm_event_id(pssvm_t *e, const char *path) {
    if (e == NULL || path == NULL) return -1;
    for (uint32_t i = 0; i < e->img.event_count; i++) {
        const char *p = zbc_image_str(&e->img, e->img.events[i].path);
        if (p && !strcmp(p, path)) return (int)i;
    }
    return -1;
}

int pssvm_time_exp(pssvm_t *e) {
    if (e == NULL || e->img.ident == NULL
            || e->img.ident_size < sizeof(zbc_ident)) return -12;
    return (int32_t)e->img.ident->time_exp;
}

size_t pssvm_comp_read(pssvm_t *e, uint64_t *buf, size_t cap) {
    if (e == NULL || e->cobj == NULL || e->img.comp == NULL) return 0;
    size_t n = e->img.comp->n_slots;
    if (buf != NULL) memcpy(buf, e->cobj, (n < cap ? n : cap) * sizeof(uint64_t));
    return n;
}

size_t pssvm_comp_write(pssvm_t *e, const uint64_t *buf, size_t n) {
    if (e == NULL || e->cobj == NULL || e->img.comp == NULL || buf == NULL) return 0;
    size_t m = e->img.comp->n_slots;
    if (n < m) m = n;
    memcpy(e->cobj, buf, m * sizeof(uint64_t));
    return m;
}

/* Whether N's and N+1's component objects lay out alike: the same instances
 * at the same bases and the same slot count (so N's slots carry over). */
static int same_layout(const zbc_image_t *a, const zbc_image_t *b) {
    if (a->comp == NULL || b->comp == NULL) return a->comp == b->comp;
    if (a->comp->n_slots != b->comp->n_slots || a->comp->n_inst != b->comp->n_inst) return 0;
    return memcmp(a->comp_bases, b->comp_bases, 4ull * a->comp->n_inst) == 0;
}

/* One `inst\t<path>\t<type>\t<base>\t<end>\t<sig>` line of an image's
 * `pssc.native` META (be-bc generations.native_inst_lines); older images
 * give the path only (`full` is then 0). */
typedef struct {
    const char *path, *typ, *sig;
    size_t      pl, tl, sl;
    uint32_t    base, end;
    int         full;
} native_inst_t;

/* The next inst line at or after *p into `o`; 0 at the end of the META. */
static int next_inst(const char **p, native_inst_t *o) {
    const char *q = *p;
    while (q && *q) {
        const char *eol = strchr(q, '\n');
        if (eol == NULL) eol = q + strlen(q);
        if (!strncmp(q, "inst\t", 5)) {
            const char *col[6];
            size_t cl[6];
            int n = 0;
            const char *c = q + 5;
            while (n < 6) {
                const char *t = memchr(c, '\t', (size_t)(eol - c));
                const char *ce = t ? t : eol;
                col[n] = c; cl[n] = (size_t)(ce - c); n++;
                if (t == NULL) break;
                c = t + 1;
            }
            memset(o, 0, sizeof(*o));
            o->path = col[0]; o->pl = cl[0];
            if (n >= 5) {
                o->typ = col[1]; o->tl = cl[1];
                o->base = (uint32_t)strtoul(col[2], NULL, 10);
                o->end = (uint32_t)strtoul(col[3], NULL, 10);
                o->sig = col[4]; o->sl = cl[4];
                o->full = o->end >= o->base;
            }
            *p = *eol ? eol + 1 : eol;
            return 1;
        }
        q = *eol ? eol + 1 : eol;
    }
    *p = q;
    return 0;
}

/* Whether both images list their instances with types and slot ranges, so
 * a reload can migrate by path. */
static int has_inst_layout(pssvm_t *e) {
    const char *p = zbc_image_meta(&e->img, "pssc.native");
    native_inst_t in;
    int any = 0;
    if (p == NULL || e->img.comp == NULL) return 0;
    while (next_inst(&p, &in)) {
        if (!in.full || in.end > e->img.comp->n_slots) return 0;
        any = 1;
    }
    return any;
}

/* Copy N's component state into N+1's freshly built tree by instance path
 * (be-bc generations.migrate): each instance whose type and fields are
 * unchanged takes N's slots; the rest keep their fresh values. */
static void migrate_by_path(pssvm_t *e, pssvm_t *n) {
    const char *np = zbc_image_meta(&n->img, "pssc.native");
    native_inst_t b, a;
    while (next_inst(&np, &b)) {
        const char *op = zbc_image_meta(&e->img, "pssc.native");
        while (next_inst(&op, &a)) {
            if (a.pl != b.pl || strncmp(a.path, b.path, a.pl)) continue;
            if (a.tl == b.tl && !strncmp(a.typ, b.typ, a.tl) && a.sl == b.sl
                && !strncmp(a.sig, b.sig, a.sl) && a.end - a.base == b.end - b.base
                && a.end > a.base)
                memcpy(n->cobj + b.base, e->cobj + a.base,
                       (size_t)(a.end - a.base) * sizeof(uint64_t));
            break;
        }
    }
}

int pssvm_reload(pssvm_t *e, const uint8_t *img, size_t len, uint32_t flags) {
    if (e == NULL) return PSSVM_E_ARGS;
    if (flags & ~(uint32_t)PSSVM_R_STRICT) {
        set_err(e->err, PSSVM_E_ARGS, 0, "reload: unsupported flags 0x%x", (unsigned)flags);
        return PSSVM_E_ARGS;
    }
    pssvm_t *n = pssvm_load(img, len, NULL);
    if (n == NULL) {
        snprintf(e->err, PSSVM_ERR_MAX, "%s", g_load_err);
        return PSSVM_E_IMAGE;
    }
    uint64_t gen = e->gen + 1;
    uint64_t old_api = e->img.ident ? e->img.ident->api_hash : 0;
    uint64_t new_api = n->img.ident ? n->img.ident->api_hash : 0;
    if (old_api != new_api) {
        set_err(e->err, PSSVM_E_API, 0, "api: generation %llu changes the entry points or "
                "imports (api hash %016llx -> %016llx)", (unsigned long long)gen,
                (unsigned long long)old_api, (unsigned long long)new_api);
        pssvm_free(n);
        return PSSVM_E_API;
    }
    int same = same_layout(&e->img, &n->img);
    if (!same && ((flags & PSSVM_R_STRICT) || !has_inst_layout(e) || !has_inst_layout(n))) {
        /* Non-strict, the state moves by instance path; that needs the
         * paths, types and slot ranges in both images' META. */
        set_err(e->err, PSSVM_E_API, 0, "structure: generation %llu changes the component "
                "tree's layout%s", (unsigned long long)gen,
                (flags & PSSVM_R_STRICT) ? "" : " (an image lists no instance layout to migrate by)");
        pssvm_free(n);
        return PSSVM_E_API;
    }
    n->host = e->host;
    n->events = e->events;
    n->verbosity = e->verbosity;
    n->step_limit = e->step_limit;
    n->seed_keyed = e->seed_keyed;
    if (e->constructed) {
        /* N+1's tree is built beside N's; it must not touch the bus. */
        int rc = pssvm_construct(n, NULL, NULL, 0);
        if (rc != PSSVM_OK) {
            set_err(e->err, PSSVM_E_API, 0, "%s: generation %llu %s",
                    strstr(n->err, "construct-yield") ? "bus" : "construct",
                    (unsigned long long)gen,
                    strstr(n->err, "construct-yield") ? "made a bus access or import while constructing"
                                                       : "failed to construct");
            pssvm_free(n);
            return PSSVM_E_API;
        }
        if (e->cobj && n->cobj) {
            if (same)
                memcpy(n->cobj, e->cobj, e->img.comp->n_slots * sizeof(uint64_t));
            else
                migrate_by_path(e, n);
        }
    }
    /* Swap N+1 into `e` (the host holds `e`); the host's bindings, interrupt
     * handler and breakpoints name N's coroutines, so they are cleared. */
    free(e->data);
    free(e->cobj);
    free(e->bound);
    e->data = n->data;
    e->img = n->img;
    e->img.spin_stuck = &e->spin_stuck;
    e->cobj = n->cobj;
    e->img.cobj = e->cobj;
    e->constructed = n->constructed;
    e->bound = NULL;
    e->irq_coro = 0xFFFFFFFFu;
    e->dbg.n_breaks = 0;
    e->gen = gen;
    e->err[0] = 0;
    n->data = NULL;
    n->cobj = NULL;
    pssvm_free(n);
    return PSSVM_OK;
}

uint64_t pssvm_generation(pssvm_t *e) { return e ? e->gen : 0; }

/* The slots of action entry `entry`'s object (NULL or "": the image's entry
 * coroutine), as pssc native.py `_action_obj` counts them: its activation's
 * size, else the fields of the ENTRY obj layout; 0 for a function or none. */
/* The entry named `entry`: its symbol, or an action's qualified type
 * (`pss_top::A`); NULL or "": the one on the image's entry coroutine. */
/* The elements of the JSON list `[[name, descriptor], ...]` at `p` (an
 * entry's sig params or obj layout): items[i] is the '[' of element i.
 * Returns their number (at most max), or -1 if `p` is not such a list. */
static int json_pairs(const char *p, const char **items, int max) {
    if (p == NULL || *p != '[') return -1;
    int depth = 0, n = 0, str = 0;
    for (; *p; p++) {
        if (str) {
            if (*p == '\\' && p[1]) p++;
            else if (*p == '"') str = 0;
            continue;
        }
        if (*p == '"') str = 1;
        else if (*p == '[' || *p == '{') {
            if (++depth == 2 && *p == '[' && n < max) items[n++] = p;
        } else if (*p == ']' || *p == '}') {
            if (--depth == 0) return n;
        }
    }
    return -1;
}

/* Element `it` (from json_pairs) has name `name`. */
static int json_pair_is(const char *it, const char *name) {
    size_t k = strlen(name);
    return it[1] == '"' && strncmp(it + 2, name, k) == 0 && it[2 + k] == '"';
}

/* `"key":<int>` in element `it` (up to its end); dflt if absent. */
static long json_pair_int(const char *it, const char *key, long dflt) {
    const char *end = strchr(it, ']');
    const char *f = strstr(it, key);
    if (f == NULL || (end && f > end)) return dflt;
    f += strlen(key);
    if (strncmp(f, "true", 4) == 0) return 1;
    if (strncmp(f, "false", 5) == 0) return 0;
    return strtol(f, NULL, 10);
}

/* An exported action's arguments fix its parameters' fields (LRM 20.10, F2.3b;
 * pyvm VM._arg_bounds): each value cut to its parameter's width (and sign)
 * pins the slot its name has in the entry's object layout. */
static int action_pins(pssvm_t *e, const zbc_entry *en, pssvm_call_t *h,
                       size_t nargs, const char *ename) {
    const char *sig = en->sig ? zbc_image_str(&e->img, en->sig) : NULL;
    const char *obj = en->obj ? zbc_image_str(&e->img, en->obj) : NULL;
    const char *pp = sig ? strstr(sig, "\"params\":") : NULL;
    const char *params[ZBC_CALL_MAX_ARGS], *fields[256];
    int np = pp ? json_pairs(pp + 9, params, ZBC_CALL_MAX_ARGS) : 0;
    int nf = json_pairs(obj, fields, 256);
    if (np < 0) np = 0;
    if ((size_t)np != nargs) {
        set_err(e->err, PSSVM_E_ARGS, 0, "action %s takes %d arguments, not %u",
                ename, np, (unsigned)nargs);
        return PSSVM_E_ARGS;
    }
    for (int i = 0; i < np; i++) {
        int slot = -1;
        for (int f = 0; f < nf && slot < 0; f++) {
            const char *q = params[i] + 2, *qe = strchr(q, '"');
            char name[128];
            size_t k = qe ? (size_t)(qe - q) : 0;
            if (k >= sizeof(name)) k = sizeof(name) - 1;
            memcpy(name, q, k);
            name[k] = 0;
            if (json_pair_is(fields[f], name)) slot = f;
        }
        if (slot < 0) {
            set_err(e->err, PSSVM_E_ARGS, 0, "action %s: parameter %d is no field", ename, i);
            return PSSVM_E_ARGS;
        }
        long w = json_pair_int(params[i], "\"width\":", 64);
        int sgn = (int)json_pair_int(params[i], "\"signed\":", 0);
        uint64_t v = h->args[i];
        if (w > 0 && w < 64) {
            v &= (1ull << w) - 1;
            if (sgn && (v >> (w - 1))) v |= ~((1ull << w) - 1);
        }
        h->pin_slot[i] = (uint32_t)slot;
        h->pin_val[i] = (int64_t)v;
    }
    h->n_pins = (uint32_t)np;
    return PSSVM_OK;
}

static const zbc_entry *find_entry(pssvm_t *e, const char *entry) {
    for (uint32_t i = 0; e->img.entries && i < e->img.entry_count; i++) {
        const zbc_entry *x = &e->img.entries[i];
        if (entry == NULL || entry[0] == 0) {
            if (x->coro == e->img.entry_coro) return x;
            continue;
        }
        const char *nm = zbc_image_str(&e->img, x->name);
        if (nm && !strcmp(nm, entry)) return x;
    }
    if (entry == NULL || entry[0] == 0) return NULL;
    for (uint32_t i = 0; e->img.entries && i < e->img.entry_count; i++) {
        const zbc_entry *x = &e->img.entries[i];
        const char *qn = x->kind == ZBC_ENTRY_ACTION && x->qname
                         ? zbc_image_str(&e->img, x->qname) : NULL;
        if (qn && !strcmp(qn, entry)) return x;
    }
    return NULL;
}

static uint32_t action_slots(pssvm_t *e, const char *entry) {
    const zbc_entry *en = find_entry(e, entry);
    if (en == NULL || en->kind != ZBC_ENTRY_ACTION) return 0;
    const zbc_act *a = e->img.acttab ? zbc_image_act(&e->img, en->coro) : NULL;
    if (a != NULL) return a->size;
    const char *p = en->obj ? zbc_image_str(&e->img, en->obj) : NULL;
    uint32_t n = 0;
    int depth = 0, str = 0;
    for (; p && *p; p++) {                 /* [[name, desc], ...]: depth-2 '[' */
        if (str) { if (*p == '\\' && p[1]) p++; else if (*p == '"') str = 0; continue; }
        if (*p == '"') str = 1;
        else if (*p == '[' || *p == '{') { if (++depth == 2 && *p == '[') n++; }
        else if (*p == ']' || *p == '}') depth--;
    }
    return n;
}

pssvm_call_t *pssvm_call_start(pssvm_t *e, const char *entry, const char *comp_path,
                               const uint8_t *args, size_t len, uint64_t seed) {
    /* An action entry gets an object of its own, zeroed, which the call owns
     * (pssvm_call_end frees it); use pssvm_call_start_obj to read it after. */
    uint32_t n = e ? action_slots(e, entry) : 0;
    uint64_t *slots = n ? (uint64_t *)calloc(n, sizeof(uint64_t)) : NULL;
    pssvm_call_t *h = pssvm_call_start_obj(e, entry, comp_path, args, len, seed, slots, n);
    if (h != NULL) h->own_slots = slots;
    else free(slots);
    return h;
}

/* The index (pre-order, as img.comp_bases) of the instance at `path`, from
 * the image's `pssc.native` lines `inst\t<path>...` (one per instance, in
 * that order); -1 if there is none. */
static int64_t inst_index(pssvm_t *e, const char *path) {
    const char *p = zbc_image_meta(&e->img, "pssc.native");
    size_t pl = strlen(path);
    native_inst_t in;
    int64_t i = 0;
    if (p == NULL || e->img.comp == NULL) return -1;
    for (; next_inst(&p, &in); i++)
        if (in.pl == pl && !strncmp(in.path, path, pl))
            return i < (int64_t)e->img.comp->n_inst ? i : -1;
    return -1;
}

pssvm_call_t *pssvm_call_start_obj(pssvm_t *e, const char *entry, const char *comp_path,
                                   const uint8_t *args, size_t len, uint64_t seed,
                                   uint64_t *slots, uint32_t n_slots) {
    if (e == NULL) return NULL;
    if (n_slots && slots == NULL) {
        set_err(e->err, PSSVM_E_ARGS, 0, "no slots for an action object of %u",
                (unsigned)n_slots);
        return NULL;
    }
    if (!e->constructed && pssvm_construct(e, NULL, NULL, 0) != PSSVM_OK) return NULL;
    if (check_image(e, e->err) != PSSVM_OK) return NULL;
    if (entry != NULL && strcmp(entry, "$run_end") == 0) {
        /* A simulation's end of run (F2.5): this engine refuses an image with
         * exec run_start/run_end (ZBC_ERR_COMP_INIT), so it has none to run. */
        pssvm_call_t *n = (pssvm_call_t *)calloc(1, sizeof(pssvm_call_t));
        n->e = e;
        n->noop = 1;
        n->state = CALL_READY;
        return n;
    }

    /* NULL or "": the image's entry coroutine (header), result reported. */
    uint32_t coro = e->img.entry_coro;
    int has_ret = 1;
    const zbc_entry *action = NULL;
    const char *layout = NULL;
    if (entry != NULL && entry[0] != 0) {
        const zbc_entry *found = find_entry(e, entry);
        if (found == NULL) {
            char esc[128];
            json_escape(esc, sizeof(esc), entry);
            set_err(e->err, PSSVM_E_ARGS, 0, "no entry named '%s'", esc);
            return NULL;
        }
        coro = found->coro;
        if (found->kind == ZBC_ENTRY_ACTION && found->obj)
            layout = zbc_image_str(&e->img, found->obj);
        if (found->kind == ZBC_ENTRY_ACTION && len != 0) action = found;
        const char *sig = found->sig ? zbc_image_str(&e->img, found->sig) : NULL;
        has_ret = sig != NULL && strstr(sig, "\"returns\":null") == NULL;
    }
    uint32_t cbase = 0;
    if (comp_path != NULL && comp_path[0] != 0) {
        int64_t i = inst_index(e, comp_path);
        if (i < 0) {
            char esc[128];
            json_escape(esc, sizeof(esc), comp_path);
            set_err(e->err, PSSVM_E_ARGS, 0, "no component instance '%s'", esc);
            return NULL;
        }
        cbase = e->img.comp_bases[i];
    }
    if ((len & 7) != 0 || len / 8 > ZBC_CALL_MAX_ARGS || (len && args == NULL)) {
        set_err(e->err, PSSVM_E_ARGS, 0, "bad argument size %u", (unsigned)len);
        return NULL;
    }

    pssvm_call_t *h = (pssvm_call_t *)calloc(1, sizeof(pssvm_call_t));
    h->e = e;
    for (size_t i = 0; i < len / 8; i++) {
        uint64_t v = 0;
        for (int b = 7; b >= 0; b--) v = (v << 8) | args[i * 8 + (size_t)b];
        h->args[i] = v;
    }
    if (action != NULL) {
        char esc[128];
        json_escape(esc, sizeof(esc), entry);
        if (action_pins(e, action, h, len / 8, esc) != PSSVM_OK) {
            free(h);
            return NULL;
        }
    }
    h->spawn_budget = ZBC_SPAWN_LIMIT;
    h->has_ret = has_ret;
    h->state = CALL_READY;
    if (entry != NULL) json_escape(h->call, sizeof(h->call), entry);
    call_host(e, &h->host, &h->yield);
    h->host.cbase = cbase;
    h->host.pin_slot = h->pin_slot;
    h->host.pin_val = h->pin_val;
    h->host.n_pins = h->n_pins;
    h->yield.wait_time = 1;
    h->yield.wait_event = 1;
    h->seed = seed;
    h->obj.slots = slots;
    h->obj.n = n_slots;
    h->layout = layout;
    h->tb = zsp_timebase_create(&e->alloc, ZSP_TIME_PS);
    /* No inline time skips: a lone thread's WAIT must reach the host too
     * (zsp_timebase_wait skips time itself unless the timebase is running;
     * pssvm never calls zsp_timebase_run_until, which is all it else gates). */
    h->tb->running = 1;
    zsp_timebase_thread_create(
        h->tb, &zbc_interp_task, ZSP_THREAD_FLAGS_NONE,
        &e->img, (int)coro, &h->res, n_slots ? &h->obj : (zbc_obj_t *)0, (uint32_t)0,
        &h->spawn_budget,
        &h->host, seed, (const uint64_t *)h->args, (uint32_t)0, &h->res, (uint32_t)0, ZBC_FRAME_ROOT);
    return h;
}

static void set_call_err(pssvm_call_t *h);

/* `notify` of a notification taken (trace-schema.md): the platform side a
 * replay feeds back. A host event: coroutine 0, on when the sink's
 * every-coroutine mask has the bit (pyvm VM.host_event). */
static void ev_notify(zbc_ev_sink_t *s, uint32_t kind, uint32_t id,
                      uint64_t value, int delivered) {
    if (!s || !s->any || !(s->mask & ZBC_EV_NOTIFY)) return;
    zbc_ev_begin(s, "notify", 0, 0);
    zbc_ev_map(s, 3);
    zbc_ev_key(s, "delivered");
    zbc_ev_bool(s, delivered);
    if (kind == PSSVM_N_IRQ) zbc_ev_key(s, "irq");
    else if (kind == PSSVM_N_CHAN) zbc_ev_key(s, "chan");
    else zbc_ev_key(s, "kind");
    zbc_ev_uint(s, kind == PSSVM_N_IRQ || kind == PSSVM_N_CHAN ? id : kind);
    zbc_ev_key(s, "value");
    zbc_ev_uint(s, value);
    zbc_ev_end(s);
}

/* A host put on the host-fed channel `id` (its EVENT row): try_put, the
 * ring as be-bc's _chan_put has it (`buf + (head + count) % depth`). 0, or
 * -1 (full; the call's error set). Spinning get()s see it on their re-test. */
static int chan_put(pssvm_call_t *h, uint32_t id, uint64_t value) {
    pssvm_t *e = h->e;
    const zbc_evtent *ev = &e->img.events[id];
    uint64_t *c = e->cobj;
    if (c[ev->count] >= ev->depth) {
        char esc[128];
        const char *p = zbc_image_str(&e->img, ev->path);
        json_escape(esc, sizeof(esc), p ? p : "?");
        h->state = CALL_ERROR;
        h->res.status = ZBC_ERR_UNSUPPORTED_OP;
        set_err(h->err, PSSVM_ERROR, 0, "host put on full channel %s", esc);
        return -1;
    }
    if (ev->width > 0 && ev->width < 64) {
        value &= (1ull << ev->width) - 1;
        if ((ev->flags & 1) && (value >> (ev->width - 1)) & 1)
            value |= ~((1ull << ev->width) - 1);
    }
    c[ev->buf + (c[ev->head] + c[ev->count]) % ev->depth] = value;
    c[ev->count]++;
    return 0;
}

/* Take the engine's notifications into call `h` (host-abi.md "Notify"): an
 * IRQ starts the interrupt handler as a thread of its own in the root
 * component, seeded like the call (pyvm HostCall._irq); a CHAN puts on its
 * channel. A kind with no handler ends the call in ERROR, as pyvm's VMError
 * does. */
static int take_notes(pssvm_call_t *h) {
    pssvm_t *e = h->e;
    uint32_t n = e->n_notes;
    e->n_notes = 0;
    for (uint32_t i = 0; i < n; i++) {
        int chan = e->notes[i].kind == PSSVM_N_CHAN && e->cobj != NULL
                   && e->notes[i].id < e->img.event_count;
        ev_notify(h->host.events, e->notes[i].kind, e->notes[i].id, e->notes[i].value,
                  chan || (e->notes[i].kind == PSSVM_N_IRQ && e->irq_coro != 0xFFFFFFFFu));
        if (chan) {
            if (chan_put(h, e->notes[i].id, e->notes[i].value) != 0) return -1;
            continue;
        }
        if (e->notes[i].kind == PSSVM_N_IRQ && e->irq_coro != 0xFFFFFFFFu) {
            zsp_timebase_thread_create(
                h->tb, &zbc_interp_task, ZSP_THREAD_FLAGS_NONE,
                &e->img, (int)e->irq_coro, (zbc_result_t *)0, (zbc_obj_t *)0,
                (uint32_t)0, &h->spawn_budget, &h->host, h->seed,
                (const uint64_t *)0, (uint32_t)0, &h->res, (uint32_t)0, ZBC_FRAME_ROOT);
            continue;
        }
        h->state = CALL_ERROR;
        h->res.status = ZBC_ERR_UNSUPPORTED_OP;
        set_err(h->err, PSSVM_ERROR, 0, "notify kind %u has no handler",
                (unsigned)e->notes[i].kind);
        return -1;
    }
    return 0;
}

int pssvm_set_irq(pssvm_t *e, const char *entry) {
    if (e == NULL) return PSSVM_E_ARGS;
    if (entry == NULL || entry[0] == 0) {
        e->irq_coro = 0xFFFFFFFFu;
        return PSSVM_OK;
    }
    for (uint32_t i = 0; i < e->img.entry_count; i++) {
        const char *nm = zbc_image_str(&e->img, e->img.entries[i].name);
        if (nm && strcmp(nm, entry) == 0) {
            e->irq_coro = e->img.entries[i].coro;
            return PSSVM_OK;
        }
    }
    char esc[128];
    json_escape(esc, sizeof(esc), entry);
    set_err(e->err, PSSVM_E_ARGS, 0, "no entry named '%s'", esc);
    return PSSVM_E_ARGS;
}

int pssvm_bind(pssvm_t *e, uint32_t coro, int on) {
    if (e == NULL) return PSSVM_E_ARGS;
    if (coro >= e->img.coro_count) {
        set_err(e->err, PSSVM_E_ARGS, 0, "no coroutine %u", (unsigned)coro);
        return PSSVM_E_ARGS;
    }
    if (e->bound == NULL) {
        if (!on) return PSSVM_OK;
        e->bound = (uint8_t *)calloc(e->img.coro_count, 1);
        if (e->bound == NULL) return PSSVM_E_STATE;
    }
    e->bound[coro] = on ? 1 : 0;
    return PSSVM_OK;
}

int pssvm_notify(pssvm_t *e, uint32_t kind, uint32_t id, uint64_t value) {
    if (e == NULL) return PSSVM_E_ARGS;
    if (kind == PSSVM_N_CHAN && id >= e->img.event_count) {
        set_err(e->err, PSSVM_E_ARGS, 0, "no host-fed channel %u", (unsigned)id);
        return PSSVM_E_ARGS;
    }
    if (e->n_notes >= PSSVM_NOTES_MAX) {
        set_err(e->err, PSSVM_E_STATE, 0, "more than %d notifications before a run",
                PSSVM_NOTES_MAX);
        return PSSVM_E_STATE;
    }
    e->notes[e->n_notes].kind = kind;
    e->notes[e->n_notes].id = id;
    e->notes[e->n_notes].value = value;
    e->n_notes++;
    return PSSVM_OK;
}

int pssvm_run(pssvm_call_t *h) {
    if (h == NULL) return PSSVM_E_ARGS;
    if (h->state != CALL_READY) {
        set_err(h->err, PSSVM_E_STATE, 0, "the call has ended");
        return PSSVM_E_STATE;
    }
    if (h->noop) {
        h->state = CALL_DONE;
        return PSSVM_DONE;
    }
    /* A WAIT is over: the host has waited, and the engine's time (moved to
     * the timed batch when the WAIT was posted) is now. */
    if (h->yield.state == ZBC_YIELD_WAIT) h->yield.state = ZBC_YIELD_NONE;
    /* Run again while stopped: continue. */
    if (h->yield.state == ZBC_YIELD_STOP) pssvm_dbg_resume(h, PSSVM_RESUME);
    if (h->e->n_notes && take_notes(h) != 0) return PSSVM_ERROR;
    /* One request outstanding: until it is answered, nothing runs. */
    h->in_wait_reqs = 0;
    if (h->yield.state == ZBC_YIELD_PENDING) {
        if (!h->taken) return PSSVM_REQS;
        memset(&h->wait_reqs, 0, sizeof(h->wait_reqs));
        h->wait_reqs.status = PSSVM_WAIT;
        h->wait_reqs.on = PSSVM_ON_REQS;
        h->wait_reqs.reg_id = h->wait_reqs.src_ref = 0xFFFFFFFFu;
        h->in_wait_reqs = 1;
        return PSSVM_WAIT;
    }
    if (zbc_drain_until(h->tb, &h->e->img, &h->res, &h->yield) == 0)
        goto quiet;
    /* Stopped on a request: show it as pssvm_req_t. */
    {
        const zbc_yield_t *y = &h->yield;
        pssvm_req_t *r = &h->req;
        memset(r, 0, sizeof(*r));
        if (y->state == ZBC_YIELD_WAIT) {
            /* `now` stays the time the call waits from until it runs again. */
            r->status = PSSVM_WAIT;
            r->on = y->on_event ? PSSVM_ON_EVENT : PSSVM_ON_TIME;
            r->delay = y->delay;
            r->reg_id = 0xFFFFFFFFu;
            r->src_ref = 0xFFFFFFFFu;
            return r->status;
        }
        if (y->state == ZBC_YIELD_STOP) {
            h->res.now = zsp_timebase_current_ticks(h->tb);
            r->status = PSSVM_STOP;
            r->reg_id = 0xFFFFFFFFu;
            r->src_ref = h->e->dbg.stop.src_ref;
            if (h->e->dbg.stop.reason == ZBC_DBG_ERROR)
                h->e->dbg.stop.message = zbc_status_name(h->e->dbg.stop.status);
            return r->status;
        }
        h->res.now = zsp_timebase_current_ticks(h->tb);
        r->status = PSSVM_REQS;
        r->req_id = ++h->next_req ? h->next_req : ++h->next_req;
        h->taken = 0;
        r->api = y->kind == ZBC_YIELD_ACCESS ? PSSVM_API_MEM : PSSVM_API_USER;
        r->fn = y->kind == ZBC_YIELD_ACCESS ? (uint32_t)y->is_write : y->fn_id;
        r->thread = zbc_dbg_thread_id(h->e->dbg_on ? &h->e->dbg : NULL, y->thread);
        r->executor = y->executor;
        r->kind = (uint32_t)y->is_write;
        r->addr = y->addr;
        r->size = y->size;
        r->data = y->data;
        /* The REG side table names the register; C runs at the root
         * instance only (non-root instances: P4.10), so its id is `inst`. */
        {
            const zbc_regent *re = zbc_image_reg_at(&h->e->img, y->pc);
            r->reg_id = re ? re->inst : 0xFFFFFFFFu;
        }
        /* The requesting instruction's PROV record (0xFFFFFFFF: none). */
        r->src_ref = y->pc < h->e->img.code_count && h->e->img.code[y->pc].src_ref
                     ? h->e->img.code[y->pc].src_ref : 0xFFFFFFFFu;
        r->bound = y->kind == ZBC_YIELD_BOUND ? 1u : 0u;
        r->name = zbc_image_import_name(&h->e->img, y->fn_id);   /* NULL: no IMPORT entry */
        for (uint32_t i = 0; i < y->n_args; i++)
            for (int b = 0; b < 8; b++) h->req_args[8 * i + b] = (uint8_t)(y->args[i] >> (8 * b));
        r->args = h->req_args;
        r->args_len = 8u * y->n_args;
        r->blocking = (y->flags & ZBC_F_BLOCKING) ? 1u : 0u;
        r->has_ret = (y->flags & ZBC_F_HAS_RET) ? 1u : 0u;
        r->nret = r->has_ret ? y->n_ret : 0u;
        return r->status;
    }
quiet:
    h->res.now = zsp_timebase_current_ticks(h->tb);
    if (h->res.status != ZBC_OK) {
        h->state = CALL_ERROR;
        set_call_err(h);
        return PSSVM_ERROR;
    }
    h->state = CALL_DONE;
    return PSSVM_DONE;
}

/* A call's ERROR JSON: set_err's fields and where the first error happened,
 * {"call", "coro", "pc"} (coro and pc null when no frame halted, as for a
 * deadlock), and its source as pyvm's VMError has it: "src_ref" (the
 * instruction's PROV record, else its coroutine's) and that record's "file",
 * "line", "col" (null when the image has no PROV). "thread" is null. */
static void set_call_err(pssvm_call_t *h) {
    const zbc_image_t *img = &h->e->img;
    char loc[64], src[320];
    snprintf(src, sizeof(src), "\"src_ref\":null,\"file\":null,\"line\":null,\"col\":null");
    if (h->yield.err_coro != 0xFFFFFFFFu) {
        snprintf(loc, sizeof(loc), "\"coro\":%u,\"pc\":%u",
                 (unsigned)h->yield.err_coro, (unsigned)h->yield.err_pc);
        uint32_t pc = h->yield.err_coro < img->coro_count
                      ? img->coros[h->yield.err_coro].code_start + h->yield.err_pc : 0xFFFFFFFFu;
        uint32_t sr = zbc_image_src_ref(img, h->yield.err_coro, pc);
        const zbc_prov *p = zbc_image_prov(img, sr);
        if (p) {
            const char *path = zbc_image_file(img, p->file);
            char file[200];
            if (path) {
                char esc[196];
                json_escape(esc, sizeof(esc), path);
                snprintf(file, sizeof(file), "\"%s\"", esc);
            } else {
                snprintf(file, sizeof(file), "null");
            }
            snprintf(src, sizeof(src), "\"src_ref\":%u,\"file\":%s,\"line\":%u,\"col\":%u",
                     (unsigned)sr, file, (unsigned)p->line, (unsigned)p->col);
        }
    } else {
        snprintf(loc, sizeof(loc), "\"coro\":null,\"pc\":null");
    }
    /* An unsat solve: "solve" (its SOLVE index) and "pins" ([[var, value]]). */
    char solve[1200];
    solve[0] = 0;
    if (h->yield.err_solve != 0xFFFFFFFFu) {
        size_t n = (size_t)snprintf(solve, sizeof(solve), ",\"solve\":%u,\"pins\":[",
                                    (unsigned)h->yield.err_solve);
        for (uint32_t i = 0; i < h->yield.err_npin && n + 48 < sizeof(solve); i++)
            n += (size_t)snprintf(solve + n, sizeof(solve) - n, "%s[%u,%lld]", i ? "," : "",
                                  (unsigned)h->yield.err_pin_var[i],
                                  (long long)h->yield.err_pin_val[i]);
        snprintf(solve + n, sizeof(solve) - n, "]");
    } else if (h->yield.err_act != 0xFFFFFFFFu) {
        size_t n = (size_t)snprintf(solve, sizeof(solve), ",\"act\":%u,\"cone\":%u,\"enabled\":[",
                                    (unsigned)h->yield.err_act, (unsigned)h->yield.err_cone);
        for (uint32_t i = 0; i < h->yield.err_nen && n + 16 < sizeof(solve); i++)
            n += (size_t)snprintf(solve + n, sizeof(solve) - n, "%s%u", i ? "," : "",
                                  (unsigned)h->yield.err_en[i]);
        n += (size_t)snprintf(solve + n, sizeof(solve) - n, "],\"pins\":[");
        for (uint32_t i = 0; i < h->yield.err_npin && n + 48 < sizeof(solve); i++)
            n += (size_t)snprintf(solve + n, sizeof(solve) - n, "%s[%u,%lld]", i ? "," : "",
                                  (unsigned)h->yield.err_pin_var[i],
                                  (long long)h->yield.err_pin_val[i]);
        snprintf(solve + n, sizeof(solve) - n, "]");
    }
    /* error()/fatal(): its text, as pyvm says it (F6.11f) */
    char msg[2 * sizeof(h->yield.err_text)];
    if (h->yield.err_text[0])
        json_escape(msg, sizeof(msg), h->yield.err_text);
    else
        snprintf(msg, sizeof(msg), "%s (%d)", zbc_status_name(h->res.status), h->res.status);
    snprintf(h->err, PSSVM_ERR_MAX,
             "{\"message\":\"%s\",\"status\":%d,\"halted_op\":%d,"
             "\"call\":\"%s\",%s,%s,\"thread\":null%s}",
             msg, PSSVM_ERROR,
             h->res.halted_op, h->call, loc, src, solve);
}

int pssvm_dbg_enable(pssvm_t *e, int on) {
    if (e == NULL) return PSSVM_E_ARGS;
    e->dbg_on = on != 0;
    return PSSVM_OK;
}

int pssvm_dbg_set_breaks(pssvm_t *e, const uint32_t *id_coro_pc, uint32_t n,
                         uint8_t *verified) {
    if (e == NULL || (n && id_coro_pc == NULL)) return PSSVM_E_ARGS;
    if (n > ZBC_DBG_MAX_BREAKS) {
        set_err(e->err, PSSVM_E_ARGS, 0, "more than %d breakpoints", ZBC_DBG_MAX_BREAKS);
        return PSSVM_E_ARGS;
    }
    zbc_dbg_t *d = &e->dbg;
    d->n_breaks = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint32_t id = id_coro_pc[3 * i], coro = id_coro_pc[3 * i + 1], pc = id_coro_pc[3 * i + 2];
        int ok = coro < e->img.coro_count && pc < e->img.coros[coro].code_count;
        if (verified) verified[i] = (uint8_t)ok;
        if (!ok) continue;
        d->breaks[d->n_breaks].id = id;
        d->breaks[d->n_breaks].coro = coro;
        d->breaks[d->n_breaks].pc = pc;
        d->n_breaks++;
    }
    return PSSVM_OK;
}

int pssvm_dbg_set_watches(pssvm_t *e, const pssvm_watch_t *w, uint32_t n) {
    if (e == NULL || (n && w == NULL)) return PSSVM_E_ARGS;
    if (n > ZBC_DBG_MAX_WATCHES) {
        set_err(e->err, PSSVM_E_ARGS, 0, "more than %d watches", ZBC_DBG_MAX_WATCHES);
        return PSSVM_E_ARGS;
    }
    for (uint32_t i = 0; i < n; i++) {
        if (w[i].size == 0 || (w[i].rw & ~3u) || w[i].rw == 0) {
            set_err(e->err, PSSVM_E_ARGS, 0, "watch %u: bad size or rw", (unsigned)w[i].id);
            return PSSVM_E_ARGS;
        }
    }
    zbc_dbg_t *d = &e->dbg;
    for (uint32_t i = 0; i < n; i++) d->watches[i] = w[i];
    d->n_watches = n;
    if (n == 0) d->pend.n_hits = 0;
    return PSSVM_OK;
}

int pssvm_dbg_set_stop_on(pssvm_t *e, uint32_t kinds) {
    if (e == NULL || (kinds & ~(uint32_t)PSSVM_STOP_ON_ERROR)) return PSSVM_E_ARGS;
    e->dbg.stop_on_error = (kinds & PSSVM_STOP_ON_ERROR) != 0;
    return PSSVM_OK;
}

const zbc_image_t *pssvm_image(pssvm_t *e) {
    return e != NULL ? &e->img : NULL;
}

int pssvm_dbg_pause(pssvm_t *e) {
    if (e == NULL) return PSSVM_E_ARGS;
    e->dbg.pause = 1;
    return PSSVM_OK;
}

int pssvm_dbg_resume(pssvm_call_t *h, int kind) {
    if (h == NULL || kind < PSSVM_RESUME || kind > PSSVM_STEP_OUT) return PSSVM_E_ARGS;
    zbc_yield_t *y = &h->yield;
    if (h->state != CALL_READY || y->state != ZBC_YIELD_STOP) {
        set_err(h->err, PSSVM_E_STATE, 0, "the call is not stopped");
        return PSSVM_E_STATE;
    }
    zbc_dbg_t *d = &h->e->dbg;
    d->step_kind = kind;
    d->step_thread = kind ? y->thread : NULL;
    d->step_depth = d->stop.depth;
    d->step_thread_done = 0;
    y->state = ZBC_YIELD_NONE;
    /* The stopped thread runs next, from the instruction it stopped at. */
    zsp_thread_t *t = (zsp_thread_t *)y->thread;
    y->thread = NULL;
    y->frame = NULL;
    zsp_timebase_t *tb = h->tb;
    tb->active++;
    t->flags &= ~ZSP_THREAD_FLAGS_BLOCKED;
    t->next = tb->ready_head;
    tb->ready_head = t;
    if (tb->ready_tail == NULL) tb->ready_tail = t;
    return PSSVM_OK;
}

const pssvm_stop_t *pssvm_dbg_stop(pssvm_call_t *h) {
    if (h == NULL || h->state != CALL_READY || h->yield.state != ZBC_YIELD_STOP) return NULL;
    return &h->e->dbg.stop;
}

uint32_t pssvm_dbg_threads(pssvm_call_t *h, uint32_t *ids, uint32_t cap) {
    if (pssvm_dbg_stop(h) == NULL) return 0;
    return zbc_dbg_threads(&h->e->dbg, ids, cap);
}

uint32_t pssvm_dbg_frames(pssvm_call_t *h, uint32_t thread_id, pssvm_frame_t *out,
                          uint32_t cap) {
    if (pssvm_dbg_stop(h) == NULL) return 0;
    return zbc_dbg_frames(&h->e->dbg, thread_id, out, cap);
}

int pssvm_dbg_frame(pssvm_call_t *h, uint32_t frame_id, pssvm_frame_t *out) {
    if (out == NULL) return PSSVM_E_ARGS;
    if (pssvm_dbg_stop(h) == NULL) return PSSVM_E_STATE;
    return zbc_dbg_frame(&h->e->dbg, frame_id, out) ? PSSVM_OK : PSSVM_E_ARGS;
}

const pssvm_req_t *pssvm_request(pssvm_call_t *h) {
    if (h == NULL || h->state != CALL_READY
            || (h->yield.state != ZBC_YIELD_PENDING && h->yield.state != ZBC_YIELD_WAIT
                && h->yield.state != ZBC_YIELD_STOP))
        return NULL;
    return h->in_wait_reqs ? &h->wait_reqs : &h->req;
}

const pssvm_req_t *pssvm_take(pssvm_call_t *h) {
    if (h == NULL || h->state != CALL_READY || h->yield.state != ZBC_YIELD_PENDING
            || h->taken)
        return NULL;
    h->taken = 1;
    return &h->req;
}

int pssvm_complete(pssvm_call_t *h, uint32_t req_id, const uint8_t *data, size_t len) {
    if (h == NULL) return PSSVM_E_ARGS;
    zbc_yield_t *y = &h->yield;
    if (h->state != CALL_READY || y->state != ZBC_YIELD_PENDING
            || req_id != h->req.req_id) {
        set_err(h->err, PSSVM_E_STATE, 0, "request %u is not outstanding", (unsigned)req_id);
        return PSSVM_E_STATE;
    }
    /* A read answers with its data (its size, or a u64); a write with
     * nothing; an import with its result when it has one (one u64, or one
     * per leaf of a struct result: F6.4b2). */
    size_t want = (y->kind == ZBC_YIELD_ACCESS) ? (y->is_write ? 0 : y->size)
                : ((y->flags & ZBC_F_HAS_RET) ? 8u * (y->n_ret ? y->n_ret : 1u) : 0);
    if (len != want && !(want != 0 && want <= 8 && len == 8)) {
        set_err(h->err, PSSVM_E_STATE, 0, "answer is %u bytes, the request wants %u",
                (unsigned)len, (unsigned)want);
        return PSSVM_E_STATE;
    }
    if (len && data == NULL) return PSSVM_E_ARGS;
    uint64_t v = 0;
    for (size_t i = len > 8 ? 8 : len; i > 0; i--) v = (v << 8) | data[i - 1];
    y->value = v;
    for (size_t k = 0; 8 * k + 8 <= len && k < ZBC_CALL_MAX_ARGS; k++) {
        uint64_t w = 0;
        for (int b = 7; b >= 0; b--) w = (w << 8) | data[8 * k + (size_t)b];
        y->values[k] = w;
    }
    y->state = ZBC_YIELD_DONE;
    h->in_wait_reqs = 0;
    /* The asking thread runs next, as if the answer had come inline. */
    zsp_thread_t *t = (zsp_thread_t *)y->thread;
    zsp_timebase_t *tb = h->tb;
    tb->active++;
    t->flags &= ~ZSP_THREAD_FLAGS_BLOCKED;
    t->next = tb->ready_head;
    tb->ready_head = t;
    if (tb->ready_tail == NULL) tb->ready_tail = t;
    return PSSVM_OK;
}

size_t pssvm_result(pssvm_call_t *h, uint8_t *buf, size_t cap) {
    if (h == NULL || h->state != CALL_DONE || !h->has_ret) return 0;
    if (buf != NULL) {
        for (size_t i = 0; i < 8 && i < cap; i++) buf[i] = (uint8_t)(h->res.retval >> (8 * i));
    }
    return 8;
}

/* The slot of field `name` in an action-object layout ([[name, desc], ...]
 * in slot order, the ENTRY's obj), or -1. */
static int64_t layout_slot(const char *p, const char *name) {
    size_t nl = strlen(name);
    int64_t n = -1;
    int depth = 0, first = 0;          /* first: the next string is a name */
    for (; p && *p; p++) {
        if (*p == '"') {
            const char *s = ++p;
            for (; *p && *p != '"'; p++) if (*p == '\\' && p[1]) p++;
            if (first && (size_t)(p - s) == nl && !strncmp(s, name, nl)) return n;
            first = 0;
            if (!*p) break;
        }
        else if (*p == '[' || *p == '{') {
            if (++depth == 2 && *p == '[') { n++; first = 1; }
        }
        else if (*p == ']' || *p == '}') depth--;
    }
    return -1;
}

int pssvm_call_field(pssvm_call_t *h, const char *name, uint64_t *out) {
    if (h == NULL || name == NULL) return PSSVM_E_ARGS;
    if (h->state != CALL_DONE) {
        set_err(h->err, PSSVM_E_STATE, 0, "field '%s' read before the call is done", name);
        return PSSVM_E_STATE;
    }
    int64_t i = h->layout ? layout_slot(h->layout, name) : -1;
    if (i < 0 || (uint64_t)i >= h->obj.n) {
        char esc[128];
        json_escape(esc, sizeof(esc), name);
        set_err(h->err, PSSVM_E_ARGS, 0, "no field '%s' in the call's action object", esc);
        return PSSVM_E_ARGS;
    }
    if (out) *out = h->obj.slots[i];
    return PSSVM_OK;
}

int pssvm_call_status(pssvm_call_t *h, int *halted_op, uint64_t *now) {
    if (h == NULL) return PSSVM_E_ARGS;
    if (halted_op) *halted_op = h->res.halted_op;
    if (now) *now = h->res.now;
    return h->res.status;
}

void pssvm_call_end(pssvm_call_t *h) {
    if (h == NULL) return;
    if (h->tb != NULL)
        zsp_timebase_destroy(h->tb);   /* drops threads that never finished */
    free(h->own_slots);
    free(h);
}

const char *pssvm_error(pssvm_t *e, pssvm_call_t *h) {
    if (h != NULL) return h->err[0] ? h->err : NULL;
    if (e != NULL) return e->err[0] ? e->err : NULL;
    return g_load_err[0] ? g_load_err : NULL;
}

void pssvm_free(pssvm_t *e) {
    if (e == NULL) return;
    zbc_files_close_all();
    free(e->bound);
    free(e->cobj);
    free(e->data);
    free(e);
}
