/*
 * pssvm_stub.c -- the debug stub (be-bc docs/spec/debug-stub.md) over the C
 * engine's stops (pssvm_dbg_*), in C: the requests of zuspec.rt.eng.debug's
 * NativeStub, as one-line JSON texts, with no transport (pssvm.h).
 *
 * Differences from NativeStub: no image sha256; read_comp: no_comp (the
 * image names no component paths or fields); backdoor_read needs a host
 * back door (pssvm_stub_set_backdoor). As NativeStub: engine "c", no
 * exec_snippet, set_stop_on knows "error", read_frame's `this` is null and
 * step steps the stopped thread only.
 */
#include "pssvm.h"
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "pssvm_json.h"

/* ---- the stub -------------------------------------------------------- */

enum { S_DETACHED, S_STARTING, S_STOPPED, S_RUNNING, S_EXITED };
static const char *const STATE_NAMES[] = {"detached", "starting", "stopped", "running", "exited"};
static const char *const STEP_NAMES[] = {"stmt", "stmt", "into", "out"};
static const char *const REASONS[] = {"?", "pause", "step", "breakpoint", "watch", "error"};
static const char *const KINDS[] = {"int", "bool", "enum", "string", "chandle", "opaque", "float"};
static const char *const TSTATES[] = {"running", "ready", "waiting"};
#define ATTACH_TIMEOUT_MS 10000

typedef struct ev { char *s; struct ev *next; } ev_t;

struct pssvm_stub_s {
    pssvm_t           *e;
    const zbc_image_t *img;
    pthread_mutex_t    req_mu;     /* serializes requests (and `reply`) */
    pthread_mutex_t    mu;         /* the state below */
    pthread_cond_t     cv;         /* state changes, resumes */
    pthread_cond_t     ev_cv;      /* events queued */
    int                state;
    int                observed, terminate, attach_failed;
    unsigned           resumed;
    int                resume_kind;
    int                stop_on;
    pssvm_call_t      *h;          /* the stopped call, or NULL */
    pssvm_stop_t       where;
    int64_t            root_thread;
    ev_t              *ev_head, *ev_tail;
    char              *reply, *ev_out;
    pssvm_peek_f       peek;
    void              *peek_ctx;
};

typedef struct { sbuf body; const char *code; char msg[200]; } rq_t;

#define FAIL(c, ...) do { r->code = (c); snprintf(r->msg, sizeof(r->msg), __VA_ARGS__); return -1; } while (0)

static void deadline(struct timespec *ts, int ms) {
    clock_gettime(CLOCK_REALTIME, ts);
    ts->tv_sec += ms / 1000;
    ts->tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts->tv_nsec >= 1000000000L) { ts->tv_sec++; ts->tv_nsec -= 1000000000L; }
}

static void emit(pssvm_stub_t *s, sbuf *msg) {     /* mu held; takes msg */
    ev_t *e = calloc(1, sizeof(*e));
    e->s = msg->b ? msg->b : strdup("{}");
    if (s->ev_tail) s->ev_tail->next = e; else s->ev_head = e;
    s->ev_tail = e;
    pthread_cond_broadcast(&s->ev_cv);
}

static void resume(pssvm_stub_t *s, int kind) {
    s->state = S_RUNNING;
    s->resume_kind = kind;
    s->resumed++;
    pthread_cond_broadcast(&s->cv);
}

static const char *coro_name(pssvm_stub_t *s, uint32_t coro) {
    if (coro >= s->img->coro_count) return "";
    const char *n = zbc_image_str(s->img, s->img->coros[coro].name);
    return n ? n : "";
}

/* the statement containing coroutine pc `pc`: the last start at or before */
static uint32_t src_ref_at(pssvm_stub_t *s, uint32_t coro, uint32_t pc) {
    const zbc_image_t *img = s->img;
    if (coro >= img->coro_count) return 0;
    uint32_t lo = img->coros[coro].code_start, g = lo + pc, sr = 0, best = 0;
    int found = 0;
    for (uint32_t j = 0; j < img->stmt_count; j++) {
        uint32_t ps = img->stmts[j].pc_start;
        if (ps > g) break;
        if (ps >= lo && (!found || ps != best)) { best = ps; sr = img->stmts[j].src_ref; found = 1; }
    }
    return sr;
}

static int need_stopped(pssvm_stub_t *s, rq_t *r) {
    if (s->h == NULL) FAIL("not_stopped", "needs a stopped run");
    return 0;
}

/* the frames of thread `tid` (count; 0: none) into *out (malloc'd) */
static uint32_t frames_of(pssvm_stub_t *s, int64_t tid, pssvm_frame_t **out) {
    *out = NULL;
    if (tid < 0 || tid > 0xFFFFFFFFLL) return 0;
    uint32_t n = pssvm_dbg_frames(s->h, (uint32_t)tid, NULL, 0);
    if (n == 0) return 0;
    *out = calloc(n, sizeof(pssvm_frame_t));
    uint32_t m = pssvm_dbg_frames(s->h, (uint32_t)tid, *out, n);
    return m < n ? m : n;
}

static int thread_by_id(pssvm_stub_t *s, rq_t *r, jv *tid, pssvm_frame_t **f, uint32_t *n) {
    if (!jisint(tid)) FAIL("bad_request", "needs an int thread");
    if (need_stopped(s, r)) return -1;
    *n = frames_of(s, tid->i, f);
    if (*n == 0) FAIL("no_thread", "no live thread %lld", (long long)tid->i);
    return 0;
}

static int cmd_attach(pssvm_stub_t *s, rq_t *r, jv *a) {
    if (s->state != S_DETACHED) FAIL("bad_request", "already attached");
    jv *ver = jget(a, "version"), *entry = jget(a, "entry");
    if (ver && !(jisint(ver) && ver->i == 1)) FAIL("bad_request", "protocol version 1 only");
    int hosted = entry != NULL && ((entry->t == J_BOOL && !entry->b) || entry->t == J_NULL
                                   || (entry->t == J_INT && entry->i == 0));
    s->state = hosted ? S_RUNNING : S_STARTING;
    s->observed = 1;
    pssvm_dbg_enable(s->e, 1);
    pssvm_dbg_set_stop_on(s->e, s->stop_on);
    if (!hosted) pssvm_dbg_pause(s->e);
    pthread_cond_broadcast(&s->cv);       /* pssvm_stub_wait_attached */
    sb_f(&r->body, "{\"version\":1,\"engine\":\"c\",\"capabilities\":[\"access_watch\","
         "\"backdoor_read\"],\"image\":{\"coros\":%u}}", s->img->coro_count);
    return 0;
}

static int cmd_detach(pssvm_stub_t *s, rq_t *r, jv *a) {
    (void)r; (void)a;
    pssvm_dbg_set_breaks(s->e, NULL, 0, NULL);
    pssvm_dbg_set_watches(s->e, NULL, 0);
    pssvm_dbg_set_stop_on(s->e, 0);
    pssvm_dbg_enable(s->e, 0);
    s->stop_on = 0;
    s->observed = 0;
    if (s->state == S_STOPPED) resume(s, PSSVM_RESUME);
    if (s->state != S_EXITED) s->state = S_DETACHED;
    sb_f(&r->body, "{}");
    return 0;
}

static int cmd_terminate(pssvm_stub_t *s, rq_t *r, jv *a) {
    (void)a;
    sb_f(&r->body, "{}");
    if (s->state == S_EXITED) return 0;
    s->terminate = 1;
    if (s->state == S_STOPPED) resume(s, PSSVM_RESUME);
    else pssvm_dbg_pause(s->e);       /* the next instruction stops, and ends */
    pthread_cond_broadcast(&s->cv);
    return 0;
}

static int cmd_continue(pssvm_stub_t *s, rq_t *r, jv *a) {
    (void)a;
    resume(s, PSSVM_RESUME);
    sb_f(&r->body, "{}");
    return 0;
}

static int cmd_stop(pssvm_stub_t *s, rq_t *r, jv *a) {
    (void)a;
    if (s->state != S_RUNNING) FAIL("not_running", "the run is already stopped");
    pssvm_dbg_pause(s->e);
    sb_f(&r->body, "{}");
    return 0;
}

static int cmd_step(pssvm_stub_t *s, rq_t *r, jv *a) {
    jv *k = jget(a, "kind"), *tid = jget(a, "thread");
    const char *kind = k == NULL ? "stmt" : (k->t == J_STR ? k->s : "?");
    int kv = !strcmp(kind, "stmt") ? PSSVM_STEP_STMT : !strcmp(kind, "into") ? PSSVM_STEP_INTO
           : !strcmp(kind, "out") ? PSSVM_STEP_OUT : -1;
    if (kv < 0) FAIL("bad_request", "unknown step kind '%s'", kind);
    if (!jisint(tid)) FAIL("bad_request", "step needs a thread");
    pssvm_frame_t *f;
    uint32_t n;
    if (thread_by_id(s, r, tid, &f, &n)) return -1;
    free(f);
    if (tid->i != (int64_t)s->where.thread_id)
        FAIL("unsupported", "the C engine steps the stopped thread only");
    resume(s, kv);
    sb_f(&r->body, "{}");
    return 0;
}

static int cmd_threads(pssvm_stub_t *s, rq_t *r, jv *a) {
    (void)a;
    if (need_stopped(s, r)) return -1;
    uint32_t n = pssvm_dbg_threads(s->h, NULL, 0);
    uint32_t *ids = calloc(n ? n : 1, sizeof(uint32_t));
    uint32_t m = pssvm_dbg_threads(s->h, ids, n);
    if (m < n) n = m;
    sb_f(&r->body, "{\"threads\":[");
    int first = 1;
    for (uint32_t j = 0; j < n; j++) {
        pssvm_frame_t *f;
        uint32_t nf = frames_of(s, ids[j], &f);
        if (nf) {
            pssvm_frame_t *b = &f[nf - 1];
            sb_f(&r->body, "%s{\"id\":%u,\"coro\":%u,\"state\":", first ? "" : ",", ids[j], b->coro);
            sb_str(&r->body, b->state < 3 ? TSTATES[b->state] : "?");
            sb_f(&r->body, ",\"name\":");
            sb_str(&r->body, coro_name(s, b->coro));
            sb_f(&r->body, "}");
            first = 0;
        }
        free(f);
    }
    sb_f(&r->body, "]}");
    free(ids);
    return 0;
}

static int cmd_frames(pssvm_stub_t *s, rq_t *r, jv *a) {
    pssvm_frame_t *f;
    uint32_t n;
    if (thread_by_id(s, r, jget(a, "thread"), &f, &n)) return -1;
    sb_f(&r->body, "{\"frames\":[");
    for (uint32_t j = 0; j < n; j++) {
        sb_f(&r->body, "%s{\"id\":%u,\"coro\":%u,\"name\":", j ? "," : "", f[j].id, f[j].coro);
        sb_str(&r->body, coro_name(s, f[j].coro));
        sb_f(&r->body, ",\"pc\":%u,\"src_ref\":%u,\"depth\":%u}", f[j].pc,
             src_ref_at(s, f[j].coro, f[j].pc), f[j].call_depth);
    }
    sb_f(&r->body, "]}");
    free(f);
    return 0;
}

static int cmd_read_frame(pssvm_stub_t *s, rq_t *r, jv *a) {
    jv *fid = jget(a, "frame");
    if (!jisint(fid)) FAIL("bad_request", "needs an int frame");
    if (need_stopped(s, r)) return -1;
    pssvm_frame_t f;
    if (fid->i < 0 || fid->i > 0xFFFFFFFFLL
            || pssvm_dbg_frame(s->h, (uint32_t)fid->i, &f) != PSSVM_OK)
        FAIL("no_frame", "no live frame %lld", (long long)fid->i);
    const zbc_image_t *img = s->img;
    uint32_t g = (f.coro < img->coro_count ? img->coros[f.coro].code_start : 0) + f.pc;
    int any = 0, first = 1;
    sb_f(&r->body, "{\"locals\":[");
    for (uint32_t j = 0; j < img->local_count; j++) {
        const zbc_localent *v = &img->locals[j];
        if (v->coro != f.coro) continue;
        any = 1;
        if (!(v->pc_start <= g && g < v->pc_end) || v->slot >= f.nlocals) continue;
        sb_f(&r->body, "%s{\"name\":", first ? "" : ",");
        sb_str(&r->body, zbc_image_str(img, v->name));
        sb_f(&r->body, ",\"value\":%llu,\"width\":%u,\"signed\":%s,\"kind\":",
             (unsigned long long)f.locals[v->slot], v->width, (v->flags & 1) ? "true" : "false");
        sb_str(&r->body, v->kind < 7 ? KINDS[v->kind] : "opaque");
        sb_f(&r->body, "}");
        first = 0;
    }
    int na = 0;
    for (int j = 0; j < ZBC_CALL_MAX_ARGS; j++) if (f.args[j]) na = j + 1;
    sb_f(&r->body, "],\"args\":[");
    for (int j = 0; j < na; j++)
        sb_f(&r->body, "%s%llu", j ? "," : "", (unsigned long long)f.args[j]);
    sb_f(&r->body, "],\"this\":null");
    if (!any) {
        sb_f(&r->body, ",\"regs\":{");
        first = 1;
        for (uint32_t j = 0; j < f.nregs; j++) {
            if (!f.regs[j]) continue;
            sb_f(&r->body, "%s\"%u\":%llu", first ? "" : ",", j, (unsigned long long)f.regs[j]);
            first = 0;
        }
        sb_f(&r->body, "}");
    }
    sb_f(&r->body, "}");
    return 0;
}

static int cmd_read_comp(pssvm_stub_t *s, rq_t *r, jv *a) {
    (void)s; (void)a;
    FAIL("no_comp", "the image names no component tree");
}

static int cmd_backdoor_read(pssvm_stub_t *s, rq_t *r, jv *a) {
    jv *addr = jget(a, "addr"), *w = jget(a, "width");
    if (!jisint(addr) || !jisint(w) || !(w->i == 8 || w->i == 16 || w->i == 32 || w->i == 64))
        FAIL("bad_request", "backdoor_read needs int addr, width 8|16|32|64");
    if (s->peek == NULL) FAIL("unsupported", "the run has no host memory");
    uint64_t v = 0;
    if (s->peek(s->peek_ctx, (uint64_t)addr->i, (uint32_t)(w->i / 8), &v) != 0)
        FAIL("unsupported", "the platform memory has no back door");
    sb_f(&r->body, "{\"value\":%llu}", (unsigned long long)v);
    return 0;
}

static int cmd_exec_snippet(pssvm_stub_t *s, rq_t *r, jv *a) {
    (void)s; (void)a;
    FAIL("unsupported", "the C engine runs no snippets");
}

static int cmd_set_access_watch(pssvm_stub_t *s, rq_t *r, jv *a) {
    jv *ws = jget(a, "watches");
    if (ws == NULL || ws->t != J_ARR) FAIL("bad_request", "set_access_watch needs watches");
    for (int j = 0; j < ws->n; j++)
        if (ws->v[j].t != J_OBJ || !jisint(jget(&ws->v[j], "id")))
            FAIL("bad_request", "a watch needs an int id");
    pssvm_watch_t *good = calloc((size_t)ws->n + 1, sizeof(pssvm_watch_t));
    uint32_t ng = 0;
    sb_f(&r->body, "{\"watches\":[");
    for (int j = 0; j < ws->n; j++) {
        jv *w = &ws->v[j], *id = jget(w, "id"), *ad = jget(w, "addr"), *sz = jget(w, "size");
        jv *rw = jget(w, "rw"), *val = jget(w, "value"), *mask = jget(w, "mask");
        const char *rws = rw == NULL ? "rw" : (rw->t == J_STR ? rw->s : "");
        uint32_t rwv = !strcmp(rws, "r") ? PSSVM_WATCH_R : !strcmp(rws, "w") ? PSSVM_WATCH_W
                     : !strcmp(rws, "rw") ? PSSVM_WATCH_RW : 0;
        int ok = jisint(ad) && jisint(sz) && sz->i > 0 && rwv && ng < ZBC_DBG_MAX_WATCHES;
        if (ok) {
            pssvm_watch_t *g = &good[ng++];
            g->id = (uint32_t)id->i; g->rw = rwv;
            g->addr = (uint64_t)ad->i; g->size = (uint64_t)sz->i;
            g->has_value = jisint(val);
            g->value = jisint(val) ? (uint64_t)val->i : 0;
            g->mask = jisint(mask) ? (uint64_t)mask->i : ~(uint64_t)0;
        }
        sb_f(&r->body, "%s{\"id\":%lld,\"verified\":%s}", j ? "," : "", (long long)id->i,
             ok ? "true" : "false");
    }
    sb_f(&r->body, "]}");
    int rc = pssvm_dbg_set_watches(s->e, good, ng);
    free(good);
    if (rc != PSSVM_OK) FAIL("bad_request", "the engine refused the watches");
    return 0;
}

static int cmd_set_stop_on(pssvm_stub_t *s, rq_t *r, jv *a) {
    jv *ks = jget(a, "kinds");
    if (ks == NULL || ks->t != J_ARR) FAIL("bad_request", "set_stop_on needs kinds [str]");
    int on = 0;
    for (int j = 0; j < ks->n; j++) {
        if (ks->v[j].t != J_STR) FAIL("bad_request", "set_stop_on needs kinds [str]");
        if (!strcmp(ks->v[j].s, "error")) on = PSSVM_STOP_ON_ERROR;
    }
    s->stop_on = on;
    pssvm_dbg_set_stop_on(s->e, (uint32_t)on);
    sb_f(&r->body, on ? "{\"kinds\":[\"error\"]}" : "{\"kinds\":[]}");
    return 0;
}

static int cmd_set_pc_breaks(pssvm_stub_t *s, rq_t *r, jv *a) {
    jv *bs = jget(a, "breaks");
    if (bs == NULL || bs->t != J_ARR) FAIL("bad_request", "set_pc_breaks needs breaks");
    for (int j = 0; j < bs->n; j++) {
        jv *b = &bs->v[j];
        if (b->t != J_OBJ || !jisint(jget(b, "id")) || !jisint(jget(b, "coro"))
                || !jisint(jget(b, "pc")))
            FAIL("bad_request", "a break needs int id, coro, pc");
    }
    uint32_t *tab = calloc(3 * (size_t)bs->n + 1, sizeof(uint32_t)), nt = 0;
    sb_f(&r->body, "{\"breaks\":[");
    for (int j = 0; j < bs->n; j++) {
        jv *b = &bs->v[j];
        int64_t id = jget(b, "id")->i, c = jget(b, "coro")->i, pc = jget(b, "pc")->i;
        sb_f(&r->body, "%s{\"id\":%lld,\"verified\":", j ? "," : "", (long long)id);
        if (c < 0 || c >= (int64_t)s->img->coro_count)
            sb_f(&r->body, "false,\"message\":\"no coroutine %lld\"}", (long long)c);
        else if (pc < 0 || pc >= (int64_t)s->img->coros[c].code_count)
            sb_f(&r->body, "false,\"message\":\"pc %lld out of range\"}", (long long)pc);
        else if (nt >= ZBC_DBG_MAX_BREAKS)
            sb_f(&r->body, "false,\"message\":\"too many breakpoints\"}");
        else {
            tab[3 * nt] = (uint32_t)id; tab[3 * nt + 1] = (uint32_t)c; tab[3 * nt + 2] = (uint32_t)pc;
            nt++;
            sb_f(&r->body, "true}");
        }
    }
    sb_f(&r->body, "]}");
    pssvm_dbg_set_breaks(s->e, tab, nt, NULL);
    free(tab);
    return 0;
}

typedef int (*cmd_f)(pssvm_stub_t *, rq_t *, jv *);
static const struct { const char *name; cmd_f fn; int while_running; } CMDS[] = {
    {"attach", cmd_attach, 0},           {"detach", cmd_detach, 1},
    {"terminate", cmd_terminate, 1},     {"continue", cmd_continue, 0},
    {"stop", cmd_stop, 1},               {"step", cmd_step, 0},
    {"threads", cmd_threads, 0},         {"frames", cmd_frames, 0},
    {"read_frame", cmd_read_frame, 0},   {"read_comp", cmd_read_comp, 0},
    {"backdoor_read", cmd_backdoor_read, 0}, {"exec_snippet", cmd_exec_snippet, 0},
    {"set_access_watch", cmd_set_access_watch, 1}, {"set_stop_on", cmd_set_stop_on, 1},
    {"set_pc_breaks", cmd_set_pc_breaks, 1},
};

static int dispatch(pssvm_stub_t *s, rq_t *r, jv *msg, int *is_attach) {
    jv *cmd = jget(msg, "cmd");
    if (msg->t != J_OBJ || cmd == NULL || cmd->t != J_STR) FAIL("bad_request", "a request needs a cmd");
    jv empty = {0}, *a = jget(msg, "args");
    empty.t = J_OBJ;
    if (a == NULL || a->t == J_NULL || (a->t == J_ARR && a->n == 0)) a = &empty;
    if (a->t != J_OBJ) FAIL("bad_request", "args must be an object");
    int ci = -1;
    for (size_t j = 0; j < sizeof(CMDS) / sizeof(CMDS[0]); j++)
        if (!strcmp(CMDS[j].name, cmd->s)) ci = (int)j;
    if (ci < 0) FAIL("bad_request", "unknown cmd '%s'", cmd->s);
    *is_attach = ci == 0;
    if (ci != 0 && s->state == S_DETACHED) FAIL("bad_request", "not attached");
    if (s->state == S_EXITED && strcmp(cmd->s, "detach") && strcmp(cmd->s, "terminate"))
        FAIL("not_stopped", "the run has ended");
    if (s->state == S_RUNNING && !CMDS[ci].while_running)
        FAIL("not_stopped", "%s needs a stopped run", cmd->s);
    int rc = CMDS[ci].fn(s, r, a);
    if (rc && ci == 0) {
        s->attach_failed = 1;
        pthread_cond_broadcast(&s->cv);
    }
    return rc;
}

const char *pssvm_stub_request(pssvm_stub_t *s, const char *line) {
    if (s == NULL || line == NULL) return NULL;
    pthread_mutex_lock(&s->req_mu);
    rq_t r;
    memset(&r, 0, sizeof(r));
    jv msg;
    const char *p = line;
    int bad = jparse(&p, &msg, 0);
    jv *seq = bad ? NULL : jget(&msg, "seq");
    int is_attach = 0, rc;
    if (bad) {
        r.code = "bad_request";
        snprintf(r.msg, sizeof(r.msg), "not a JSON request");
        rc = -1;
    } else {
        pthread_mutex_lock(&s->mu);
        rc = dispatch(s, &r, &msg, &is_attach);
        if (rc == 0 && is_attach) {
            struct timespec ts;
            deadline(&ts, ATTACH_TIMEOUT_MS);
            while (s->state == S_STARTING)
                if (pthread_cond_timedwait(&s->cv, &s->mu, &ts) == ETIMEDOUT) break;
            if (s->state == S_STARTING) {
                r.code = "timeout";
                snprintf(r.msg, sizeof(r.msg), "the run did not start");
                rc = -1;
            }
        }
        pthread_mutex_unlock(&s->mu);
    }
    sbuf o = {0};
    sb_f(&o, "{\"seq\":");
    if (seq) sb_put(&o, seq->raw, seq->rawlen); else sb_f(&o, "null");
    if (rc == 0) {
        sb_f(&o, ",\"ok\":true,\"body\":");
        if (r.body.b) sb_put(&o, r.body.b, r.body.n); else sb_f(&o, "{}");
    } else {
        sb_f(&o, ",\"ok\":false,\"error\":{\"code\":");
        sb_str(&o, r.code);
        sb_f(&o, ",\"message\":");
        sb_str(&o, r.msg);
        sb_f(&o, "}");
    }
    sb_f(&o, "}");
    free(r.body.b);
    jfree(&msg);
    free(s->reply);
    s->reply = o.b;
    pthread_mutex_unlock(&s->req_mu);
    return s->reply;
}

int pssvm_stub_wait_attached(pssvm_stub_t *s, int timeout_ms) {
    struct timespec ts;
    deadline(&ts, timeout_ms);
    pthread_mutex_lock(&s->mu);
    while (s->state == S_DETACHED && !s->attach_failed)
        if (pthread_cond_timedwait(&s->cv, &s->mu, &ts) == ETIMEDOUT) break;
    int rc = s->state != S_DETACHED ? 1 : s->attach_failed ? -1 : 0;
    s->attach_failed = 0;
    pthread_mutex_unlock(&s->mu);
    return rc;
}

int pssvm_stub_on_stop(pssvm_stub_t *s, pssvm_call_t *h) {
    pthread_mutex_lock(&s->mu);
    if (s->terminate) { pthread_mutex_unlock(&s->mu); return 1; }
    const pssvm_stop_t *st = pssvm_dbg_stop(h);
    if (!s->observed || st == NULL) {               /* detached meanwhile */
        pssvm_dbg_resume(h, PSSVM_RESUME);
        pthread_mutex_unlock(&s->mu);
        return 0;
    }
    s->h = h;
    s->where = *st;
    if (s->root_thread < 0) s->root_thread = st->thread_id;
    int starting = s->state == S_STARTING;
    s->state = S_STOPPED;
    pthread_cond_broadcast(&s->cv);
    if (!starting) {
        sbuf m = {0};
        sb_f(&m, "{\"event\":\"stopped\",\"body\":{\"reason\":");
        sb_str(&m, st->reason < 6 ? REASONS[st->reason] : "?");
        sb_f(&m, ",\"thread\":%u,\"frame\":%u,\"coro\":%u,\"pc\":%u,\"src_ref\":%u,\"detail\":",
             st->thread_id, st->frame_id, st->coro, st->pc, st->src_ref);
        if (st->reason == ZBC_DBG_STEP) {
            sb_f(&m, "{\"kind\":");
            sb_str(&m, STEP_NAMES[s->resume_kind & 3]);
            sb_f(&m, "}");
        } else if (st->reason == ZBC_DBG_WATCH) {
            sb_f(&m, "{\"rw\":\"%s\",\"width\":%u,\"addr\":%llu,\"data\":%llu}",
                 st->is_write ? "w" : "r", 8 * st->size, (unsigned long long)st->addr,
                 (unsigned long long)st->data);
        } else if (st->reason == ZBC_DBG_ERROR) {
            char e[160];
            snprintf(e, sizeof(e), "%s (%d)", st->message ? st->message : "error", st->status);
            sb_f(&m, "{\"error\":");
            sb_str(&m, e);
            sb_f(&m, ",\"status\":%d,\"halted_op\":%d}", st->status, st->op);
        } else {
            sb_f(&m, "{}");
        }
        if (st->n_hits) {
            sb_f(&m, ",\"hits\":[");
            for (uint32_t j = 0; j < st->n_hits && j < ZBC_DBG_MAX_HITS; j++)
                sb_f(&m, "%s%u", j ? "," : "", st->hits[j]);
            sb_f(&m, "]");
        }
        sb_f(&m, "}}");
        emit(s, &m);
    }
    unsigned mark = s->resumed;
    while (s->resumed == mark) pthread_cond_wait(&s->cv, &s->mu);
    s->h = NULL;
    int term = s->terminate, kind = s->resume_kind;
    pthread_mutex_unlock(&s->mu);
    if (term) return 1;
    pssvm_dbg_resume(h, kind);
    return 0;
}

void pssvm_stub_exited(pssvm_stub_t *s, const char *status, const char *message) {
    pthread_mutex_lock(&s->mu);
    if (status == NULL) status = "ok";
    if (!strcmp(status, "ok") && s->terminate) status = "terminated";
    s->state = S_EXITED;
    s->h = NULL;
    pthread_cond_broadcast(&s->cv);
    if (s->observed) {
        sbuf m = {0};
        sb_f(&m, "{\"event\":\"exited\",\"body\":{\"status\":");
        sb_str(&m, status);
        if (message) { sb_f(&m, ",\"message\":"); sb_str(&m, message); }
        sb_f(&m, "}}");
        emit(s, &m);
    }
    pthread_mutex_unlock(&s->mu);
}

const char *pssvm_stub_next_event(pssvm_stub_t *s, int timeout_ms) {
    pthread_mutex_lock(&s->mu);
    free(s->ev_out);
    s->ev_out = NULL;
    struct timespec ts;
    if (timeout_ms >= 0) deadline(&ts, timeout_ms);
    while (s->ev_head == NULL) {
        if (timeout_ms < 0) pthread_cond_wait(&s->ev_cv, &s->mu);
        else if (pthread_cond_timedwait(&s->ev_cv, &s->mu, &ts) == ETIMEDOUT) break;
    }
    ev_t *e = s->ev_head;
    if (e) {
        s->ev_head = e->next;
        if (s->ev_head == NULL) s->ev_tail = NULL;
        s->ev_out = e->s;
        free(e);
    }
    pthread_mutex_unlock(&s->mu);
    return s->ev_out;
}

const char *pssvm_stub_state(pssvm_stub_t *s) {
    pthread_mutex_lock(&s->mu);
    const char *n = STATE_NAMES[s->state];
    pthread_mutex_unlock(&s->mu);
    return n;
}

void pssvm_stub_set_backdoor(pssvm_stub_t *s, pssvm_peek_f peek, void *ctx) {
    pthread_mutex_lock(&s->mu);
    s->peek = peek;
    s->peek_ctx = ctx;
    pthread_mutex_unlock(&s->mu);
}

pssvm_stub_t *pssvm_stub_new(pssvm_t *e) {
    const zbc_image_t *img = pssvm_image(e);
    if (img == NULL) return NULL;
    pssvm_stub_t *s = calloc(1, sizeof(*s));
    s->e = e;
    s->img = img;
    pthread_mutex_init(&s->req_mu, NULL);
    pthread_mutex_init(&s->mu, NULL);
    pthread_cond_init(&s->cv, NULL);
    pthread_cond_init(&s->ev_cv, NULL);
    s->state = S_DETACHED;
    s->stop_on = PSSVM_STOP_ON_ERROR;
    s->root_thread = -1;
    return s;
}

void pssvm_stub_free(pssvm_stub_t *s) {
    if (s == NULL) return;
    while (s->ev_head) {
        ev_t *e = s->ev_head;
        s->ev_head = e->next;
        free(e->s);
        free(e);
    }
    free(s->reply);
    free(s->ev_out);
    pthread_cond_destroy(&s->cv);
    pthread_cond_destroy(&s->ev_cv);
    pthread_mutex_destroy(&s->mu);
    pthread_mutex_destroy(&s->req_mu);
    free(s);
}
