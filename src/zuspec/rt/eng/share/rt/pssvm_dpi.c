/*
 * pssvm_dpi.c -- the host ABI (pssvm.h) in the shapes SystemVerilog DPI-C
 * imports take: handles as chandles, strings in, the request read field by
 * field, an answer as one u64. pssc's pssvm_pkg.sv (`PSSVM_DPI`,
 * class pssvm_engine_dpi) imports these and, directly, pssvm_abi_version,
 * pssvm_call_end, pssvm_notify and pssvm_free; it runs calls with
 * pssvm_dpi_run. Server mode (pssvm_dpi_serve ..; the daemon's sim socket,
 * the C debug stub) is at the end.
 *
 * No svdpi.h: every argument is a plain C type (chandle = void *, string =
 * const char *, int = int32_t, longint unsigned = uint64_t), so the engine
 * library builds without a simulator.
 *
 * Call arguments are staged (pssvm_dpi_arg_push) before pssvm_dpi_call_start
 * rather than passed as an open array, which some simulators (Verilator
 * 5.052) do not compile in an import. A simulation runs one thread of DPI
 * calls, so the stage is global.
 */
#include "pssvm.h"
#include "pssvm_json.h"
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char     g_dpi_err[512];
static uint64_t g_seed;
static uint64_t g_args[ZBC_CALL_MAX_ARGS];
static uint32_t g_nargs;
static int      g_args_over;
static char     g_str[64];
static char     g_line[512];

static void remember_image(pssvm_t *e, const char *path);

static void dpi_err(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_dpi_err, sizeof(g_dpi_err), fmt, ap);
    va_end(ap);
}

/* Load the image file `path` (`pssc build --image`). `opts` as pssvm_load,
 * plus `seed=N`: the seed of the calls this engine starts (default 0). */
/* The bytes of the image file `path` (malloc'd), or NULL (g_dpi_err set). */
static uint8_t *read_image(const char *path, long *len) {
    FILE *f = path ? fopen(path, "rb") : NULL;
    if (f == NULL) {
        dpi_err("cannot open image '%s'", path ? path : "");
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = (uint8_t *)malloc(n > 0 ? (size_t)n : 1);
    size_t got = n > 0 ? fread(buf, 1, (size_t)n, f) : 0;
    fclose(f);
    if (n < 0 || got != (size_t)n) {
        free(buf);
        dpi_err("cannot read image '%s'", path);
        return NULL;
    }
    *len = n;
    return buf;
}

void *pssvm_dpi_load(const char *path, const char *opts) {
    g_dpi_err[0] = 0;
    long n = 0;
    uint8_t *buf = read_image(path, &n);
    if (buf == NULL) return NULL;
    pssvm_t *e = pssvm_load(buf, (size_t)n, opts);
    free(buf);      /* the engine keeps its own copy */
    if (e == NULL) {
        const char *m = pssvm_error(NULL, NULL);
        dpi_err("%s: %s", path, m ? m : "load failed");
        return NULL;
    }
    const char *s = opts ? strstr(opts, "seed=") : NULL;
    g_seed = s ? strtoull(s + 5, NULL, 0) : 0;
    remember_image(e, path);
    return e;
}

/* Build the component tree; again (a clean model) when one is built. */
int pssvm_dpi_construct(void *e, const char *root_type) {
    return pssvm_fresh((pssvm_t *)e, root_type);
}

/* Stage one argument (value ABI: one u64 leaf) of the next call_start. */
void pssvm_dpi_arg_push(void *e, uint64_t v) {
    (void)e;
    if (g_nargs < ZBC_CALL_MAX_ARGS) g_args[g_nargs++] = v;
    else g_args_over = 1;
}

/* Start `entry` with the staged arguments (and clear the stage). NULL:
 * refused (pssvm_dpi_error(e, NULL)). */
void *pssvm_dpi_call_start(void *e, const char *entry, const char *comp_path) {
    uint8_t a[8 * ZBC_CALL_MAX_ARGS];
    uint32_t n = g_nargs;
    int over = g_args_over;
    g_nargs = 0;
    g_args_over = 0;
    g_dpi_err[0] = 0;
    if (over) {
        dpi_err("more than %d arguments for %s", ZBC_CALL_MAX_ARGS, entry ? entry : "");
        return NULL;
    }
    for (uint32_t i = 0; i < n; i++)
        for (int b = 0; b < 8; b++) a[8 * i + b] = (uint8_t)(g_args[i] >> (8 * b));
    return pssvm_call_start((pssvm_t *)e, entry, comp_path, a, 8u * n, g_seed);
}

int pssvm_dpi_req_int(void *h, const char *field) {
    const pssvm_req_t *r = pssvm_request((pssvm_call_t *)h);
    if (r == NULL || field == NULL) return 0;
    if (!strcmp(field, "status"))   return r->status;
    if (!strcmp(field, "kind"))     return (int)r->kind;
    if (!strcmp(field, "size"))     return (int)r->size;
    if (!strcmp(field, "reg_id"))   return (int)r->reg_id;
    if (!strcmp(field, "fn_id"))    return (int)r->fn_id;
    if (!strcmp(field, "blocking")) return (int)r->blocking;
    if (!strcmp(field, "has_ret"))  return (int)r->has_ret;
    if (!strcmp(field, "on"))       return (int)r->on;
    if (!strcmp(field, "bound"))    return (int)r->bound;
    return 0;
}

uint64_t pssvm_dpi_req_u64(void *h, const char *field) {
    const pssvm_req_t *r = pssvm_request((pssvm_call_t *)h);
    if (r == NULL || field == NULL) return 0;
    if (!strcmp(field, "addr"))  return r->addr;
    if (!strcmp(field, "data"))  return r->data;
    if (!strcmp(field, "delay")) return r->delay;
    return 0;
}

/* name (an import's; "" when the image has none), src_ref (its index, ""
 * when unknown), reason ("": the engine gives none). Valid until the next
 * call. */
const char *pssvm_dpi_req_str(void *h, const char *field) {
    const pssvm_req_t *r = pssvm_request((pssvm_call_t *)h);
    g_str[0] = 0;
    if (r == NULL || field == NULL) return g_str;
    if (!strcmp(field, "name") && r->name) return r->name;
    if (!strcmp(field, "src_ref") && r->src_ref != 0xFFFFFFFFu && r->src_ref != 0)
        snprintf(g_str, sizeof(g_str), "%u", (unsigned)r->src_ref);
    return g_str;
}

int pssvm_dpi_req_nargs(void *h) {
    const pssvm_req_t *r = pssvm_request((pssvm_call_t *)h);
    return r ? (int)(r->args_len / 8) : 0;
}

uint64_t pssvm_dpi_req_arg(void *h, int i) {
    const pssvm_req_t *r = pssvm_request((pssvm_call_t *)h);
    if (r == NULL || i < 0 || (size_t)i >= r->args_len / 8) return 0;
    uint64_t v = 0;
    for (int b = 7; b >= 0; b--) v = (v << 8) | r->args[8 * i + b];
    return v;
}

/* Answer the pending request: a read's data or an import's result; `data`
 * is ignored where the request wants no answer (a write, a void import). */
int pssvm_dpi_complete(void *h, uint64_t data) {
    const pssvm_req_t *r = pssvm_request((pssvm_call_t *)h);
    uint8_t b[8];
    size_t len = 8;
    if (r != NULL && ((r->status == PSSVM_ACCESS && r->kind == 1)
                      || (r->status == PSSVM_IMPORT && !r->has_ret)))
        len = 0;
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(data >> (8 * i));
    return pssvm_complete((pssvm_call_t *)h, b, len);
}

uint64_t pssvm_dpi_result(void *h) {
    uint8_t b[8] = {0};
    uint64_t v = 0;
    pssvm_result((pssvm_call_t *)h, b, sizeof(b));
    for (int i = 7; i >= 0; i--) v = (v << 8) | b[i];
    return v;
}

/* The last error of call `h`, else of engine `e`, else of a load: "" when
 * none. */
const char *pssvm_dpi_error(void *e, void *h) {
    const char *m = NULL;
    if (h != NULL) m = pssvm_error((pssvm_t *)e, (pssvm_call_t *)h);
    if (m == NULL && e != NULL) m = pssvm_error((pssvm_t *)e, NULL);
    if (m == NULL && g_dpi_err[0]) m = g_dpi_err;
    return m ? m : "";
}

/* ---- the image's tests (pssvm_runner) ------------------------------------
 * pssc writes them as the META document "pssc.native": tab-separated lines
 * `test <comp::fn> <expected error>`, `session|setup|teardown <comp::fn>`
 * (in the order to call them) and `fail <slot>` (a pssunit ledger's n_fail
 * slot in the component object). */

/* Column `col` of the `i`th line tagged `tag`, or "". Valid until the next
 * call. */
static const char *native_field(void *e, const char *tag, int i, int col) {
    const char *p = pssvm_meta((pssvm_t *)e, "pssc.native");
    size_t tl = tag ? strlen(tag) : 0;
    g_line[0] = 0;
    if (p == NULL || tag == NULL || i < 0) return g_line;
    while (*p) {
        const char *eol = strchr(p, '\n');
        if (eol == NULL) eol = p + strlen(p);
        if ((size_t)(eol - p) > tl && !strncmp(p, tag, tl) && p[tl] == '\t' && i-- == 0) {
            const char *f = p + tl + 1;
            for (int c = 1; c < col && f < eol; c++) {
                const char *t = memchr(f, '\t', (size_t)(eol - f));
                f = t ? t + 1 : eol;
            }
            const char *t = memchr(f, '\t', (size_t)(eol - f));
            size_t n = (size_t)((t ? t : eol) - f);
            if (n >= sizeof(g_line)) n = sizeof(g_line) - 1;
            memcpy(g_line, f, n);
            g_line[n] = 0;
            return g_line;
        }
        p = *eol ? eol + 1 : eol;
    }
    return g_line;
}

/* Test `i` as `comp::fn`; "" past the last. */
const char *pssvm_dpi_test_name(void *e, int i) { return native_field(e, "test", i, 1); }

/* The error test `i` expects (`@pssunit_pkg::expect_error`), or "". */
const char *pssvm_dpi_test_expect(void *e, int i) { return native_field(e, "test", i, 2); }

/* Session, setup or teardown function `i` (`kind`); "" past the last. */
const char *pssvm_dpi_hook(void *e, const char *kind, int i) {
    return native_field(e, kind, i, 1);
}

/* pssunit checks failed so far: the ledgers' n_fail slots, summed. */
int pssvm_dpi_checks_failed(void *e) {
    size_t n = pssvm_comp_read((pssvm_t *)e, NULL, 0);
    if (n == 0) return 0;
    uint64_t *slots = (uint64_t *)malloc(n * sizeof(uint64_t));
    if (slots == NULL) return 0;
    pssvm_comp_read((pssvm_t *)e, slots, n);
    long total = 0;
    for (int i = 0; *native_field(e, "fail", i, 1); i++) {
        unsigned long s = strtoul(g_line, NULL, 10);
        if (s < n) total += (long)slots[s];
    }
    free(slots);
    return (int)total;
}

/* ---- server mode (pssc's pssvm_dpi_shim.py `serve` .. `serve_done`, and
 * pssc.devenv.sim.serve.Server) -------------------------------------------
 * The testbench registers with the workspace daemon's sim socket and
 * answers its requests: newline-delimited JSON, one request
 * {"seq","cmd","args"} per line, replies {"seq","ok","body"|"error"},
 * events {"event","body"} (each body with the sim time `t`, fs). A reader
 * thread queues requests; the SV thread answers them in pssvm_dpi_poll
 * (ping, info, end, run, resume, reload). `debug` {on} is answered on the
 * reader thread: it puts the C debug stub (pssvm_stub.c) on the engine;
 * while one is on, the requests that are not the session's go to it on the
 * reader thread (the SV thread may be stopped in pssvm_dpi_run), and an
 * event pump thread forwards its events. One server per simulation. */
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define SIM_PROTOCOL 1
#define MAX_IMAGES   16

static struct { pssvm_t *e; char *path; } g_images[MAX_IMAGES];

static void remember_image(pssvm_t *e, const char *path) {
    int slot = -1;
    for (int i = 0; i < MAX_IMAGES; i++) {
        if (g_images[i].e == e) { slot = i; break; }
        if (slot < 0 && g_images[i].e == NULL) slot = i;
    }
    if (slot < 0) slot = 0;
    free(g_images[slot].path);
    g_images[slot].e = e;
    g_images[slot].path = strdup(path ? path : "");
}

static const char *image_of(pssvm_t *e) {
    for (int i = 0; i < MAX_IMAGES; i++)
        if (g_images[i].e == e && e != NULL) return g_images[i].path;
    return "";
}

typedef struct qn { char *line; struct qn *next; } qn_t;

typedef struct {
    pssvm_t        *e;
    int             fd;
    char            session[128];
    char           *info;          /* the registration, a JSON object */
    pthread_mutex_t mu;            /* queue, closed, stub, in_stop */
    pthread_cond_t  cv;
    pthread_mutex_t wmu;           /* socket writes */
    pthread_t       reader, pump;
    int             has_reader, has_pump;
    qn_t           *qh, *qt;
    int             closed;        /* the channel closed (reader) */
    int             ended;         /* the daemon sent `end` (SV thread) */
    int             run_pending;
    char           *run_seq;       /* the pending `run`'s seq (JSON text) */
    char           *run_sel;
    int             held;
    char           *held_why;
    int             resume;        /* -1: none yet; 0/1: rerun */
    pssvm_stub_t   *stub;
    int             pump_stop;
    int             in_stop;       /* the SV thread is in pssvm_stub_on_stop */
    char           *rb;            /* read buffer */
    size_t          rn, rcap;
} srv_t;

static srv_t   *g_srv;
static uint64_t g_now_fs;

/* -- SHA-1 (the daemon's socket is named by a hash of the workspace root) */
static uint32_t rol(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static void sha1_hex(const char *msg, char out[41]) {
    uint32_t h[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};
    size_t len = strlen(msg), tot = ((len + 8) / 64 + 1) * 64;
    uint8_t *m = calloc(tot, 1);
    memcpy(m, msg, len);
    m[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) m[tot - 1 - i] = (uint8_t)(bits >> (8 * i));
    for (size_t off = 0; off < tot; off += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++)
            w[i] = (uint32_t)m[off + 4 * i] << 24 | (uint32_t)m[off + 4 * i + 1] << 16
                 | (uint32_t)m[off + 4 * i + 2] << 8 | m[off + 4 * i + 3];
        for (int i = 16; i < 80; i++) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20)      { f = (b & c) | (~b & d);          k = 0x5A827999u; }
            else if (i < 40) { f = b ^ c ^ d;                   k = 0x6ED9EBA1u; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCu; }
            else             { f = b ^ c ^ d;                   k = 0xCA62C1D6u; }
            uint32_t t = rol(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rol(b, 30); b = a; a = t;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }
    free(m);
    for (int i = 0; i < 5; i++) snprintf(out + 8 * i, 9, "%08x", h[i]);
}

static int path_exists(const char *p) {
    struct stat st;
    return stat(p, &st) == 0;
}

/* pssc.devenv: sim_path(protocol.socket_path(protocol.find_root())) */
static void default_sim_path(char *out, size_t n) {
    static const char *const MARKERS[] = {"pyproject.toml", ".git", "flow.dv", "flow.yaml"};
    char here[4096], d[4096], p[4600], root[4096];
    if (realpath(".", here) == NULL) snprintf(here, sizeof(here), ".");
    snprintf(root, sizeof(root), "%s", here);
    snprintf(d, sizeof(d), "%s", here);
    for (;;) {
        int found = 0;
        for (int i = 0; i < 4 && !found; i++) {
            snprintf(p, sizeof(p), "%s/%s", strcmp(d, "/") ? d : "", MARKERS[i]);
            found = path_exists(p);
        }
        if (found) { snprintf(root, sizeof(root), "%s", d); break; }
        char *sl = strrchr(d, '/');
        if (sl == NULL || !strcmp(d, "/")) break;
        if (sl == d) sl[1] = 0; else *sl = 0;
    }
    char key[41];
    sha1_hex(root, key);
    key[16] = 0;
    const char *dir = getenv("PSSC_DAEMON_DIR");
    char rd[4200];
    if (dir == NULL || !*dir) {
        const char *base = getenv("XDG_RUNTIME_DIR");
        static const char *const TMPS[] = {"TMPDIR", "TEMP", "TMP"};
        for (int i = 0; i < 3 && (base == NULL || !*base); i++) base = getenv(TMPS[i]);
        if (base == NULL || !*base) base = "/tmp";
        snprintf(rd, sizeof(rd), "%s/pssd-%u", base, (unsigned)getuid());
        dir = rd;
    }
    snprintf(out, n, "%s/%s.sim", dir, key);
}

/* -- the channel --------------------------------------------------------- */

static void send_line(srv_t *s, const char *txt, size_t len) {
    pthread_mutex_lock(&s->wmu);
    if (s->fd >= 0) {
        const char *p = txt;
        size_t left = len;
        while (left > 0) {
            ssize_t w = send(s->fd, p, left, MSG_NOSIGNAL);
            if (w < 0 && errno == EINTR) continue;
            if (w <= 0) break;
            p += w; left -= (size_t)w;
        }
        if (left == 0) while (send(s->fd, "\n", 1, MSG_NOSIGNAL) < 0 && errno == EINTR) {}
    }
    pthread_mutex_unlock(&s->wmu);
}

/* A line from the socket (malloc'd, no newline), or NULL at its end. */
static char *read_line(srv_t *s) {
    for (;;) {
        char *nl = s->rn ? memchr(s->rb, '\n', s->rn) : NULL;
        if (nl != NULL) {
            size_t k = (size_t)(nl - s->rb);
            char *line = malloc(k + 1);
            memcpy(line, s->rb, k);
            line[k] = 0;
            memmove(s->rb, nl + 1, s->rn - k - 1);
            s->rn -= k + 1;
            return line;
        }
        if (s->rn + 4096 > s->rcap) {
            s->rcap = s->rcap ? 2 * s->rcap : 8192;
            s->rb = realloc(s->rb, s->rcap);
        }
        ssize_t r = recv(s->fd, s->rb + s->rn, s->rcap - s->rn, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return NULL;
        s->rn += (size_t)r;
    }
}

static void put_raw(sbuf *o, jv *x) {
    if (x) sb_put(o, x->raw, x->rawlen); else sb_f(o, "null");
}

static void send_ok(srv_t *s, const char *seq, const char *body) {
    sbuf o = {0};
    sb_f(&o, "{\"seq\":");
    sb_put(&o, seq, strlen(seq));
    sb_f(&o, ",\"ok\":true,\"body\":");
    sb_put(&o, body, strlen(body));
    sb_f(&o, "}");
    send_line(s, o.b, o.n);
    free(o.b);
}

static void send_err(srv_t *s, const char *seq, const char *code, const char *msg) {
    sbuf o = {0};
    sb_f(&o, "{\"seq\":");
    sb_put(&o, seq, strlen(seq));
    sb_f(&o, ",\"ok\":false,\"error\":{\"code\":");
    sb_str(&o, code);
    sb_f(&o, ",\"message\":");
    sb_str(&o, msg);
    sb_f(&o, "}}");
    send_line(s, o.b, o.n);
    free(o.b);
}

/* An event; `body` the members of its body ("" none), `t` added. */
static void send_event(srv_t *s, const char *name, const char *body, size_t blen) {
    sbuf o = {0};
    sb_f(&o, "{\"event\":");
    sb_str(&o, name);
    sb_f(&o, ",\"body\":{");
    if (blen) { sb_put(&o, body, blen); sb_f(&o, ","); }
    sb_f(&o, "\"t\":%llu}}", (unsigned long long)__atomic_load_n(&g_now_fs, __ATOMIC_RELAXED));
    send_line(s, o.b, o.n);
    free(o.b);
}

static char *seq_text(jv *msg) {
    jv *seq = jget(msg, "seq");
    if (seq == NULL) return strdup("null");
    char *t = malloc(seq->rawlen + 1);
    memcpy(t, seq->raw, seq->rawlen);
    t[seq->rawlen] = 0;
    return t;
}

static int truthy(jv *x) {
    if (x == NULL) return 0;
    switch (x->t) {
    case J_BOOL: return x->b;
    case J_INT:  return x->i != 0;
    case J_STR:  return x->s[0] != 0;
    case J_ARR: case J_OBJ: return x->n != 0;
    case J_NUM:  return 1;
    default:     return 0;
    }
}

/* -- the debug stub ------------------------------------------------------ */

static void *pump_main(void *arg) {
    srv_t *s = (srv_t *)arg;
    pssvm_stub_t *st = s->stub;
    for (;;) {
        pthread_mutex_lock(&s->mu);
        int stop = s->pump_stop || s->closed;
        pthread_mutex_unlock(&s->mu);
        if (stop) break;
        const char *ev = pssvm_stub_next_event(st, 200);
        if (ev == NULL) continue;
        jv m;
        const char *p = ev;
        if (jparse(&p, &m, 0) == 0 && m.t == J_OBJ) {
            jv *name = jget(&m, "event"), *body = jget(&m, "body");
            if (name && name->t == J_STR) {
                const char *b = "";
                size_t bl = 0;
                if (body && body->t == J_OBJ && body->n > 0) {
                    b = body->raw + 1;                 /* inside the braces */
                    bl = body->rawlen - 2;
                }
                send_event(s, name->s, b, bl);
            }
        }
        jfree(&m);
    }
    return NULL;
}

/* Take the stub off (reader thread, or the SV thread with the reader
 * gone). */
static void stub_off(srv_t *s) {
    pthread_mutex_lock(&s->mu);
    pssvm_stub_t *st = s->stub;
    s->stub = NULL;
    s->pump_stop = 1;
    pthread_mutex_unlock(&s->mu);
    if (st == NULL) return;
    const char *state = pssvm_stub_state(st);
    if (strcmp(state, "detached") && strcmp(state, "exited"))
        pssvm_stub_request(st, "{\"seq\":0,\"cmd\":\"detach\"}");
    pthread_mutex_lock(&s->mu);
    while (s->in_stop) pthread_cond_wait(&s->cv, &s->mu);
    pthread_mutex_unlock(&s->mu);
    if (s->has_pump) pthread_join(s->pump, NULL);
    s->has_pump = 0;
    pssvm_stub_free(st);
}

/* `debug` {on}: on the reader thread. */
static void on_debug(srv_t *s, const char *seq, jv *args) {
    jv *on = jget(args, "on");
    stub_off(s);
    if (on != NULL && !truthy(on)) {
        send_ok(s, seq, "{}");
        return;
    }
    pssvm_stub_t *st = pssvm_stub_new(s->e);
    if (st == NULL) {
        send_err(s, seq, "failed", "no image loaded");
        return;
    }
    pthread_mutex_lock(&s->mu);
    s->stub = st;
    s->pump_stop = 0;
    pthread_mutex_unlock(&s->mu);
    s->has_pump = pthread_create(&s->pump, NULL, pump_main, s) == 0;
    sbuf b = {0};
    sb_f(&b, "{\"image\":");
    sb_str(&b, image_of(s->e));
    sb_f(&b, "}");
    send_ok(s, seq, b.b);
    free(b.b);
}

/* The commands the session answers itself (not forwarded to a stub). */
static int session_cmd(const char *c) {
    static const char *const CMDS[] = {"ping", "info", "end", "run", "reload", "resume"};
    for (size_t i = 0; i < sizeof(CMDS) / sizeof(CMDS[0]); i++)
        if (!strcmp(c, CMDS[i])) return 1;
    return 0;
}

static void *reader_main(void *arg) {
    srv_t *s = (srv_t *)arg;
    char *line;
    while ((line = read_line(s)) != NULL) {
        jv msg;
        const char *p = line;
        jv *cmd = NULL;
        if (jparse(&p, &msg, 0) == 0 && msg.t == J_OBJ) cmd = jget(&msg, "cmd");
        if (cmd != NULL && cmd->t == J_STR) {
            if (!strcmp(cmd->s, "debug")) {
                char *seq = seq_text(&msg);
                on_debug(s, seq, jget(&msg, "args"));
                free(seq);
            } else if (s->stub != NULL && !session_cmd(cmd->s)) {
                const char *r = pssvm_stub_request(s->stub, line);
                if (r) send_line(s, r, strlen(r));
            } else {
                qn_t *q = calloc(1, sizeof(*q));
                q->line = line;
                line = NULL;
                pthread_mutex_lock(&s->mu);
                if (s->qt) s->qt->next = q; else s->qh = q;
                s->qt = q;
                pthread_cond_broadcast(&s->cv);
                pthread_mutex_unlock(&s->mu);
            }
        }
        jfree(&msg);
        free(line);
    }
    pthread_mutex_lock(&s->mu);
    s->closed = 1;
    pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->mu);
    return NULL;
}

static void server_close(srv_t *s) {
    if (s == NULL) return;
    if (s->fd >= 0) shutdown(s->fd, SHUT_RDWR);
    if (s->has_reader) pthread_join(s->reader, NULL);
    s->has_reader = 0;
    s->closed = 1;
    stub_off(s);
    pthread_mutex_lock(&s->wmu);
    if (s->fd >= 0) close(s->fd);
    s->fd = -1;
    pthread_mutex_unlock(&s->wmu);
    while (s->qh) {
        qn_t *q = s->qh;
        s->qh = q->next;
        free(q->line);
        free(q);
    }
    free(s->info); free(s->run_seq); free(s->run_sel); free(s->held_why); free(s->rb);
    pthread_cond_destroy(&s->cv);
    pthread_mutex_destroy(&s->mu);
    pthread_mutex_destroy(&s->wmu);
    if (g_srv == s) g_srv = NULL;
    free(s);
}

/* The session's `info` body (malloc'd). */
static char *make_info(const char *cwd, const char *image, const char *name, const char *top) {
    sbuf info = {0};
    sb_f(&info, "{\"cwd\":");
    sb_str(&info, cwd ? cwd : "");
    sb_f(&info, ",\"image\":");
    sb_str(&info, image ? image : "");
    sb_f(&info, ",\"name\":");
    sb_str(&info, name ? name : "");
    sb_f(&info, ",\"pid\":%d,\"protocol\":%d,\"top\":", (int)getpid(), SIM_PROTOCOL);
    sb_str(&info, top ? top : "");
    sb_f(&info, "}");
    return info.b;
}

static const char *jstr(jv *o, const char *k) {
    jv *v = jget(o, k);
    return v && v->t == J_STR ? v->s : "";
}

/* `reload` {image?, strict?, cancel?} (plan P4.9e3): the image file (default:
 * the one loaded, rebuilt in place) becomes the engine's next generation, at
 * once (requests are answered between calls). A refusal is error `refused`,
 * its `detail` {code, reason, message, changes} as the Python shim's, and
 * leaves the engine as it was. pssvm_reload clears breakpoints: a debugger
 * that is on re-sends them (reply `breaks_cleared`). */
static void on_reload(srv_t *s, const char *seq, jv *args) {
    const char *path = jstr(args, "image");
    if (!*path) path = image_of(s->e);
    if (!*path) {
        send_err(s, seq, "failed", "no image: give one to reload");
        return;
    }
    char *p = strdup(path);           /* remember_image frees the old path */
    long n = 0;
    g_dpi_err[0] = 0;
    uint8_t *buf = read_image(p, &n);
    if (buf == NULL) {
        send_err(s, seq, "failed", g_dpi_err);
        free(p);
        return;
    }
    uint64_t old = pssvm_generation(s->e);
    int rc = pssvm_reload(s->e, buf, (size_t)n,
                          truthy(jget(args, "strict")) ? PSSVM_R_STRICT : 0);
    free(buf);
    if (rc != PSSVM_OK) {
        const char *m = pssvm_error(s->e, NULL);
        jv ej;                         /* {"message", "status", "halted_op"} */
        const char *ep = m ? m : "";
        int parsed = jparse(&ep, &ej, 0) == 0;
        if (parsed && ej.t == J_OBJ && *jstr(&ej, "message")) m = jstr(&ej, "message");
        m = m && *m ? m : "reload failed";
        const char *colon = strchr(m, ':');
        char reason[32] = "image";
        if (rc == PSSVM_E_API && colon && colon - m < (long)sizeof(reason)) {
            memcpy(reason, m, (size_t)(colon - m));
            reason[colon - m] = 0;
        }
        const char *why = rc == PSSVM_E_API && colon ? colon + 1 : m;
        while (*why == ' ') why++;
        sbuf o = {0};
        sb_f(&o, "{\"seq\":");
        sb_put(&o, seq, strlen(seq));
        sb_f(&o, ",\"ok\":false,\"error\":{\"code\":\"refused\",\"message\":");
        sbuf msg = {0};
        sb_f(&msg, "reload refused (%s): %s", reason, why);
        sb_str(&o, msg.b);
        sb_f(&o, ",\"detail\":{\"code\":%d,\"reason\":", rc);
        sb_str(&o, reason);
        sb_f(&o, ",\"message\":");
        sb_str(&o, why);
        sb_f(&o, ",\"changes\":[]}}}");
        send_line(s, o.b, o.n);
        free(o.b);
        free(msg.b);
        jfree(&ej);
        free(p);
        return;
    }
    remember_image(s->e, p);
    jv info;
    const char *ip = s->info;
    if (jparse(&ip, &info, 0) == 0 && info.t == J_OBJ) {
        char *ni = make_info(jstr(&info, "cwd"), p, jstr(&info, "name"), jstr(&info, "top"));
        free(s->info);
        s->info = ni;
    }
    jfree(&info);
    sbuf b = {0};
    sb_f(&b, "{\"old\":%llu,\"new\":%llu,\"changed\":[],"
         "\"structure\":{\"added\":[],\"removed\":[],\"changed\":[]},\"migrated\":0,"
         "\"cancelled\":[],\"applied\":true,\"unbound\":[],\"reimported\":[],"
         "\"breaks_cleared\":%s,\"image\":",
         (unsigned long long)old, (unsigned long long)pssvm_generation(s->e),
         s->stub ? "true" : "false");
    sb_str(&b, p);
    sb_f(&b, "}");
    send_ok(s, seq, b.b);
    free(b.b);
    free(p);
}

/* One request from the queue, answered on the SV thread. */
static void handle(srv_t *s, const char *line) {
    jv msg;
    const char *p = line;
    if (jparse(&p, &msg, 0) != 0 || msg.t != J_OBJ) { jfree(&msg); return; }
    jv *cmdv = jget(&msg, "cmd"), *args = jget(&msg, "args");
    const char *cmd = cmdv && cmdv->t == J_STR ? cmdv->s : "";
    char *seq = seq_text(&msg);
    char tmp[256];
    if (!strcmp(cmd, "ping")) {
        snprintf(tmp, sizeof(tmp), "{\"pid\":%d}", (int)getpid());
        send_ok(s, seq, tmp);
    } else if (!strcmp(cmd, "info")) {
        send_ok(s, seq, s->info);
    } else if (!strcmp(cmd, "end")) {
        s->ended = 1;
        send_ok(s, seq, "{}");
    } else if (!strcmp(cmd, "run")) {
        if (s->held) {
            send_err(s, seq, "failed", "held after a failed test: resume it first");
        } else if (s->run_pending) {
            send_err(s, seq, "failed", "a run is in progress");
        } else {
            jv *sel = jget(args, "sel");
            sbuf o = {0};
            sb_f(&o, "");
            if (sel && sel->t == J_STR) sb_put(&o, sel->s, strlen(sel->s));
            else if (sel && sel->t == J_ARR)
                for (int i = 0; i < sel->n; i++) {
                    if (i) sb_put(&o, ",", 1);
                    if (sel->v[i].t == J_STR) sb_put(&o, sel->v[i].s, strlen(sel->v[i].s));
                }
            free(s->run_seq);
            free(s->run_sel);
            s->run_seq = seq;
            seq = NULL;
            s->run_sel = o.b;
            s->run_pending = 1;           /* answered by pssvm_dpi_serve_done */
        }
    } else if (!strcmp(cmd, "resume")) {
        if (!s->held) {
            send_err(s, seq, "failed", "not held: nothing to resume");
        } else {
            s->resume = truthy(jget(args, "rerun"));
            sbuf b = {0};
            sb_f(&b, "{\"why\":");
            sb_str(&b, s->held_why ? s->held_why : "");
            sb_f(&b, ",\"rerun\":%s}", s->resume ? "true" : "false");
            send_ok(s, seq, b.b);
            free(b.b);
        }
    } else if (!strcmp(cmd, "reload")) {
        on_reload(s, seq, args);
    } else {
        snprintf(tmp, sizeof(tmp), "no handler for '%s'", cmd);
        send_err(s, seq, "unsupported", tmp);
    }
    free(seq);
    jfree(&msg);
}

/* Answer one queued request, waiting up to `ms` (< 0: until one comes).
 * 1 if one was answered. */
static int serve_one(srv_t *s, int ms) {
    struct timespec ts;
    if (ms > 0) {
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += ms / 1000;
        ts.tv_nsec += (long)(ms % 1000) * 1000000L;
        if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    }
    pthread_mutex_lock(&s->mu);
    while (s->qh == NULL && !s->closed && ms != 0) {
        if (ms < 0) pthread_cond_wait(&s->cv, &s->mu);
        else if (pthread_cond_timedwait(&s->cv, &s->mu, &ts) == ETIMEDOUT) break;
    }
    qn_t *q = s->qh;
    if (q) {
        s->qh = q->next;
        if (s->qh == NULL) s->qt = NULL;
    }
    pthread_mutex_unlock(&s->mu);
    if (q == NULL) return 0;
    handle(s, q->line);
    free(q->line);
    free(q);
    return 1;
}

static int srv_closed(srv_t *s) {
    pthread_mutex_lock(&s->mu);
    int c = s->closed;
    pthread_mutex_unlock(&s->mu);
    return c;
}

/* Register `e` with the daemon's sim socket (env PSSC_SIM_SOCKET, else the
 * cwd's workspace daemon; not started from here) as `name` ("" =
 * sim-<pid>), top module `top`. The session id, or "" (pssvm_dpi_error(e,
 * NULL)). */
const char *pssvm_dpi_serve(void *e, const char *name, const char *top) {
    g_dpi_err[0] = 0;
    if (g_srv != NULL) {
        if (!g_srv->ended && !srv_closed(g_srv)) return g_srv->session;
        server_close(g_srv);
    }
    char path[4400];
    const char *env = getenv("PSSC_SIM_SOCKET");
    if (env && *env) snprintf(path, sizeof(path), "%s", env);
    else default_sim_path(path, sizeof(path));
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(a.sun_path)) {
        dpi_err("sim socket path too long: %s", path);
        return "";
    }
    strcpy(a.sun_path, path);
    int fd = -1;
    struct timespec t0, now;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd >= 0 && connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0) break;
        int err = errno;
        if (fd >= 0) close(fd);
        fd = -1;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - t0.tv_sec >= 10) {
            dpi_err("cannot connect to %s: %s", path, strerror(err));
            return "";
        }
        struct timespec nap = {0, 50000000L};
        nanosleep(&nap, NULL);
    }
    srv_t *s = calloc(1, sizeof(*s));
    s->e = (pssvm_t *)e;
    s->fd = fd;
    s->resume = -1;
    pthread_mutex_init(&s->mu, NULL);
    pthread_cond_init(&s->cv, NULL);
    pthread_mutex_init(&s->wmu, NULL);
    char cwd[4096], nm[64];
    if (getcwd(cwd, sizeof(cwd)) == NULL) cwd[0] = 0;
    if (name == NULL || !*name) {
        snprintf(nm, sizeof(nm), "sim-%d", (int)getpid());
        name = nm;
    }
    s->info = make_info(cwd, image_of(s->e), name, top);
    sbuf reg = {0};
    sb_f(&reg, "{\"args\":");
    sb_put(&reg, s->info, strlen(s->info));
    sb_f(&reg, ",\"cmd\":\"register\",\"seq\":0}");
    send_line(s, reg.b, reg.n);
    free(reg.b);
    char *line = read_line(s);
    jv r;
    const char *p = line ? line : "";
    int ok = line && jparse(&p, &r, 0) == 0 && r.t == J_OBJ && truthy(jget(&r, "ok"));
    jv *sid = ok ? jget(jget(&r, "body"), "session") : NULL;
    if (sid && sid->t == J_STR) snprintf(s->session, sizeof(s->session), "%s", sid->s);
    else ok = 0;
    if (!ok) dpi_err("register refused: %s", line ? line : "(no reply)");
    if (line) jfree(&r);
    free(line);
    if (!ok) {
        server_close(s);
        return "";
    }
    g_srv = s;
    s->has_reader = pthread_create(&s->reader, NULL, reader_main, s) == 0;
    return s->session;
}

/* Answer one request, waiting up to `timeout_ms` (< 0: until one comes):
 * 1 answered, 2 a `run` is pending (pssvm_dpi_pending_sel; then
 * pssvm_dpi_serve_done), 0 none, -1 the channel closed or the session
 * ended. */
int pssvm_dpi_poll(void *e, int timeout_ms) {
    (void)e;
    srv_t *s = g_srv;
    if (s == NULL) return -1;
    if (s->ended || srv_closed(s)) {
        server_close(s);
        return -1;
    }
    int done = serve_one(s, timeout_ms);
    if (s->ended) {
        server_close(s);
        return -1;
    }
    if (s->run_pending) return 2;
    if (done) return 1;
    return srv_closed(s) ? -1 : 0;
}

/* The pending `run`'s selection (`+pssunit` form; "" = every test). */
const char *pssvm_dpi_pending_sel(void *e) {
    (void)e;
    return (g_srv && g_srv->run_pending && g_srv->run_sel) ? g_srv->run_sel : "";
}

/* A test of the pending `run` finished: a `test` event. */
void pssvm_dpi_serve_test(void *e, const char *name, int passed) {
    (void)e;
    if (g_srv == NULL) return;
    sbuf b = {0};
    sb_f(&b, "\"name\":");
    sb_str(&b, name ? name : "");
    sb_f(&b, ",\"status\":\"%s\"", passed ? "pass" : "fail");
    send_event(g_srv, "test", b.b, b.n);
    free(b.b);
}

/* The pending `run` finished: answer it with the counts. */
void pssvm_dpi_serve_done(void *e, int n_pass, int n_fail) {
    (void)e;
    srv_t *s = g_srv;
    if (s == NULL || !s->run_pending) return;
    char body[96];
    snprintf(body, sizeof(body), "{\"failed\":%d,\"passed\":%d}", n_fail, n_pass);
    send_ok(s, s->run_seq ? s->run_seq : "null", body);
    s->run_pending = 0;
    free(s->run_seq);
    free(s->run_sel);
    s->run_seq = s->run_sel = NULL;
}

/* The sim time (fs) the events carry from now on. */
void pssvm_dpi_set_time(void *e, uint64_t t_fs) {
    (void)e;
    __atomic_store_n(&g_now_fs, t_fs, __ATOMIC_RELAXED);
}

/* Hold the simulation for a debugger: register if not serving yet, send a
 * `held` event {why}, answer requests here until a `resume` {rerun}; then a
 * `resumed` event. 1: run the failed test again, 0: go on, -1: no daemon,
 * or the session ended. */
int pssvm_dpi_dbg_wait(void *e, const char *why) {
    srv_t *s = g_srv;
    if (s == NULL || s->ended || srv_closed(s)) {
        if (!*pssvm_dpi_serve(e, "", "")) return -1;
        s = g_srv;
    }
    s->resume = -1;
    s->held = 1;
    free(s->held_why);
    s->held_why = strdup(why ? why : "");
    sbuf b = {0};
    sb_f(&b, "\"why\":");
    sb_str(&b, s->held_why);
    send_event(s, "held", b.b, b.n);
    free(b.b);
    while (s->resume < 0) {
        serve_one(s, 100);
        if (s->ended || srv_closed(s)) {
            server_close(s);
            return -1;
        }
    }
    int rerun = s->resume;
    s->held = 0;
    s->resume = -1;
    b = (sbuf){0};
    sb_f(&b, "\"rerun\":%s,\"why\":", rerun ? "true" : "false");
    sb_str(&b, s->held_why);
    send_event(s, "resumed", b.b, b.n);
    free(b.b);
    return rerun ? 1 : 0;
}

/* pssvm_run for SV: a STOP (a debugger's breakpoint, step, pause) goes to
 * the attached debug stub, which blocks it until the debugger resumes; then
 * the run goes on. Never returns PSSVM_STOP; a debugger's `terminate` ends
 * the call with PSSVM_ERROR. */
int pssvm_dpi_run(void *h) {
    for (;;) {
        int st = pssvm_run((pssvm_call_t *)h);
        if (st != PSSVM_STOP) return st;
        srv_t *s = g_srv;
        pssvm_stub_t *stub = NULL;
        if (s != NULL) {
            pthread_mutex_lock(&s->mu);
            stub = s->stub;
            if (stub) s->in_stop++;
            pthread_mutex_unlock(&s->mu);
        }
        if (stub == NULL) {
            pssvm_dbg_resume((pssvm_call_t *)h, PSSVM_RESUME);
            continue;
        }
        int term = pssvm_stub_on_stop(stub, (pssvm_call_t *)h);
        pthread_mutex_lock(&s->mu);
        s->in_stop--;
        pthread_cond_broadcast(&s->cv);
        pthread_mutex_unlock(&s->mu);
        if (term) {
            dpi_err("terminated by the debugger");
            return PSSVM_ERROR;
        }
    }
}
