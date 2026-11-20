/*
 * pssvm.h -- the engine's host ABI (be-bc docs/spec/host-abi.md).
 *
 * A host loads an image once (pssvm_load), builds its component tree
 * (pssvm_construct), then starts calls by entry name (pssvm_call_start) and
 * runs each to a status (pssvm_run).
 *
 * P4.3b (this version): pssvm_run runs a call to DONE or ERROR, or stops at
 * a bus access (ACCESS) or an import (IMPORT); pssvm_request shows it and
 * pssvm_complete answers it, and the next pssvm_run goes on from there.
 * message / error / fatal do not yield.
 * P4.3c: when no thread of a call is ready and one waits on time, pssvm_run
 * returns WAIT (on TIME, `delay` ticks); the host waits, then pssvm_run goes
 * on at that time. An ERROR's JSON says where it happened (coroutine, pc).
 * P4.4e: a call whose threads all wait on something only the host can change
 * returns WAIT (on EVENT) and keeps them; pssvm_notify queues a host event
 * that the next pssvm_run of any call takes (IRQ: start the handler named by
 * pssvm_set_irq; a kind with no handler ends that call in ERROR). A host with
 * nothing to notify reports the deadlock itself (rt-eng host.run_sync).
 *
 * Value ABI, as far as P4.3a needs it: arguments are `len / 8` little-endian
 * u64 leaves in `sig` order (the root frame's LD_ARG slots); a result is one
 * little-endian u64.
 */
#ifndef ZUSPEC_PSSVM_H
#define ZUSPEC_PSSVM_H

#include <stddef.h>
#include <stdint.h>
#include "zbc_interp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PSSVM_ABI_VERSION 1

/* pssvm_run status */
enum {
    PSSVM_DONE   =  0,
    PSSVM_ACCESS =  1,
    PSSVM_IMPORT =  2,
    PSSVM_WAIT   =  3,
    PSSVM_STOP   =  4,
    PSSVM_ERROR  = -1
};

/* Return codes */
enum {
    PSSVM_OK      =  0,
    PSSVM_E_STATE = -2,   /* call made in the wrong state */
    PSSVM_E_ARGS  = -3,   /* bad entry, path or argument size */
    PSSVM_E_API   = -4,   /* reload refused */
    PSSVM_E_IMAGE = -5    /* bad image */
};

/* pssvm_req_t.on, for WAIT */
enum { PSSVM_ON_TIME = 1, PSSVM_ON_EVENT = 2 };

/* pssvm_notify kinds; host-fed channels (CHAN) have no handler yet */
enum { PSSVM_N_IRQ = 1, PSSVM_N_CHAN = 2 };
#define PSSVM_NOTES_MAX 64

/* The pending request of a call that pssvm_run left in ACCESS, IMPORT or WAIT.
 * `args` points into the call and is valid until the next call on it. */
typedef struct {
    int32_t        status;     /* PSSVM_ACCESS / PSSVM_IMPORT */
    uint32_t       kind;       /* ACCESS: 0 read, 1 write */
    uint64_t       addr;
    uint32_t       size;       /* bytes: 1, 2, 4, 8 */
    uint64_t       data;       /* write data, little-endian u64 */
    uint32_t       reg_id;     /* 0xFFFFFFFF: not a register access / unknown */
    uint32_t       src_ref;    /* 0xFFFFFFFF: unknown */
    uint32_t       fn_id;      /* IMPORT: */
    const char    *name;       /* the import's name (image IMPORT table), else NULL */
    const uint8_t *args;       /* value ABI: u64 leaves */
    size_t         args_len;
    uint32_t       blocking;
    uint32_t       has_ret;    /* the answer is one u64 (else empty) */
    uint32_t       on;         /* WAIT: PSSVM_ON_TIME / PSSVM_ON_EVENT */
    uint64_t       delay;      /* WAIT TIME: engine ticks (ps) */
    uint32_t       bound;      /* IMPORT: 1 = a call of a pssvm_bind function;
                                * fn_id is its coroutine, args its arguments */
} pssvm_req_t;

typedef struct pssvm_s      pssvm_t;
typedef struct pssvm_call_s pssvm_call_t;

int           pssvm_abi_version(void);
pssvm_t      *pssvm_load(const uint8_t *img, size_t len, const char *opts);
int           pssvm_construct(pssvm_t *e, const char *root_type,
                              const uint8_t *args, size_t len);
/* Drop the component tree and build it again: a clean model for the next
 * test (call it with no call running). Constructs when nothing was. */
int           pssvm_fresh(pssvm_t *e, const char *root_type);
/* The text of the image's host metadata document `name` (debug images;
 * pssc writes them), or NULL. Valid while `e` is. */
const char   *pssvm_meta(pssvm_t *e, const char *name);
pssvm_call_t *pssvm_call_start(pssvm_t *e, const char *entry, const char *comp_path,
                               const uint8_t *args, size_t len, uint64_t seed);
/* As pssvm_call_start, with an action object: `n_slots` fields in `slots`,
 * which the host owns and the call reads and writes until pssvm_call_end. */
pssvm_call_t *pssvm_call_start_obj(pssvm_t *e, const char *entry, const char *comp_path,
                                   const uint8_t *args, size_t len, uint64_t seed,
                                   uint64_t *slots, uint32_t n_slots);
int           pssvm_run(pssvm_call_t *h);
const pssvm_req_t *pssvm_request(pssvm_call_t *h);
int           pssvm_complete(pssvm_call_t *h, const uint8_t *data, size_t len);
size_t        pssvm_result(pssvm_call_t *h, uint8_t *buf, size_t cap);
void          pssvm_call_end(pssvm_call_t *h);
const char   *pssvm_error(pssvm_t *e, pssvm_call_t *h);
void          pssvm_free(pssvm_t *e);

/* A host event, taken at the next pssvm_run of any call of `e` (call it
 * between engine calls). PSSVM_E_STATE: PSSVM_NOTES_MAX already queued. */
int           pssvm_notify(pssvm_t *e, uint32_t kind, uint32_t id, uint64_t value);

/* The function entry an IRQ notification starts, as a thread of its own in
 * the root component (NULL or "": none). PSSVM_E_ARGS: no such entry. */
int           pssvm_set_irq(pssvm_t *e, const char *entry);

/* Bind (on != 0) or unbind coroutine `coro`: from the next call on, each
 * CALL of it is an IMPORT request with `bound` set that the host answers with
 * the function's result (pssvm_complete), in place of its body.
 * PSSVM_E_ARGS: no such coroutine. */
int           pssvm_bind(pssvm_t *e, uint32_t coro, int on);

/* Interim: the message callback, verbosity and import log every call of `e`
 * uses (NULL: none); its mem_access and import_returns are not used, as
 * imports and memory yield. The host keeps it alive. Events
 * (pssvm_set_events: message, import, access) now carry what the callback
 * and log did; this stays only to set the verbosity, until a run option does. */
void          pssvm_set_host(pssvm_t *e, zbc_host_t *host);

/* Raise debug events into `sink` (zbc_events.h; NULL: none) in every later
 * call of `e`; which events, per coroutine, is the sink's zbc_ev_watch mask.
 * It wins over the events of pssvm_set_host's host. The host keeps it alive. */
void          pssvm_set_events(pssvm_t *e, struct zbc_ev_sink_s *sink);

/* The engine-side ZBC_* status and halting opcode of a call that ended in
 * ERROR, and its end time in ticks (for tests that compare with zbc_run). */
int           pssvm_call_status(pssvm_call_t *h, int *halted_op, uint64_t *now);

/* Interim, until state reads over events (P4.4): copy up to `cap` slots of the
 * component object (constructed by the first call) into `buf`; returns the
 * slot count, 0 if there is none yet. Slot i is the image's component field i. */
size_t        pssvm_comp_read(pssvm_t *e, uint64_t *buf, size_t cap);

/* Hot reload from a Python host (P4.6a): overwrite the first `n` slots of the
 * constructed component object with `buf` (N's state migrated into N+1);
 * returns the slots written, 0 before construction. Call with no call live. */
size_t        pssvm_comp_write(pssvm_t *e, const uint64_t *buf, size_t n);

/* Hot reload in C (P4.9e; be-bc docs/spec/host-abi.md, Reload): load `img` as
 * generation N+1 in place of N, now (call it with no call live). Refused with
 * PSSVM_E_API (pssvm_error's message starts with the reason: "api", "structure",
 * "bus" or "construct") when the entry points or imports change, when the
 * component tree's layout changes (same-layout only, for now), or when building
 * N+1's tree needs the host; N is then untouched. A constructed N's state
 * carries into N+1. Bindings, the interrupt handler and breakpoints are
 * cleared: set them again for N+1. PSSVM_E_IMAGE: a bad image. */
enum { PSSVM_R_STRICT = 1 };  /* refuse any change to the component tree */
int           pssvm_reload(pssvm_t *e, const uint8_t *img, size_t len, uint32_t flags);
/* The engine's generation: 1 at load, one more for each reload. */
uint64_t      pssvm_generation(pssvm_t *e);

/* Debugging (P4.5a; be-bc docs/spec/host-abi.md, STOP). With debugging on,
 * a call's run stops at a breakpoint, on pause and after a step: pssvm_run
 * returns PSSVM_STOP and pssvm_dbg_stop says where; the host serves its
 * debugger, then resumes (pssvm_dbg_resume, or just pssvm_run: continue).
 * Breakpoints are (id, coro, pc) triples, pc in the coroutine; `verified[i]`
 * (may be NULL) says whether triple i names an instruction. */
typedef zbc_dbg_stop_t pssvm_stop_t;
enum { PSSVM_RESUME = 0, PSSVM_STEP_STMT = 1, PSSVM_STEP_INTO = 2, PSSVM_STEP_OUT = 3 };
int           pssvm_dbg_enable(pssvm_t *e, int on);
int           pssvm_dbg_set_breaks(pssvm_t *e, const uint32_t *id_coro_pc, uint32_t n,
                                   uint8_t *verified);
int           pssvm_dbg_pause(pssvm_t *e);
/* P4.5b2: access watches (replace the set; at most ZBC_DBG_MAX_WATCHES): a
 * watched access stops (reason WATCH) before the next instruction, with the
 * access in the stop record. Stop-on kinds (a mask; 0 = none, the default):
 * PSSVM_STOP_ON_ERROR stops (reason ERROR) where the run's first error
 * happened, frames still live; any resume then ends the call with it. */
typedef zbc_dbg_watch_t pssvm_watch_t;
enum { PSSVM_WATCH_R = 1, PSSVM_WATCH_W = 2, PSSVM_WATCH_RW = 3 };
enum { PSSVM_STOP_ON_ERROR = 1 };
int           pssvm_dbg_set_watches(pssvm_t *e, const pssvm_watch_t *w, uint32_t n);
int           pssvm_dbg_set_stop_on(pssvm_t *e, uint32_t kinds);
int           pssvm_dbg_resume(pssvm_call_t *h, int kind);
const pssvm_stop_t *pssvm_dbg_stop(pssvm_call_t *h);

/* Inspection while stopped (P4.5b): the live threads' ids (a thread's id is
 * its bottom frame's), a thread's frames innermost first, and one frame:
 * its coro, pc, depth, thread state and its registers, locals and call
 * arguments (pointers valid until the run goes on). The counts are the full
 * counts (up to `cap` filled); 0 when not stopped. Component fields:
 * pssvm_comp_read. Memory is the host's (a back-door read is the host's). */
typedef zbc_dbg_frame_t pssvm_frame_t;
uint32_t      pssvm_dbg_threads(pssvm_call_t *h, uint32_t *ids, uint32_t cap);
uint32_t      pssvm_dbg_frames(pssvm_call_t *h, uint32_t thread_id, pssvm_frame_t *out,
                               uint32_t cap);
int           pssvm_dbg_frame(pssvm_call_t *h, uint32_t frame_id, pssvm_frame_t *out);
/* The engine's image (names, statements, named locals), or NULL. */
const zbc_image_t *pssvm_image(pssvm_t *e);

/* The debug stub (be-bc docs/spec/debug-stub.md) in C, transport-agnostic:
 * requests and events are one-line JSON texts. The stub does not run calls:
 * the host's run thread calls pssvm_run, hands each PSSVM_STOP to
 * pssvm_stub_on_stop and reports the end with pssvm_stub_exited.
 *
 *   pssvm_stub_request: one request; returns its reply, owned by the stub
 *     and valid until the next request (requests are serialized). `attach`
 *     (entry true, the default) pauses the engine and replies once the run
 *     reached that first stop (error `timeout` after 10 s with none).
 *   pssvm_stub_wait_attached: for the run thread before its first
 *     pssvm_run: waits (up to timeout_ms) for a successful attach; 1:
 *     attached, 0: timed out, -1: the attach failed.
 *   pssvm_stub_on_stop: (run thread) a STOP of `h`: shows it and blocks
 *     until a request resumes it; 0: call pssvm_run again, 1: terminate was
 *     requested, end the run (then pssvm_stub_exited).
 *   pssvm_stub_exited: (run thread) the run ended: status "ok" / "error" /
 *     "terminated" ("ok" after a terminate request reads "terminated"),
 *     `message` may be NULL.
 *   pssvm_stub_next_event: the next event, waiting up to timeout_ms (< 0:
 *     forever); NULL if none. Owned by the stub, valid until the next call.
 *   pssvm_stub_set_backdoor: the host memory's back door for
 *     `backdoor_read` (peek returns 0 and the n-byte value in *out). */
typedef struct pssvm_stub_s pssvm_stub_t;
typedef int (*pssvm_peek_f)(void *ctx, uint64_t addr, uint32_t n, uint64_t *out);
pssvm_stub_t *pssvm_stub_new(pssvm_t *e);
void          pssvm_stub_free(pssvm_stub_t *s);
const char   *pssvm_stub_request(pssvm_stub_t *s, const char *json_line);
int           pssvm_stub_wait_attached(pssvm_stub_t *s, int timeout_ms);
int           pssvm_stub_on_stop(pssvm_stub_t *s, pssvm_call_t *h);
void          pssvm_stub_exited(pssvm_stub_t *s, const char *status, const char *message);
const char   *pssvm_stub_next_event(pssvm_stub_t *s, int timeout_ms);
const char   *pssvm_stub_state(pssvm_stub_t *s);
void          pssvm_stub_set_backdoor(pssvm_stub_t *s, pssvm_peek_f peek, void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ZUSPEC_PSSVM_H */
