/*
 * zbc_interp.h -- the ZBC interpreter as a scheduler coroutine.
 *
 * `zbc_interp_task` is a `zsp_task_func`: the entrypoint for every interpreted
 * ZBC coroutine (interpreter-as-coroutine design, rt-core docs). Its bytecode
 * arrives via the thread-create args; its pc + register/local file are frame
 * resident (the coroutine stack IS the interpreter's variable stack). Suspend/
 * resume uses the stackless task-func protocol, so interpreted coroutines
 * interleave with compiled ones under the shared scheduler.
 */
#ifndef ZUSPEC_ZBC_INTERP_H
#define ZUSPEC_ZBC_INTERP_H

#include <stdarg.h>
#include "zsp_timebase.h"
#include "zbc_reader.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Frame capacities. A frame holds the registers and locals its coroutine uses
 * (verify_coro counts them, at least ZBC_MIN_REGS/ZBC_MIN_LOCALS); the MAX
 * values bound an operand, and the whole frame must fit ZBC_MAX_FRAME_BYTES,
 * else ZBC_ERR_OOB_REG (a frame over 8 KiB gets a stack block of its own,
 * zsp_timebase_alloc_frame). */
#define ZBC_MIN_REGS    64
#define ZBC_MIN_LOCALS  32
#define ZBC_MAX_REGS    65536  /* bc lowering gives each temporary its own register:
                                * a 600-clause if-chain uses ~9700 */
#define ZBC_MAX_LOCALS  1024
#define ZBC_MAX_FRAME_BYTES (1u << 20)
#define ZBC_MAX_CHILDREN 64   /* max joinable children a single JOIN can await */
#define ZBC_CALL_MAX_ARGS  32    /* arguments a CALL or host call passes: model.CALL_MAX_ARGS
                                  * (16) bounds a CALL; a host call flattens struct
                                  * parameters (wb_dma transfer_single: 18 words) */
#define ZBC_CALL_MAX_DEPTH 1024  /* CALL nesting a run allows (model.CALL_MAX_DEPTH) */

/* Runaway-loop watchdog: max bytecode steps a single coroutine may execute
 * across its whole life (frame-resident, so it spans suspends/resumes). Real
 * skeleton programs are tiny; this trips a malformed back-edge in well under a
 * second instead of hanging. */
#define ZBC_STEP_LIMIT  10000000u
/* zbc_host_t.step_limit for no budget at all: a run that loops forever then
 * hangs, as it does on the Python VM, which counts no steps. */
#define ZBC_STEP_UNLIMITED UINT64_MAX

/* Total SPAWN budget for a whole run (shared across all coroutines). Bounds a
 * malformed/cyclic image that would otherwise fork threads without limit (OOM).
 * Real PSS activity graphs are an acyclic fan-out of distinct sub-coroutines. */
#define ZBC_SPAWN_LIMIT 100000u

/*
 * The action object: N 64-bit field slots addressed by index (LD/ST_FIELD).
 * Matches the oracle's `Obj` (M1: raw 64-bit slots, no per-field truncation).
 * The caller owns `slots`; the engine mutates it in place.
 */
typedef struct {
    uint64_t *slots;
    uint32_t  n;
} zbc_obj_t;

/* Execution result, filled by the entry coroutine (`now` is set by the driver). */
typedef struct {
    int      status;      /* ZBC_OK or a negative ZBC_ERR_* */
    int      halted_op;   /* opcode that halted execution on error (else 0) */
    uint64_t retval;      /* entry coroutine return value */
    uint64_t now;         /* final sim time in ticks (driver-filled) */
} zbc_result_t;

/* Max IMPORT value args the engine records/passes (M1 lowering caps at 2). */
#define ZBC_IMPORT_MAX_ARGS 4

/*
 * IMPORT host seam. IMPORT is the interpreter's window to the outside world: the
 * instruction fully encodes the call (fn_id, arg registers), so nothing is
 * serialized beyond the bytecode -- the *host* just records each call and supplies
 * a return value. This mirrors the oracle's `RecordingImportProvider`: the engine
 * records into `import_log` (for the differential's call-sequence check) and reads
 * a per-fn_id return value from `import_returns` (default 0 when absent).
 */
typedef struct {
    uint32_t fn_id;
    uint32_t n_args;
    uint64_t args[ZBC_IMPORT_MAX_ARGS];
} zbc_import_call_t;

typedef struct {
    zbc_import_call_t *calls;    /* caller-allocated record array (may be NULL) */
    uint32_t           capacity; /* slots in `calls` */
    uint32_t           count;    /* calls made (engine-written; may exceed capacity) */
} zbc_import_log_t;

typedef struct {
    const uint32_t *fn_ids;      /* parallel arrays: fn_id -> value (first match wins) */
    const uint64_t *values;
    uint32_t        count;
} zbc_import_returns_t;

/* Platform memory (LRM 21.13.9): the builtin read8..64 / write8..64 imports.
 * Called with is_write 0 (read: return the value, nbytes wide, little-endian) or
 * 1 (write `data`, already masked to nbytes; the return value is ignored). */
typedef uint64_t (*zbc_mem_access_f)(void *ctx, int is_write, uint64_t addr,
                                     uint32_t nbytes, uint64_t data);

/* Formatted message text (P4.2g). severity is a ZBC_MSG_SEV_*; level is the
 * message() verbosity or the fatal() status (0 otherwise); text is
 * NUL-terminated, len bytes (at most ZBC_MSG_TEXT_MAX - 1: longer is cut). */
enum {
    ZBC_MSG_SEV_INFO    = 0,   /* message() at or below the run's verbosity */
    ZBC_MSG_SEV_ERROR   = 1,   /* error(): the run stops */
    ZBC_MSG_SEV_FATAL   = 2,   /* fatal(): the run stops */
    ZBC_MSG_SEV_RUNTIME = 3    /* an LRM "shall" error raised by the run; it stops */
};
#define ZBC_MSG_TEXT_MAX 1024
typedef void (*zbc_message_f)(void *ctx, uint32_t severity, uint64_t level,
                              const char *text, uint32_t len);

/* The text of message entry msg_idx with its values read from `locals`
 * (slot 0 = verbosity/status, stored in *level). Returns the length written
 * to out (NUL-terminated, cut at cap - 1), or -1 if the image has no such
 * entry or a value cannot be formatted (the oracle raises VMError). */
int zbc_format_message(const zbc_image_t *img, uint32_t msg_idx,
                       const uint64_t *locals, char *out, uint32_t cap,
                       uint64_t *level);

/* A host request a thread waits on (P4.3b, the pssvm host ABI). With
 * host->yield set, an IMPORT other than the message builtins (message, error,
 * error/fatal text) does not call mem_access or read import_returns: it posts
 * the request here (state PENDING, `thread` = the zsp_thread_t asking), blocks
 * its thread without advancing past the IMPORT, and the run stops. The host
 * answers by setting `value` and state DONE and scheduling `thread` again; it
 * re-runs the IMPORT, takes `value` and goes on. One request at a time.
 * P4.3c: with `wait_time` set, a run with no ready thread does not advance
 * time itself: it moves to the next timed batch, posts state WAIT with
 * `delay` (ticks), and stops; the host clears the state once it has waited.
 * P4.4e: with `wait_event` set, a run whose threads all wait on something no
 * thread and no time can change posts state WAIT with `on_event` (instead of
 * the deadlock error) and keeps them; the host may start a thread (an
 * interrupt handler) before it runs again.
 * The first error of the run records where it happened (`err_coro`,
 * `err_pc`; err_coro 0xFFFFFFFF: not in a coroutine). */
enum { ZBC_YIELD_NONE = 0, ZBC_YIELD_PENDING = 1, ZBC_YIELD_DONE = 2, ZBC_YIELD_WAIT = 3,
       ZBC_YIELD_STOP = 4 };
/* ZBC_YIELD_BOUND: a CALL of a host-bound function (zbc_host_t.bound);
 * fn_id is the callee coroutine, args its staged arguments. */
enum { ZBC_YIELD_ACCESS = 1, ZBC_YIELD_IMPORT = 2, ZBC_YIELD_BOUND = 3 };
typedef struct {
    int       state;      /* ZBC_YIELD_* */
    int       kind;       /* ZBC_YIELD_ACCESS / ZBC_YIELD_IMPORT / ZBC_YIELD_BOUND */
    uint32_t  fn_id;
    uint32_t  n_args;
    uint64_t  args[ZBC_CALL_MAX_ARGS];   /* an IMPORT uses ZBC_IMPORT_MAX_ARGS */
    uint32_t  flags;      /* the IMPORT's ZBC_F_BLOCKING / ZBC_F_HAS_RET */
    int       is_write;   /* ACCESS: */
    uint64_t  addr;
    uint32_t  size;       /* bytes: 1, 2, 4, 8 */
    uint64_t  data;       /* write data */
    uint64_t  value;      /* the answer: read data or the import's result */
    void     *thread;
    const void *frame;    /* the frame whose IMPORT is answered */
    uint32_t  pc;         /* the IMPORT's global CODE index (REG side table) */
    int       wait_time;  /* the host waits on time (WAIT) */
    uint64_t  delay;      /* WAIT: ticks to the next timed batch */
    int       wait_event; /* the host may notify (WAIT on EVENT) */
    int       on_event;   /* WAIT: on an event, not time */
    uint32_t  err_coro;   /* the first error's coroutine and pc */
    uint32_t  err_pc;
} zbc_yield_t;

/* Debugging (P4.5a; be-bc debug.py `Stub` is the reference). With
 * zbc_host_t.dbg set, every instruction boundary is checked: a pause, a
 * breakpoint at (coro, pc) (pc in the coroutine) or a step reaching a
 * statement start stops the run -- the thread blocks before the instruction
 * and posts state STOP on `yield`, so a run with a stop is all-stop. Resuming
 * unblocks it; it does not stop again at that pc. */
enum { ZBC_DBG_PAUSE = 1, ZBC_DBG_STEP = 2, ZBC_DBG_BREAK = 3, ZBC_DBG_WATCH = 4,
       ZBC_DBG_ERROR = 5 };
enum { ZBC_DBG_STEP_STMT = 1, ZBC_DBG_STEP_INTO = 2, ZBC_DBG_STEP_OUT = 3 };
#define ZBC_DBG_MAX_BREAKS 256
#define ZBC_DBG_MAX_HITS   16
#define ZBC_DBG_MAX_WATCHES 64
typedef struct {
    uint32_t  reason;     /* ZBC_DBG_PAUSE / STEP / BREAK / WATCH / ERROR */
    uint32_t  thread_id;  /* the thread's bottom frame's id */
    uint32_t  frame_id;   /* the stopped frame's id */
    uint32_t  coro;
    uint32_t  pc;         /* in the coroutine */
    uint32_t  src_ref;    /* the statement's, else the instruction's (0xFFFFFFFF: none) */
    uint32_t  depth;      /* frames on the thread (1: the bottom one) */
    uint32_t  n_hits;     /* BREAK: the breakpoints' ids */
    uint32_t  hits[ZBC_DBG_MAX_HITS];
    void     *thread;     /* zsp_thread_t */
    void     *frame;      /* zsp_frame_t */
    /* P4.5b2: WATCH: the access (is_write, bytes, addr, data: written or
     * read); ERROR: the run's status (ZBC_ERR_*) and halted op, and its name
     * (pssvm fills `message`). */
    uint32_t  is_write;
    uint32_t  size;
    uint64_t  addr;
    uint64_t  data;
    int32_t   status;
    int32_t   op;
    const char *message;
} zbc_dbg_stop_t;

/* P4.5b2: an access watch (debug.py `_cmd_set_access_watch`): an access of
 * kind `rw` (bit 0 read, bit 1 write) overlapping [addr, addr+size), whose
 * data matches `value` under `mask` when `has_value`. */
typedef struct {
    uint32_t  id;
    uint32_t  rw;
    uint64_t  addr;
    uint64_t  size;
    uint32_t  has_value;
    uint64_t  value;
    uint64_t  mask;
} zbc_dbg_watch_t;
typedef struct {
    uint32_t  next_id;    /* frame ids (0: none) */
    uint32_t  n_breaks;
    struct { uint32_t id, coro, pc; } breaks[ZBC_DBG_MAX_BREAKS];
    volatile int pause;   /* the next instruction of any thread stops */
    int       step_kind;  /* 0: none, ZBC_DBG_STEP_* */
    void     *step_thread;
    uint32_t  step_depth;
    int       step_thread_done;  /* it ended: any thread's next statement */
    zbc_dbg_stop_t stop;  /* valid while `yield` is STOP */
    void     *frames;     /* P4.5b: the live frames (zbc_interp.c; reset per call) */
    /* P4.5b2: access watches and stop-on-error. A watched access (after it
     * is done, so a read has its value) leaves a pending WATCH stop in
     * `pend` (n_hits != 0); the next instruction checked stops with it. An
     * error with `stop_on_error` stops where it happened, frames live; the
     * resume ends the run with that error. */
    uint32_t  n_watches;
    zbc_dbg_watch_t watches[ZBC_DBG_MAX_WATCHES];
    int       stop_on_error;
    zbc_dbg_stop_t pend;
} zbc_dbg_t;

/* Inspection (P4.5b; debug.py Stub `threads`/`frames`/`read_frame`): read
 * while the run is stopped. A thread's id is its bottom frame's id. */
enum { ZBC_DBG_RUNNING = 0, ZBC_DBG_READY = 1, ZBC_DBG_WAITING = 2 };
typedef struct {
    uint32_t  id;         /* the frame's id */
    uint32_t  thread_id;
    uint32_t  coro;
    uint32_t  pc;         /* in the coroutine */
    uint32_t  depth;      /* frames on the thread up to this one (1: the bottom) */
    uint32_t  call_depth; /* CALL nesting (Frame.depth) */
    uint32_t  state;      /* its thread's: ZBC_DBG_RUNNING (stopped there) / READY / WAITING */
    uint32_t  base;       /* the action object slot of its field 0 */
    const uint64_t *regs;    /* nregs */
    const uint64_t *locals;  /* nlocals */
    const uint64_t *args;    /* ZBC_CALL_MAX_ARGS */
    void     *frame;      /* zsp_frame_t */
    void     *thread;     /* zsp_thread_t */
    uint32_t  nregs;      /* the frame's registers and locals (its coroutine's) */
    uint32_t  nlocals;
} zbc_dbg_frame_t;
/* The live threads' ids, ascending; returns the count (fills up to cap). */
uint32_t zbc_dbg_threads(const zbc_dbg_t *d, uint32_t *ids, uint32_t cap);
/* Thread `thread_id`'s frames, innermost first; returns the count (0: no such thread). */
uint32_t zbc_dbg_frames(const zbc_dbg_t *d, uint32_t thread_id, zbc_dbg_frame_t *out,
                        uint32_t cap);
/* Frame `frame_id`; 0 if it is not live. */
int      zbc_dbg_frame(const zbc_dbg_t *d, uint32_t frame_id, zbc_dbg_frame_t *out);

/* Run-wide host environment threaded to every coroutine (like the SPAWN budget).
 * All members are optional (NULL). With no mem_access and no yield, an image
 * that uses platform memory is refused before it runs. */
typedef struct {
    zbc_import_log_t     *import_log;
    zbc_import_returns_t *import_returns;
    zbc_mem_access_f      mem_access;
    void                 *mem_ctx;
    /* message()/error()/fatal() text, when the image has a MSG section.
     * verbosity: the run's (21.1.3: NONE=0 .. FULL=4; the Python VM's
     * default is MEDIUM=2); a message() above it is not formatted. */
    zbc_message_f         message;
    void                 *msg_ctx;
    uint32_t              verbosity;
    zbc_yield_t          *yield;   /* NULL: imports and memory answer inline */
    /* Debug events (P4.4c; zbc_events.h): raised per the sink's masks into
     * its binary trace. NULL: none. */
    struct zbc_ev_sink_s *events;
    /* Debug stops (P4.5a; needs `yield`). NULL: no checks. */
    zbc_dbg_t            *dbg;
    /* Host-bound functions (needs `yield`): bound[coro] != 0 makes a CALL
     * of that coroutine a ZBC_YIELD_BOUND request the host answers with
     * the result, in place of the body. NULL: none. */
    const uint8_t        *bound;
    /* The component object slot of the instance every frame of this run
     * runs in (pyvm Frame.cbase: LD_COMP/ST_COMP address cbase + slot).
     * 0: the root. */
    uint32_t              cbase;
    /* Each frame's step budget: 0 is ZBC_STEP_LIMIT, ZBC_STEP_UNLIMITED
     * none (pssvm_load's `step_limit=N`). */
    uint64_t              step_limit;
} zbc_host_t;

/*
 * Task-func entrypoint. Created via:
 *   zsp_timebase_thread_create(tb, &zbc_interp_task, flags,
 *                              const zbc_image_t *img, int coro_index,
 *                              zbc_result_t *result, zbc_obj_t *obj,
 *                              uint32_t base, uint64_t *spawn_budget,
 *                              zbc_host_t *host, uint64_t seed,
 *                              const uint64_t *call_args, uint32_t depth,
 *                              zbc_result_t *run, uint32_t start_pc,
 *                              const zbc_act *act, uint32_t node, uint32_t comp,
 *                              struct zbc_actrun_s *ar);
 * call_args / depth are a CALL's (NULL / 0 otherwise). act / node / comp are
 * the frame's activation, node and component instance (P4.10c4; comp
 * 0xFFFFFFFF: the host's cbase); ar is the activation's run state, shared by
 * its frames (P4.10d). A root passes ZBC_FRAME_ROOT, which finds the
 * activation rooted at its coroutine and makes its run state. `result` is the root's
 * (NULL for every other frame); `run` is the run's, shared by all frames, and
 * receives the first error any of them halts with.
 */
struct zbc_actrun_s;
#define ZBC_FRAME_ROOT (const zbc_act *)0, 0xFFFFFFFEu, 0xFFFFFFFFu, (struct zbc_actrun_s *)0

zsp_frame_t *zbc_interp_task(zsp_timebase_t *tb, zsp_thread_t *thread,
                             int idx, va_list *args);

#ifdef __cplusplus
}
#endif

#endif /* ZUSPEC_ZBC_INTERP_H */
