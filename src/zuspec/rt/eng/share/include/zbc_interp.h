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

/* Fixed frame capacities for the walking skeleton; sized from the coro/TYPE
 * metadata in a later slice. */
#define ZBC_MAX_REGS    64
#define ZBC_MAX_LOCALS  32
#define ZBC_MAX_CHILDREN 64   /* max joinable children a single JOIN can await */

/* Runaway-loop watchdog: max bytecode steps a single coroutine may execute
 * across its whole life (frame-resident, so it spans suspends/resumes). Real
 * skeleton programs are tiny; this trips a malformed back-edge in well under a
 * second instead of hanging. */
#define ZBC_STEP_LIMIT  10000000u

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

/* Run-wide host environment threaded to every coroutine (like the SPAWN budget).
 * Both members are optional (NULL). */
typedef struct {
    zbc_import_log_t     *import_log;
    zbc_import_returns_t *import_returns;
} zbc_host_t;

/*
 * Task-func entrypoint. Created via:
 *   zsp_timebase_thread_create(tb, &zbc_interp_task, flags,
 *                              const zbc_image_t *img, int coro_index,
 *                              zbc_result_t *result);
 */
zsp_frame_t *zbc_interp_task(zsp_timebase_t *tb, zsp_thread_t *thread,
                             int idx, va_list *args);

#ifdef __cplusplus
}
#endif

#endif /* ZUSPEC_ZBC_INTERP_H */
