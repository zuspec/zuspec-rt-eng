/*
 * zbc_engine.c -- see zbc_engine.h.
 */
#include "zbc_engine.h"
#include "zbc_ops.h"
#include "zsp_timebase.h"
#include "zsp_alloc.h"

int zbc_run(const void *data, size_t size,
            uint64_t *fields, uint32_t nfields,
            zbc_host_t *host, zbc_result_t *out) {
    out->status = ZBC_OK;
    out->halted_op = 0;
    out->retval = 0;
    out->now = 0;

    zbc_image_t img;
    int rc = zbc_image_open(&img, data, size);
    if (rc != ZBC_OK) {
        out->status = rc;
        return rc;
    }

    /* Picosecond-resolution timebase over a malloc allocator (M1). */
    zsp_alloc_t *alloc = zsp_alloc_malloc_create();
    zsp_timebase_t *tb = zsp_timebase_create(alloc, ZSP_TIME_PS);

    /* The activation solve scope (SCOPE_ENTER / SOLVE_NODE) and traversal
     * initializers (an INVOKE that starts its callee past its initial
     * values), P1.4, are the Python oracle's alone until P8 ports them.
     * Refuse an image that uses them before running anything, naming the
     * opcode, rather than run a model whose cone constraints or initializers
     * would not hold (P1-D6). */
    for (uint32_t i = 0; i < img.code_count; i++) {
        uint32_t op = img.code[i].op;
        if (op == ZBC_OP_SCOPE_ENTER || op == ZBC_OP_SOLVE_NODE
                || (op == ZBC_OP_INVOKE && (img.code[i].flags & ZBC_F_INITED))) {
            out->status = ZBC_ERR_UNSUPPORTED_OP;
            out->halted_op = (int)op;
            return out->status;
        }
    }

    zbc_obj_t obj = { fields, nfields };
    zbc_obj_t *objp = (fields != NULL && nfields > 0) ? &obj : NULL;

    /* Shared, run-wide SPAWN budget (fork-bomb guard), threaded to every coro. */
    uint64_t spawn_budget = ZBC_SPAWN_LIMIT;

    /* The entry coroutine runs as an interpreted coroutine; it writes back into
     * `out` at RET (or on an unsupported op) and mutates `fields` in place. */
    /* Root frame's seed stream is the run seed (0, matching the oracle's
     * run_model default); children fork deterministically from it. `host` is the
     * IMPORT seam, threaded to every coroutine like the spawn budget. */
    zsp_timebase_thread_create(
        tb, &zbc_interp_task, ZSP_THREAD_FLAGS_NONE,
        &img, (int)img.entry_coro, out, objp, (uint32_t)0, &spawn_budget, host,
        (uint64_t)0);

    /* Drive to quiescence: run all ready, advance to the next timed batch. */
    for (;;) {
        while (zsp_timebase_run(tb)) { /* keep running ready threads */ }
        if (!zsp_timebase_advance(tb)) {
            break;
        }
    }

    out->now = zsp_timebase_current_ticks(tb);

    zsp_timebase_destroy(tb);
    return out->status;
}
