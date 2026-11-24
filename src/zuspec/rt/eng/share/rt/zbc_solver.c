/*
 * zbc_solver.c -- drive the real dv-solve constraint solver for ZBC_OP_SOLVE.
 *
 * The dv-solve C ABI is forward-declared here (opaque handles as void*, only the
 * SolveOpts layout replicated exactly) so the engine neither includes dv-solve
 * headers nor hard-depends on the library: the symbols resolve at link/load time
 * against libdv_solve when it is linked, and the blob-less minimal SOLVE path
 * never reaches this translation unit's calls.
 *
 * The mirrored solve sequence (matches dv_solve.ctx.SolveCtx):
 *   block_alloc = dvs_block_alloc_create(NULL, N)
 *   ctx         = dvs_solver_create(static_buf[N], N, block_alloc)
 *   dvs_solver_compile(ctx, blob)    -> 0 ok | -2 UNSAT | else fail
 *   dvs_solver_solve(ctx, {seed})    -> 0 SOLVE_OK | 1 UNSAT | 2 timeout
 *   dvs_solver_get_value(ctx, var_id) per writeback pair
 */
#include <stddef.h>
#include <stdlib.h>
#include "zbc_solver.h"

/* dv-solve dvs_solve_opts_t (dv_solve.h), field for field: dvs_solver_solve reads every
 * field, so a short copy is a read past the end of `opts` (it used to stop
 * before time_limit_ms, and the solve's wall-clock limit was stack garbage).
 * Zero == the Python wrapper's all-default solve(seed=...) (deterministic MRV,
 * no CDCL, dv-solve's default restart budget and time limit). */
typedef struct {
    uint64_t seed;
    uint32_t max_conflicts;
    uint32_t max_restarts;
    uint8_t  use_phase_save;
    uint8_t  use_lcg;
    uint8_t  fair_pick;
    uint8_t  _pad;
    uint32_t max_shave_iters;
    uint32_t time_limit_ms;
} zbc_dv_solve_opts_t;
_Static_assert(sizeof(zbc_dv_solve_opts_t) == 32 &&
               offsetof(zbc_dv_solve_opts_t, time_limit_ms) == 24,
               "zbc_dv_solve_opts_t must match dv-solve's dvs_solve_opts_t");

/* Weak: the engine loads without libdv_solve (a host links it only for images
 * with solves); a SOLVE then fails with ZBC_SOLVER_FAIL instead of the load. */
#define ZBC_DVS __attribute__((weak))
ZBC_DVS extern void   *dvs_block_alloc_create(void *alloc, size_t block_size);
ZBC_DVS extern void    dvs_block_alloc_destroy(void *ba);
ZBC_DVS extern void   *dvs_solver_create(void *static_buf, size_t static_size, void *block_alloc);
ZBC_DVS extern int     dvs_solver_compile(void *ctx, void *sp);
ZBC_DVS extern int     dvs_solver_solve(void *ctx, const zbc_dv_solve_opts_t *opts);
ZBC_DVS extern int64_t dvs_solver_get_value(const void *ctx, uint32_t var_id);
ZBC_DVS extern void    dvs_solver_destroy(void *ctx);
ZBC_DVS extern int     dvs_solver_checkpoint(void *ctx);
ZBC_DVS extern void    dvs_solver_restore(void *ctx, uint32_t cp);
ZBC_DVS extern int     dvs_solver_add_constraint(void *ctx, void *sp);
ZBC_DVS extern int     dvs_solver_pin_var(void *ctx, uint32_t var_id, int64_t value);

/* The oracle's solve (be-bc interp/solve_cache.py, SolveCache.solve), step for
 * step, so both draw the same values: a short clause-learning search first,
 * then -- if it found nothing -- the plain search from the same state under
 * the full budget. */
#define ZBC_LCG_RESTARTS 5u
#define ZBC_MAX_RESTARTS 10000u

/* Working memory for one solve. 1 MiB matches dv_solve.ctx._CTX_BUF_SIZE; freed
 * immediately after the solve so nothing persists in the coroutine frame. */
#define ZBC_SOLVER_CTX_SIZE (1u << 20)

int zbc_solver_run(const void *problem_blob, uint64_t seed,
                   const uint32_t *pairs, uint32_t n_pairs,
                   uint64_t *slots) {
    return zbc_solver_run_pinned(problem_blob, seed, pairs, n_pairs, slots,
                                 (const uint32_t *)0, (const int64_t *)0, 0);
}

int zbc_solver_run_pinned(const void *problem_blob, uint64_t seed,
                          const uint32_t *pairs, uint32_t n_pairs, uint64_t *slots,
                          const uint32_t *pin_var, const int64_t *pin_val,
                          uint32_t n_pins) {
    int rc = ZBC_SOLVER_FAIL;
    if (!dvs_solver_create || (n_pins && !dvs_solver_pin_var)) {
        return ZBC_SOLVER_FAIL;   /* libdv_solve not linked */
    }
    void *ctx_buf = malloc(ZBC_SOLVER_CTX_SIZE);
    if (!ctx_buf) {
        return ZBC_SOLVER_FAIL;
    }
    void *ba = dvs_block_alloc_create(NULL, ZBC_SOLVER_CTX_SIZE);
    if (!ba) {
        free(ctx_buf);
        return ZBC_SOLVER_FAIL;
    }
    void *ctx = dvs_solver_create(ctx_buf, ZBC_SOLVER_CTX_SIZE, ba);
    if (!ctx) {
        dvs_block_alloc_destroy(ba);
        free(ctx_buf);
        return ZBC_SOLVER_FAIL;
    }

    /* solver_compile: 0 ok, -2 UNSAT (empty domain at compile), <0 error, >0 some
     * constraints not natively compilable -- the latter would silently drop them,
     * so (unlike the Python backend, which falls back) we treat it as a failure. */
    int crc = dvs_solver_compile(ctx, (void *)problem_blob);
    if (crc == -2) {
        rc = ZBC_SOLVER_UNSAT;
        goto done;
    }
    if (crc != 0) {
        rc = ZBC_SOLVER_FAIL;
        goto done;
    }
    if (n_pins) (void)dvs_solver_checkpoint(ctx);     /* as zbc_solver_cone */
    for (uint32_t i = 0; i < n_pins; i++) {
        if (dvs_solver_pin_var(ctx, pin_var[i], pin_val[i]) != 0) {
            rc = ZBC_SOLVER_UNSAT;
            goto done;
        }
    }

    zbc_dv_solve_opts_t opts = {0};
    opts.seed = seed;
    opts.max_restarts = ZBC_MAX_RESTARTS;
    int sr = -1;
    {
        zbc_dv_solve_opts_t lopts = opts;
        lopts.use_lcg = 1;
        lopts.max_restarts = ZBC_LCG_RESTARTS;
        int cp = dvs_solver_checkpoint(ctx);
        sr = dvs_solver_solve(ctx, &lopts);
        if (sr != 0 && cp >= 0)
            dvs_solver_restore(ctx, (uint32_t)cp);
    }
    if (sr != 0)
        sr = dvs_solver_solve(ctx, &opts);
    if (sr == 1) {          /* SOLVE_UNSAT */
        rc = ZBC_SOLVER_UNSAT;
        goto done;
    }
    if (sr != 0) {          /* SOLVE_TIMEOUT or unexpected */
        rc = ZBC_SOLVER_FAIL;
        goto done;
    }

    for (uint32_t i = 0; i < n_pairs; i++) {
        uint32_t slot = pairs[2 * i], var_id = pairs[2 * i + 1];
        slots[slot] = (uint64_t)dvs_solver_get_value(ctx, var_id);
    }
    rc = ZBC_SOLVER_OK;

done:
    dvs_solver_destroy(ctx);           /* frees the clause-learning state */
    dvs_block_alloc_destroy(ba);
    free(ctx_buf);
    return rc;
}

/* One solve of an activation cone (pyvm activation.py `_attempt` through
 * SolveCache): compile `base`, add each of `adds` (the constraints in force),
 * checkpoint, pin, then the same two searches as zbc_solver_run. On success
 * vals[i] = the value of cone variable i for i < n_vals. A compile-time or
 * pin conflict is UNSAT, as pyvm's "no solution". */
int zbc_solver_cone(const void *base, const void *const *adds, uint32_t n_adds,
                    const uint32_t *pin_var, const int64_t *pin_val, uint32_t n_pins,
                    uint64_t seed, int64_t *vals, uint32_t n_vals) {
    int rc = ZBC_SOLVER_FAIL;
    if (!dvs_solver_create || (n_adds && !dvs_solver_add_constraint)
            || (n_pins && !dvs_solver_pin_var)) {
        return ZBC_SOLVER_FAIL;
    }
    void *ctx_buf = malloc(ZBC_SOLVER_CTX_SIZE);
    if (!ctx_buf) return ZBC_SOLVER_FAIL;
    void *ba = dvs_block_alloc_create(NULL, ZBC_SOLVER_CTX_SIZE);
    if (!ba) {
        free(ctx_buf);
        return ZBC_SOLVER_FAIL;
    }
    void *ctx = dvs_solver_create(ctx_buf, ZBC_SOLVER_CTX_SIZE, ba);
    if (!ctx) {
        dvs_block_alloc_destroy(ba);
        free(ctx_buf);
        return ZBC_SOLVER_FAIL;
    }
    int crc = dvs_solver_compile(ctx, (void *)base);
    if (crc != 0) {
        rc = crc == -2 ? ZBC_SOLVER_UNSAT : ZBC_SOLVER_FAIL;
        goto done;
    }
    for (uint32_t i = 0; i < n_adds; i++) {
        crc = dvs_solver_add_constraint(ctx, (void *)adds[i]);
        if (crc != 0) {
            rc = crc == -2 ? ZBC_SOLVER_UNSAT : ZBC_SOLVER_FAIL;
            goto done;
        }
    }
    (void)dvs_solver_checkpoint(ctx);     /* pyvm pins inside a session */
    for (uint32_t i = 0; i < n_pins; i++) {
        if (dvs_solver_pin_var(ctx, pin_var[i], pin_val[i]) != 0) {
            rc = ZBC_SOLVER_UNSAT;
            goto done;
        }
    }

    zbc_dv_solve_opts_t opts = {0};
    opts.seed = seed;
    opts.max_restarts = ZBC_MAX_RESTARTS;
    int sr;
    {
        zbc_dv_solve_opts_t lopts = opts;
        lopts.use_lcg = 1;
        lopts.max_restarts = ZBC_LCG_RESTARTS;
        int cp = dvs_solver_checkpoint(ctx);
        sr = dvs_solver_solve(ctx, &lopts);
        if (sr != 0 && cp >= 0)
            dvs_solver_restore(ctx, (uint32_t)cp);
    }
    if (sr != 0)
        sr = dvs_solver_solve(ctx, &opts);
    if (sr != 0) {
        rc = sr == 1 ? ZBC_SOLVER_UNSAT : ZBC_SOLVER_FAIL;
        goto done;
    }
    for (uint32_t i = 0; i < n_vals; i++)
        vals[i] = dvs_solver_get_value(ctx, i);
    rc = ZBC_SOLVER_OK;

done:
    dvs_solver_destroy(ctx);
    dvs_block_alloc_destroy(ba);
    free(ctx_buf);
    return rc;
}
