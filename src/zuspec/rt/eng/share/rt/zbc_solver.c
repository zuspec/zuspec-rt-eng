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
 *   block_alloc = zsp_block_alloc_create(NULL, N)
 *   ctx         = solver_create(static_buf[N], N, block_alloc)
 *   solver_compile(ctx, blob)        -> 0 ok | -2 UNSAT | else fail
 *   solver_solve(ctx, {seed})        -> 0 SOLVE_OK | 1 UNSAT | 2 timeout
 *   solver_get_value(ctx, var_id)    per writeback pair
 */
#include <stdlib.h>
#include "zbc_solver.h"

/* dv-solve SolveOpts (zsp_search.h): 24 bytes, must match exactly. Zero == the
 * Python wrapper's all-default solve(seed=...) (deterministic MRV, no CDCL). */
typedef struct {
    uint64_t seed;
    uint32_t max_conflicts;
    uint32_t max_restarts;
    uint8_t  use_phase_save;
    uint8_t  use_lcg;
    uint8_t  fair_pick;
    uint8_t  _pad;
    uint32_t max_shave_iters;
} zbc_dv_solve_opts_t;

extern void   *zsp_block_alloc_create(void *alloc, size_t block_size);
extern void    zsp_block_alloc_destroy(void *ba);
extern void   *solver_create(void *static_buf, size_t static_size, void *block_alloc);
extern int     solver_compile(void *ctx, void *sp);
extern int     solver_solve(void *ctx, const zbc_dv_solve_opts_t *opts);
extern int64_t solver_get_value(const void *ctx, uint32_t var_id);

/* Working memory for one solve. 1 MiB matches dv_solve.ctx._CTX_BUF_SIZE; freed
 * immediately after the solve so nothing persists in the coroutine frame. */
#define ZBC_SOLVER_CTX_SIZE (1u << 20)

int zbc_solver_run(const void *problem_blob, uint64_t seed,
                   const uint32_t *pairs, uint32_t n_pairs,
                   uint64_t *slots) {
    int rc = ZBC_SOLVER_FAIL;
    void *ctx_buf = malloc(ZBC_SOLVER_CTX_SIZE);
    if (!ctx_buf) {
        return ZBC_SOLVER_FAIL;
    }
    void *ba = zsp_block_alloc_create(NULL, ZBC_SOLVER_CTX_SIZE);
    if (!ba) {
        free(ctx_buf);
        return ZBC_SOLVER_FAIL;
    }
    void *ctx = solver_create(ctx_buf, ZBC_SOLVER_CTX_SIZE, ba);
    if (!ctx) {
        zsp_block_alloc_destroy(ba);
        free(ctx_buf);
        return ZBC_SOLVER_FAIL;
    }

    /* solver_compile: 0 ok, -2 UNSAT (empty domain at compile), <0 error, >0 some
     * constraints not natively compilable -- the latter would silently drop them,
     * so (unlike the Python backend, which falls back) we treat it as a failure. */
    int crc = solver_compile(ctx, (void *)problem_blob);
    if (crc == -2) {
        rc = ZBC_SOLVER_UNSAT;
        goto done;
    }
    if (crc != 0) {
        rc = ZBC_SOLVER_FAIL;
        goto done;
    }

    zbc_dv_solve_opts_t opts = {0};
    opts.seed = seed;
    int sr = solver_solve(ctx, &opts);
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
        slots[slot] = (uint64_t)solver_get_value(ctx, var_id);
    }
    rc = ZBC_SOLVER_OK;

done:
    zsp_block_alloc_destroy(ba);
    free(ctx_buf);
    return rc;
}
