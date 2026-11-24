/*
 * zbc_solver.h -- the engine's seam to the real dv-solve constraint solver.
 *
 * ZBC_OP_SOLVE hands a relocatable dv-solve SolveProblem blob (carried in the
 * image's SPROB pool) to zbc_solver_run(), which compiles + solves it with the
 * frame's drawn seed and writes each solved variable back to its object slot.
 * The dv-solve C ABI is forward-declared in zbc_solver.c and resolved at link/
 * load time against libdv_solve -- so this seam adds no header coupling and the
 * minimal (blob-less) SOLVE path stays free of any solver dependency.
 */
#ifndef ZUSPEC_ZBC_SOLVER_H
#define ZUSPEC_ZBC_SOLVER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    ZBC_SOLVER_OK    = 0,  /* solved; slots written                         */
    ZBC_SOLVER_UNSAT = 1,  /* problem is unsatisfiable                      */
    ZBC_SOLVER_FAIL  = 2   /* setup / compile / timeout / incomplete failure */
};

/*
 * Compile + solve `problem_blob` (a relocatable dv-solve SolveProblem) with
 * `seed`, then write dvs_solver_get_value(var_id) into slots[slot] for each
 * (slot, var_id) pair in `pairs` (2*n_pairs u32s: slot0,var0, slot1,var1, ...).
 * Slot indices must be pre-validated in range by the caller. Returns ZBC_SOLVER_*.
 */
int zbc_solver_run(const void *problem_blob, uint64_t seed,
                   const uint32_t *pairs, uint32_t n_pairs,
                   uint64_t *slots);

/*
 * zbc_solver_run with variable pin_var[i] fixed to pin_val[i] (an exported
 * action's arguments, F2.3b); a value the constraints refuse is UNSAT.
 */
int zbc_solver_run_pinned(const void *problem_blob, uint64_t seed,
                          const uint32_t *pairs, uint32_t n_pairs, uint64_t *slots,
                          const uint32_t *pin_var, const int64_t *pin_val,
                          uint32_t n_pins);

/*
 * Solve an activation cone: compile `base`, add the blobs `adds[0..n_adds)`,
 * pin cone variable pin_var[i] to pin_val[i], solve with `seed`, and write the
 * value of cone variables 0..n_vals-1 to vals. Returns ZBC_SOLVER_* (a pin or
 * compile conflict is ZBC_SOLVER_UNSAT).
 */
int zbc_solver_cone(const void *base, const void *const *adds, uint32_t n_adds,
                    const uint32_t *pin_var, const int64_t *pin_val, uint32_t n_pins,
                    uint64_t seed, int64_t *vals, uint32_t n_vals);

#ifdef __cplusplus
}
#endif

#endif /* ZUSPEC_ZBC_SOLVER_H */
