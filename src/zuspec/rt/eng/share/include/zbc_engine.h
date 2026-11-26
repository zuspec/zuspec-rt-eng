/*
 * zbc_engine.h -- top-level ZBC execution driver.
 *
 * Opens a .zbc image, runs its entry coroutine as an interpreted coroutine on a
 * fresh rt-core timebase, and reports the result. The engine's correctness
 * contract is the Python oracle: same image + seed -> matching results.
 */
#ifndef ZUSPEC_ZBC_ENGINE_H
#define ZUSPEC_ZBC_ENGINE_H

#include <stddef.h>
#include "zbc_interp.h"
#include "zsp_timebase.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Load + run the image in `data[0..size)` over an action object of `nfields`
 * 64-bit slots in `fields` (mutated in place; pass NULL/0 for no object). `host`
 * is the optional IMPORT seam (NULL = imports record nowhere and return 0); an
 * image that reads or writes platform memory needs its `mem_access`. Fills
 * `*out` (status, retval, now, halted_op). Returns `out->status`.
 */
int zbc_run(const void *data, size_t size,
            uint64_t *fields, uint32_t nfields,
            zbc_host_t *host, zbc_result_t *out);

/*
 * Pieces of zbc_run that the host ABI (pssvm_host.c) reuses.
 * zbc_image_check refuses an image the engine cannot run with `host` (no
 * COMP for a component tree, solve scopes, platform memory without
 * mem_access, address claims): ZBC_OK, or the error with *halted_op set for an opcode.
 * zbc_drain runs `tb` to quiescence, setting ZBC_ERR_DEADLOCK in `out` when
 * every thread spins and nothing timed is left.
 */
/* *halted_op for an image whose activation nodes claim addresses (no
 * opcode names it; the C engine has no address ledger until M14). */
#define ZBC_HALT_ADDR_CLAIM 0x10000
/* ... whose activations need an inferred stream partner (M9a6b; none runs here until M14). */
#define ZBC_HALT_INFER      0x10001
/* ... whose activations number uid slots (actinit unknown == 2; M14). */
#define ZBC_HALT_UID        0x10002
int  zbc_image_check(const zbc_image_t *img, const zbc_host_t *host, int *halted_op);
void zbc_drain(zsp_timebase_t *tb, zbc_image_t *img, zbc_result_t *out);
/* zbc_drain that stops (returning 1) when `y` holds a pending request, or a
 * WAIT when `y->wait_time` is set; 0 when the run is quiescent. */
int  zbc_drain_until(zsp_timebase_t *tb, zbc_image_t *img, zbc_result_t *out,
                     zbc_yield_t *y);

#ifdef __cplusplus
}
#endif

#endif /* ZUSPEC_ZBC_ENGINE_H */
