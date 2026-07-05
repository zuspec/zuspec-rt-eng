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

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Load + run the image in `data[0..size)` over an action object of `nfields`
 * 64-bit slots in `fields` (mutated in place; pass NULL/0 for no object). `host`
 * is the optional IMPORT seam (NULL = imports record nowhere and return 0). Fills
 * `*out` (status, retval, now, halted_op). Returns `out->status`.
 */
int zbc_run(const void *data, size_t size,
            uint64_t *fields, uint32_t nfields,
            zbc_host_t *host, zbc_result_t *out);

#ifdef __cplusplus
}
#endif

#endif /* ZUSPEC_ZBC_ENGINE_H */
