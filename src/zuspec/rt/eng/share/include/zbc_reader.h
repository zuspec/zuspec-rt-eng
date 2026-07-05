/*
 * zbc_reader.h -- zero-copy reader over a .zbc image.
 *
 * Validates the header (magic / version / abi_id) and indexes the section
 * directory, exposing the CODE (zbc_instr[]) and CORO (zbc_coro[]) arrays by
 * casting directly over the mapped bytes [D§3a]. The caller owns the buffer and
 * must keep it alive for the reader's lifetime.
 */
#ifndef ZUSPEC_ZBC_READER_H
#define ZUSPEC_ZBC_READER_H

#include <stdint.h>
#include <stddef.h>
#include "zbc_format.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The value-ABI version this engine implements; must match the image header. */
#define ZBC_ENGINE_ABI_ID 1

enum {
    ZBC_OK               =  0,
    ZBC_ERR_TOO_SMALL    = -1,
    ZBC_ERR_BAD_MAGIC    = -2,
    ZBC_ERR_BAD_VERSION  = -3,
    ZBC_ERR_BAD_ABI      = -4,
    ZBC_ERR_BAD_SECTIONS = -5,
    ZBC_ERR_NO_CODE      = -6,
    ZBC_ERR_NO_CORO      = -7,
    ZBC_ERR_UNSUPPORTED_OP = -8,
    ZBC_ERR_BAD_ENTRY    = -9,
    ZBC_ERR_OOB_REG      = -10,  /* register index >= ZBC_MAX_REGS */
    ZBC_ERR_OOB_LOCAL    = -11,  /* local slot >= ZBC_MAX_LOCALS */
    ZBC_ERR_BAD_TARGET   = -12,  /* branch target outside the coro */
    ZBC_ERR_STEP_LIMIT   = -13,  /* step budget exhausted (runaway loop) */
    ZBC_ERR_DIV_ZERO     = -14,
    ZBC_ERR_NO_OBJ       = -15,  /* LD/ST_FIELD with no active object */
    ZBC_ERR_OOB_FIELD    = -16,  /* field slot >= object field count */
    ZBC_ERR_SPAWN_LIMIT  = -17,  /* total SPAWN budget exhausted (fork bomb) */
    ZBC_ERR_SELECT_NONE  = -18,  /* SELECT: no eligible branch and allow_none unset */
    ZBC_ERR_BAD_SELECT   = -19,  /* SELECT: descriptor id / oplist range out of bounds */
    ZBC_ERR_BAD_SOLVE    = -20,  /* SOLVE: descriptor id / oplist range out of bounds */
    ZBC_ERR_SOLVE_UNSAT  = -21,  /* SOLVE: real solver reports the problem unsatisfiable */
    ZBC_ERR_SOLVE_FAIL   = -22   /* SOLVE: real solver setup / compile / timeout failure */
};

typedef struct {
    const uint8_t     *data;
    size_t             size;
    const zbc_header  *hdr;
    const zbc_section *sections;
    uint32_t           section_count;

    const zbc_instr   *code;
    uint32_t           code_count;
    const zbc_coro    *coros;
    uint32_t           coro_count;
    uint32_t           entry_coro;

    /* Optional SELECT tables (NULL/0 if the image has no SELECT). The OPLIST pool
     * holds, per descriptor, three u32 runs of length n_branches: branch coro ids,
     * weights, then guard registers (0xFFFFFFFF = unguarded). */
    const zbc_select  *selects;
    uint32_t           select_count;
    const uint32_t    *oplist;
    uint32_t           oplist_count;

    /* Optional SOLVE tables (NULL/0 if absent). Writeback (field_slot, var_id) pairs
     * live in the shared OPLIST pool above. */
    const zbc_solve   *solves;
    uint32_t           solve_count;

    /* Optional SPROB pool (NULL/0 if absent): raw relocatable dv-solve SolveProblem
     * blobs. A zbc_solve with prob_len>0 references (prob_off, prob_len) here; the
     * engine hands that address straight to solver_compile() for a real solve. */
    const uint8_t     *sprob;
    uint32_t           sprob_count;   /* pool size in bytes */
} zbc_image_t;

/* Validate + index. Returns ZBC_OK or a negative ZBC_ERR_*. */
int zbc_image_open(zbc_image_t *img, const void *data, size_t size);

/* Section directory lookup by ZBC_SEC_* kind; NULL if absent. */
const zbc_section *zbc_find_section(const zbc_image_t *img, uint32_t kind);

#ifdef __cplusplus
}
#endif

#endif /* ZUSPEC_ZBC_READER_H */
