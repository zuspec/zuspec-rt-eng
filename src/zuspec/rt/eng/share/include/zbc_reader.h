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
    ZBC_ERR_SOLVE_FAIL   = -22,  /* SOLVE: real solver setup / compile / timeout failure */
    ZBC_ERR_COMP_INIT    = -23,  /* the image constructs a component tree (P1.5): refused until P8 */
    ZBC_ERR_CALL_DEPTH   = -24,  /* CALL nested deeper than ZBC_CALL_MAX_DEPTH */
    ZBC_ERR_RUNTIME      = -25,  /* BUILTIN_ERROR: a run-time error the LRM requires */
    ZBC_ERR_OOB_COMP     = -26,  /* LD/ST_COMP slot >= component object slot count */
    ZBC_ERR_DEADLOCK     = -27,  /* every thread spins on a channel and nothing timed is left */
    ZBC_ERR_COMP_UNCHOSEN = -28  /* LD/ST_COMP before the solve chose the action's instance */
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
     * engine hands that address straight to dvs_solver_compile() for a real solve. */
    const uint8_t     *sprob;
    uint32_t           sprob_count;   /* pool size in bytes */

    /* Optional COMP record (NULL if the image has no component tree, P1.5) and
     * its n_inst instance bases. `cobj` is the run's component object, which
     * zbc_run allocates (comp->n_slots) and LD_COMP/ST_COMP address; it is not
     * part of the image, only carried with it to every coroutine. */
    const zbc_comp    *comp;
    const uint32_t    *comp_bases;
    uint64_t          *cobj;
    /* Optional MSG table (msgtab NULL if absent, P4.2g): message()/error()/
     * fatal() call sites, their value types, and the strings (the run's
     * string ids first, then formats and enum item names). zbc_image_open
     * has checked every index, so the formatter can trust them. */
    const zbc_msgtab  *msgtab;
    const zbc_msg     *msgs;
    const zbc_msgarg  *msgargs;
    const zbc_msgitem *msgitems;
    const uint32_t    *msgslots;
    const uint32_t    *msgstr_off;
    const char        *msgstrb;
    /* Optional host tables (P4.3a; NULL/0 if absent): the string table
     * (STRB/STRO, codegen and debug profiles), the ENTRY points and the
     * IDENT record. zbc_image_open has checked that every STRO offset lies
     * in STRB and every entry's StrIds and coro are in range. */
    const char        *strb;
    uint32_t           strb_size;
    const uint32_t    *stro;        /* str_count + 1 offsets; the last is the end */
    uint32_t           str_count;
    const zbc_entry   *entries;
    uint32_t           entry_count;
    /* Optional user import names (IMPORT; NULL/0 if absent), sorted by
     * fn_id; zbc_image_open has checked the order and StrIds. */
    const zbc_impent  *imports;
    uint32_t           import_count;
    const zbc_ident   *ident;
    /* Optional debug side tables (P4.4a; NULL/0 if absent): register
     * accesses (REG) and channel operations (CHAN), each sorted by global
     * pc. zbc_image_open has checked the order, pcs and StrIds. */
    const zbc_regent  *regs;
    uint32_t           reg_count;
    const zbc_chanent *chans;
    uint32_t           chan_count;
    /* Optional coverage items (COV, P4.7; NULL/0 if absent): statements and
     * branch arms, sorted by global pc (a statement and an arm may share
     * one). zbc_image_open has checked the order, pcs and StrIds. */
    const zbc_covent  *covs;
    uint32_t           cov_count;
    /* Optional provenance (P4.4b; NULL/0 if absent): PROV records, which
     * instructions' src_ref index, and the FILE table they name (FileId 0:
     * none). zbc_image_open has checked every FileId and path StrId. */
    const zbc_prov    *provs;
    uint32_t           prov_count;
    const zbc_file    *files;
    uint32_t           file_count;
    /* Optional statement starts (P4.4c; NULL/0 if absent): the LINE table
     * when it is flagged ZBC_SECF_LINE_STMT, sorted by pc (a pc may start
     * more than one statement). */
    const zbc_lineent *stmts;
    uint32_t           stmt_count;
    /* Optional named locals (LOCAL; debug lowering; NULL/0 if absent),
     * grouped by coro; pcs are global CODE indices. zbc_image_open has
     * checked the coro order, coros, pcs and name StrIds. */
    const zbc_localent *locals;
    uint32_t           local_count;
    /* Optional activity table (ACT, P4.10c2; acttab NULL if absent): the
     * records in the order zbc_acttab lists them, the u32 lists, the string
     * offsets and text (ACT's own strings, not STRB) and the blob area.
     * Record indices (*0) are section-global; ids inside an activation are
     * local to it. zbc_image_open has checked every range and id. */
    const zbc_acttab   *acttab;
    const zbc_actinit  *actinits;
    const zbc_act      *acts;
    const zbc_actnode  *actnodes;
    const zbc_actscope *actscopes;
    const zbc_actsite  *actsites;
    const zbc_actcone  *actcones;
    const zbc_actvar   *actvars;
    const zbc_actcon   *actcons;
    const zbc_actpool  *actpools;
    const zbc_actclaim *actclaims;
    const zbc_actwrite *actwrites;
    const zbc_actpick  *actpicks;
    const uint32_t     *actlist;
    const uint32_t     *actstr_off;
    const char         *actstrb;
    const uint8_t      *actblob;
    /* Run state, also carried with the image: a SPIN YIELD sets *spin_stuck
     * when its frame made no progress since it last resumed (zbc_run's
     * deadlock check reads and clears it around each thread run). */
    uint32_t          *spin_stuck;
} zbc_image_t;

/* Validate + index. Returns ZBC_OK or a negative ZBC_ERR_*. */
int zbc_image_open(zbc_image_t *img, const void *data, size_t size);

/* Section directory lookup by ZBC_SEC_* kind; NULL if absent. */
const zbc_section *zbc_find_section(const zbc_image_t *img, uint32_t kind);

/* The text of host metadata document `name` (META; debug profile), or NULL. */
const char *zbc_image_meta(const zbc_image_t *img, const char *name);
/* The name of user import `fn_id`, or NULL (not in the IMPORT table). */
const char *zbc_image_import_name(const zbc_image_t *img, uint32_t fn_id);
/* The REG entry of the access at global pc `pc`, or NULL. */
const zbc_regent *zbc_image_reg_at(const zbc_image_t *img, uint32_t pc);
/* The CHAN entry of the operation ending at global pc `pc`, or NULL. */
const zbc_chanent *zbc_image_chan_at(const zbc_image_t *img, uint32_t pc);

/* The coverage item at global pc `pc` that is an arm (`arm` != 0) or a
 * statement, or NULL; the last one if there are several (as the Python VM). */
const zbc_covent *zbc_image_cov_at(const zbc_image_t *img, uint32_t pc, int arm);
/* The statements starting at global pc `pc`: the first entry, *n of them
 * (NULL, 0 if none). */
const zbc_lineent *zbc_image_stmts_at(const zbc_image_t *img, uint32_t pc, uint32_t *n);
/* The PROV record `src_ref` (0: none), or NULL. */
const zbc_prov *zbc_image_prov(const zbc_image_t *img, uint32_t src_ref);
/* The source path of FileId `file`, or NULL (none, or no FILE table). */
const char *zbc_image_file(const zbc_image_t *img, uint32_t file);
/* The provenance index of global pc `pc`: its instruction's src_ref, else
 * its coroutine's `coro` (0xFFFFFFFF: not known); 0 when neither has one. */
uint32_t zbc_image_src_ref(const zbc_image_t *img, uint32_t coro, uint32_t pc);
/* The activation rooted at coroutine `coro`, or NULL (none, or no ACT). */
const zbc_act *zbc_image_act(const zbc_image_t *img, uint32_t coro);
/* Node / scope / site / cone `id` (local to activation `a`); the caller keeps
 * `id` below the activation's count (zbc_image_open checked the ids the
 * table holds). */
const zbc_actnode *zbc_act_node(const zbc_image_t *img, const zbc_act *a, uint32_t id);
const zbc_actscope *zbc_act_scope(const zbc_image_t *img, const zbc_act *a, uint32_t id);
const zbc_actsite *zbc_act_site(const zbc_image_t *img, const zbc_act *a, uint32_t id);
const zbc_actcone *zbc_act_cone(const zbc_image_t *img, const zbc_act *a, uint32_t id);
/* Cone variable / constraint record `i` (section-global: a cone's var0/con0 + k). */
const zbc_actvar *zbc_act_var(const zbc_image_t *img, uint32_t i);
const zbc_actcon *zbc_act_con(const zbc_image_t *img, uint32_t i);
/* The blob at offset `off` of the ACT blob area (a cone's base_off, a
 * constraint's blob_off; zbc_image_open checked off + size). */
const uint8_t *zbc_act_blob(const zbc_image_t *img, uint32_t off);
/* Activation `a`'s initial value record for object slot `slot`, or NULL. */
const zbc_actinit *zbc_act_init(const zbc_image_t *img, const zbc_act *a, uint32_t slot);
/* Write record `i` (section-global: a node's swrite0/bwrite0 + k). */
const zbc_actwrite *zbc_act_write(const zbc_image_t *img, uint32_t i);
/* The u32 list from entry `i` (section-global: a record's *0 field). */
const uint32_t *zbc_act_list(const zbc_image_t *img, uint32_t i);
/* The NUL-terminated ACT string `sid`, or NULL when out of range. */
const char *zbc_image_act_str(const zbc_image_t *img, uint32_t sid);
/* The NUL-terminated string `sid` of the image's string table, or NULL when
 * the image has none or `sid` is out of range. */
const char *zbc_image_str(const zbc_image_t *img, uint32_t sid);

#ifdef __cplusplus
}
#endif

#endif /* ZUSPEC_ZBC_READER_H */
