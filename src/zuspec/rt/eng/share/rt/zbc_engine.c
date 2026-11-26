/*
 * zbc_engine.c -- see zbc_engine.h.
 */
#include "zbc_engine.h"
#include "zbc_ops.h"
#include "zsp_timebase.h"
#include "zsp_alloc.h"
#include <stdlib.h>
#include <string.h>

/* Run to quiescence: run the ready threads, advance to the next timed batch.
 * `stuck` counts the thread runs in a row that ended in a SPIN yield with no
 * progress; once it exceeds the ready count, every ready thread waits on a
 * condition no ready thread will change, so time must advance, or nothing
 * can (the oracle's VM._drain). */
void zbc_drain(zsp_timebase_t *tb, zbc_image_t *img, zbc_result_t *out) {
    (void)zbc_drain_until(tb, img, out, NULL);
}

/* Move to the next timed batch. Under a host that waits on time, a move
 * that takes time posts WAIT with the delay (2); else 1, or 0: none. A run
 * that has failed winds down without waiting. */
static int advance(zsp_timebase_t *tb, zbc_yield_t *y, const zbc_result_t *out) {
    uint64_t t0 = tb->current_time;
    if (!zsp_timebase_advance(tb)) return 0;
    if (y && y->wait_time && out->status == ZBC_OK && tb->current_time > t0) {
        y->state = ZBC_YIELD_WAIT;
        y->on_event = 0;
        y->delay = tb->current_time - t0;
        return 2;
    }
    return 1;
}

int zbc_drain_until(zsp_timebase_t *tb, zbc_image_t *img, zbc_result_t *out,
                    zbc_yield_t *y) {
    uint32_t stuck = 0;
    for (;;) {
        if (y && (y->state == ZBC_YIELD_PENDING || y->state == ZBC_YIELD_STOP)) return 1;
        if (tb->ready_head == NULL) {
            int a = advance(tb, y, out);
            if (a == 0) break;
            if (a == 2) return 1;
            continue;
        }
        if (stuck > (uint32_t)tb->active) {
            int a = advance(tb, y, out);
            if (a == 2) return 1;
            if (a == 0) {
                /* Only the host can help now (WAIT EVENT): keep the threads. */
                if (y && y->wait_event && out->status == ZBC_OK) {
                    y->state = ZBC_YIELD_WAIT;
                    y->on_event = 1;
                    y->delay = 0;
                    return 1;
                }
                if (out->status == ZBC_OK) {
                    out->status = ZBC_ERR_DEADLOCK;
                    out->halted_op = ZBC_OP_YIELD;
                }
                break;   /* the spinning threads are dropped with the timebase */
            }
            stuck = 0;
            continue;
        }
        *img->spin_stuck = 0;
        zsp_timebase_run(tb);
        stuck = *img->spin_stuck ? stuck + 1 : 0;
    }
    return 0;
}


/* The cone solves of img's activations need nothing the C engine lacks
 * (P4.10d1; an instance choice, comp_slot, since d2; state pools since d3):
 * buffer picks since d4; resource claims since e1 (parallel footprints since
 * e2), but no resource pool over 63 instances (one busy mask word, BUSY_WORD_BITS); no
 * pools but state,
 * buffer and resource ones (a loop index read by a `with` since f3). */
static int act_solve_supported(const zbc_image_t *img) {
    const zbc_acttab *t = img->acttab;
    if (!t) return 1;
    for (uint32_t a = 0; a < t->n_acts; a++) {
        const zbc_act *r = &img->acts[a];
        if (!r->n_cones) continue;
        for (uint32_t p = 0; p < r->n_pools; p++) {
            const zbc_actpool *pl = &img->actpools[r->pool0 + p];
            const char *k = zbc_image_act_str(img, pl->kind);
            if (k && !strcmp(k, "resource") && pl->size <= 63) continue;
            if (!k || (strcmp(k, "state") && strcmp(k, "buffer"))) return 0;
        }
    }
    return 1;
}

/* A cone of img's activations reads a list (actvar flag 8, F6.10d): its
 * elements are heap values, so it is refused with the heap. */
static int act_reads_list(const zbc_image_t *img) {
    const zbc_acttab *t = img->acttab;
    if (!t) return 0;
    for (uint32_t i = 0; i < t->n_vars; i++)
        if (img->actvars[i].flags & 8u) return 1;
    return 0;
}

/* A node of img's activations claims addresses (actnode addr0, F7.3d): the
 * run's ledger keeps live and permanent claims apart and places contiguous
 * ones first-fit, and the C engine has neither yet (M14), so it is refused
 * rather than run with claims that may overlap. */
static int act_claims_addrs(const zbc_image_t *img) {
    const zbc_acttab *t = img->acttab;
    if (!t) return 0;
    for (uint32_t i = 0; i < t->n_nodes; i++) {
        uint32_t a = img->actnodes[i].addr0;
        if (a && a < t->n_u32 && img->actlist[a]) return 1;
    }
    return 0;
}

/* Skip a u32-list group block of the form n, then per entry (ref string,
 * m, m (instance, k, k hidden node ids)) and return the index after it, or
 * 0 when it runs past the list. */
static uint32_t act_skip_infer_groups(const zbc_image_t *img, uint32_t i, uint32_t *n_hidden) {
    const zbc_acttab *t = img->acttab;
    if (i >= t->n_u32) return 0;
    uint32_t n = img->actlist[i++];
    for (uint32_t e = 0; e < n; e++) {
        if (i + 2 > t->n_u32) return 0;
        uint32_t m = img->actlist[i + 1];
        i += 2;
        for (uint32_t g = 0; g < m; g++) {
            if (i + 2 > t->n_u32) return 0;
            uint32_t k = img->actlist[i + 1];
            *n_hidden += k;
            i += 2 + k;
        }
    }
    return i;
}

/* An activation of img has a stream reference whose partner must be
 * inferred (sinfer0's second block, M9a6b). Unlike an inferred buffer
 * producer or state writer, which pyvm adds only when the solve needs one
 * (the C engine then fails that solve, saying inference is what it lacks,
 * pssvm_host.c err_infer), an unpaired stream always needs its partner, and
 * without it the run would end with the sender's output unconsumed and no
 * error. The C engine runs no inferred node until M14, so it refuses. */
static int act_infers_streams(const zbc_image_t *img) {
    const zbc_acttab *t = img->acttab;
    if (!t) return 0;
    for (uint32_t i = 0; i < t->n_nodes; i++) {
        uint32_t s0 = img->actnodes[i].sinfer0, hidden = 0;
        if (!s0) continue;
        uint32_t j = act_skip_infer_groups(img, s0, &hidden);   /* state writers */
        hidden = 0;
        if (!j || !act_skip_infer_groups(img, j, &hidden) || hidden) return 1;
    }
    return 0;
}

/* An activation of img has uid slots (actinit unknown == 2): the Python
 * engine numbers them at activation and on each re-traversal; the C engine
 * does not until M14 and would leave every uid 0. Refused instead. */
static int act_numbers_uids(const zbc_image_t *img) {
    const zbc_acttab *t = img->acttab;
    if (!t) return 0;
    for (uint32_t i = 0; i < t->n_init; i++)
        if (img->actinits[i].unknown == 2) return 1;
    return 0;
}

/* An opcode the interpreter has a case for (zbc_interp.c). PAR has none: no
 * lowering emits it, and the Python engine rejects it too. */
static int op_known(uint32_t op) {
    switch (op) {
    case ZBC_OP_NOP: case ZBC_OP_RET:
    case ZBC_OP_CONST: case ZBC_OP_MOV: case ZBC_OP_LD_LOCAL: case ZBC_OP_ST_LOCAL:
    case ZBC_OP_LD_FIELD: case ZBC_OP_ST_FIELD: case ZBC_OP_LD_COMP: case ZBC_OP_ST_COMP:
    case ZBC_OP_ARG: case ZBC_OP_LD_ARG: case ZBC_OP_LD_RES:
    case ZBC_OP_ADD: case ZBC_OP_SUB: case ZBC_OP_MUL: case ZBC_OP_DIV: case ZBC_OP_MOD:
    case ZBC_OP_AND: case ZBC_OP_OR: case ZBC_OP_XOR: case ZBC_OP_SHL: case ZBC_OP_SHR:
    case ZBC_OP_NEG: case ZBC_OP_NOT:
    case ZBC_OP_FARITH: case ZBC_OP_FCVT: case ZBC_OP_FCMP: case ZBC_OP_FMATH:
    case ZBC_OP_CMP_EQ: case ZBC_OP_CMP_NE: case ZBC_OP_CMP_LT: case ZBC_OP_CMP_LE:
    case ZBC_OP_CMP_GT: case ZBC_OP_CMP_GE:
    case ZBC_OP_BR: case ZBC_OP_BRZ:
    case ZBC_OP_SPAWN: case ZBC_OP_INVOKE: case ZBC_OP_JOIN: case ZBC_OP_WAIT:
    case ZBC_OP_SELECT: case ZBC_OP_SOLVE: case ZBC_OP_BIND: case ZBC_OP_YIELD:
    case ZBC_OP_IMPORT: case ZBC_OP_SCOPE_ENTER: case ZBC_OP_SOLVE_NODE: case ZBC_OP_CALL:
    case ZBC_OP_SOLVE_PIN: case ZBC_OP_SOLVE_GET: case ZBC_OP_COV_SAMPLE:
    case ZBC_OP_EXEC_SET: case ZBC_OP_EXEC_GET:
        return 1;
    default:
        return 0;
    }
}

int zbc_image_check(const zbc_image_t *img, const zbc_host_t *host, int *halted_op) {
    /* The component tree (P1.5): its object, and a coroutine that constructs
     * it before the entry. Without a COMP section the engine cannot find
     * either, so the image is refused rather than its construction skipped
     * (P1-D6); so is one whose activation nodes run in an instance other than
     * instance 0 but that has no ACT section to say which (frames carry
     * their instance from it, P4.10c4). The tree's run_start/run_end
     * coroutines (ZBC_COMP_F_RUN_HOOKS) are not run here yet: refused rather
     * than skipped. */
    if (((img->hdr->flags & ZBC_HDR_COMP_INIT) && img->comp == NULL)
            || (img->comp && (img->comp->flags & ZBC_COMP_F_RUN_HOOKS))
            || (img->comp && (img->comp->flags & ZBC_COMP_F_NODE_INST) && !img->acttab)
            || (img->comp && img->comp->init_coro != 0xFFFFFFFFu
                && img->comp->init_coro >= img->coro_count)) {
        return ZBC_ERR_COMP_INIT;
    }

    /* Cone solves (SOLVE_NODE) whose activations need what the C engine
     * does not have yet (act_solve_supported), and component attributes
     * (LD_COMP / ST_COMP) without a COMP section, P1.5, are the Python
     * oracle's alone. Refuse an image that uses them before running
     * anything, naming the opcode, rather than run a model whose cone
     * constraints, initializers or component state would not hold (P1-D6). */
    for (uint32_t i = 0; i < img->code_count; i++) {
        uint32_t op = img->code[i].op;
        /* An extension's opcode in an image that does not declare it
         * (zbc-format.md "Profiles"). */
        if (op > ZBC_OP_CORE_LAST
                && !(op >= ZBC_OP_PSS_FIRST && op <= ZBC_OP_PSS_LAST
                     && (img->hdr->flags & ZBC_HDR_EXT_PSS))) {
            *halted_op = (int)op;
            return ZBC_ERR_BAD_PROFILE;
        }
        /* file_read* / file_write_lines make or read heap values: refused as the heap. */
        int heap_file = (op == ZBC_OP_IMPORT && img->code[i].arg0 >= ZBC_BUILTIN_FILE_READ
                && img->code[i].arg0 <= ZBC_BUILTIN_FILE_WRITE_LINES)
                /* ... and so does a cone solve that reads a list. */
                || (op == ZBC_OP_SOLVE_NODE && act_reads_list(img));
        if (!op_known(op)
                /* An opcode from a newer format, refused before any of it runs. */
                /* Heap ops (heap.md s.9): the Python engine's alone until M14. */
                || op == ZBC_OP_HEAP || heap_file
                || (op == ZBC_OP_SOLVE_NODE && !act_solve_supported(img))
                || ((op == ZBC_OP_LD_COMP || op == ZBC_OP_ST_COMP) && img->comp == NULL)
                /* join_select / join_branch (F8 M8b1): the Python engine's alone until M14. */
                || (op == ZBC_OP_JOIN && (img->code[i].flags & ZBC_F_SUBSET))
                /* Platform memory (B-D6): only a host with mem_access answers it. */
                || (op == ZBC_OP_IMPORT && (host == NULL || (host->mem_access == NULL && host->yield == NULL))
                    && img->code[i].arg0 >= ZBC_BUILTIN_MEM_FIRST
                    && img->code[i].arg0 <= ZBC_BUILTIN_MEM_LAST)) {
            *halted_op = heap_file ? ZBC_OP_HEAP : (int)op;
            return ZBC_ERR_UNSUPPORTED_OP;
        }
    }
    if (act_claims_addrs(img)) {
        *halted_op = ZBC_HALT_ADDR_CLAIM;
        return ZBC_ERR_UNSUPPORTED_OP;
    }
    if (act_infers_streams(img)) {
        *halted_op = ZBC_HALT_INFER;
        return ZBC_ERR_UNSUPPORTED_OP;
    }
    if (act_numbers_uids(img)) {
        *halted_op = ZBC_HALT_UID;
        return ZBC_ERR_UNSUPPORTED_OP;
    }
    return ZBC_OK;
}

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
    uint32_t spin_stuck = 0;
    img.spin_stuck = &spin_stuck;

    /* Picosecond-resolution timebase over a malloc allocator (M1). */
    zsp_alloc_t *alloc = zsp_alloc_malloc_create();
    zsp_timebase_t *tb = zsp_timebase_create(alloc, ZSP_TIME_PS);

    int halted = 0;
    rc = zbc_image_check(&img, host, &halted);
    if (rc != ZBC_OK) {
        out->status = rc;
        out->halted_op = halted;
        return rc;
    }

    zbc_obj_t obj = { fields, nfields };
    zbc_obj_t *objp = (fields != NULL && nfields > 0) ? &obj : NULL;

    /* Shared, run-wide SPAWN budget (fork-bomb guard), threaded to every coro. */
    uint64_t spawn_budget = ZBC_SPAWN_LIMIT;

    /* The component object, all 0 until its constructing coroutine (if any)
     * runs to completion in instance 0, before the entry (LRM 20.1.3). It
     * draws from the run seed and shares the spawn budget and host. */
    if (img.comp) {
        img.cobj = (uint64_t *)calloc(img.comp->n_slots ? img.comp->n_slots : 1,
                                      sizeof(uint64_t));
        if (img.comp->init_coro != 0xFFFFFFFFu) {
            zsp_timebase_thread_create(
                tb, &zbc_interp_task, ZSP_THREAD_FLAGS_NONE,
                &img, (int)img.comp->init_coro, out, (zbc_obj_t *)0, (uint32_t)0,
                &spawn_budget, host, (uint64_t)0, (const uint64_t *)0, (uint32_t)0, out, (uint32_t)0, ZBC_FRAME_ROOT);
            zbc_drain(tb, &img, out);
            if (out->status != ZBC_OK) {
                out->now = zsp_timebase_current_ticks(tb);
                zsp_timebase_destroy(tb);
                free(img.cobj);
                return out->status;
            }
        }
    }

    /* The entry coroutine runs as an interpreted coroutine; it writes back into
     * `out` at RET (or on an unsupported op) and mutates `fields` in place. */
    /* Root frame's seed stream is the run seed (0, matching the oracle's
     * run_model default); children fork deterministically from it. `host` is the
     * IMPORT seam, threaded to every coroutine like the spawn budget. */
    zsp_timebase_thread_create(
        tb, &zbc_interp_task, ZSP_THREAD_FLAGS_NONE,
        &img, (int)img.entry_coro, out, objp, (uint32_t)0, &spawn_budget, host,
        (uint64_t)0, (const uint64_t *)0, (uint32_t)0, out, (uint32_t)0, ZBC_FRAME_ROOT);

    zbc_drain(tb, &img, out);

    out->now = zsp_timebase_current_ticks(tb);
    zbc_files_close_all();

    zsp_timebase_destroy(tb);
    free(img.cobj);
    return out->status;
}
