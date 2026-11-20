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
 * e2), but no resource pool over 64 instances (busy masks are 64-bit); no
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
            if (k && !strcmp(k, "resource") && pl->size <= 64) continue;
            if (!k || (strcmp(k, "state") && strcmp(k, "buffer"))) return 0;
        }
    }
    return 1;
}

int zbc_image_check(const zbc_image_t *img, const zbc_host_t *host, int *halted_op) {
    /* The component tree (P1.5): its object, and a coroutine that constructs
     * it before the entry. Without a COMP section the engine cannot find
     * either, so the image is refused rather than its construction skipped
     * (P1-D6); so is one whose activation nodes run in an instance other than
     * instance 0 but that has no ACT section to say which (frames carry
     * their instance from it, P4.10c4). */
    if (((img->hdr->flags & ZBC_HDR_COMP_INIT) && img->comp == NULL)
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
        if ((op == ZBC_OP_SOLVE_NODE && !act_solve_supported(img))
                || ((op == ZBC_OP_LD_COMP || op == ZBC_OP_ST_COMP) && img->comp == NULL)
                /* Platform memory (B-D6): only a host with mem_access answers it. */
                || (op == ZBC_OP_IMPORT && (host == NULL || (host->mem_access == NULL && host->yield == NULL))
                    && img->code[i].arg0 >= ZBC_BUILTIN_MEM_FIRST
                    && img->code[i].arg0 <= ZBC_BUILTIN_MEM_LAST)) {
            *halted_op = (int)op;
            return ZBC_ERR_UNSUPPORTED_OP;
        }
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

    zsp_timebase_destroy(tb);
    free(img.cobj);
    return out->status;
}
