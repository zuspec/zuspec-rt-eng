/*
 * zbc_interp.c -- ZBC bytecode dispatch loop (walking skeleton).
 *
 * Mirrors the Python oracle's procedural + WAIT/RET semantics (be.bc.interp):
 * registers are unsigned 64-bit bit patterns (C wraps them for free); BR/BRZ
 * targets are code-relative instruction indices within the coro; WAIT uses the
 * same suspend/resume protocol as a compiled coroutine (save pc -> wait -> return
 * leaf). Orchestration beyond WAIT/YIELD, fields, and the const pool land later.
 */
#include <string.h>
#include "zbc_interp.h"
#include "zbc_ops.h"
#include "zbc_solver.h"

/* Determinism substrate (mirrors be.bc.determinism exactly; do not change without
 * an abi/determinism version bump). uint64_t arithmetic wraps mod 2^64, matching
 * the Python MASK64 anchoring, so SELECT draws are bit-identical to the oracle. */
#define ZBC_LCG_MUL   6364136223846793005ull
#define ZBC_LCG_ADD   1442695040888963407ull
#define ZBC_FORK_MIX  0x9E3779B97F4A7C15ull

static uint64_t lcg_next(uint64_t s) {
    return s * ZBC_LCG_MUL + ZBC_LCG_ADD;
}

/* Child stream seed for the index-th SPAWN/INVOKE/SELECT child of a frame. Depends
 * on the parent's *current* state at the fork point (the parent state is unchanged
 * by forking -- only an explicit draw advances it). */
static uint64_t fork_seed(uint64_t parent_state, uint32_t index) {
    return lcg_next(parent_state ^ ((uint64_t)index * ZBC_FORK_MIX));
}

typedef struct interp_locals_s {
    const zbc_image_t *img;
    const zbc_coro    *coro;
    zbc_result_t      *result;
    zbc_obj_t         *obj;       /* active action object (NULL if none) */
    uint32_t           pc;
    uint64_t           steps;     /* remaining step budget (frame-resident) */
    int                resuming_call;  /* re-entered from a blocking INVOKE */
    int                call_ret_reg;   /* register to receive the callee's rval (-1 = none) */
    /* Fork/join concurrency (SPAWN/JOIN). A spawned child carries a link back to
     * its parent so it can decrement the parent's pending count on completion. */
    zsp_thread_t          *self_thread;      /* this coroutine's own scheduler thread */
    struct interp_locals_s *parent_locals;  /* parent's frame (NULL if not a spawned child) */
    zsp_thread_t          *parent_thread;    /* parent's scheduler thread */
    int                    counted;          /* this child is awaited by the parent's active JOIN */
    uint32_t               n_children;       /* children spawned since the last JOIN */
    uint32_t               join_pending;     /* children still to complete before JOIN resumes */
    struct interp_locals_s *children[ZBC_MAX_CHILDREN];  /* spawned children awaiting a JOIN */
    uint64_t              *spawn_budget;     /* shared run-wide SPAWN budget (fork-bomb guard) */
    zbc_host_t            *host;             /* run-wide IMPORT seam (NULL = record nowhere, return 0) */
    /* Determinism (SELECT/SOLVE): this frame's own seed stream + the fork index for
     * its next child. A SELECT draw advances seed_state; every child creation forks
     * fork_seed(seed_state, child_index++) and hands the child its own stream. */
    uint64_t               seed_state;
    uint32_t               child_index;
    uint64_t           regs[ZBC_MAX_REGS];
    uint64_t           locals[ZBC_MAX_LOCALS];
} interp_locals_t;

/* One-time operand verifier: reject a coro whose register/local/branch operands
 * fall outside the fixed frame before executing a single instruction. This keeps
 * the dispatch loop free of per-access bounds checks and makes a malformed image
 * a clean error rather than memory corruption. Returns ZBC_OK or a negative err. */
static int verify_coro(const zbc_instr *code, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) {
        const zbc_instr *in = &code[i];
        uint32_t a0 = in->arg0, a1 = in->arg1, a2 = in->arg2;
        switch (in->op) {
        /* arg0 is a register only when present (WAIT/RET may take none). */
        case ZBC_OP_CONST:
            if (a0 >= ZBC_MAX_REGS) return ZBC_ERR_OOB_REG;
            break;
        case ZBC_OP_WAIT: case ZBC_OP_RET:
            if (in->nargs > 0 && a0 >= ZBC_MAX_REGS) return ZBC_ERR_OOB_REG;
            break;
        case ZBC_OP_MOV: case ZBC_OP_NEG: case ZBC_OP_NOT:
            if (a0 >= ZBC_MAX_REGS || a1 >= ZBC_MAX_REGS) return ZBC_ERR_OOB_REG;
            break;
        case ZBC_OP_LD_LOCAL: case ZBC_OP_ST_LOCAL:
            if (a0 >= ZBC_MAX_REGS) return ZBC_ERR_OOB_REG;
            if (a1 >= ZBC_MAX_LOCALS) return ZBC_ERR_OOB_LOCAL;
            break;
        case ZBC_OP_LD_FIELD: case ZBC_OP_ST_FIELD:
            /* a1 (field slot) is checked at runtime against the live object. */
            if (a0 >= ZBC_MAX_REGS) return ZBC_ERR_OOB_REG;
            break;
        case ZBC_OP_ADD: case ZBC_OP_SUB: case ZBC_OP_MUL: case ZBC_OP_DIV:
        case ZBC_OP_MOD: case ZBC_OP_AND: case ZBC_OP_OR:  case ZBC_OP_XOR:
        case ZBC_OP_SHL: case ZBC_OP_SHR:
        case ZBC_OP_CMP_EQ: case ZBC_OP_CMP_NE: case ZBC_OP_CMP_LT:
        case ZBC_OP_CMP_LE: case ZBC_OP_CMP_GT: case ZBC_OP_CMP_GE:
            if (a0 >= ZBC_MAX_REGS || a1 >= ZBC_MAX_REGS || a2 >= ZBC_MAX_REGS)
                return ZBC_ERR_OOB_REG;
            break;
        case ZBC_OP_BR:
            if (a0 >= n) return ZBC_ERR_BAD_TARGET;
            break;
        case ZBC_OP_BRZ:
            if (a0 >= ZBC_MAX_REGS) return ZBC_ERR_OOB_REG;
            if (a1 >= n) return ZBC_ERR_BAD_TARGET;
            break;
        case ZBC_OP_INVOKE:
            /* arg0 is a coro index (runtime-checked); arg1 is the result reg. */
            if ((in->flags & ZBC_F_HAS_RET) && a1 >= ZBC_MAX_REGS)
                return ZBC_ERR_OOB_REG;
            break;
        case ZBC_OP_IMPORT:
            /* arg0 = fn_id; arg1 = ret reg (0xFFFFFFFF = void); arg2/arg3 = arg regs. */
            if ((in->flags & ZBC_F_HAS_RET) && a1 != 0xFFFFFFFFu && a1 >= ZBC_MAX_REGS)
                return ZBC_ERR_OOB_REG;
            if (in->nargs > 2 && a2 >= ZBC_MAX_REGS) return ZBC_ERR_OOB_REG;
            if (in->nargs > 3 && in->arg3 >= ZBC_MAX_REGS) return ZBC_ERR_OOB_REG;
            break;
        default:
            break;   /* NOP, YIELD, and (as-yet) unsupported ops: no operands to check here */
        }
    }
    return ZBC_OK;
}

static zsp_frame_t *halt(zsp_thread_t *thread, interp_locals_t *L,
                         int status, int op, uint64_t rv) {
    if (L->result) {
        L->result->status = status;
        L->result->halted_op = op;
        L->result->retval = rv;
    }
    /* Notify the parent only if a JOIN actually counted this child (PAR-ALL).
     * A detached child (non-blocking INVOKE) or an un-joined SPAWN (NONE policy)
     * has counted == 0, so it never touches the parent frame -- which may already
     * have been freed if the parent completed first. */
    if (L->counted && L->parent_locals != NULL) {
        interp_locals_t *P = L->parent_locals;
        L->parent_locals = NULL;              /* notify exactly once */
        L->counted = 0;
        if (P->join_pending > 0 && --P->join_pending == 0) {
            /* A FIRST(n) join is satisfied: cancel the surplus children that are
             * still counted (i.e. have not completed). Their WAITs are dropped
             * from the timed heap without advancing time (rt-core cancel). */
            for (uint32_t i = 0; i < P->n_children; i++) {
                interp_locals_t *sib = P->children[i];
                if (sib->counted) {
                    sib->counted = 0;
                    zsp_timebase_cancel(thread->timebase, sib->self_thread);
                }
            }
            P->n_children = 0;
            zsp_timebase_schedule(thread->timebase, L->parent_thread);
        }
    }
    return zsp_timebase_return(thread, rv);
}

zsp_frame_t *zbc_interp_task(zsp_timebase_t *tb, zsp_thread_t *thread,
                             int idx, va_list *args) {
    zsp_frame_t *ret = thread->leaf;
    interp_locals_t *L;

    if (idx == 0) {
        /* Frame + register/local file live in the coroutine's stack arena. */
        ret = zsp_timebase_alloc_frame(thread, sizeof(interp_locals_t), &zbc_interp_task);
        L = zsp_frame_locals(ret, interp_locals_t);
        L->img    = va_arg(*args, const zbc_image_t *);
        int coro_index = va_arg(*args, int);
        L->coro   = &L->img->coros[coro_index];
        L->result = va_arg(*args, zbc_result_t *);
        L->obj    = va_arg(*args, zbc_obj_t *);
        L->spawn_budget = va_arg(*args, uint64_t *);
        L->host = va_arg(*args, zbc_host_t *);
        L->seed_state = va_arg(*args, uint64_t);   /* forked by the parent (root: run seed) */
        L->child_index = 0;
        L->pc = 0;
        L->steps = ZBC_STEP_LIMIT;
        L->resuming_call = 0;
        L->call_ret_reg = -1;
        L->self_thread = thread;
        L->parent_locals = (interp_locals_t *)0;   /* set by the parent's SPAWN */
        L->parent_thread = (zsp_thread_t *)0;
        L->counted = 0;
        L->n_children = 0;
        L->join_pending = 0;
        memset(L->regs, 0, sizeof(L->regs));
        memset(L->locals, 0, sizeof(L->locals));
        ret->idx = 1;

        int vrc = verify_coro(L->img->code + L->coro->code_start,
                              L->coro->code_count);
        if (vrc != ZBC_OK) {
            return halt(thread, L, vrc, 0, 0);
        }
        return ret;
    }

    L = zsp_frame_locals(ret, interp_locals_t);
    const zbc_instr *code = L->img->code + L->coro->code_start;
    uint32_t n = L->coro->code_count;

    /* Re-entered after a blocking INVOKE's callee completed: the callee's return
     * value is in thread->rval; deliver it to the caller's result register. */
    if (L->resuming_call) {
        L->resuming_call = 0;
        if (L->call_ret_reg >= 0) {
            L->regs[L->call_ret_reg] = thread->rval;
        }
    }

    for (;;) {
        if (L->steps-- == 0) {
            return halt(thread, L, ZBC_ERR_STEP_LIMIT, 0, 0);
        }
        if (L->pc >= n) {
            /* Fell off the end without RET -> complete (matches the oracle). */
            return halt(thread, L, ZBC_OK, 0, 0);
        }
        const zbc_instr *in = &code[L->pc];
        uint32_t a0 = in->arg0, a1 = in->arg1, a2 = in->arg2;

        switch (in->op) {
        case ZBC_OP_NOP:      L->pc++; break;

        case ZBC_OP_CONST:
            if (in->flags & ZBC_F_FROM_POOL) {
                return halt(thread, L, ZBC_ERR_UNSUPPORTED_OP, in->op, 0);
            }
            L->regs[a0] = in->imm; L->pc++; break;

        case ZBC_OP_MOV:      L->regs[a0] = L->regs[a1]; L->pc++; break;
        case ZBC_OP_LD_LOCAL: L->regs[a0] = L->locals[a1]; L->pc++; break;
        case ZBC_OP_ST_LOCAL: L->locals[a1] = L->regs[a0]; L->pc++; break;

        case ZBC_OP_LD_FIELD:
            if (!L->obj) return halt(thread, L, ZBC_ERR_NO_OBJ, in->op, 0);
            if (a1 >= L->obj->n) return halt(thread, L, ZBC_ERR_OOB_FIELD, in->op, 0);
            L->regs[a0] = L->obj->slots[a1]; L->pc++; break;
        case ZBC_OP_ST_FIELD:
            if (!L->obj) return halt(thread, L, ZBC_ERR_NO_OBJ, in->op, 0);
            if (a1 >= L->obj->n) return halt(thread, L, ZBC_ERR_OOB_FIELD, in->op, 0);
            L->obj->slots[a1] = L->regs[a0]; L->pc++; break;

        case ZBC_OP_ADD: L->regs[a0] = L->regs[a1] + L->regs[a2]; L->pc++; break;
        case ZBC_OP_SUB: L->regs[a0] = L->regs[a1] - L->regs[a2]; L->pc++; break;
        case ZBC_OP_MUL: L->regs[a0] = L->regs[a1] * L->regs[a2]; L->pc++; break;
        case ZBC_OP_DIV:
            if (L->regs[a2] == 0) return halt(thread, L, ZBC_ERR_DIV_ZERO, in->op, 0);
            L->regs[a0] = L->regs[a1] / L->regs[a2]; L->pc++; break;
        case ZBC_OP_MOD:
            if (L->regs[a2] == 0) return halt(thread, L, ZBC_ERR_DIV_ZERO, in->op, 0);
            L->regs[a0] = L->regs[a1] % L->regs[a2]; L->pc++; break;
        case ZBC_OP_AND: L->regs[a0] = L->regs[a1] & L->regs[a2]; L->pc++; break;
        case ZBC_OP_OR:  L->regs[a0] = L->regs[a1] | L->regs[a2]; L->pc++; break;
        case ZBC_OP_XOR: L->regs[a0] = L->regs[a1] ^ L->regs[a2]; L->pc++; break;
        case ZBC_OP_SHL: L->regs[a0] = L->regs[a1] << (L->regs[a2] & 63); L->pc++; break;
        case ZBC_OP_SHR: L->regs[a0] = L->regs[a1] >> (L->regs[a2] & 63); L->pc++; break;
        case ZBC_OP_NEG: L->regs[a0] = (uint64_t)(-(int64_t)L->regs[a1]); L->pc++; break;
        case ZBC_OP_NOT: L->regs[a0] = ~L->regs[a1]; L->pc++; break;

        case ZBC_OP_CMP_EQ: L->regs[a0] = (L->regs[a1] == L->regs[a2]); L->pc++; break;
        case ZBC_OP_CMP_NE: L->regs[a0] = (L->regs[a1] != L->regs[a2]); L->pc++; break;
        case ZBC_OP_CMP_LT: L->regs[a0] = (L->regs[a1] <  L->regs[a2]); L->pc++; break;
        case ZBC_OP_CMP_LE: L->regs[a0] = (L->regs[a1] <= L->regs[a2]); L->pc++; break;
        case ZBC_OP_CMP_GT: L->regs[a0] = (L->regs[a1] >  L->regs[a2]); L->pc++; break;
        case ZBC_OP_CMP_GE: L->regs[a0] = (L->regs[a1] >= L->regs[a2]); L->pc++; break;

        case ZBC_OP_BR:  L->pc = a0; break;
        case ZBC_OP_BRZ: L->pc = (L->regs[a0] == 0) ? a1 : L->pc + 1; break;

        case ZBC_OP_WAIT: {
            uint64_t delay = (in->nargs > 0) ? L->regs[a0] : in->imm;
            L->pc++;   /* advance past WAIT before suspending */
            if (zsp_timebase_wait(thread, ZSP_TIME_PS(delay))) {
                return ret;   /* suspend; resume re-enters here at the new pc */
            }
            break;            /* fast path: time advanced inline */
        }

        case ZBC_OP_INVOKE: {
            /* Blocking INVOKE == a sequential `do Sub` traversal: call the callee
             * as a NESTED coroutine on this thread's frame stack (zsp_timebase_call).
             * The callee shares our object, runs to completion (possibly across its
             * own suspends), and its return value comes back in thread->rval when the
             * scheduler re-invokes us. Non-blocking INVOKE (fork) lands with SPAWN. */
            uint32_t target = a0;
            if (target >= L->img->coro_count) {
                return halt(thread, L, ZBC_ERR_BAD_TARGET, in->op, 0);
            }
            if (!(in->flags & ZBC_F_BLOCKING)) {
                /* Non-blocking INVOKE: fire-and-forget. Fork a fully detached
                 * child (counted == 0, no parent back-link) and continue. */
                if (L->spawn_budget && *L->spawn_budget == 0) {
                    return halt(thread, L, ZBC_ERR_SPAWN_LIMIT, in->op, 0);
                }
                if (L->spawn_budget) (*L->spawn_budget)--;
                zsp_timebase_thread_create(
                    thread->timebase, &zbc_interp_task, ZSP_THREAD_FLAGS_NONE,
                    L->img, (int)target, (zbc_result_t *)0, L->obj, L->spawn_budget, L->host,
                    fork_seed(L->seed_state, L->child_index++));
                L->pc++;
                break;
            }
            L->pc++;   /* resume after the INVOKE */
            L->call_ret_reg = (in->flags & ZBC_F_HAS_RET) ? (int)a1 : -1;
            L->resuming_call = 1;
            /* Callee gets a NULL result (only the root writes the final result) and
             * shares our object; its rval is delivered on our re-entry. */
            return zsp_timebase_call(thread, &zbc_interp_task,
                                     L->img, (int)target, (zbc_result_t *)0,
                                     L->obj, L->spawn_budget, L->host,
                                     fork_seed(L->seed_state, L->child_index++));
        }

        case ZBC_OP_SPAWN: {
            /* Fork a child coroutine (own frame, shared object), joinable by a
             * later JOIN. Non-blocking: the parent continues. The child is queued
             * but (cooperative scheduler) does not run until the parent suspends. */
            uint32_t target = a0;
            if (target >= L->img->coro_count) {
                return halt(thread, L, ZBC_ERR_BAD_TARGET, in->op, 0);
            }
            if (L->n_children >= ZBC_MAX_CHILDREN) {
                return halt(thread, L, ZBC_ERR_SPAWN_LIMIT, in->op, 0);
            }
            if (L->spawn_budget && *L->spawn_budget == 0) {
                return halt(thread, L, ZBC_ERR_SPAWN_LIMIT, in->op, 0);
            }
            if (L->spawn_budget) (*L->spawn_budget)--;
            zsp_thread_t *child = zsp_timebase_thread_create(
                thread->timebase, &zbc_interp_task, ZSP_THREAD_FLAGS_NONE,
                L->img, (int)target, (zbc_result_t *)0, L->obj, L->spawn_budget, L->host,
                fork_seed(L->seed_state, L->child_index++));
            interp_locals_t *cl = zsp_frame_locals(child->leaf, interp_locals_t);
            cl->parent_locals = L;
            cl->parent_thread = thread;
            cl->counted = 0;                    /* JOIN decides joinability */
            L->children[L->n_children++] = cl;
            L->pc++;
            break;
        }

        case ZBC_OP_JOIN: {
            /* imm == 0 -> join ALL spawned children (PAR-ALL); imm == n -> resume
             * after the first n complete (PAR-FIRST), cancelling the surplus. All
             * spawned children are marked counted (cooperative scheduling means
             * none have run yet, so all are still live); `join_pending` is the
             * count that must complete before the parent resumes. */
            uint32_t nlive = L->n_children;
            uint32_t want = (in->imm == 0) ? nlive : (uint32_t)in->imm;
            if (want > nlive) want = nlive;
            for (uint32_t i = 0; i < nlive; i++) {
                L->children[i]->counted = 1;
            }
            L->join_pending = want;
            /* Keep children[]/n_children so a satisfied FIRST(n) can cancel the
             * surplus at the n-th completion (see halt). */
            L->pc++;
            if (L->join_pending == 0) {
                L->n_children = 0;
                break;   /* nothing to wait for */
            }
            /* Suspend until the children re-schedule us (block so the run loop
             * does not auto-reschedule). */
            thread->flags |= ZSP_THREAD_FLAGS_BLOCKED;
            return ret;
        }

        case ZBC_OP_BIND:
            /* Flow-object bind: a traced no-op in M1 (the oracle's _op_bind emits a
             * BIND event and continues; the engine has no operands to act on). */
            L->pc++;
            break;

        case ZBC_OP_YIELD:
            L->pc++;
            zsp_timebase_yield(thread);
            return ret;

        case ZBC_OP_SOLVE: {
            /* Two randomizers select on prob_len. prob_len==0: the minimal M1
             * randomizer == the oracle's FixedSolveBackend (base 0), each written
             * field slot = seed + var_id. prob_len>0: the real dv-solve path --
             * compile + solve the SPROB blob with the drawn seed and write
             * solver_get_value(var_id) back per pair. Either way the seed is the
             * descriptor's fixed value or (inherit) the frame's next raw draw,
             * advanced even with no object, matching _op_solve's ordering. */
            uint32_t pid = a0;
            if (!L->img->solves || pid >= L->img->solve_count) {
                return halt(thread, L, ZBC_ERR_BAD_SOLVE, in->op, 0);
            }
            const zbc_solve *p = &L->img->solves[pid];
            uint32_t nwb = p->n_writeback;
            uint64_t need = (uint64_t)p->oplist_off + 2ull * nwb;
            if (need > L->img->oplist_count) {
                return halt(thread, L, ZBC_ERR_BAD_SOLVE, in->op, 0);
            }
            uint64_t seed;
            if (p->flags & ZBC_SOLVE_SEED_FIXED) {
                seed = p->seed_value;
            } else {
                L->seed_state = lcg_next(L->seed_state);   /* next_raw(): advance+return */
                seed = L->seed_state;
            }
            const uint32_t *pairs = L->img->oplist + p->oplist_off;
            if (p->prob_len) {
                /* Real solve: bound the blob, validate slots, then drive dv-solve. */
                if (!L->img->sprob ||
                    (uint64_t)p->prob_off + p->prob_len > L->img->sprob_count) {
                    return halt(thread, L, ZBC_ERR_BAD_SOLVE, in->op, 0);
                }
                if (L->obj) {
                    for (uint32_t i = 0; i < nwb; i++) {
                        if (pairs[2 * i] >= L->obj->n) {
                            return halt(thread, L, ZBC_ERR_OOB_FIELD, in->op, 0);
                        }
                    }
                    int sr = zbc_solver_run(L->img->sprob + p->prob_off, seed,
                                            pairs, nwb, L->obj->slots);
                    if (sr == ZBC_SOLVER_UNSAT) {
                        return halt(thread, L, ZBC_ERR_SOLVE_UNSAT, in->op, 0);
                    }
                    if (sr != ZBC_SOLVER_OK) {
                        return halt(thread, L, ZBC_ERR_SOLVE_FAIL, in->op, 0);
                    }
                }
            } else if (L->obj) {
                for (uint32_t i = 0; i < nwb; i++) {
                    uint32_t slot = pairs[2 * i], var_id = pairs[2 * i + 1];
                    if (slot >= L->obj->n) {
                        return halt(thread, L, ZBC_ERR_OOB_FIELD, in->op, 0);
                    }
                    L->obj->slots[slot] = seed + var_id;
                }
            }
            L->pc++;
            break;
        }

        case ZBC_OP_IMPORT: {
            /* The interpreter's window to the outside world. The instruction fully
             * encodes the call (fn_id=arg0, ret reg=arg1 or 0xFFFFFFFF void, arg
             * regs=arg2/arg3), so we just record it in the host log and read a
             * per-fn_id return value. Synchronous in M1 (even a BLOCKING import
             * completes inline), matching the oracle's _op_import -> CONTINUE. */
            uint32_t fn_id = a0;
            uint32_t ret_slot = a1;
            uint32_t nval = (in->nargs > 2) ? (in->nargs - 2) : 0;
            if (nval > ZBC_IMPORT_MAX_ARGS) nval = ZBC_IMPORT_MAX_ARGS;
            uint64_t argv[ZBC_IMPORT_MAX_ARGS];
            if (nval > 0) argv[0] = L->regs[a2];
            if (nval > 1) argv[1] = L->regs[in->arg3];

            if (L->host && L->host->import_log) {
                zbc_import_log_t *lg = L->host->import_log;
                if (lg->count < lg->capacity && lg->calls) {
                    zbc_import_call_t *rec = &lg->calls[lg->count];
                    rec->fn_id = fn_id;
                    rec->n_args = nval;
                    for (uint32_t i = 0; i < nval; i++) rec->args[i] = argv[i];
                }
                lg->count++;   /* count all calls; overflow is visible as count>capacity */
            }

            uint64_t rv = 0;
            if (L->host && L->host->import_returns) {
                const zbc_import_returns_t *rt = L->host->import_returns;
                for (uint32_t i = 0; i < rt->count; i++) {
                    if (rt->fn_ids[i] == fn_id) { rv = rt->values[i]; break; }
                }
            }
            if ((in->flags & ZBC_F_HAS_RET) && ret_slot != 0xFFFFFFFFu) {
                L->regs[ret_slot] = rv;
            }
            L->pc++;
            break;
        }

        case ZBC_OP_SELECT: {
            /* Weighted choice among guarded branches, drawn from this frame's own
             * seed stream, then run the chosen branch as a blocking child (== a
             * `do` of one alternative). Determinism mirrors be.bc.determinism, so
             * the native and oracle draws pick the *same* branch bit-for-bit. */
            uint32_t sid = a0;
            if (!L->img->selects || sid >= L->img->select_count) {
                return halt(thread, L, ZBC_ERR_BAD_SELECT, in->op, 0);
            }
            const zbc_select *sel = &L->img->selects[sid];
            uint32_t nb = sel->n_branches;
            uint64_t need = (uint64_t)sel->oplist_off + 3ull * nb;
            if (need > L->img->oplist_count) {
                return halt(thread, L, ZBC_ERR_BAD_SELECT, in->op, 0);
            }
            const uint32_t *branches = L->img->oplist + sel->oplist_off;
            const uint32_t *weights  = branches + nb;
            const uint32_t *guards   = branches + 2 * nb;

            /* Total weight over eligible branches (unguarded, or guard reg != 0),
             * in declaration order -- the cumulative order the draw walks. */
            uint64_t total = 0;
            uint32_t eligible = 0;
            for (uint32_t i = 0; i < nb; i++) {
                uint32_t g = guards[i];
                if (g != 0xFFFFFFFFu) {
                    if (g >= ZBC_MAX_REGS) {
                        return halt(thread, L, ZBC_ERR_OOB_REG, in->op, 0);
                    }
                    if (L->regs[g] == 0) continue;   /* guard false -> not eligible */
                }
                total += weights[i];
                eligible++;
            }

            if (eligible == 0 || total == 0) {
                if (sel->flags & ZBC_SEL_ALLOW_NONE) {
                    L->pc++;              /* run nothing; fall through */
                    break;
                }
                return halt(thread, L, ZBC_ERR_SELECT_NONE, in->op, 0);
            }

            /* One draw against the eligible cumulative weights (next_below). */
            L->seed_state = lcg_next(L->seed_state);
            uint64_t draw = L->seed_state % total;
            uint32_t chosen = 0;
            uint64_t acc = 0;
            for (uint32_t i = 0; i < nb; i++) {
                uint32_t g = guards[i];
                if (g != 0xFFFFFFFFu && L->regs[g] == 0) continue;
                acc += weights[i];
                if (draw < acc) { chosen = i; break; }
            }
            uint32_t target = branches[chosen];
            if (target >= L->img->coro_count) {
                return halt(thread, L, ZBC_ERR_BAD_TARGET, in->op, 0);
            }

            L->pc++;                      /* resume after the SELECT */
            L->call_ret_reg = -1;         /* a SELECT branch yields no value */
            L->resuming_call = 1;
            return zsp_timebase_call(thread, &zbc_interp_task,
                                     L->img, (int)target, (zbc_result_t *)0,
                                     L->obj, L->spawn_budget, L->host,
                                     fork_seed(L->seed_state, L->child_index++));
        }

        case ZBC_OP_RET: {
            uint64_t rv = (in->nargs > 0) ? L->regs[a0] : 0;
            return halt(thread, L, ZBC_OK, 0, rv);
        }

        default:
            return halt(thread, L, ZBC_ERR_UNSUPPORTED_OP, in->op, 0);
        }
    }
}
