/*
 * zbc_interp.c -- ZBC bytecode dispatch loop (walking skeleton).
 *
 * Mirrors the Python oracle's procedural + WAIT/RET semantics (be.bc.interp):
 * registers are unsigned 64-bit bit patterns (C wraps them for free); BR/BRZ
 * targets are code-relative instruction indices within the coro; WAIT uses the
 * same suspend/resume protocol as a compiled coroutine (save pc -> wait -> return
 * leaf). Orchestration beyond WAIT/YIELD, fields, and the const pool land later.
 */
#include <math.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "zbc_interp.h"
#include "zbc_events.h"
#include "zbc_ops.h"
#include "zbc_solver.h"
#include "zbc_rng.h"

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
static uint64_t fork_seed(uint64_t parent_state, uint64_t index) {
    return lcg_next(parent_state ^ ((uint64_t)index * ZBC_FORK_MIX));
}

typedef struct interp_locals_s {
    const zbc_image_t *img;
    const zbc_coro    *coro;
    zbc_result_t      *result;    /* the root's: its final status and retval (NULL below it) */
    zbc_result_t      *run;       /* the run's result, shared by every frame: first error wins */
    zbc_obj_t         *obj;       /* active action object (NULL if none) */
    uint32_t           base;      /* P1-D1: the object slot this frame's field 0 is */
    uint32_t           cbase;     /* component object slot of its instance */
    /* P4.10c4: the activation this frame runs in (NULL: none), its node,
     * and its component instance (0xFFFFFFFF: the host's cbase). A node's
     * child runs in this instance + the child node's comp_rel. */
    const zbc_act     *act;
    uint32_t           node;
    uint32_t           comp;
    struct zbc_actrun_s *ar;      /* P4.10d: act's run state (NULL: none) */
    int                is_node;   /* P4.10d3: runs a node (root or a traversal) */
    int                is_entry;  /* the run's root frame (host pins apply, F2.3b) */
    uint32_t           pc;
    uint32_t           resume_pc; /* pc this run of the frame started at (SPIN progress test) */
    uint64_t           steps;     /* remaining step budget (frame-resident) */
    int                resuming_call;  /* re-entered from a blocking INVOKE */
    int                invoke_yield;   /* that INVOKE's caller yields once on return */
    int                call_ret_reg;   /* register to receive the callee's rval (-1 = none) */
    int                sync_call;      /* a CALL's callee is running on this C stack */
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
    /* Keyed seeds (host->seed_stream 0): the seed this frame was created with,
     * and how many children of each seed key it has forked (key_n pairs). */
    uint64_t               origin;
    uint64_t              *key_cnt;    /* [2*i] key, [2*i+1] count; malloc'd */
    uint32_t               key_n, key_cap;
    /* CALL (B-D5): arguments staged for the next call, this frame's own, and
     * its call depth. */
    uint32_t               depth;
    uint64_t               staged[ZBC_CALL_MAX_ARGS];
    uint64_t               call_args[ZBC_CALL_MAX_ARGS];
    uint32_t               n_staged;   /* ARGs staged since the last CALL */
    /* F6.4a: what the last CALL's callee staged before its RET (LD_RES), and
     * whether this frame is a CALL's callee (its RET hands them back). */
    uint64_t               results[ZBC_CALL_MAX_ARGS];
    int                    called;
    /* Procedural randomize (F3.7c): inputs SOLVE_PIN staged for the next
     * SOLVE, and the last procedural SOLVE's values for SOLVE_GET. */
    uint32_t               n_pins;
    uint32_t               pin_var[ZBC_SOLVE_MAX_INPUTS];
    int64_t                pin_val[ZBC_SOLVE_MAX_INPUTS];
    uint32_t               n_solved;   /* 0: no procedural SOLVE yet */
    uint64_t               solved[ZBC_SOLVE_MAX_VARS];
    /* Events (P4.4c): this frame's id (the Python VM's Frame.id) and a pc
     * whose stmt events are already out (an IMPORT re-run after its answer). */
    uint32_t               ev_id;
    uint32_t               ev_skip_pc;
    /* F5.4a: the executor (EXEC row; 0xFFFFFFFF: none) this frame's
     * requests carry; set by EXEC_SET, inherited from the parent frame. */
    uint32_t               executor;
    /* Debugging (P4.5a): this frame's id, and the pc whose debug check is
     * done (a re-entry there -- resume, IMPORT answer, wait -- skips it). */
    uint32_t               dbg_id;
    uint32_t               dbg_pass_pc;
    /* P4.5b: this frame in zbc_dbg_t.frames, the live frames list. */
    zsp_frame_t           *dbg_frame;
    struct interp_locals_s *dbg_next, *dbg_prev;
    int                    dbg_listed;
    /* P4.5b2: an error stopped here (1; status/op kept), or already shown (2). */
    int                    dbg_err;
    int                    dbg_err_status, dbg_err_op;
    /* The register and local files, sized for the coroutine (verify_coro). */
    uint32_t           nregs, nlocals;
    uint64_t          *regs;
    uint64_t          *locals;
    uint64_t           slots[];
} interp_locals_t;

/* The seed of a child coroutine `target` this frame starts (SPAWN, INVOKE,
 * SELECT branch). By position: fork_seed(seed_state, child_index++). Keyed
 * (host->seed_stream 0, F3.9; be-bc determinism.keyed_index): from the frame's
 * creation seed by the child's seed key and how many children with that key
 * it forked before, so adding an unrelated traversal moves no other seed. */
static uint64_t child_seed(interp_locals_t *L, uint32_t target) {
    if ((L->host && L->host->seed_stream) || !L->img->seed_keys)
        return fork_seed(L->seed_state, L->child_index++);
    uint64_t key = L->img->seed_keys[target], n = 0;
    uint32_t i = 0;
    while (i < L->key_n && L->key_cnt[2 * i] != key) i++;
    if (i == L->key_n) {
        if (L->key_n == L->key_cap) {
            uint32_t cap = L->key_cap ? 2 * L->key_cap : 4;
            uint64_t *kc = (uint64_t *)realloc(L->key_cnt, 16u * cap);
            if (!kc) return fork_seed(L->seed_state, L->child_index++);
            L->key_cnt = kc;
            L->key_cap = cap;
        }
        L->key_cnt[2 * i] = key;
        L->key_cnt[2 * i + 1] = 0;
        L->key_n++;
    }
    n = L->key_cnt[2 * i + 1]++;
    return fork_seed(L->origin, lcg_next(key ^ ((n + 1) * ZBC_LCG_MUL)));
}

/* The events sink of L's run and L's coroutine's mask, or 0. */
static inline uint32_t ev_mask(const interp_locals_t *L) {
    return L->host ? zbc_ev_mask(L->host->events, (uint32_t)(L->coro - L->img->coros)) : 0;
}

static void ev_fn(zbc_ev_sink_t *s, const zbc_image_t *img, const zbc_coro *c) {
    const char *nm = zbc_image_str(img, c->name);
    zbc_ev_key(s, "fn");
    zbc_ev_str(s, nm ? nm : "", nm ? strlen(nm) : 0);
}

/* `return` of a called frame (has_rv: RET with a value). */
static void ev_return(interp_locals_t *L, int has_rv, uint64_t rv) {
    zbc_ev_sink_t *s = L->host->events;
    zbc_ev_begin(s, "return", L->ev_id, L->coro->src_ref);
    zbc_ev_map(s, has_rv ? 3 : 2);
    zbc_ev_key(s, "depth");
    zbc_ev_uint(s, L->depth);
    ev_fn(s, L->img, L->coro);
    if (has_rv) {
        zbc_ev_key(s, "retval");
        zbc_ev_uint(s, rv);
    }
    zbc_ev_end(s);
}

/* `message` (severity 0 info, 1 error, 2 fatal) at L's pc. */
static void ev_message(interp_locals_t *L, int sev, uint64_t lvl, const char *txt, int n) {
    zbc_ev_sink_t *s = L->host->events;
    zbc_ev_begin(s, "message", L->ev_id, L->img->code[L->coro->code_start + L->pc].src_ref);
    zbc_ev_map(s, sev == 1 ? 2 : 3);
    if (sev == 0) { zbc_ev_key(s, "level"); zbc_ev_uint(s, lvl); }
    zbc_ev_key(s, "severity");
    zbc_ev_str(s, sev == 0 ? "info" : sev == 1 ? "error" : "fatal", sev == 0 ? 4 : 5);
    if (sev == 2) { zbc_ev_key(s, "status"); zbc_ev_uint(s, lvl); }
    zbc_ev_key(s, "text");
    zbc_ev_str(s, txt, (size_t)n);
    zbc_ev_end(s);
}

/* `access` of the memory builtin at L's pc, once it is answered; the REG
 * table names the register (root instance only, as pssvm_host does). */
static void ev_access(interp_locals_t *L, int is_write, uint32_t nbytes,
                      uint64_t addr, uint64_t data) {
    zbc_ev_sink_t *s = L->host->events;
    uint32_t gpc = L->coro->code_start + L->pc;
    const zbc_regent *re = zbc_image_reg_at(L->img, gpc);
    int has_reg = re && re->inst != 0xFFFFFFFFu;
    int disc = has_reg && !is_write && (re->flags & ZBC_REG_F_DISCARD);
    zbc_ev_begin(s, "access", L->ev_id, L->img->code[gpc].src_ref);
    zbc_ev_map(s, 4u + (uint32_t)has_reg + (uint32_t)disc);
    zbc_ev_key(s, "rw");
    zbc_ev_str(s, is_write ? "w" : "r", 1);
    zbc_ev_key(s, "width");
    zbc_ev_uint(s, 8u * nbytes);
    zbc_ev_key(s, "addr");
    zbc_ev_uint(s, addr);
    zbc_ev_key(s, "data");
    zbc_ev_uint(s, data);
    if (has_reg) { zbc_ev_key(s, "reg_id"); zbc_ev_uint(s, re->inst); }
    if (disc) { zbc_ev_key(s, "discarded"); zbc_ev_bool(s, 1); }
    zbc_ev_end(s);
}

/* `import` of a user import at L's pc, once it is answered. Its name is the
 * image's IMPORT entry (null: none); whether it was mocked is the host's. */
static void ev_import(interp_locals_t *L, uint32_t fn_id, const uint64_t *argv,
                      uint32_t nval, int blocking, int has_ret, uint64_t ret) {
    zbc_ev_sink_t *s = L->host->events;
    zbc_ev_begin(s, "import", L->ev_id, L->img->code[L->coro->code_start + L->pc].src_ref);
    zbc_ev_map(s, has_ret ? 6 : 5);
    zbc_ev_key(s, "name");
    {
        const char *nm = zbc_image_import_name(L->img, fn_id);
        if (nm) zbc_ev_str(s, nm, strlen(nm)); else zbc_ev_null(s);
    }
    zbc_ev_key(s, "fn_id");
    zbc_ev_uint(s, fn_id);
    zbc_ev_key(s, "args");
    zbc_ev_list(s, nval);
    for (uint32_t i = 0; i < nval; i++) zbc_ev_uint(s, argv[i]);
    zbc_ev_key(s, "blocking");
    zbc_ev_bool(s, blocking);
    zbc_ev_key(s, "mocked");
    zbc_ev_bool(s, 0);
    if (has_ret) { zbc_ev_key(s, "ret"); zbc_ev_uint(s, ret); }
    zbc_ev_end(s);
}

/* One-time operand verifier: reject a coro whose register/local/branch operands
 * fall outside the fixed frame before executing a single instruction. This keeps
 * the dispatch loop free of per-access bounds checks and makes a malformed image
 * a clean error rather than memory corruption. Returns ZBC_OK or a negative err. */
static int verify_coro(const zbc_instr *code, uint32_t n,
                       uint32_t *nregs, uint32_t *nlocals) {
    uint32_t nr = ZBC_MIN_REGS, nl = ZBC_MIN_LOCALS;
#define USE_R(r) do { if ((r) < ZBC_MAX_REGS && (r) + 1 > nr) nr = (r) + 1; } while (0)
    for (uint32_t i = 0; i < n; i++) {
        const zbc_instr *in = &code[i];
        uint32_t a0 = in->arg0, a1 = in->arg1, a2 = in->arg2;
        /* Count every operand the switch below checks as a register/local. */
        switch (in->op) {
        case ZBC_OP_CONST: case ZBC_OP_LD_FIELD: case ZBC_OP_ST_FIELD:
        case ZBC_OP_LD_COMP: case ZBC_OP_ST_COMP: case ZBC_OP_BRZ:
        case ZBC_OP_ARG: case ZBC_OP_LD_ARG: case ZBC_OP_LD_RES:
            USE_R(a0); break;
        case ZBC_OP_WAIT: case ZBC_OP_RET:
            if (in->nargs > 0) USE_R(a0);
            break;
        case ZBC_OP_MOV: case ZBC_OP_NEG: case ZBC_OP_NOT: case ZBC_OP_FCVT:
            USE_R(a0); USE_R(a1); break;
        case ZBC_OP_LD_LOCAL: case ZBC_OP_ST_LOCAL:
            USE_R(a0);
            if (a1 < ZBC_MAX_LOCALS && a1 + 1 > nl) nl = a1 + 1;
            break;
        case ZBC_OP_ADD: case ZBC_OP_SUB: case ZBC_OP_MUL: case ZBC_OP_DIV:
        case ZBC_OP_MOD: case ZBC_OP_AND: case ZBC_OP_OR:  case ZBC_OP_XOR:
        case ZBC_OP_SHL: case ZBC_OP_SHR:
        case ZBC_OP_CMP_EQ: case ZBC_OP_CMP_NE: case ZBC_OP_CMP_LT:
        case ZBC_OP_CMP_LE: case ZBC_OP_CMP_GT: case ZBC_OP_CMP_GE:
        case ZBC_OP_FARITH: case ZBC_OP_FCMP: case ZBC_OP_FMATH:
            USE_R(a0); USE_R(a1); USE_R(a2); break;
        case ZBC_OP_CALL:
            if (a1 != 0xFFFFFFFFu) USE_R(a1);
            break;
        case ZBC_OP_SOLVE_PIN:
            USE_R(a1); break;
        case ZBC_OP_SOLVE_GET:
        case ZBC_OP_EXEC_GET:
            USE_R(a0); break;
        case ZBC_OP_INVOKE:
            if (in->flags & ZBC_F_HAS_RET) USE_R(a1);
            break;
        case ZBC_OP_IMPORT:
            if ((in->flags & ZBC_F_HAS_RET) && a1 != 0xFFFFFFFFu) USE_R(a1);
            if (in->nargs > 2) USE_R(a2);
            if (in->nargs > 3) USE_R(in->arg3);
            break;
        default:
            break;
        }
        switch (in->op) {
        /* arg0 is a register only when present (WAIT/RET may take none). */
        case ZBC_OP_CONST:
            if (a0 >= ZBC_MAX_REGS) return ZBC_ERR_OOB_REG;
            break;
        case ZBC_OP_WAIT: case ZBC_OP_RET:
            if (in->nargs > 0 && a0 >= ZBC_MAX_REGS) return ZBC_ERR_OOB_REG;
            break;
        case ZBC_OP_MOV: case ZBC_OP_NEG: case ZBC_OP_NOT: case ZBC_OP_FCVT:
            if (a0 >= ZBC_MAX_REGS || a1 >= ZBC_MAX_REGS) return ZBC_ERR_OOB_REG;
            break;
        case ZBC_OP_LD_LOCAL: case ZBC_OP_ST_LOCAL:
            if (a0 >= ZBC_MAX_REGS) return ZBC_ERR_OOB_REG;
            if (a1 >= ZBC_MAX_LOCALS) return ZBC_ERR_OOB_LOCAL;
            break;
        case ZBC_OP_LD_FIELD: case ZBC_OP_ST_FIELD:
        case ZBC_OP_LD_COMP:  case ZBC_OP_ST_COMP:
            /* a1 (field slot) is checked at runtime against the live object. */
            if (a0 >= ZBC_MAX_REGS) return ZBC_ERR_OOB_REG;
            break;
        case ZBC_OP_ADD: case ZBC_OP_SUB: case ZBC_OP_MUL: case ZBC_OP_DIV:
        case ZBC_OP_MOD: case ZBC_OP_AND: case ZBC_OP_OR:  case ZBC_OP_XOR:
        case ZBC_OP_SHL: case ZBC_OP_SHR:
        case ZBC_OP_CMP_EQ: case ZBC_OP_CMP_NE: case ZBC_OP_CMP_LT:
        case ZBC_OP_CMP_LE: case ZBC_OP_CMP_GT: case ZBC_OP_CMP_GE:
        case ZBC_OP_FARITH: case ZBC_OP_FCMP: case ZBC_OP_FMATH:
            if (a0 >= ZBC_MAX_REGS || a1 >= ZBC_MAX_REGS || a2 >= ZBC_MAX_REGS)
                return ZBC_ERR_OOB_REG;
            break;
        /* A branch to n leaves the coro (falls off its end), as the
         * oracle's ``while frame.pc < n`` does. */
        case ZBC_OP_BR:
            if (a0 > n) return ZBC_ERR_BAD_TARGET;
            break;
        case ZBC_OP_BRZ:
            if (a0 >= ZBC_MAX_REGS) return ZBC_ERR_OOB_REG;
            if (a1 > n) return ZBC_ERR_BAD_TARGET;
            break;
        case ZBC_OP_ARG: case ZBC_OP_LD_ARG: case ZBC_OP_LD_RES:
            if (a0 >= ZBC_MAX_REGS) return ZBC_ERR_OOB_REG;
            if (a1 >= ZBC_CALL_MAX_ARGS) return ZBC_ERR_OOB_LOCAL;
            break;
        case ZBC_OP_CALL:
            /* arg0 is a coro index (runtime-checked); arg1 the result reg. */
            if (a1 != 0xFFFFFFFFu && a1 >= ZBC_MAX_REGS) return ZBC_ERR_OOB_REG;
            break;
        case ZBC_OP_SOLVE_PIN:
            if (a1 >= ZBC_MAX_REGS) return ZBC_ERR_OOB_REG;
            break;
        case ZBC_OP_SOLVE_GET:
        case ZBC_OP_EXEC_GET:
            if (a0 >= ZBC_MAX_REGS) return ZBC_ERR_OOB_REG;
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
            /* imm bits 0-7 = n > 0: the n arguments were staged by ARG
             * (F6.5b); bits 8-15: the struct result's leaves (F6.4b2). */
            if ((in->imm & 0xFF) > ZBC_IMPORT_MAX_ARGS
                    || ((in->imm >> 8) & 0xFF) > ZBC_CALL_MAX_ARGS
                    || (in->imm >> 16) != 0) return ZBC_ERR_OOB_LOCAL;
            break;
        default:
            break;   /* NOP, YIELD, and (as-yet) unsupported ops: no operands to check here */
        }
    }
#undef USE_R
    *nregs = nr;
    *nlocals = nl;
    if (sizeof(interp_locals_t) + 8u * ((size_t)nr + nl) > ZBC_MAX_FRAME_BYTES)
        return ZBC_ERR_OOB_REG;
    return ZBC_OK;
}

/* Stop `thread` at L's pc (frame `f`) for `reason`: fill the stop record
 * (no hits, no access, no error), post STOP on `yield` and block the thread
 * (`yield` must be NONE). Resuming unblocks it. */
static zbc_dbg_stop_t *dbg_post_stop(zsp_thread_t *thread, zsp_frame_t *f,
                                     interp_locals_t *L, int reason, uint32_t src_ref) {
    zbc_dbg_t *d = L->host->dbg;
    zbc_yield_t *y = L->host->yield;
    zbc_dbg_stop_t *s = &d->stop;
    uint32_t depth = 0;
    for (zsp_frame_t *g = thread->leaf; g; g = g->prev) depth++;
    zsp_frame_t *bottom = thread->leaf;
    while (bottom->prev) bottom = bottom->prev;
    d->step_kind = 0;
    d->step_thread = NULL;
    d->step_thread_done = 0;
    memset(s, 0, sizeof(*s));
    s->reason = (uint32_t)reason;
    s->thread_id = zsp_frame_locals(bottom, interp_locals_t)->dbg_id;
    s->frame_id = L->dbg_id;
    s->coro = (uint32_t)(L->coro - L->img->coros);
    s->pc = L->pc;
    s->src_ref = src_ref ? src_ref : 0xFFFFFFFFu;
    s->depth = depth;
    s->thread = thread;
    s->frame = f;
    y->state = ZBC_YIELD_STOP;
    y->thread = thread;
    y->frame = L;
    thread->flags |= ZSP_THREAD_FLAGS_BLOCKED;
    return s;
}

/* P4.5a: the debug check before L's instruction at L->pc (be-bc debug.py
 * Stub._before). 1: the thread stops here (state STOP, blocked) or waits
 * behind another request; the caller returns `ret`. 0: run the instruction. */
static int dbg_check(zsp_thread_t *thread, zsp_frame_t *ret, interp_locals_t *L,
                     int reentry) {
    zbc_dbg_t *d = L->host->dbg;
    zbc_yield_t *y = L->host->yield;
    uint32_t pc = L->pc;
    if (y == NULL || (reentry && pc == L->dbg_pass_pc)) return 0;
    uint32_t coro = (uint32_t)(L->coro - L->img->coros);
    uint32_t hits[ZBC_DBG_MAX_HITS], nh = 0, ns = 0, depth = 0;
    for (uint32_t i = 0; i < d->n_breaks; i++) {
        if (d->breaks[i].coro == coro && d->breaks[i].pc == pc && nh < ZBC_DBG_MAX_HITS)
            hits[nh++] = d->breaks[i].id;
    }
    for (zsp_frame_t *f = thread->leaf; f; f = f->prev) depth++;
    const zbc_lineent *st = zbc_image_stmts_at(L->img, L->coro->code_start + pc, &ns);
    int reason = 0;
    if (d->pend.n_hits) {
        reason = ZBC_DBG_WATCH;
    } else if (d->pause) {
        reason = ZBC_DBG_PAUSE;
    } else if (nh) {
        reason = ZBC_DBG_BREAK;
    } else if (d->step_kind && ns) {
        if (d->step_thread_done) {
            reason = ZBC_DBG_STEP;
        } else if (d->step_thread == (void *)thread) {
            if (d->step_kind == ZBC_DBG_STEP_INTO
                    || (d->step_kind == ZBC_DBG_STEP_STMT && depth <= d->step_depth)
                    || (d->step_kind == ZBC_DBG_STEP_OUT && depth < d->step_depth))
                reason = ZBC_DBG_STEP;
        }
    }
    if (!reason) {
        L->dbg_pass_pc = pc;
        return 0;
    }
    if (y->state != ZBC_YIELD_NONE) {
        /* Another thread's request (or stop) is open: check again after it. */
        zsp_timebase_yield(thread);
        return 1;
    }
    if (reason == ZBC_DBG_PAUSE) d->pause = 0;
    uint32_t sr = ns ? st[0].src_ref
                : zbc_image_src_ref(L->img, coro, L->coro->code_start + pc);
    zbc_dbg_stop_t *s = dbg_post_stop(thread, ret, L, reason, sr);
    if (reason == ZBC_DBG_WATCH) {
        /* Where the watched access was, and what it did. */
        s->src_ref = d->pend.src_ref;
        s->n_hits = d->pend.n_hits;
        for (uint32_t i = 0; i < s->n_hits; i++) s->hits[i] = d->pend.hits[i];
        s->is_write = d->pend.is_write;
        s->size = d->pend.size;
        s->addr = d->pend.addr;
        s->data = d->pend.data;
        d->pend.n_hits = 0;
    } else if (reason == ZBC_DBG_BREAK) {
        s->n_hits = nh;
        for (uint32_t i = 0; i < nh; i++) s->hits[i] = hits[i];
    }
    L->dbg_pass_pc = pc;   /* resumed, it runs this instruction */
    return 1;
}

/* P4.5b2: an access (done; `data` written or read) that a watch covers
 * leaves a pending WATCH stop (the first one wins until it is shown). */
static void dbg_access(interp_locals_t *L, int is_write, uint32_t size,
                       uint64_t addr, uint64_t data) {
    zbc_dbg_t *d = L->host->dbg;
    if (d->pend.n_hits) return;
    uint32_t n = 0;
    for (uint32_t i = 0; i < d->n_watches && n < ZBC_DBG_MAX_HITS; i++) {
        const zbc_dbg_watch_t *w = &d->watches[i];
        if (w->addr < addr + size && addr < w->addr + w->size
                && (w->rw & (is_write ? 2u : 1u))
                && (!w->has_value || (data & w->mask) == (w->value & w->mask)))
            d->pend.hits[n++] = w->id;
    }
    if (n == 0) return;
    uint32_t coro = (uint32_t)(L->coro - L->img->coros);
    uint32_t sr = zbc_image_src_ref(L->img, coro, L->coro->code_start + L->pc);
    d->pend.src_ref = sr ? sr : 0xFFFFFFFFu;
    d->pend.is_write = (uint32_t)is_write;
    d->pend.size = size;
    d->pend.addr = addr;
    d->pend.data = data;
    d->pend.n_hits = n;
}

/* P4.5b: the live frames list, for inspection while stopped. */
static void dbg_link(zbc_dbg_t *d, interp_locals_t *L, zsp_frame_t *f) {
    L->dbg_frame = f;
    L->dbg_prev = NULL;
    L->dbg_next = (interp_locals_t *)d->frames;
    if (L->dbg_next) L->dbg_next->dbg_prev = L;
    d->frames = L;
    L->dbg_listed = 1;
}

static void dbg_unlink(zbc_dbg_t *d, interp_locals_t *L) {
    if (!L->dbg_listed) return;
    if (L->dbg_prev) L->dbg_prev->dbg_next = L->dbg_next;
    else d->frames = L->dbg_next;
    if (L->dbg_next) L->dbg_next->dbg_prev = L->dbg_prev;
    L->dbg_listed = 0;
}

/* A cancelled thread is dropped without halting: unlist its frames. */
static void dbg_unlink_thread(zbc_dbg_t *d, zsp_thread_t *t) {
    for (zsp_frame_t *f = t->leaf; f; f = f->prev) {
        if (f->func == &zbc_interp_task) dbg_unlink(d, zsp_frame_locals(f, interp_locals_t));
    }
}

/* A thread's bottom interpreter frame (its id is the thread's). */
static zsp_frame_t *dbg_bottom(zsp_thread_t *t) {
    zsp_frame_t *b = NULL;
    for (zsp_frame_t *f = t->leaf; f; f = f->prev) {
        if (f->func == &zbc_interp_task) b = f;
    }
    return b;
}

static int dbg_is_bottom(const interp_locals_t *L) {
    for (zsp_frame_t *f = L->dbg_frame->prev; f; f = f->prev) {
        if (f->func == &zbc_interp_task) return 0;
    }
    return 1;
}

static void dbg_fill(const zbc_dbg_t *d, const interp_locals_t *L, zbc_dbg_frame_t *o) {
    zsp_thread_t *t = L->self_thread;
    o->id = L->dbg_id;
    o->thread_id = zsp_frame_locals(dbg_bottom(t), interp_locals_t)->dbg_id;
    o->coro = (uint32_t)(L->coro - L->img->coros);
    o->pc = L->pc;
    o->depth = 0;
    for (zsp_frame_t *f = L->dbg_frame; f; f = f->prev) {
        if (f->func == &zbc_interp_task) o->depth++;
    }
    o->call_depth = L->depth;
    o->state = ZBC_DBG_WAITING;
    if ((void *)t == d->stop.thread) {
        o->state = ZBC_DBG_RUNNING;
    } else {
        for (zsp_thread_t *r = t->timebase->ready_head; r; r = r->next) {
            if (r == t) { o->state = ZBC_DBG_READY; break; }
        }
    }
    o->base = L->base;
    o->regs = L->regs;
    o->locals = L->locals;
    o->nregs = L->nregs;
    o->nlocals = L->nlocals;
    o->args = L->call_args;
    o->frame = L->dbg_frame;
    o->thread = t;
}

uint32_t zbc_dbg_thread_id(const zbc_dbg_t *d, const void *thread) {
    if (d == NULL) return 0;
    for (const interp_locals_t *L = (const interp_locals_t *)d->frames; L; L = L->dbg_next)
        if (dbg_is_bottom(L) && (const void *)L->self_thread == thread) return L->dbg_id;
    return 0;
}

uint32_t zbc_dbg_threads(const zbc_dbg_t *d, uint32_t *ids, uint32_t cap) {
    uint32_t n = 0;
    for (const interp_locals_t *L = (const interp_locals_t *)d->frames; L; L = L->dbg_next) {
        if (!dbg_is_bottom(L) || (L->self_thread->flags & ZSP_THREAD_FLAGS_CANCELLED)) continue;
        if (n < cap) {
            /* insertion sort: ascending ids */
            uint32_t i = n;
            while (i > 0 && ids[i - 1] > L->dbg_id) { ids[i] = ids[i - 1]; i--; }
            ids[i] = L->dbg_id;
        }
        n++;
    }
    return n;
}

int zbc_dbg_frame(const zbc_dbg_t *d, uint32_t frame_id, zbc_dbg_frame_t *out) {
    for (const interp_locals_t *L = (const interp_locals_t *)d->frames; L; L = L->dbg_next) {
        if (L->dbg_id == frame_id) {
            dbg_fill(d, L, out);
            return 1;
        }
    }
    return 0;
}

uint32_t zbc_dbg_frames(const zbc_dbg_t *d, uint32_t thread_id, zbc_dbg_frame_t *out,
                        uint32_t cap) {
    const interp_locals_t *B = NULL;
    for (const interp_locals_t *L = (const interp_locals_t *)d->frames; L; L = L->dbg_next) {
        if (L->dbg_id == thread_id && dbg_is_bottom(L)) { B = L; break; }
    }
    if (B == NULL) return 0;
    uint32_t n = 0;
    for (zsp_frame_t *f = B->self_thread->leaf; f; f = f->prev) {
        if (f->func != &zbc_interp_task) continue;
        if (n < cap) dbg_fill(d, zsp_frame_locals(f, interp_locals_t), &out[n]);
        n++;
    }
    return n;
}

#define ACT_NONE 0xFFFFFFFFu
/* Set in the node a caller passes a frame that runs a traversal (pyvm
 * Frame.is_node): its exit makes its state outputs current (P4.10d3). */
#define ACT_NODE_FRAME 0x40000000u
/* zbc_actscope.kind (ScopeKind order) */
#define ACT_KIND_PARALLEL 2u
#define ACT_KIND_SCHEDULE 3u
#define ACT_KIND_SELECT_BRANCH 5u   /* .. IF_THEN, IF_ELSE, MATCH_CASE, */
#define ACT_KIND_LOOP_BODY 9u       /* LOOP_BODY: the committing kinds */

/* The run state of one activation (P4.10d), as pyvm's Activation: per node
 * committed / started / the site it was traversed through, per site fired,
 * per scope entered and when, and per cone its last solution (witness:
 * valid, the constraints then in force, the values). Made by the root
 * frame, shared by its descendants (refs), freed by the last to end. The
 * derived lists of pyvm's ActivationTable (subtree, node_sites,
 * scope_sites, scope_nested) are walked from the ACT parent links instead. */
typedef struct zbc_actrun_s {
    uint32_t  refs;
    uint32_t  clock;
    uint32_t  con_lo, var_lo;   /* first section-global con / var of the cones */
    uint8_t  *committed, *started, *fired, *entered;
    uint32_t *by_site, *entered_at;
    uint32_t *site_of;          /* per node: the site of its running traversal */
    uint8_t  *wit_taken;        /* per node: took its values from its cone's witness */
    uint8_t  *wit_free;         /* per var - var_lo: unpinned in the witness solve */
    uint8_t  *wit_valid;        /* per cone */
    uint8_t  *wit_en;           /* per con - con_lo */
    uint64_t *wit_val;          /* per var - var_lo */
    /* pyvm outputs (d4): each buffer object a completed node output, with
     * its pool, consumer count, its place among its pool's objects of that
     * count (pyvm's per-count lists), and its values (bval[val0..+nval]). */
    struct act_bobj_s { uint32_t pid, cons, pos, val0, nval; } *bobj;
    uint32_t  n_bobj, cap_bobj, n_bval, cap_bval;
    uint64_t *bval;
    /* pyvm claims (P4.10e1): the claims held now (held) and, per (pool,
     * node, site, instance, lock), the latest released one (pyvm's holds,
     * held_by and released in one list). */
    struct act_claim_s { uint32_t pid, node, site, iid, lock, at, held; } *cl;
    uint32_t  n_cl, cap_cl;
    /* pyvm ActivationTable.par and Activation.footprint (P4.10e2): per
     * scope, a parallel's branches (scope id, or a site | high bit, as
     * act_below_on_chain), the pools two of them lock (shared), and the
     * footprint chosen at its entry `at` (fp[branch * n_pools + pool]: the
     * instances the branch may lock). has_par: some parallel shares one. */
    struct act_par_s { uint32_t nbr, n_shared, at; uint32_t *key; uint8_t *shared;
                       uint64_t *fp; } *par;
    uint32_t  n_par;
    uint8_t   has_par;
    /* pyvm Activation.attr_held / attr_claimed (F8.6e): the slots of
     * resource attributes (actvar flag 16) a solve chose and holds, and
     * those a claim has fixed. */
    struct act_slots_s { uint32_t *s; uint32_t n, cap; } attr_held, attr_claimed;
} zbc_actrun_t;

static int act_slots_has(const struct act_slots_s *x, uint32_t slot) {
    for (uint32_t i = 0; i < x->n; i++)
        if (x->s[i] == slot) return 1;
    return 0;
}

static int act_slots_add(struct act_slots_s *x, uint32_t slot) {
    if (act_slots_has(x, slot)) return ZBC_OK;
    if (x->n == x->cap) {
        uint32_t cap = x->cap ? 2 * x->cap : 8;
        void *p = realloc(x->s, cap * sizeof(*x->s));
        if (!p) return ZBC_ERR_SOLVE_FAIL;
        x->s = p; x->cap = cap;
    }
    x->s[x->n++] = slot;
    return ZBC_OK;
}

static void act_par_build(const zbc_image_t *img, const zbc_act *a, zbc_actrun_t *r);

static zbc_actrun_t *actrun_new(const zbc_image_t *img, const zbc_act *a) {
    uint32_t nn = a->n_nodes, ns = a->n_sites, nc = a->n_scopes;
    uint32_t clo = 0xFFFFFFFFu, chi = 0, vlo = 0xFFFFFFFFu, vhi = 0;
    for (uint32_t i = 0; i < a->n_cones; i++) {
        const zbc_actcone *c = zbc_act_cone(img, a, i);
        if (c->n_cons && c->con0 < clo) clo = c->con0;
        if (c->n_cons && c->con0 + c->n_cons > chi) chi = c->con0 + c->n_cons;
        if (c->n_vars && c->var0 < vlo) vlo = c->var0;
        if (c->n_vars && c->var0 + c->n_vars > vhi) vhi = c->var0 + c->n_vars;
    }
    uint32_t ncon = chi > clo ? chi - clo : 0, nvar = vhi > vlo ? vhi - vlo : 0;
    size_t sz = sizeof(zbc_actrun_t) + 8u * (size_t)nvar + 4u * (2u * (size_t)nn + nc)
        + 3u * nn + ns + nc + a->n_cones + ncon + nvar;
    zbc_actrun_t *r = (zbc_actrun_t *)calloc(1, sz);
    if (!r) return NULL;
    uint8_t *p = (uint8_t *)(r + 1);
    r->wit_val = (uint64_t *)p;    p += 8u * (size_t)nvar;
    r->by_site = (uint32_t *)p;    p += 4u * (size_t)nn;
    r->entered_at = (uint32_t *)p; p += 4u * (size_t)nc;
    r->site_of = (uint32_t *)p;    p += 4u * (size_t)nn;
    r->wit_taken = p; p += nn;
    r->wit_free = p;  p += nvar;
    r->committed = p; p += nn;
    r->started = p;   p += nn;
    r->fired = p;     p += ns;
    r->entered = p;   p += nc;
    r->wit_valid = p; p += a->n_cones;
    r->wit_en = p;
    r->con_lo = clo; r->var_lo = vlo;
    for (uint32_t i = 0; i < nn; i++) r->by_site[i] = r->site_of[i] = ACT_NONE;
    r->refs = 1;
    r->par = (struct act_par_s *)calloc(nc + 1, sizeof(*r->par));
    if (!r->par) { free(r); return NULL; }
    r->n_par = nc;
    act_par_build(img, a, r);
    return r;
}

static void actrun_release(zbc_actrun_t *r) {
    if (r && --r->refs == 0) {
        for (uint32_t i = 0; i < r->n_par; i++) {
            free(r->par[i].key); free(r->par[i].shared); free(r->par[i].fp);
        }
        free(r->par);
        free(r->bobj); free(r->bval); free(r->cl);
        free(r->attr_held.s); free(r->attr_claimed.s); free(r);
    }
}

/* Node `d` is `root` or below it. */
static int act_below(const zbc_image_t *img, const zbc_act *a, uint32_t root, uint32_t d) {
    for (uint32_t i = 0; d != ACT_NONE && i <= a->n_nodes; i++) {
        if (d == root) return 1;
        d = zbc_act_node(img, a, d)->parent;
    }
    return 0;
}

/* Scope `sid` is a block nested in scope `p` of the same node (pyvm's
 * scope_nested[p]). */
static int act_nested(const zbc_image_t *img, const zbc_act *a, uint32_t p, uint32_t sid) {
    uint32_t node = zbc_act_scope(img, a, sid)->node;
    uint32_t q = zbc_act_scope(img, a, sid)->parent;
    for (uint32_t i = 0; q != ACT_NONE && i <= a->n_scopes; i++) {
        const zbc_actscope *qs = zbc_act_scope(img, a, q);
        if (qs->node != node) return 0;
        if (q == p) return 1;
        q = qs->parent;
    }
    return 0;
}

/* pyvm Activation._reset_node: `node` and its subtree hold no values, none
 * of their traversals has run, no block of theirs was entered. */
static void act_reset_node(const zbc_image_t *img, const zbc_act *a, zbc_actrun_t *r,
                           uint32_t node) {
    for (uint32_t d = 0; d < a->n_nodes; d++) {
        if (!act_below(img, a, node, d)) continue;
        r->committed[d] = 0; r->started[d] = 0; r->by_site[d] = ACT_NONE;
    }
    for (uint32_t s = 0; s < a->n_sites; s++)
        if (act_below(img, a, node, zbc_act_site(img, a, s)->owner)) r->fired[s] = 0;
    for (uint32_t c = 0; c < a->n_scopes; c++)
        if (act_below(img, a, node, zbc_act_scope(img, a, c)->node)) r->entered[c] = 0;
}

/* pyvm Activation.enter_node: a traversal of `node` starts, through `site`
 * (ACT_NONE: the root). */
static void act_enter_node(const zbc_image_t *img, const zbc_act *a, zbc_actrun_t *r,
                           uint32_t node, uint32_t site) {
    act_reset_node(img, a, r, node);
    if (node == 0) r->attr_held.n = r->attr_claimed.n = 0;
    r->started[node] = 1;
    r->site_of[node] = site;
    if (site != ACT_NONE) r->fired[site] = 1;
}

/* pyvm Activation.enter_scope (the par footprints are P4.10e's): entry to
 * block `scope` resets what it and its nested blocks traverse. */
static void act_enter_scope(const zbc_image_t *img, const zbc_act *a, zbc_actrun_t *r,
                            uint32_t scope) {
    for (uint32_t s = 0; s < a->n_sites; s++) {
        uint32_t ss = zbc_act_site(img, a, s)->scope;
        if (ss == ACT_NONE || (ss != scope && !act_nested(img, a, scope, ss))) continue;
        r->fired[s] = 0;
        act_reset_node(img, a, r, zbc_act_site(img, a, s)->target);
    }
    for (uint32_t c = 0; c < a->n_scopes; c++)
        if (act_nested(img, a, scope, c)) r->entered[c] = 0;
    r->entered[scope] = 1;
    r->entered_at[scope] = ++r->clock;
    /* A committing scope (a branch chosen: select branch, if/else, match
     * case, loop body) frees the attributes no claim has fixed (F8.6e). */
    uint32_t k = zbc_act_scope(img, a, scope)->kind;
    if (k >= ACT_KIND_SELECT_BRANCH && k <= ACT_KIND_LOOP_BODY) {
        uint32_t m = 0;
        for (uint32_t i = 0; i < r->attr_held.n; i++)
            if (act_slots_has(&r->attr_claimed, r->attr_held.s[i]))
                r->attr_held.s[m++] = r->attr_held.s[i];
        r->attr_held.n = m;
    }
}

/* A node's first scope (pyvm's _Node.scope_base): SCOPE_ENTER's imm is
 * relative to it. ACT_NONE: the node has none. */
static uint32_t act_scope_base(const zbc_image_t *img, const zbc_act *a, uint32_t node) {
    for (uint32_t c = 0; c < a->n_scopes; c++)
        if (zbc_act_scope(img, a, c)->node == node) return c;
    return ACT_NONE;
}

/* pyvm Activation.scope_live: no block from `scope` out is one that commits
 * on entry (select branch, if/else, match case, loop body) and not entered. */
static int act_scope_live(const zbc_image_t *img, const zbc_act *a,
                          const zbc_actrun_t *r, uint32_t scope) {
    for (uint32_t i = 0; scope != ACT_NONE && i <= a->n_scopes; i++) {
        const zbc_actscope *sc = zbc_act_scope(img, a, scope);
        if (sc->kind >= 5 && sc->kind <= 9 && !r->entered[scope]) return 0;
        scope = sc->parent;
    }
    return 1;
}

/* pyvm Activation._pending_site: the first unfired live site of `node`. */
static uint32_t act_pending_site(const zbc_image_t *img, const zbc_act *a,
                                 const zbc_actrun_t *r, uint32_t node) {
    for (uint32_t s = 0; s < a->n_sites; s++) {
        const zbc_actsite *st = zbc_act_site(img, a, s);
        if (st->target == node && !r->fired[s] && act_scope_live(img, a, r, st->scope))
            return s;
    }
    return ACT_NONE;
}

static int act_node_live(const zbc_image_t *img, const zbc_act *a,
                         const zbc_actrun_t *r, uint32_t node) {
    return node == 0 || r->committed[node] || r->started[node]
        || act_pending_site(img, a, r, node) != ACT_NONE;
}

/* pyvm Activation._in_force: constraint `c` holds in the solve of `cur`
 * (traversed through `cur_site`). */
static int act_in_force(const zbc_image_t *img, const zbc_act *a, const zbc_actrun_t *r,
                        const zbc_actcon *c, uint32_t cur, uint32_t cur_site) {
    const uint32_t *ns = zbc_act_list(img, c->node0);
    for (uint32_t k = 0; k < c->n_nodes; k++)
        if (!act_node_live(img, a, r, ns[k])) return 0;   /* vacuously satisfied */
    if (!(a->flags & 1u))
        for (uint32_t k = 0; k < c->n_nodes; k++)
            if (ns[k] != cur && !r->committed[ns[k]]) return 0;   /* no lookahead */
    if (c->kind == 4) return 0;   /* INFER: this engine runs no inferred node (M9a3; M14) */
    if (c->kind == 0 || c->kind == 3) return act_node_live(img, a, r, c->owner);
    if (c->kind == 1) return act_scope_live(img, a, r, c->scope);
    const zbc_actsite *st = zbc_act_site(img, a, c->site);
    if (!act_scope_live(img, a, r, st->scope)) return 0;
    if (c->site == cur_site) return 1;
    if (r->committed[st->target] || r->started[st->target])
        return r->by_site[st->target] == c->site && st->target != cur;
    return act_pending_site(img, a, r, st->target) == c->site;
}

/* The cone (local id) node `node` is solved in, or ACT_NONE. */
static uint32_t act_cone_of(const zbc_image_t *img, const zbc_act *a, uint32_t node) {
    for (uint32_t i = 0; i < a->n_cones; i++) {
        const zbc_actcone *c = zbc_act_cone(img, a, i);
        const uint32_t *ns = zbc_act_list(img, c->node0);
        for (uint32_t k = 0; k < c->n_nodes; k++)
            if (ns[k] == node) return i;
    }
    return ACT_NONE;
}

/* pyvm _domain_value: an object slot's pattern as a value of v's domain. */
static int64_t act_domain_value(uint64_t val, const zbc_actvar *v) {
    uint32_t w = v->width ? v->width : 32;
    if (w >= 64) return (int64_t)val;
    uint64_t x = val & ((1ull << w) - 1);
    if ((v->flags & 1u) && (x >> (w - 1))) x -= 1ull << w;
    return (int64_t)x;
}

/* Below scope `sc` on site `st`'s scope chain: the scope just inside it, or
 * the site itself (high bit), as pyvm's concurrent() compares them;
 * ACT_NONE if `sc` is not on the chain. */
static uint32_t act_below_on_chain(const zbc_image_t *img, const zbc_act *a,
                                   uint32_t st, uint32_t sc) {
    uint32_t prev = 0x80000000u | st, q = zbc_act_site(img, a, st)->scope;
    for (uint32_t i = 0; q != ACT_NONE && i <= a->n_scopes; i++) {
        if (q == sc) return prev;
        prev = q;
        q = zbc_act_scope(img, a, q)->parent;
    }
    return ACT_NONE;
}

/* pyvm ActivationTable.concurrent: the parallel or schedule scope in which
 * sites `sa` and `sb` are in different branches; ACT_NONE if none. */
static uint32_t act_concurrent(const zbc_image_t *img, const zbc_act *a,
                               uint32_t sa, uint32_t sb) {
    uint32_t prev = 0x80000000u | sa, q = zbc_act_site(img, a, sa)->scope;
    for (uint32_t i = 0; q != ACT_NONE && i <= a->n_scopes; i++) {
        uint32_t bb = act_below_on_chain(img, a, sb, q);
        if (bb != ACT_NONE) {
            uint32_t k = zbc_act_scope(img, a, q)->kind;
            return ((k == ACT_KIND_PARALLEL || k == ACT_KIND_SCHEDULE) && bb != prev)
                ? q : ACT_NONE;
        }
        prev = q;
        q = zbc_act_scope(img, a, q)->parent;
    }
    return ACT_NONE;
}

/* A node of the subtree of `root` has a lock claim with pool `pid`. */
static int act_locks(const zbc_image_t *img, const zbc_act *a, uint32_t root, uint32_t pid) {
    for (uint32_t d = 0; d < a->n_nodes; d++) {
        if (!act_below(img, a, root, d)) continue;
        const zbc_actnode *n = zbc_act_node(img, a, d);
        for (uint32_t k = 0; k < n->n_claims; k++) {
            const zbc_actclaim *c = &img->actclaims[n->claim0 + k];
            const uint32_t *pr = zbc_act_list(img, c->pool0);
            for (uint32_t i = 0; c->lock && i < c->n_pools; i++)
                if (pr[2 * i + 1] == pid) return 1;
        }
    }
    return 0;
}

/* Activation `a` has a parallel two of whose branches lock the same pool
 * (pyvm ActivationTable.par non-empty): its footprints are P4.10e2's. */
int zbc_act_par_shared(const zbc_image_t *img, const zbc_act *a) {
    for (uint32_t sc = 0; sc < a->n_scopes; sc++) {
        const zbc_actscope *ps = zbc_act_scope(img, a, sc);
        if (ps->kind != ACT_KIND_PARALLEL) continue;
        for (uint32_t pid = 0; pid < a->n_pools; pid++) {
            uint32_t first = ACT_NONE;
            for (uint32_t st = 0; st < a->n_sites; st++) {
                /* Branches are the parallel's own (pyvm: scopes and sites of
                 * its node); a sub-action's activity is in its site's branch. */
                if (zbc_act_site(img, a, st)->owner != ps->node) continue;
                uint32_t key = act_below_on_chain(img, a, st, sc);
                if (key == ACT_NONE || key == first
                        || !act_locks(img, a, zbc_act_site(img, a, st)->target, pid)) continue;
                if (first != ACT_NONE) return 1;
                first = key;
            }
        }
    }
    return 0;
}

/* Site `st` is in branch `key` of a parallel: the branch's site, or a site
 * of the branch's block or of a block nested in it. */
static int act_site_in(const zbc_image_t *img, const zbc_act *a, uint32_t key, uint32_t st) {
    if (key & 0x80000000u) return st == (key & 0x7FFFFFFFu);
    uint32_t ss = zbc_act_site(img, a, st)->scope;
    return ss != ACT_NONE && (ss == key || act_nested(img, a, key, ss));
}

/* Node `x` is in branch `key`: in the subtree of one of its sites' targets. */
static int act_node_in(const zbc_image_t *img, const zbc_act *a, uint32_t key, uint32_t x) {
    for (uint32_t st = 0; st < a->n_sites; st++)
        if (act_site_in(img, a, key, st)
                && act_below(img, a, zbc_act_site(img, a, st)->target, x)) return 1;
    return 0;
}

/* Node `x` has a lock claim with pool `pid` (ACT_NONE: with any pool). */
static int act_node_locks(const zbc_image_t *img, const zbc_act *a, uint32_t x, uint32_t pid) {
    const zbc_actnode *n = zbc_act_node(img, a, x);
    for (uint32_t k = 0; k < n->n_claims; k++) {
        const zbc_actclaim *c = &img->actclaims[n->claim0 + k];
        if (!c->lock) continue;
        if (pid == ACT_NONE) return 1;
        const uint32_t *pr = zbc_act_list(img, c->pool0);
        for (uint32_t i = 0; i < c->n_pools; i++)
            if (pr[2 * i + 1] == pid) return 1;
    }
    return 0;
}

/* pyvm ActivationTable.par: per parallel, its branches (the child blocks
 * of its node, then its own sites) and the pools two of them lock. */
static void act_par_build(const zbc_image_t *img, const zbc_act *a, zbc_actrun_t *r) {
    uint32_t np = a->n_pools;
    for (uint32_t sc = 0; sc < a->n_scopes; sc++) {
        const zbc_actscope *ps = zbc_act_scope(img, a, sc);
        if (ps->kind != ACT_KIND_PARALLEL) continue;
        struct act_par_s *P = &r->par[sc];
        P->key = (uint32_t *)calloc(a->n_scopes + a->n_sites + 1, sizeof(uint32_t));
        P->shared = (uint8_t *)calloc(np + 1, 1);
        if (!P->key || !P->shared) continue;
        for (uint32_t c = 0; c < a->n_scopes; c++)
            if (zbc_act_scope(img, a, c)->parent == sc && zbc_act_scope(img, a, c)->node == ps->node)
                P->key[P->nbr++] = c;
        for (uint32_t st = 0; st < a->n_sites; st++)
            if (zbc_act_site(img, a, st)->scope == sc) P->key[P->nbr++] = 0x80000000u | st;
        for (uint32_t pid = 0; pid < np; pid++) {
            uint32_t users = 0;
            for (uint32_t bi = 0; bi < P->nbr; bi++)
                for (uint32_t x = 0; x < a->n_nodes; x++)
                    if (act_node_in(img, a, P->key[bi], x) && act_node_locks(img, a, x, pid)) {
                        users++;
                        break;
                    }
            if (users > 1) { P->shared[pid] = 1; P->n_shared++; }
        }
        if (P->n_shared) {
            P->fp = (uint64_t *)calloc((size_t)P->nbr * np + 1, sizeof(uint64_t));
            if (P->fp) r->has_par = 1; else P->n_shared = 0;
        }
    }
}

/* All the instances of pool `pid`. */
static uint64_t act_pool_full(const zbc_image_t *img, const zbc_act *a, uint32_t pid) {
    uint32_t s = img->actpools[a->pool0 + pid].size;
    return s >= 64 ? ~0ull : (1ull << s) - 1;
}

/* pyvm Activation._fp_mask: the instances of pool `pid` outside the
 * footprint of the branch site `site` is in, for each parallel it is in. */
static uint64_t act_fp_mask(const zbc_image_t *img, const zbc_act *a, const zbc_actrun_t *r,
                            uint32_t pid, uint32_t site) {
    if (site == ACT_NONE || pid >= a->n_pools) return 0;
    uint64_t mask = 0;
    uint32_t prev = 0x80000000u | site, q = zbc_act_site(img, a, site)->scope;
    for (uint32_t i = 0; q != ACT_NONE && i <= a->n_scopes; i++) {
        const struct act_par_s *P = &r->par[q];
        if (P->fp && P->at && P->at == r->entered_at[q] && P->shared[pid])
            for (uint32_t bi = 0; bi < P->nbr; bi++)
                if (P->key[bi] == prev) {
                    mask |= act_pool_full(img, a, pid) & ~P->fp[bi * a->n_pools + pid];
                    break;
                }
        prev = q;
        q = zbc_act_scope(img, a, q)->parent;
    }
    return mask;
}

/* pyvm Activation._concurrent_since. */
static int act_concurrent_since(const zbc_image_t *img, const zbc_act *a,
                                const zbc_actrun_t *r, uint32_t site, uint32_t hsite,
                                uint32_t at) {
    if (site == ACT_NONE || hsite == ACT_NONE) return 0;
    uint32_t sc = act_concurrent(img, a, site, hsite);
    return sc != ACT_NONE && at >= r->entered_at[sc];
}

/* pyvm Activation._busy: the instances of pool `pid` a claim of `node` may
 * not take. */
static uint64_t act_busy(const zbc_image_t *img, const zbc_act *a, const zbc_actrun_t *r,
                         uint32_t pid, uint32_t node, int lock) {
    uint32_t site = r->by_site[node];
    uint64_t mask = 0;
    for (uint32_t k = 0; k < r->n_cl; k++) {
        const struct act_claim_s *h = &r->cl[k];
        if (h->pid != pid || !(lock || h->lock) || h->node == node || h->iid >= 64) continue;
        if ((h->held && !act_below(img, a, h->node, node))
                || act_concurrent_since(img, a, r, site, h->site, h->at))
            mask |= 1ull << h->iid;
    }
    if (r->has_par)
        mask |= act_fp_mask(img, a, r, pid,
                            site != ACT_NONE ? site : act_pending_site(img, a, r, node));
    return mask;
}

/* The frame that called or spawned L (pyvm Frame.parent): the one below
 * it on its thread's stack, else the frame that spawned the thread. */
static const interp_locals_t *frame_up(const interp_locals_t *L) {
    const zsp_frame_t *f = (const zsp_frame_t *)
        ((const char *)L - offsetof(zsp_frame_wrap_t, locals));
    if (f->prev && f->prev->func == &zbc_interp_task)
        return zsp_frame_locals(f->prev, interp_locals_t);
    return L->parent_locals;
}

/* pyvm _loop_counter (P4.10f3): loop index `v`'s counter in the nearest
 * frame above L that runs node v->loop_node in a coro holding it (the
 * image's (coro, slot) pairs). 0 if there is none. */
static int act_loop_counter(const interp_locals_t *L, const zbc_actvar *v,
                            uint64_t *out) {
    const uint32_t *hs = zbc_act_list(L->img, v->loop0);
    for (const interp_locals_t *f = frame_up(L); f; f = frame_up(f)) {
        if (f->node != v->loop_node) continue;
        uint32_t ci = (uint32_t)(f->coro - L->img->coros);
        for (uint32_t m = 0; m < hs[0]; m++) {
            if (hs[1 + 2 * m] != ci) continue;
            uint32_t slot = hs[2 + 2 * m];
            if (slot >= f->nlocals) return 0;
            *out = f->locals[slot];
            return 1;
        }
    }
    return 0;
}

/* pyvm Activation._pin for what zbc_image_check lets through: 1 and *out
 * if `v` is pinned in the solve of `node`, 0 if free. `probe`: a
 * footprint probe's solve, where a loop index is free. */
/* An exported action's argument for field `slot` of the run's root object
 * (zbc_host_t pin_slot/pin_val), as pyvm VM.arg_bounds. */
static int entry_pin(const interp_locals_t *L, uint32_t slot, uint64_t *out) {
    const zbc_host_t *h = L->host;
    for (uint32_t i = 0; h && i < h->n_pins; i++) {
        if (h->pin_slot[i] == slot) {
            *out = (uint64_t)h->pin_val[i];
            return 1;
        }
    }
    return 0;
}

static int act_pin(const interp_locals_t *L, const zbc_actvar *v, uint32_t node,
                   int probe, uint64_t *out) {
    const zbc_actrun_t *r = L->ar;
    /* The root node's fields an exported action's caller passed (F2.3b). */
    if (v->node == 0 && (v->flags & 2u) && v->busy_pool == ACT_NONE
            && entry_pin(L, v->slot, out))
        return 1;
    if (v->busy_pool != ACT_NONE) {
        /* The instances a claim may not take; in other nodes' solves, what
         * a footprint keeps from it if it is not solved yet, else free. */
        if (v->node != node) {
            if (!r->has_par || r->committed[v->node]) return 0;
            uint32_t s = r->by_site[v->node];
            if (s == ACT_NONE || s == 0)          /* pyvm: `by_site or _pending_site` */
                s = act_pending_site(L->img, L->act, r, v->node);
            *out = act_fp_mask(L->img, L->act, r, v->busy_pool, s);
            return 1;
        }
        *out = act_busy(L->img, L->act, r, v->busy_pool, node, (v->flags & 4u) != 0);
        return 1;
    }
    if (v->live_from != ACT_NONE) {
        /* A state input: its pool's current object (12.5); free before. */
        if (v->node == node) {
            *out = v->live_from < L->obj->n ? L->obj->slots[v->live_from] : 0;
            return 1;
        }
        if (!r->committed[v->node]) return 0;
    }
    if (v->flags & 16u) {
        /* A resource attribute: held from the last solve that chose it,
         * until a branch frees it; fixed once a claim takes it (F8.6e). */
        if (!act_slots_has(&r->attr_held, v->slot)) return 0;
        *out = v->slot < L->obj->n ? L->obj->slots[v->slot] : 0;
        return 1;
    }
    if (v->comp_read != ACT_NONE) {
        *out = (L->img->cobj && v->comp_read < L->img->comp->n_slots)
            ? L->img->cobj[v->comp_read] : 0;
        return 1;
    }
    if (v->loop_local != ACT_NONE && v->node == node) {
        /* A loop's index at the traversal it constrains: this iteration's
         * counter (before, free; after, committed with the node's values). */
        return !probe && act_loop_counter(L, v, out);
    }
    int rand = (v->flags & 2u) != 0;
    if (v->node == node && rand) return 0;
    if (r->started[v->node] || r->committed[v->node]) {
        if (rand && !r->committed[v->node]) return 0;
        *out = v->slot < L->obj->n ? L->obj->slots[v->slot] : 0;
        return 1;
    }
    if (!rand) {
        const zbc_actinit *in = zbc_act_init(L->img, L->act, v->slot);
        if (in && in->unknown) return 0;
        *out = in ? in->value : 0;
        return 1;
    }
    return 0;
}

static uint32_t act_pool_for(const zbc_image_t *img, uint32_t l0, uint32_t n,
                             uint32_t comp);

/* The variable of `cone` holding slot `slot` (the last, as pyvm's values by
 * slot), or ACT_NONE. */
static uint32_t act_cone_slot(const zbc_image_t *img, const zbc_actcone *cone, uint32_t slot) {
    uint32_t f = ACT_NONE;
    for (uint32_t i = 0; i < cone->n_vars; i++)
        if (zbc_act_var(img, cone->var0 + i)->slot == slot) f = i;
    return f;
}

/* pyvm Activation._instance_of: the instance node `x` runs in, given the
 * solved `vals` of `cone` for the slots that choose one. */
static uint32_t act_instance_of(const interp_locals_t *L, const zbc_actcone *cone,
                                const int64_t *vals, uint32_t x) {
    uint32_t off = 0;
    for (uint32_t i = 0; x != ACT_NONE && i <= L->act->n_nodes; i++) {
        const zbc_actnode *n = zbc_act_node(L->img, L->act, x);
        if (n->comp_slot != ACT_NONE) {
            uint32_t k = act_cone_slot(L->img, cone, n->comp_slot);
            uint64_t v = k != ACT_NONE ? (uint64_t)vals[k]
                : n->comp_slot < L->obj->n ? L->obj->slots[n->comp_slot] : 0;
            return (uint32_t)v + off;
        }
        if (n->n_comp == 1) off += zbc_act_list(L->img, n->comp0)[0];
        x = n->parent;
    }
    return off;
}

/* pyvm Activation._probe: solve `member`'s cone as branch `bi` of parallel
 * `P` would traverse it, writing nothing. 1 and every variable's value in
 * `vals`; 0 if there is none; -1 on an error. */
static int act_probe(interp_locals_t *L, const struct act_par_s *P, uint32_t member,
                     uint32_t bi, const int32_t *branch_of, const uint64_t *reserved,
                     uint64_t seed, int64_t *vals) {
    const zbc_image_t *img = L->img;
    const zbc_act *a = L->act;
    zbc_actrun_t *r = L->ar;
    uint32_t np = a->n_pools, site = ACT_NONE;
    const zbc_actcone *cone = zbc_act_cone(img, a, act_cone_of(img, a, member));
    uint32_t nv = cone->n_vars, nc = cone->n_cons, npin = 0, nadd = 0;
    for (uint32_t s = 0; s < a->n_sites && site == ACT_NONE; s++)
        if (zbc_act_site(img, a, s)->target == member) site = s;
    uint8_t *en = (uint8_t *)calloc(nc + a->n_scopes + 1, 1);
    uint32_t *pin_var = (uint32_t *)calloc(nv + 1, sizeof(uint32_t));
    int64_t *pin_val = (int64_t *)calloc(nv + 1, sizeof(int64_t));
    const void **adds = (const void **)calloc(nc + 1, sizeof(void *));
    int rc = -1;
    if (!en || !pin_var || !pin_val || !adds) goto out;
    /* The blocks on the branch's way there are as if entered. */
    uint8_t *saved = en + nc;
    memcpy(saved, r->entered, a->n_scopes);
    if (site != ACT_NONE) {
        uint32_t q = zbc_act_site(img, a, site)->scope;
        for (uint32_t i = 0; q != ACT_NONE && i <= a->n_scopes; i++) {
            r->entered[q] = 1;
            q = zbc_act_scope(img, a, q)->parent;
        }
    }
    for (uint32_t i = 0; i < nc; i++)
        en[i] = (uint8_t)act_in_force(img, a, r, zbc_act_con(img, cone->con0 + i), member, site);
    memcpy(r->entered, saved, a->n_scopes);
    for (uint32_t i = 0; i < nv; i++) {
        const zbc_actvar *v = zbc_act_var(img, cone->var0 + i);
        uint64_t pv = 0;
        if (v->busy_pool != ACT_NONE) {
            /* A lock of a branch probed already takes an instance it
             * reserved; any other, none the probed branches reserved. */
            if (r->committed[v->node]) continue;
            uint32_t pid = v->busy_pool;
            int32_t j = branch_of[v->node];
            if (pid < np && P->shared[pid])
                pv = (j >= 0 && (uint32_t)j < bi)
                    ? act_pool_full(img, a, pid) & ~P->fp[(uint32_t)j * np + pid] : reserved[pid];
            pv |= act_busy(img, a, r, pid, v->node, (v->flags & 4u) != 0);
        } else if (!act_pin(L, v, member, 1, &pv)) continue;
        pin_var[npin] = i;
        pin_val[npin++] = act_domain_value(pv, v);
    }
    for (uint32_t i = 0; i < nc; i++)
        if (en[i]) adds[nadd++] = zbc_act_blob(img, zbc_act_con(img, cone->con0 + i)->blob_off);
    int sr = zbc_solver_cone(zbc_act_blob(img, cone->base_off), adds, nadd,
                             pin_var, pin_val, npin, seed, vals, nv);
    rc = sr == ZBC_SOLVER_OK ? 1 : sr == ZBC_SOLVER_UNSAT ? 0 : -1;
out:
    free(en); free(pin_var); free(pin_val); free(adds);
    return rc;
}

/* pyvm Activation._footprints: choose each branch of parallel `scope` the
 * instances of the shared pools its locks may take, disjoint from the other
 * branches'. Each branch's probes (per cone, its shallowest node whose cone
 * holds a locker of the branch) reserve what one traversal needs; the rest
 * are dealt at random (MT19937 seeded `seed`) among the branches using the
 * pool. ZBC_ERR_SOLVE_UNSAT: a branch locks more than is left. */
static int act_footprints(interp_locals_t *L, uint32_t scope, uint64_t seed) {
    const zbc_image_t *img = L->img;
    const zbc_act *a = L->act;
    zbc_actrun_t *r = L->ar;
    struct act_par_s *P = &r->par[scope];
    uint32_t np = a->n_pools, nn = a->n_nodes, nvmax = 0;
    for (uint32_t i = 0; i < a->n_cones; i++)
        if (zbc_act_cone(img, a, i)->n_vars > nvmax) nvmax = zbc_act_cone(img, a, i)->n_vars;
    uint64_t *reserved = (uint64_t *)calloc(np + 1, sizeof(uint64_t));
    int32_t *branch_of = (int32_t *)calloc(nn + 1, sizeof(int32_t));
    uint32_t *order = (uint32_t *)calloc(2 * nn + 1, sizeof(uint32_t)), *depth = order + nn;
    uint8_t *taken = (uint8_t *)calloc(a->n_cones + 1, 1);
    int64_t *vals = (int64_t *)calloc(nvmax + 1, sizeof(int64_t));
    uint32_t *users = (uint32_t *)calloc(P->nbr + 1, sizeof(uint32_t));
    int rc = ZBC_ERR_SOLVE_FAIL;
    if (!reserved || !branch_of || !order || !taken || !vals || !users) goto out;
    memset(P->fp, 0, (size_t)P->nbr * np * sizeof(uint64_t));
    /* Nodes shallowest first (pyvm sorts by depth; ties by id here). */
    for (uint32_t x = 0; x < nn; x++) {
        branch_of[x] = -1;
        uint32_t d = 0;
        for (uint32_t p = zbc_act_node(img, a, x)->parent; p != ACT_NONE && d <= nn; d++)
            p = zbc_act_node(img, a, p)->parent;
        depth[x] = d;
        uint32_t k = x;
        for (; k > 0 && depth[order[k - 1]] > d; k--) order[k] = order[k - 1];
        order[k] = x;
    }
    for (uint32_t bi = 0; bi < P->nbr; bi++)
        for (uint32_t x = 0; x < nn; x++)
            if (act_node_in(img, a, P->key[bi], x) && act_node_locks(img, a, x, ACT_NONE))
                branch_of[x] = (int32_t)bi;
    for (uint32_t bi = 0; bi < P->nbr; bi++) {
        uint32_t key = P->key[bi];
        memset(taken, 0, a->n_cones);
        for (uint32_t k = 0; k < nn; k++) {
            uint32_t x = order[k], ci = act_cone_of(img, a, x);
            if (ci == ACT_NONE || taken[ci] || !act_node_in(img, a, key, x)) continue;
            int has = 0;
            for (uint32_t y = 0; y < nn && !has; y++)
                has = act_node_in(img, a, key, y) && act_node_locks(img, a, y, ACT_NONE)
                    && act_cone_of(img, a, y) == ci;
            if (!has) continue;
            taken[ci] = 1;
            int pr = act_probe(L, P, x, bi, branch_of, reserved, seed + bi, vals);
            if (pr < 0) goto out;
            if (pr == 0) { rc = ZBC_ERR_SOLVE_UNSAT; goto out; }
            const zbc_actcone *cone = zbc_act_cone(img, a, ci);
            for (uint32_t y = 0; y < nn; y++) {
                if (!act_node_in(img, a, key, y) || !act_node_locks(img, a, y, ACT_NONE)
                        || act_cone_of(img, a, y) != ci) continue;
                uint32_t inst = act_instance_of(L, cone, vals, y);
                const zbc_actnode *n = zbc_act_node(img, a, y);
                for (uint32_t c = 0; c < n->n_claims; c++) {
                    const zbc_actclaim *cl = &img->actclaims[n->claim0 + c];
                    uint32_t pid = act_pool_for(img, cl->pool0, cl->n_pools, inst);
                    uint32_t vi = act_cone_slot(img, cone, cl->iid_slot);
                    if (!cl->lock || pid >= np || !P->shared[pid] || vi == ACT_NONE
                            || (uint64_t)vals[vi] >= 64) continue;
                    uint64_t bit = 1ull << vals[vi];
                    P->fp[bi * np + pid] |= bit;
                    reserved[pid] |= bit;
                }
            }
        }
    }
    zbc_mt_t g;
    zbc_mt_seed(&g, seed);
    for (uint32_t pid = 0; pid < np; pid++) {
        if (!P->shared[pid]) continue;
        uint32_t nu = 0;
        for (uint32_t bi = 0; bi < P->nbr; bi++)
            if (P->fp[bi * np + pid]) users[nu++] = bi;
        if (!nu) continue;
        uint64_t fr = act_pool_full(img, a, pid) & ~reserved[pid];
        uint32_t size = img->actpools[a->pool0 + pid].size;
        for (uint32_t i = 0; i < size && i < 64; i++)
            if (fr >> i & 1)
                P->fp[users[zbc_mt_randrange(&g, 0, nu)] * np + pid] |= 1ull << i;
    }
    P->at = r->entered_at[scope];
    rc = ZBC_OK;
out:
    free(reserved); free(branch_of); free(order); free(taken); free(vals); free(users);
    return rc;
}

/* pyvm Activation._attempt (write, with the constraints in force `en`):
 * solve cone `ci` with the pins; on success write the node's values and
 * make the solution the cone's witness. Returns ZBC_SOLVER_*. */
/* pyvm Activation._keep_attrs: write and hold the values a solve of cone
 * `ci` chose for its resource attributes no value holds yet (F8.6e). */
static int act_keep_attrs(interp_locals_t *L, uint32_t ci, const uint64_t *vals) {
    const zbc_actcone *cone = zbc_act_cone(L->img, L->act, ci);
    for (uint32_t i = 0; i < cone->n_vars; i++) {
        const zbc_actvar *v = zbc_act_var(L->img, cone->var0 + i);
        if (!(v->flags & 16u) || act_slots_has(&L->ar->attr_held, v->slot)) continue;
        if (v->slot >= L->obj->n) return ZBC_ERR_OOB_FIELD;
        L->obj->slots[v->slot] = vals[i];
        if (act_slots_add(&L->ar->attr_held, v->slot) != ZBC_OK) return ZBC_ERR_SOLVE_FAIL;
    }
    return ZBC_OK;
}

static int act_attempt(interp_locals_t *L, uint32_t ci, const uint8_t *en,
                       const uint32_t *pin_var, const int64_t *pin_val, uint32_t npin,
                       uint64_t seed, int64_t *vals, const void **adds) {
    const zbc_image_t *img = L->img;
    zbc_actrun_t *r = L->ar;
    uint32_t node = L->node;
    const zbc_actcone *cone = zbc_act_cone(img, L->act, ci);
    uint32_t nv = cone->n_vars, nc = cone->n_cons, nadd = 0;
    for (uint32_t i = 0; i < nc; i++)
        if (en[i]) adds[nadd++] = zbc_act_blob(img, zbc_act_con(img, cone->con0 + i)->blob_off);
    int sr = zbc_solver_cone(zbc_act_blob(img, cone->base_off), adds, nadd,
                             pin_var, pin_val, npin, seed, vals, nv);
    if (sr != ZBC_SOLVER_OK) return sr;
    for (uint32_t i = 0; i < nv; i++) {
        const zbc_actvar *v = zbc_act_var(img, cone->var0 + i);
        if (v->node == node && ((v->flags & 2u) || v->live_from != ACT_NONE))
            L->obj->slots[v->slot] = (uint64_t)vals[i];
        uint8_t free_ = 1;
        for (uint32_t k = 0; k < npin; k++)
            if (pin_var[k] == i) free_ = 0;
        r->wit_val[cone->var0 + i - r->var_lo] = (uint64_t)vals[i];
        r->wit_free[cone->var0 + i - r->var_lo] = free_;
    }
    for (uint32_t i = 0; i < nc; i++) r->wit_en[cone->con0 + i - r->con_lo] = en[i];
    const uint32_t *ns = zbc_act_list(img, cone->node0);
    for (uint32_t k = 0; k < cone->n_nodes; k++) r->wit_taken[ns[k]] = 0;
    r->wit_taken[node] = 1;
    r->wit_valid[ci] = 1;
    if (act_keep_attrs(L, ci, (const uint64_t *)vals) != ZBC_OK) return ZBC_SOLVER_FAIL;
    return ZBC_SOLVER_OK;
}

/* The number of pool `pid`'s buffer objects with `cons` consumers. */
static uint32_t act_bcount(const zbc_actrun_t *r, uint32_t pid, uint32_t cons) {
    uint32_t n = 0;
    for (uint32_t i = 0; i < r->n_bobj; i++)
        if (r->bobj[i].pid == pid && r->bobj[i].cons == cons) n++;
    return n;
}

/* Pool `pid`'s object with `cons` consumers at place `pos` (or NULL). */
static struct act_bobj_s *act_bfind(zbc_actrun_t *r, uint32_t pid, uint32_t cons,
                                    uint32_t pos) {
    for (uint32_t i = 0; i < r->n_bobj; i++)
        if (r->bobj[i].pid == pid && r->bobj[i].cons == cons && r->bobj[i].pos == pos)
            return &r->bobj[i];
    return NULL;
}

/* pyvm Activation._picked: `o` has one more consumer (swap-remove from its
 * count's list, append to the next count's). */
static void act_bpicked(zbc_actrun_t *r, struct act_bobj_s *o) {
    struct act_bobj_s *last = act_bfind(r, o->pid, o->cons, act_bcount(r, o->pid, o->cons) - 1);
    if (last && last != o) last->pos = o->pos;
    uint32_t pos = act_bcount(r, o->pid, o->cons + 1);
    o->cons++;
    o->pos = pos;
}

/* pyvm Activation.solve's pick branch: a buffer input no bind connects
 * takes one of its pools' completed objects, tried least-consumed first in
 * an order drawn from `seed` (pyvm _candidates: random.Random(seed), a lazy
 * Fisher-Yates per consumer count); the first the cone accepts is picked.
 * `pin_var`/`pin_val` hold npin pins and room for the pick's. */
static int act_pick(interp_locals_t *L, uint32_t ci, const uint8_t *en,
                    uint32_t *pin_var, int64_t *pin_val, uint32_t npin,
                    uint64_t seed, int64_t *vals, const void **adds) {
    const zbc_image_t *img = L->img;
    const zbc_act *a = L->act;
    zbc_actrun_t *r = L->ar;
    uint32_t node = L->node;
    const zbc_actcone *cone = zbc_act_cone(img, a, ci);
    const zbc_actpick *pk = &img->actpicks[zbc_act_node(img, a, node)->pick0];
    const uint32_t *pp = zbc_act_list(img, pk->pool0), *ps = zbc_act_list(img, pk->slot0);
    /* var_of: the cone var of the node's variable in each slot */
    uint32_t sel = ACT_NONE;
    for (uint32_t i = 0; i < cone->n_vars; i++) {
        const zbc_actvar *v = zbc_act_var(img, cone->var0 + i);
        if (v->node == node && v->slot == pk->sel_slot) sel = i;
    }
    if (sel == ACT_NONE) return ZBC_ERR_SOLVE_FAIL;
    /* the pick's pools, distinct and sorted */
    uint32_t np = 0, *pools = (uint32_t *)calloc(pk->n_pools + 1, sizeof(uint32_t));
    uint32_t *perm = (uint32_t *)calloc(r->n_bobj + 1, sizeof(uint32_t));
    int rc = ZBC_ERR_SOLVE_FAIL;
    if (!pools || !perm) goto out;
    for (uint32_t k = 0; k < pk->n_pools; k++) {
        uint32_t p = pp[2 * k + 1], at = 0;
        while (at < np && pools[at] < p) at++;
        if (at < np && pools[at] == p) continue;
        memmove(&pools[at + 1], &pools[at], (np - at) * sizeof(uint32_t));
        pools[at] = p; np++;
    }
    zbc_mt_t g;
    zbc_mt_seed(&g, seed);
    uint32_t times = 0;
    for (;;) {
        /* the next consumer count (ascending) any of the pools has objects at */
        uint32_t nxt = ACT_NONE;
        for (uint32_t i = 0; i < r->n_bobj; i++) {
            const struct act_bobj_s *o = &r->bobj[i];
            if ((o->cons >= times) && o->cons < nxt)
                for (uint32_t k = 0; k < np; k++)
                    if (pools[k] == o->pid) { nxt = o->cons; break; }
        }
        if (nxt == ACT_NONE) break;
        uint32_t n = 0;
        for (uint32_t k = 0; k < np; k++) n += act_bcount(r, pools[k], nxt);
        for (uint32_t k = 0; k < n; k++) perm[k] = k;
        for (uint32_t k = 0; k < n; k++) {
            uint32_t rr = (uint32_t)zbc_mt_randrange(&g, k, n);
            uint32_t x = perm[rr];
            perm[rr] = perm[k];
            struct act_bobj_s *o = NULL;
            for (uint32_t q = 0; q < np && !o; q++) {
                uint32_t c = act_bcount(r, pools[q], nxt);
                if (x < c) o = act_bfind(r, pools[q], nxt, x);
                else x -= c;
            }
            if (!o) goto out;
            uint32_t m = npin;
            pin_var[m] = sel;
            pin_val[m++] = act_domain_value(o->pid, zbc_act_var(img, cone->var0 + sel));
            for (uint32_t s = 0; s < pk->n_slots && s < o->nval; s++)
                for (uint32_t i = 0; i < cone->n_vars; i++) {
                    const zbc_actvar *v = zbc_act_var(img, cone->var0 + i);
                    if (v->node == node && v->slot == ps[s]) {
                        pin_var[m] = i;
                        pin_val[m++] = act_domain_value(r->bval[o->val0 + s], v);
                        break;
                    }
                }
            int sr = act_attempt(L, ci, en, pin_var, pin_val, m, seed, vals, adds);
            if (sr == ZBC_SOLVER_OK) { act_bpicked(r, o); rc = ZBC_OK; goto out; }
            if (sr != ZBC_SOLVER_UNSAT) goto out;
        }
        times = nxt + 1;
    }
    rc = ZBC_ERR_SOLVE_UNSAT;   /* no object output so far satisfies the input */
out:
    free(pools); free(perm);
    return rc;
}

static uint32_t act_pool_for(const zbc_image_t *img, uint32_t l0, uint32_t n,
                             uint32_t comp);

/* pyvm Activation._claim: record `node`'s claims, now that its solve chose
 * them, as held by it in instance `comp`. */
static int act_claim(interp_locals_t *L, uint32_t node, uint32_t comp) {
    const zbc_image_t *img = L->img;
    zbc_actrun_t *r = L->ar;
    const zbc_actnode *n = zbc_act_node(img, L->act, node);
    r->clock++;
    for (uint32_t k = 0; k < n->n_claims; k++) {
        const zbc_actclaim *c = &img->actclaims[n->claim0 + k];
        uint32_t pid = act_pool_for(img, c->pool0, c->n_pools, comp);
        if (pid >= L->act->n_pools || c->iid_slot >= L->obj->n) return ZBC_ERR_SOLVE_FAIL;
        if (r->n_cl == r->cap_cl) {
            uint32_t cap = r->cap_cl ? 2 * r->cap_cl : 8;
            void *p = realloc(r->cl, cap * sizeof(*r->cl));
            if (!p) return ZBC_ERR_SOLVE_FAIL;
            r->cl = p; r->cap_cl = cap;
        }
        struct act_claim_s *h = &r->cl[r->n_cl++];
        h->pid = pid; h->node = node; h->site = r->by_site[node];
        h->iid = (uint32_t)L->obj->slots[c->iid_slot];
        h->lock = c->lock != 0; h->at = r->clock; h->held = 1;
        /* The instance's attributes, as this claim's solve chose them, are
         * fixed from now on (F8.6e). */
        for (uint32_t ci = 0; ci < L->act->n_cones; ci++) {
            const zbc_actcone *cn = zbc_act_cone(img, L->act, ci);
            for (uint32_t i = 0; i < cn->n_vars; i++) {
                const zbc_actvar *v = zbc_act_var(img, cn->var0 + i);
                if ((v->flags & 16u) && v->pick == pid && (v->flags >> 16) == h->iid
                        && act_slots_add(&r->attr_claimed, v->slot) != ZBC_OK)
                    return ZBC_ERR_SOLVE_FAIL;
            }
        }
    }
    return ZBC_OK;
}

/* pyvm Activation.exit_node's release (completed or cancelled): `node`'s
 * held claims become released ones, keeping the latest of each. */
static void act_release(zbc_actrun_t *r, uint32_t node) {
    for (uint32_t k = 0; k < r->n_cl; ) {
        struct act_claim_s *h = &r->cl[k];
        if (!h->held || h->node != node) { k++; continue; }
        uint32_t j;
        for (j = 0; j < r->n_cl; j++) {
            const struct act_claim_s *o = &r->cl[j];
            if (j != k && !o->held && o->pid == h->pid && o->node == h->node
                    && o->site == h->site && o->iid == h->iid && o->lock == h->lock) break;
        }
        if (j == r->n_cl) { h->held = 0; k++; continue; }
        if (r->cl[j].at < h->at) r->cl[j].at = h->at;
        r->cl[k] = r->cl[--r->n_cl];
    }
}

static void note_cone_unsat(interp_locals_t *L, uint32_t ci, const uint8_t *en, uint32_t nc,
                            const uint32_t *pin_var, const int64_t *pin_val, uint32_t npin);

/* `solve` (F3.10b) of node L->node in cone `ci`, as pyvm Activation.explain
 * has it, less `dropped`: C has no constraint source, so it adds `act`,
 * `cone`, `enabled` (constraints in force) and `witness` (the cone's values,
 * when it has softs) for the host to find the dropped softs from (pssc
 * native.explain_solves). `softs` counts the constraints in force written
 * `soft ...`. */
static void ev_solve(interp_locals_t *L, uint32_t ci, const uint8_t *en, uint64_t seed) {
    const zbc_image_t *img = L->img;
    const zbc_act *a = L->act;
    zbc_actrun_t *r = L->ar;
    zbc_ev_sink_t *s = L->host->events;
    const zbc_actcone *cone = zbc_act_cone(img, a, ci);
    const zbc_actnode *n = zbc_act_node(img, a, L->node);
    uint32_t nv = cone->n_vars, nc = cone->n_cons, ne = 0, nsoft = 0, nval = 0;
    for (uint32_t i = 0; i < nc; i++) {
        if (!en[i]) continue;
        ne++;
        const char *t = zbc_image_act_str(img, zbc_act_con(img, cone->con0 + i)->text);
        if (t && !strncmp(t, "soft ", 5)) nsoft++;
    }
    for (uint32_t i = 0; i < nv; i++) {
        const zbc_actvar *v = zbc_act_var(img, cone->var0 + i);
        if (v->node == L->node && (v->flags & 2u)) nval++;
    }
    int wit = nsoft && r->wit_valid[ci];
    const char *path = zbc_image_act_str(img, n->path);
    const char *type = zbc_image_act_str(img, n->type);
    zbc_ev_begin(s, "solve", L->ev_id, img->code[L->coro->code_start + L->pc].src_ref);
    zbc_ev_map(s, 9u + (uint32_t)wit);
    zbc_ev_key(s, "site");
    if (path && *path) zbc_ev_str(s, path, strlen(path));
    else zbc_ev_str(s, "<root>", 6);
    zbc_ev_key(s, "node"); zbc_ev_uint(s, L->node);
    zbc_ev_key(s, "type");
    zbc_ev_str(s, type ? type : "", type ? strlen(type) : 0);
    zbc_ev_key(s, "seed"); zbc_ev_uint(s, seed);
    zbc_ev_key(s, "values");
    zbc_ev_map(s, nval);
    for (uint32_t i = 0; i < nv; i++) {
        const zbc_actvar *v = zbc_act_var(img, cone->var0 + i);
        if (v->node != L->node || !(v->flags & 2u)) continue;
        zbc_ev_key(s, zbc_image_act_str(img, v->name));
        zbc_ev_int(s, act_domain_value(L->obj->slots[v->slot], v));
    }
    zbc_ev_key(s, "softs"); zbc_ev_uint(s, nsoft);
    zbc_ev_key(s, "act"); zbc_ev_uint(s, a->coro);
    zbc_ev_key(s, "cone"); zbc_ev_uint(s, ci);
    zbc_ev_key(s, "enabled");
    zbc_ev_list(s, ne);
    for (uint32_t i = 0; i < nc; i++)
        if (en[i]) zbc_ev_uint(s, i);
    if (wit) {
        zbc_ev_key(s, "witness");
        zbc_ev_list(s, nv);
        for (uint32_t i = 0; i < nv; i++)
            zbc_ev_int(s, act_domain_value(r->wit_val[cone->var0 + i - r->var_lo],
                                           zbc_act_var(img, cone->var0 + i)));
    }
    zbc_ev_end(s);
}

/* `solve` (F3.10b) of SOLVE problem `pid` (pyvm ops_orch _solve_event),
 * less what needs the problem's names and source: `solve` (pid) and
 * `solved` ([var_id, value] per written-back variable) let the host fill
 * `values`, `softs` and `dropped` (pssc native.explain_solve). */
static void ev_solve_op(interp_locals_t *L, uint32_t pid, uint64_t seed,
                        const uint32_t *pairs, uint32_t nwb, int procedural) {
    zbc_ev_sink_t *s = L->host->events;
    const char *nm = zbc_image_str(L->img, L->coro->name);
    size_t nl = nm ? strlen(nm) : 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < nwb; i++)
        if (procedural ? pairs[2 * i] < L->n_solved
                       : L->obj && (uint64_t)L->base + pairs[2 * i] < L->obj->n) n++;
    zbc_ev_begin(s, "solve", L->ev_id, L->img->code[L->coro->code_start + L->pc].src_ref);
    zbc_ev_map(s, 9);
    zbc_ev_key(s, "site"); zbc_ev_str(s, nm ? nm : "", nl);
    zbc_ev_key(s, "node"); zbc_ev_uint(s, L->node);
    zbc_ev_key(s, "type"); zbc_ev_str(s, nm ? nm : "", nl);
    zbc_ev_key(s, "seed"); zbc_ev_uint(s, seed);
    zbc_ev_key(s, "values"); zbc_ev_map(s, 0);
    zbc_ev_key(s, "softs"); zbc_ev_uint(s, 0);
    zbc_ev_key(s, "dropped"); zbc_ev_list(s, 0);
    zbc_ev_key(s, "solve"); zbc_ev_uint(s, pid);
    zbc_ev_key(s, "solved");
    zbc_ev_list(s, n);
    for (uint32_t i = 0; i < nwb; i++) {
        uint64_t v;
        if (procedural) {
            if (pairs[2 * i] >= L->n_solved) continue;
            v = (uint64_t)L->solved[pairs[2 * i]];
        } else {
            if (!L->obj || (uint64_t)L->base + pairs[2 * i] >= L->obj->n) continue;
            v = L->obj->slots[L->base + pairs[2 * i]];
        }
        zbc_ev_list(s, 2);
        zbc_ev_uint(s, pairs[2 * i + 1]);
        zbc_ev_uint(s, v);
    }
    zbc_ev_end(s);
}

/* pyvm Activation.solve for a node of cone `ci` with no picks, pools or
 * claims: the constraints in force, the pins, the cone's witness if it is a
 * solution of this solve (_reuse), else a solve (_attempt), then commit. */
static int act_solve(interp_locals_t *L, uint32_t ci, uint64_t seed) {
    const zbc_image_t *img = L->img;
    const zbc_act *a = L->act;
    zbc_actrun_t *r = L->ar;
    uint32_t node = L->node, site = r->site_of[node];
    const zbc_actcone *cone = zbc_act_cone(img, a, ci);
    uint32_t nv = cone->n_vars, nc = cone->n_cons;
    uint8_t *en = (uint8_t *)calloc(nc + nv + 1, 1);
    uint8_t *pinned = en + nc;
    uint64_t *pv = (uint64_t *)calloc(nv + 1, sizeof(uint64_t));
    int64_t *vals = (int64_t *)calloc(nv + 1, sizeof(int64_t));
    uint32_t *pin_var = (uint32_t *)calloc(2 * nv + 2, sizeof(uint32_t));
    int64_t *pin_val = (int64_t *)calloc(2 * nv + 2, sizeof(int64_t));
    const void **adds = (const void **)calloc(nc + 1, sizeof(void *));
    int rc = ZBC_ERR_SOLVE_FAIL;
    if (!en || !pv || !vals || !pin_var || !pin_val || !adds) goto out;
    for (uint32_t i = 0; i < nc; i++)
        en[i] = (uint8_t)act_in_force(img, a, r, zbc_act_con(img, cone->con0 + i), node, site);
    r->by_site[node] = site;
    uint32_t npin = 0;
    for (uint32_t i = 0; i < nv; i++) {
        const zbc_actvar *v = zbc_act_var(img, cone->var0 + i);
        if (v->slot >= L->obj->n) { rc = ZBC_ERR_OOB_FIELD; goto out; }
        if (act_pin(L, v, node, 0, &pv[i])) {
            pinned[i] = 1;
            pin_var[npin] = i;
            pin_val[npin++] = act_domain_value(pv[i], v);
        }
    }
    if (zbc_act_node(img, a, node)->n_picks) {
        /* picks skip _reuse (pyvm: only picks[0] is used) */
        rc = act_pick(L, ci, en, pin_var, pin_val, npin, seed, vals, adds);
        if (rc != ZBC_OK) goto out;
        goto committed;
    }
    /* _reuse */
    int reuse = r->wit_valid[ci] && !r->wit_taken[node];
    for (uint32_t i = 0; reuse && i < nc; i++)
        if (en[i] && !r->wit_en[cone->con0 + i - r->con_lo]) reuse = 0;
    for (uint32_t k = 0; reuse && k < npin; k++)
        if (r->wit_val[cone->var0 + pin_var[k] - r->var_lo] != (uint64_t)pin_val[k]) reuse = 0;
    for (uint32_t i = 0; reuse && i < nv; i++)
        if (zbc_act_var(img, cone->var0 + i)->node == node && !pinned[i]
                && !r->wit_free[cone->var0 + i - r->var_lo]) reuse = 0;
    if (reuse) {
        for (uint32_t i = 0; i < nv; i++) {
            const zbc_actvar *v = zbc_act_var(img, cone->var0 + i);
            if (v->node == node && ((v->flags & 2u) || v->live_from != ACT_NONE))
                L->obj->slots[v->slot] = r->wit_val[cone->var0 + i - r->var_lo];
        }
        r->wit_taken[node] = 1;
        rc = act_keep_attrs(L, ci, r->wit_val + (cone->var0 - r->var_lo));
        if (rc != ZBC_OK) goto out;
    } else {
        int sr = act_attempt(L, ci, en, pin_var, pin_val, npin, seed, vals, adds);
        if (sr != ZBC_SOLVER_OK) {
            rc = sr == ZBC_SOLVER_UNSAT ? ZBC_ERR_SOLVE_UNSAT : ZBC_ERR_SOLVE_FAIL;
            if (sr == ZBC_SOLVER_UNSAT) note_cone_unsat(L, ci, en, nc, pin_var, pin_val, npin);
            goto out;
        }
    }
committed:
    r->committed[node] = 1;
    if (node == 0) {
        /* The root's solve chose each state pool's initial object. */
        for (uint32_t p = 0; p < a->n_pools; p++) {
            const zbc_actpool *pl = &img->actpools[a->pool0 + p];
            const uint32_t *src = zbc_act_list(img, pl->init0), *dst = zbc_act_list(img, pl->slot0);
            for (uint32_t k = 0; k < pl->n_init && k < pl->n_slots; k++) {
                if (src[k] >= L->obj->n || dst[k] >= L->obj->n) { rc = ZBC_ERR_OOB_FIELD; goto out; }
                L->obj->slots[dst[k]] = L->obj->slots[src[k]];
            }
        }
    }
    if (zbc_act_node(img, a, node)->n_claims) {
        uint32_t cs = zbc_act_node(img, a, node)->comp_slot;
        uint32_t comp = cs != ACT_NONE ? (uint32_t)L->obj->slots[cs] : L->comp;
        rc = act_claim(L, node, comp);
        if (rc != ZBC_OK) goto out;
    }
    if (ev_mask(L) & ZBC_EV_SOLVE) ev_solve(L, ci, en, seed);
    rc = ZBC_OK;
out:
    free(en); free(pv); free(vals); free(pin_var); free(pin_val); free(adds);
    return rc;
}

/* pyvm _pool_for: of the (instance, pool) pairs at list `l0`, the pool of
 * instance `comp` (the only one if there is one). */
static uint32_t act_pool_for(const zbc_image_t *img, uint32_t l0, uint32_t n,
                             uint32_t comp) {
    const uint32_t *p = zbc_act_list(img, l0);
    if (n == 1) return p[1];
    for (uint32_t i = 0; i < n; i++)
        if (p[2 * i] == comp) return p[2 * i + 1];
    return ACT_NONE;
}

/* pyvm Activation.exit_node for a node that ran to its end: its state
 * outputs become their pools' current objects (12.5), and its buffer
 * outputs join their pools' unconsumed objects, for picks (d4). */
static int act_exit_node(interp_locals_t *L) {
    const zbc_image_t *img = L->img;
    const zbc_act *a = L->act;
    zbc_actrun_t *r = L->ar;
    if (L->node >= a->n_nodes) return ZBC_OK;
    act_release(r, L->node);
    const zbc_actnode *n = zbc_act_node(img, a, L->node);
    for (uint32_t k = 0; k < n->n_bwrites; k++) {
        const zbc_actwrite *w = zbc_act_write(img, n->bwrite0 + k);
        uint32_t pid = act_pool_for(img, w->pool0, w->n_pools, L->comp);
        if (pid >= a->n_pools) return ZBC_ERR_SOLVE_FAIL;
        const uint32_t *src = zbc_act_list(img, w->src0);
        if (r->n_bobj == r->cap_bobj) {
            uint32_t c = r->cap_bobj ? 2 * r->cap_bobj : 8;
            void *p = realloc(r->bobj, c * sizeof(*r->bobj));
            if (!p) return ZBC_ERR_SOLVE_FAIL;
            r->bobj = p; r->cap_bobj = c;
        }
        if (r->n_bval + w->n_src > r->cap_bval) {
            uint32_t c = r->cap_bval ? 2 * r->cap_bval : 32;
            while (c < r->n_bval + w->n_src) c *= 2;
            void *p = realloc(r->bval, c * sizeof(uint64_t));
            if (!p) return ZBC_ERR_SOLVE_FAIL;
            r->bval = p; r->cap_bval = c;
        }
        struct act_bobj_s *o = &r->bobj[r->n_bobj];
        o->pid = pid; o->cons = 0; o->pos = act_bcount(r, pid, 0);
        o->val0 = r->n_bval; o->nval = w->n_src;
        for (uint32_t i = 0; i < w->n_src; i++) {
            if (src[i] >= L->obj->n) return ZBC_ERR_OOB_FIELD;
            r->bval[r->n_bval++] = L->obj->slots[src[i]];
        }
        r->n_bobj++;
    }
    for (uint32_t k = 0; k < n->n_swrites; k++) {
        const zbc_actwrite *w = zbc_act_write(img, n->swrite0 + k);
        uint32_t pid = act_pool_for(img, w->pool0, w->n_pools, L->comp);
        if (pid >= a->n_pools) return ZBC_ERR_SOLVE_FAIL;
        const zbc_actpool *pl = &img->actpools[a->pool0 + pid];
        const uint32_t *src = zbc_act_list(img, w->src0), *dst = zbc_act_list(img, pl->slot0);
        for (uint32_t i = 0; i < w->n_src && i < pl->n_slots; i++) {
            if (src[i] >= L->obj->n || dst[i] >= L->obj->n) return ZBC_ERR_OOB_FIELD;
            L->obj->slots[dst[i]] = L->obj->slots[src[i]];
        }
    }
    return ZBC_OK;
}

/* F3.8c: the run's first error is about to be the unsat SOLVE `pid`: keep it
 * and its pins on the yield for the host's error. */
static void note_unsat(interp_locals_t *L, uint32_t pid, const uint32_t *pin_var,
                       const int64_t *pin_val, uint32_t npin) {
    if (!L->run || L->run->status != ZBC_OK || !L->host || !L->host->yield) return;
    zbc_yield_t *y = L->host->yield;
    uint32_t max = (uint32_t)(sizeof(y->err_pin_var) / sizeof(y->err_pin_var[0]));
    y->err_solve = pid;
    y->err_npin = npin < max ? npin : max;
    for (uint32_t i = 0; i < y->err_npin; i++) {
        y->err_pin_var[i] = pin_var[i];
        y->err_pin_val[i] = pin_val[i];
    }
}

/* F3.8c: ... or the unsat cone `ci` of the run's activation, with its
 * constraints in force `en` (nc flags) and pins; skipped when they do not fit. */
static void note_cone_unsat(interp_locals_t *L, uint32_t ci, const uint8_t *en, uint32_t nc,
                            const uint32_t *pin_var, const int64_t *pin_val, uint32_t npin) {
    if (!L->run || L->run->status != ZBC_OK || !L->host || !L->host->yield || !L->act) return;
    zbc_yield_t *y = L->host->yield;
    uint32_t max = (uint32_t)(sizeof(y->err_en) / sizeof(y->err_en[0])), ne = 0;
    for (uint32_t i = 0; i < nc; i++) ne += en[i] != 0;
    if (ne > max || npin > max) return;
    y->err_act = L->act->coro;
    y->err_cone = ci;
    y->err_nen = 0;
    for (uint32_t i = 0; i < nc; i++)
        if (en[i]) y->err_en[y->err_nen++] = i;
    y->err_npin = npin;
    for (uint32_t i = 0; i < npin; i++) {
        y->err_pin_var[i] = pin_var[i];
        y->err_pin_val[i] = pin_val[i];
    }
}

/* Floats (F6.6): a register's 64 bits as a binary64, and back. */
static double f_of(uint64_t b) { double d; memcpy(&d, &b, sizeof d); return d; }
static uint64_t bits_of(double d) { uint64_t b; memcpy(&b, &d, sizeof b); return b; }

/* Division by zero as the Python VM does it (ops_proc._fdiv): 0/0 and NaN/0
 * give a positive quiet NaN, not the x86 default NaN, so the bits match. */
static double f_div(double a, double b) {
    if (b != 0.0) return a / b;
    if (a != a || a == 0.0) return f_of(0x7FF8000000000000ull);
    return ((a < 0) != (signbit(b) != 0)) ? -HUGE_VAL : HUGE_VAL;
}

/* binary64 to int64, truncated; NaN or out of range gives INT64_MIN's bits. */
static uint64_t f2s(double x) {
    if (x != x || !(x >= -9223372036854775808.0 && x < 9223372036854775808.0))
        return 0x8000000000000000ull;
    return (uint64_t)(int64_t)x;
}

static zsp_frame_t *halt(zsp_thread_t *thread, interp_locals_t *L,
                         int status, int op, uint64_t rv) {
    if (status == ZBC_OK && L->is_node && L->ar && L->obj) {
        status = act_exit_node(L);
        L->is_node = 0;
    }
    /* P4.5b2: the run's first error, with stop-on-error: stop here (frames
     * live); the resume comes back to zbc_interp_task, which halts. */
    if (status != ZBC_OK && L->run && L->run->status == ZBC_OK && L->host
            && L->host->dbg && L->host->dbg->stop_on_error && L->host->yield
            && L->host->yield->state == ZBC_YIELD_NONE && L->dbg_listed
            && L->dbg_err == 0) {
        uint32_t coro = (uint32_t)(L->coro - L->img->coros);
        zbc_dbg_stop_t *s = dbg_post_stop(thread, L->dbg_frame, L, ZBC_DBG_ERROR,
            L->pc < L->coro->code_count
                ? zbc_image_src_ref(L->img, coro, L->coro->code_start + L->pc) : 0);
        s->status = status;
        s->op = op;
        L->dbg_err = 1;
        L->dbg_err_status = status;
        L->dbg_err_op = op;
        L->dbg_pass_pc = L->pc;
        return L->dbg_frame;
    }
    /* An error in any frame -- a nested callee's too -- is the run's, and the
     * first one wins: a callee's error is never lost to its caller's RET. */
    if (status != ZBC_OK && L->run && L->run->status == ZBC_OK) {
        L->run->status = status;
        L->run->halted_op = op;
        if (L->host && L->host->yield) {
            L->host->yield->err_coro = (uint32_t)(L->coro - L->img->coros);
            L->host->yield->err_pc = L->pc;
        }
    }
    /* The thread a step follows ended: the step stops in any thread. */
    if (L->host && L->host->dbg && L->host->dbg->step_thread == (void *)thread
            && thread->leaf->prev == NULL) {
        L->host->dbg->step_thread_done = 1;
        L->host->dbg->step_thread = NULL;
    }
    if (L->result) {
        if (L->result->status == ZBC_OK) {
            L->result->status = status;
            L->result->halted_op = op;
        }
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
                    if (L->host && L->host->dbg)
                        dbg_unlink_thread(L->host->dbg, sib->self_thread);
                    /* pyvm exit_node(completed=False): a cancelled
                     * traversal's claims are released (P4.10e1). */
                    for (zsp_frame_t *f = sib->self_thread->leaf; f; f = f->prev) {
                        if (f->func != &zbc_interp_task) continue;
                        interp_locals_t *cl = zsp_frame_locals(f, interp_locals_t);
                        if (cl->is_node && cl->ar && cl->act && cl->node < cl->act->n_nodes)
                            act_release(cl->ar, cl->node);
                        free(cl->key_cnt);
                        cl->key_cnt = NULL;
                    }
                    zsp_timebase_cancel(thread->timebase, sib->self_thread);
                }
            }
            P->n_children = 0;
            zsp_timebase_schedule(thread->timebase, L->parent_thread);
        }
    }
    if (L->host && L->host->dbg) dbg_unlink(L->host->dbg, L);
    actrun_release(L->ar);
    L->ar = NULL;
    free(L->key_cnt);
    L->key_cnt = NULL;
    L->key_n = L->key_cap = 0;
    /* A callee that completes inside its caller's CALL (sync_call) pops its
     * frame and returns to that CALL, which resumes the caller in its own
     * loop. Letting zsp_timebase_return re-enter the caller instead nests
     * three C frames per call that never unwind until the run ends: one
     * statement-level loop of ~4800 calls overflows an 8 MB stack. */
    zsp_frame_t *pf = thread->leaf ? thread->leaf->prev : NULL;
    if (L->depth && pf && pf->func == &zbc_interp_task
            && zsp_frame_locals(pf, interp_locals_t)->sync_call) {
        uint32_t blocked = thread->flags & ZSP_THREAD_FLAGS_BLOCKED;
        thread->flags |= ZSP_THREAD_FLAGS_BLOCKED;   /* pop, do not continue */
        zsp_frame_t *r = zsp_timebase_return(thread, rv);
        if (!blocked) thread->flags &= ~ZSP_THREAD_FLAGS_BLOCKED;
        return r;
    }
    return zsp_timebase_return(thread, rv);
}

/* A node whose instance its solve has not chosen yet (pyvm frame.comp None);
 * reading comp there is an error (LRM 13.4.5). */
#define COMP_UNCHOSEN 0xFFFFFFFEu

/* cbase follows comp: its instance's base, else (no instance) the host's. */
static void frame_cbase(interp_locals_t *L) {
    uint32_t hbase = L->host ? L->host->cbase : 0;
    L->cbase = (L->comp != 0xFFFFFFFFu && L->img->comp_bases
                && L->comp < L->img->comp->n_inst)
        ? L->img->comp_bases[L->comp] : hbase;
}

/* A frame's activation context (P4.10c4). A root (ZBC_FRAME_ROOT) runs node
 * 0 of the activation rooted at its coroutine, if any, in the host's
 * instance + the root node's one candidate; as pyvm's VM.root_frame, which
 * runs it in instance 0 + the root node's comp_rel. cbase follows comp. */
static void frame_comp(interp_locals_t *L, int coro_index) {
    uint32_t hbase = L->host ? L->host->cbase : 0;
    if (L->node == 0xFFFFFFFEu) {
        L->act = zbc_image_act(L->img, (uint32_t)coro_index);
        L->node = 0;
        L->comp = 0xFFFFFFFFu;
        if (L->act && L->img->comp_bases) {
            for (uint32_t i = 0; i < L->img->comp->n_inst; i++)
                if (L->img->comp_bases[i] == hbase) { L->comp = i; break; }
            /* + node 0's one candidate: an action of a sub-component (comp_rel) */
            const zbc_actnode *n0 = zbc_act_node(L->img, L->act, 0);
            if (L->comp != 0xFFFFFFFFu && n0->n_comp == 1)
                L->comp += zbc_act_list(L->img, n0->comp0)[0];
        }
    }
    frame_cbase(L);
}

/* The node and instance a traversal from frame L's node runs in: site
 * `local` of L's node (its sites are consecutive, from the first it owns,
 * as pyvm's ActivationTable.site), and L's instance + the target node's one
 * candidate (none: 0xFFFFFFFF, a choice the solver makes, P4.10d). */
static void child_node(const interp_locals_t *L, uint32_t local,
                       uint32_t *node, uint32_t *comp, uint32_t *site) {
    *node = L->node; *comp = L->comp; *site = ACT_NONE;
    if (!L->act) return;
    for (uint32_t s = 0; s < L->act->n_sites; s++) {
        if (zbc_act_site(L->img, L->act, s)->owner != L->node) continue;
        if (s + local >= L->act->n_sites) return;
        *site = s + local;
        *node = zbc_act_site(L->img, L->act, s + local)->target;
        const zbc_actnode *n = zbc_act_node(L->img, L->act, *node);
        *comp = n->n_comp != 1 ? COMP_UNCHOSEN
            : L->comp >= COMP_UNCHOSEN ? L->comp
            : L->comp + zbc_act_list(L->img, n->comp0)[0];
        return;
    }
}


/* PSS files (file_open, F6.11c): handle h is f_files[h - 1]; 0 is
 * nullfilehandle. Process-wide, as the Python VM's per-VM `files`. */
#define ZBC_MAX_FILES 64
static FILE *f_files[ZBC_MAX_FILES];
static uint8_t f_modes[ZBC_MAX_FILES];
static uint32_t f_n;

static uint64_t file_open(const char *name, uint64_t mode) {
    static const char *const modes[] = { "w", "a", "r" };   /* file_option_e */
    if (mode > 2 || f_n >= ZBC_MAX_FILES) return 0;
    FILE *f = fopen(name, modes[mode]);
    if (f == NULL) return 0;
    f_files[f_n] = f;
    f_modes[f_n] = (uint8_t)mode;
    return ++f_n;
}

static FILE *file_get(uint64_t h) {
    return (h > 0 && h <= f_n) ? f_files[h - 1] : NULL;
}

static int file_close(uint64_t h) {
    FILE *f = file_get(h);
    if (f == NULL) return 0;
    fclose(f);
    f_files[h - 1] = NULL;
    return 1;
}

void zbc_files_close_all(void) {
    for (uint32_t i = 0; i < f_n; i++)
        if (f_files[i]) fclose(f_files[i]);
    f_n = 0;
}

zsp_frame_t *zbc_interp_task(zsp_timebase_t *tb, zsp_thread_t *thread,
                             int idx, va_list *args) {
    zsp_frame_t *ret = thread->leaf;
    interp_locals_t *L;

    if (idx == 0) {
        /* Frame + register/local file live in the coroutine's stack arena,
         * sized for the coroutine (verified before the frame is made). */
        va_list peek;
        va_copy(peek, *args);
        const zbc_image_t *pimg = va_arg(peek, const zbc_image_t *);
        const zbc_coro *pco = &pimg->coros[va_arg(peek, int)];
        va_end(peek);
        uint32_t nregs = 0, nlocals = 0;
        int vrc = verify_coro(pimg->code + pco->code_start, pco->code_count,
                              &nregs, &nlocals);
        if (vrc != ZBC_OK) { nregs = ZBC_MIN_REGS; nlocals = ZBC_MIN_LOCALS; }
        ret = zsp_timebase_alloc_frame(thread, sizeof(interp_locals_t)
                                       + 8u * (nregs + nlocals), &zbc_interp_task);
        L = zsp_frame_locals(ret, interp_locals_t);
        L->nregs = nregs;
        L->nlocals = nlocals;
        L->regs = L->slots;
        L->locals = L->slots + nregs;
        L->img    = va_arg(*args, const zbc_image_t *);
        int coro_index = va_arg(*args, int);
        L->coro   = &L->img->coros[coro_index];
        L->result = va_arg(*args, zbc_result_t *);
        L->obj    = va_arg(*args, zbc_obj_t *);
        L->base   = va_arg(*args, uint32_t);
        L->spawn_budget = va_arg(*args, uint64_t *);
        L->host = va_arg(*args, zbc_host_t *);
        L->seed_state = va_arg(*args, uint64_t);   /* forked by the parent (root: run seed) */
        const uint64_t *cargs = va_arg(*args, const uint64_t *);
        L->depth = va_arg(*args, uint32_t);
        L->run = va_arg(*args, zbc_result_t *);
        uint32_t start_pc = va_arg(*args, uint32_t);   /* past initializers (INITED) */
        L->act = va_arg(*args, const zbc_act *);
        L->node = va_arg(*args, uint32_t);
        L->is_node = L->node == 0xFFFFFFFEu;
        if (L->node != 0xFFFFFFFEu && L->node != ACT_NONE && (L->node & ACT_NODE_FRAME)) {
            L->node &= ~ACT_NODE_FRAME;
            L->is_node = 1;
        }
        L->comp = va_arg(*args, uint32_t);
        L->ar = va_arg(*args, zbc_actrun_t *);
        /* A called frame inherits its caller's executor; a spawned thread's
         * spawner sets it after the create. */
        L->executor = ret->prev && ret->prev->func == &zbc_interp_task
            ? zsp_frame_locals(ret->prev, interp_locals_t)->executor : 0xFFFFFFFFu;
        L->called = ret->prev && ret->prev->func == &zbc_interp_task
            && zsp_frame_locals(ret->prev, interp_locals_t)->sync_call;
        int is_root = L->node == 0xFFFFFFFEu;
        L->is_entry = is_root;
        frame_comp(L, coro_index);
        if (is_root && L->act) {
            L->ar = actrun_new(L->img, L->act);
            if (L->ar) act_enter_node(L->img, L->act, L->ar, 0, ACT_NONE);
        } else if (L->ar) {
            L->ar->refs++;
        }
        if (cargs) {
            memcpy(L->call_args, cargs, sizeof(L->call_args));
        } else {
            memset(L->call_args, 0, sizeof(L->call_args));
        }
        memset(L->staged, 0, sizeof(L->staged));
        memset(L->results, 0, sizeof(L->results));
        L->child_index = 0;
        L->origin = L->seed_state;
        L->key_cnt = NULL;
        L->key_n = L->key_cap = 0;
        L->pc = start_pc;
        L->steps = (L->host && L->host->step_limit) ? L->host->step_limit
                                                   : ZBC_STEP_LIMIT;
        L->resuming_call = 0;
        L->invoke_yield = 0;
        L->call_ret_reg = -1;
        L->sync_call = 0;
        L->self_thread = thread;
        L->parent_locals = (interp_locals_t *)0;   /* set by the parent's SPAWN */
        L->parent_thread = (zsp_thread_t *)0;
        L->counted = 0;
        L->n_children = 0;
        L->join_pending = 0;
        L->n_staged = 0;
        L->n_pins = 0;
        L->n_solved = 0;
        L->ev_id = (L->host && L->host->events) ? L->host->events->next_id++ : 0;
        L->ev_skip_pc = 0xFFFFFFFFu;
        L->dbg_id = (L->host && L->host->dbg) ? ++L->host->dbg->next_id : 0;
        L->dbg_pass_pc = 0xFFFFFFFFu;
        L->dbg_listed = 0;
        L->dbg_err = 0;
        if (L->dbg_id) dbg_link(L->host->dbg, L, ret);
        memset(L->slots, 0, 8u * (nregs + nlocals));
        ret->idx = 1;

        if (vrc == ZBC_OK && start_pc > L->coro->code_count) vrc = ZBC_ERR_BAD_TARGET;
        if (vrc == ZBC_OK && is_root && L->act && !L->ar) vrc = ZBC_ERR_SOLVE_FAIL;
        if (vrc != ZBC_OK) {
            return halt(thread, L, vrc, 0, 0);
        }
        /* A called function (depth > 0) runs at once, as the oracle's CALL
         * readies it first; a traversal or a spawned branch waits its turn. */
        if (L->depth == 0) return ret;
    }

resume:
    L = zsp_frame_locals(ret, interp_locals_t);
    const zbc_instr *code = L->img->code + L->coro->code_start;
    uint32_t n = L->coro->code_count;

    /* Re-entered after a blocking INVOKE's callee completed: the callee's return
     * value is in thread->rval; deliver it to the caller's result register. */
    if (L->dbg_err == 1) {
        /* Resumed after an error stop: the run ends with that error. */
        L->dbg_err = 2;
        return halt(thread, L, L->dbg_err_status, L->dbg_err_op, 0);
    }
    if (L->run && L->run->status != ZBC_OK) {
        /* Some frame failed (a callee, or a child this one joins): stop at
         * the resume, as the oracle's raise stops the whole run. */
        return halt(thread, L, L->run->status, L->run->halted_op, 0);
    }
    if (L->resuming_call) {
        L->resuming_call = 0;
        if (L->call_ret_reg >= 0) {
            L->regs[L->call_ret_reg] = thread->rval;
        }
        if (L->invoke_yield) {
            /* A blocking INVOKE's callee completed: the oracle readies its
             * caller at the back of the queue, so it waits its turn. */
            L->invoke_yield = 0;
            zsp_timebase_yield(thread);
            return ret;
        }
    }

    L->resume_pc = L->pc;
    const uint32_t evm = ev_mask(L);
    int dbg_reentry = 1;
    for (;;) {
        if (L->steps-- == 0) {
            return halt(thread, L, ZBC_ERR_STEP_LIMIT, 0, 0);
        }
        if (L->pc >= n) {
            /* Fell off the end without RET -> complete (matches the oracle). */
            if ((evm & ZBC_EV_CALL) && L->depth) ev_return(L, 0, 0);
            return halt(thread, L, ZBC_OK, 0, 0);
        }
        if (L->host && L->host->dbg) {
            if (dbg_check(thread, ret, L, dbg_reentry)) {
                L->steps++;
                return ret;
            }
            dbg_reentry = 0;
        }
        int ev_again = 0;                    /* an IMPORT run again: no events */
        if (L->pc == L->ev_skip_pc) {
            L->ev_skip_pc = 0xFFFFFFFFu;
            ev_again = 1;
        }
        if (evm & ZBC_EV_STMT) {
            if (!ev_again) {
                uint32_t ns;
                const zbc_lineent *st = zbc_image_stmts_at(L->img, L->coro->code_start + L->pc, &ns);
                /* The COV item names the statement (path, scope: P4.7). */
                const zbc_covent *cv = ns ? zbc_image_cov_at(L->img, L->coro->code_start + L->pc, 0) : NULL;
                const char *path = cv ? zbc_image_str(L->img, cv->path) : NULL;
                const char *scope = cv ? zbc_image_str(L->img, cv->scope) : NULL;
                int has_scope = scope && *scope;
                for (uint32_t i = 0; i < ns; i++) {
                    zbc_ev_sink_t *s = L->host->events;
                    zbc_ev_begin(s, "stmt", L->ev_id, st[i].src_ref);
                    zbc_ev_map(s, 1u + (path ? 1u : 0u) + (uint32_t)has_scope);
                    zbc_ev_key(s, "pc");
                    zbc_ev_uint(s, L->pc);
                    if (path) {
                        zbc_ev_key(s, "path");
                        zbc_ev_str(s, path, strlen(path));
                    }
                    if (has_scope) {
                        zbc_ev_key(s, "scope");
                        zbc_ev_str(s, scope, strlen(scope));
                    }
                    zbc_ev_end(s);
                }
            }
        }
        if ((evm & ZBC_EV_BRANCH) && !ev_again) {
            /* A branch arm taken (the Python VM's _ev_arms): pc, branch, arm,
             * then scope and implicit when there. */
            const zbc_covent *cv = zbc_image_cov_at(L->img, L->coro->code_start + L->pc, 1);
            const char *path = cv ? zbc_image_str(L->img, cv->path) : NULL;
            if (path) {
                zbc_ev_sink_t *s = L->host->events;
                const char *scope = zbc_image_str(L->img, cv->scope);
                int has_scope = scope && *scope;
                int implicit = (cv->flags & ZBC_COV_F_IMPLICIT) != 0;
                const char *slash = strrchr(path, '/');
                size_t blen = slash ? (size_t)(slash - path) : 0;
                const char *arm = slash ? slash + 1 : path;
                zbc_ev_begin(s, "branch", L->ev_id, cv->src_ref);
                zbc_ev_map(s, 3u + (uint32_t)has_scope + (uint32_t)implicit);
                zbc_ev_key(s, "pc");
                zbc_ev_uint(s, L->pc);
                zbc_ev_key(s, "branch");
                zbc_ev_str(s, path, blen);
                zbc_ev_key(s, "arm");
                zbc_ev_str(s, arm, strlen(arm));
                if (has_scope) {
                    zbc_ev_key(s, "scope");
                    zbc_ev_str(s, scope, strlen(scope));
                }
                if (implicit) {
                    zbc_ev_key(s, "implicit");
                    zbc_ev_bool(s, 1);
                }
                zbc_ev_end(s);
            }
        }
        if (evm & ZBC_EV_CHAN) {
            /* The CHAN table's NOP ends a channel operation (the Python VM's
             * _ev_chan): value only when it is there (ok, or no ok). */
            const zbc_chanent *c = zbc_image_chan_at(L->img, L->coro->code_start + L->pc);
            if (c) {
                zbc_ev_sink_t *s = L->host->events;
                const char *nm = zbc_image_str(L->img, c->channel);
                const char *op = zbc_image_str(L->img, c->op);
                int has_ok = c->ok != 0xFFFFFFFFu && c->ok < L->nregs;
                int ok = has_ok && L->regs[c->ok] != 0;
                int has_val = (!has_ok || ok) && c->val < L->nregs;
                zbc_ev_begin(s, "chan", L->ev_id, c->src_ref);
                zbc_ev_map(s, 2u + (uint32_t)has_ok + (uint32_t)has_val);
                zbc_ev_key(s, "channel");
                zbc_ev_str(s, nm ? nm : "", nm ? strlen(nm) : 0);
                zbc_ev_key(s, "op");
                zbc_ev_str(s, op ? op : "", op ? strlen(op) : 0);
                if (has_ok) { zbc_ev_key(s, "ok"); zbc_ev_bool(s, ok); }
                if (has_val) { zbc_ev_key(s, "value"); zbc_ev_uint(s, L->regs[c->val]); }
                zbc_ev_end(s);
            }
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
            if ((uint64_t)L->base + a1 >= L->obj->n)
                return halt(thread, L, ZBC_ERR_OOB_FIELD, in->op, 0);
            L->regs[a0] = L->obj->slots[L->base + a1]; L->pc++; break;
        case ZBC_OP_ST_FIELD:
            if (!L->obj) return halt(thread, L, ZBC_ERR_NO_OBJ, in->op, 0);
            if ((uint64_t)L->base + a1 >= L->obj->n)
                return halt(thread, L, ZBC_ERR_OOB_FIELD, in->op, 0);
            L->obj->slots[L->base + a1] = L->regs[a0]; L->pc++; break;

        /* Component attributes (P1.5): slot a1 of the frame's instance
         * (cbase: its node's instance, else the host's, set per call by
         * pssvm_call_start; frame_comp). */
        case ZBC_OP_LD_COMP:
            if (!L->img->cobj) return halt(thread, L, ZBC_ERR_NO_OBJ, in->op, 0);
            if (L->comp == COMP_UNCHOSEN) return halt(thread, L, ZBC_ERR_COMP_UNCHOSEN, in->op, 0);
            /* the slot wraps at 2^32: a reference reaches before the frame */
            if ((uint32_t)(L->cbase + a1) >= L->img->comp->n_slots)
                return halt(thread, L, ZBC_ERR_OOB_COMP, in->op, 0);
            L->regs[a0] = L->img->cobj[(uint32_t)(L->cbase + a1)]; L->pc++; break;
        case ZBC_OP_ST_COMP:
            if (!L->img->cobj) return halt(thread, L, ZBC_ERR_NO_OBJ, in->op, 0);
            if (L->comp == COMP_UNCHOSEN) return halt(thread, L, ZBC_ERR_COMP_UNCHOSEN, in->op, 0);
            if ((uint32_t)(L->cbase + a1) >= L->img->comp->n_slots)
                return halt(thread, L, ZBC_ERR_OOB_COMP, in->op, 0);
            L->img->cobj[(uint32_t)(L->cbase + a1)] = L->regs[a0]; L->pc++; break;

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

        /* Floats (F6.6): registers hold binary64 bit patterns
         * (be-bc value-abi.md 1.1). */
        case ZBC_OP_FARITH: {
            double fa = f_of(L->regs[a1]), fr;
            double fb = (in->imm != ZBC_FARITH_NEG) ? f_of(L->regs[a2]) : 0.0;
            switch (in->imm) {
            case ZBC_FARITH_ADD: fr = fa + fb; break;
            case ZBC_FARITH_SUB: fr = fa - fb; break;
            case ZBC_FARITH_MUL: fr = fa * fb; break;
            case ZBC_FARITH_DIV: fr = f_div(fa, fb); break;
            case ZBC_FARITH_NEG: fr = -fa; break;
            default: return halt(thread, L, ZBC_ERR_UNSUPPORTED_OP, in->op, 0);
            }
            L->regs[a0] = bits_of(fr); L->pc++; break;
        }
        case ZBC_OP_FCMP: {
            double fa = f_of(L->regs[a1]), fb = f_of(L->regs[a2]);
            int r;
            switch (in->imm) {
            case ZBC_FCMP_EQ: r = fa == fb; break;
            case ZBC_FCMP_NE: r = fa != fb; break;
            case ZBC_FCMP_LT: r = fa <  fb; break;
            case ZBC_FCMP_LE: r = fa <= fb; break;
            case ZBC_FCMP_GT: r = fa >  fb; break;
            case ZBC_FCMP_GE: r = fa >= fb; break;
            default: return halt(thread, L, ZBC_ERR_UNSUPPORTED_OP, in->op, 0);
            }
            L->regs[a0] = (uint64_t)r; L->pc++; break;
        }
        case ZBC_OP_FMATH: {
            /* The PSS float library (LRM 24.5.2, Table 28), in be-bc model.py
             * FMATH_FNS order; a 1-argument function ignores a2. */
            double fa = f_of(L->regs[a1]), fb = f_of(L->regs[a2]), fr;
            switch (in->imm) {
            case 0:  fr = log(fa); break;
            case 1:  fr = log10(fa); break;
            case 2:  fr = exp(fa); break;
            case 3:  fr = sqrt(fa); break;
            case 4:  fr = pow(fa, fb); break;
            case 5:  fr = round(fa); break;
            case 6:  fr = floor(fa); break;
            case 7:  fr = ceil(fa); break;
            case 8:  fr = sin(fa); break;
            case 9:  fr = cos(fa); break;
            case 10: fr = tan(fa); break;
            case 11: fr = asin(fa); break;
            case 12: fr = acos(fa); break;
            case 13: fr = atan(fa); break;
            case 14: fr = atan2(fa, fb); break;
            case 15: fr = hypot(fa, fb); break;
            case 16: fr = sinh(fa); break;
            case 17: fr = cosh(fa); break;
            case 18: fr = tanh(fa); break;
            case 19: fr = asinh(fa); break;
            case 20: fr = acosh(fa); break;
            case 21: fr = atanh(fa); break;
            default: return halt(thread, L, ZBC_ERR_UNSUPPORTED_OP, in->op, 0);
            }
            L->regs[a0] = bits_of(fr); L->pc++; break;
        }
        case ZBC_OP_FCVT: {
            uint64_t v = L->regs[a1], r;
            switch (in->imm) {
            case ZBC_FCVT_S2F: r = bits_of((double)(int64_t)v); break;
            case ZBC_FCVT_U2F: r = bits_of((double)v); break;
            case ZBC_FCVT_F2S: r = f2s(f_of(v)); break;
            case ZBC_FCVT_F32: r = bits_of((double)(float)f_of(v)); break;
            default: return halt(thread, L, ZBC_ERR_UNSUPPORTED_OP, in->op, 0);
            }
            L->regs[a0] = r; L->pc++; break;
        }

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
            /* A node of this activation runs on our object, imm slots past our
             * base (P1-D1); otherwise the callee shares our base. */
            uint32_t obase = (in->flags & ZBC_F_NODE)
                ? L->base + (uint32_t)in->imm : L->base;
            uint32_t cnode = L->node, ccomp = L->comp, csite = ACT_NONE;
            if (in->flags & ZBC_F_NODE) child_node(L, a2, &cnode, &ccomp, &csite);
            if (L->ar && csite != ACT_NONE) act_enter_node(L->img, L->act, L->ar, cnode, csite);
            uint32_t cnode_arg = csite != ACT_NONE ? (cnode | ACT_NODE_FRAME) : cnode;
            /* A traversal with initializers: the caller has written them
             * into the callee's slots; it starts past its own defaults. */
            uint32_t start = (in->flags & ZBC_F_INITED) ? in->arg3 : 0;
            if (!(in->flags & ZBC_F_BLOCKING)) {
                /* Non-blocking INVOKE: fire-and-forget. Fork a fully detached
                 * child (counted == 0, no parent back-link) and continue. */
                if (L->spawn_budget && *L->spawn_budget == 0) {
                    return halt(thread, L, ZBC_ERR_SPAWN_LIMIT, in->op, 0);
                }
                if (L->spawn_budget) (*L->spawn_budget)--;
                zsp_thread_t *nb = zsp_timebase_thread_create(
                    thread->timebase, &zbc_interp_task, ZSP_THREAD_FLAGS_NONE,
                    L->img, (int)target, (zbc_result_t *)0, L->obj, obase,
                    L->spawn_budget, L->host,
                    child_seed(L, target),
                    (const uint64_t *)0, (uint32_t)0, L->run, start,
                    L->act, cnode_arg, ccomp, L->ar);
                zsp_frame_locals(nb->leaf, interp_locals_t)->executor = L->executor;
                L->pc++;
                break;
            }
            L->pc++;   /* resume after the INVOKE */
            L->call_ret_reg = (in->flags & ZBC_F_HAS_RET) ? (int)a1 : -1;
            L->resuming_call = 1;
            L->invoke_yield = 1;
            /* Callee gets a NULL result (only the root writes the final result) and
             * shares our object; its rval is delivered on our re-entry. */
            return zsp_timebase_call(thread, &zbc_interp_task,
                                     L->img, (int)target, (zbc_result_t *)0,
                                     L->obj, obase, L->spawn_budget, L->host,
                                     child_seed(L, target),
                                     (const uint64_t *)0, (uint32_t)0, L->run, start,
                                     L->act, cnode_arg, ccomp, L->ar);
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
                L->img, (int)target, (zbc_result_t *)0, L->obj, L->base,
                L->spawn_budget, L->host,
                child_seed(L, target),
                (const uint64_t *)0, (uint32_t)0, L->run, (uint32_t)0,
                L->act, L->node, L->comp, L->ar);
            interp_locals_t *cl = zsp_frame_locals(child->leaf, interp_locals_t);
            cl->parent_locals = L;
            cl->parent_thread = thread;
            cl->executor = L->executor;
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
            /* Resumed just past this SPIN YIELD and back here: its condition
             * is still false (the oracle's _op_yield, vm.stuck). */
            if ((in->flags & ZBC_F_SPIN) && L->pc == L->resume_pc && L->img->spin_stuck)
                *L->img->spin_stuck = 1;
            zsp_timebase_yield(thread);
            return ret;

        case ZBC_OP_SCOPE_ENTER: {
            /* Entry to an activity block (pyvm _op_scope_enter): reset what
             * it traverses. */
            if (L->ar) {
                uint32_t sb = act_scope_base(L->img, L->act, L->node);
                uint32_t sc = sb + (uint32_t)in->imm;
                if (sb != ACT_NONE && sc < L->act->n_scopes) {
                    act_enter_scope(L->img, L->act, L->ar, sc);
                    /* A parallel whose branches lock the same pools draws a
                     * seed and chooses their footprints (P4.10e2). */
                    if (L->ar->par[sc].n_shared) {
                        if (!L->obj) return halt(thread, L, ZBC_ERR_NO_OBJ, in->op, 0);
                        L->seed_state = lcg_next(L->seed_state);
                        int frc = act_footprints(L, sc, L->seed_state);
                        if (frc != ZBC_OK) return halt(thread, L, frc, in->op, 0);
                    }
                }
            }
            L->pc++;
            break;
        }

        case ZBC_OP_SOLVE_NODE: {
            /* pyvm _op_solve_node: a node of a cone is solved in it with the
             * frame's next draw; a node in no cone solves its own problem as
             * SOLVE (when it has variables), else only commits. (Like SOLVE, no
             * solve event: the C engine emits none yet.) */
            uint32_t ci = L->ar ? act_cone_of(L->img, L->act, L->node) : ACT_NONE;
            if (ci != ACT_NONE) {
                if (!L->obj) return halt(thread, L, ZBC_ERR_NO_OBJ, in->op, 0);
                L->seed_state = lcg_next(L->seed_state);
                int src = act_solve(L, ci, L->seed_state);
                if (src != ZBC_OK) return halt(thread, L, src, in->op, 0);
                /* The solve chose the node's instance (comp_slot, P4.10d2). */
                uint32_t cs = zbc_act_node(L->img, L->act, L->node)->comp_slot;
                if (cs != ACT_NONE) {
                    L->comp = cs < L->obj->n ? (uint32_t)L->obj->slots[cs] : 0xFFFFFFFFu;
                    frame_cbase(L);
                }
                L->pc++;
                break;
            }
            if (a0 == 0xFFFFFFFFu || !L->img->solves || a0 >= L->img->solve_count
                    || L->img->solves[a0].n_writeback == 0) {
                if (L->ar && L->node < L->act->n_nodes) {
                    L->ar->committed[L->node] = 1;
                    L->ar->by_site[L->node] = L->ar->site_of[L->node];
                }
                L->pc++;
                break;
            }
        }
        /* fall through */
        case ZBC_OP_SOLVE: {
            /* Two randomizers select on prob_len. prob_len==0: the minimal M1
             * randomizer == the oracle's FixedSolveBackend (base 0), each written
             * field slot = seed + var_id. prob_len>0: the real dv-solve path --
             * compile + solve the SPROB blob with the drawn seed and write
             * dvs_solver_get_value(var_id) back per pair. Either way the seed is the
             * descriptor's fixed value or (inherit) the frame's next raw draw,
             * advanced even with no object, matching _op_solve's ordering. */
            uint32_t pid = a0;
            if (!L->img->solves || pid >= L->img->solve_count) {
                return halt(thread, L, ZBC_ERR_BAD_SOLVE, in->op, 0);
            }
            const zbc_solve *p = &L->img->solves[pid];
            if (p->flags & ZBC_SOLVE_ARRAYS) {
                /* A problem reading lists: no heap here yet (M14). */
                return halt(thread, L, ZBC_ERR_BAD_SOLVE, in->op, 0);
            }
            uint32_t nwb = p->n_writeback;
            uint32_t nin = p->n_input;
            uint64_t need = (uint64_t)p->oplist_off + 2ull * ((uint64_t)nwb + nin);
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
            if (p->flags & ZBC_SOLVE_PROCEDURAL) {
                /* `randomize x with {...}` (F3.7c): solve with the staged
                 * pins, keep each pair's var in solved[k] for SOLVE_GET; the
                 * statement's own stores move the values. No commit. */
                uint32_t np = L->n_pins;
                L->n_pins = 0;
                if (!p->prob_len || !L->img->sprob ||
                    (uint64_t)p->prob_off + p->prob_len > L->img->sprob_count) {
                    return halt(thread, L, ZBC_ERR_BAD_SOLVE, in->op, 0);
                }
                uint32_t nk = 0;
                for (uint32_t i = 0; i < nwb; i++) {
                    if (pairs[2 * i] >= ZBC_SOLVE_MAX_VARS) {
                        return halt(thread, L, ZBC_ERR_BAD_SOLVE, in->op, 0);
                    }
                    if (pairs[2 * i] + 1 > nk) nk = pairs[2 * i] + 1;
                }
                int sr = zbc_solver_run_pinned(L->img->sprob + p->prob_off, seed,
                                               pairs, nwb, L->solved,
                                               L->pin_var, L->pin_val, np);
                if (sr == ZBC_SOLVER_UNSAT) {
                    note_unsat(L, pid, L->pin_var, L->pin_val, np);
                    return halt(thread, L, ZBC_ERR_SOLVE_UNSAT, in->op, 0);
                }
                if (sr != ZBC_SOLVER_OK) {
                    return halt(thread, L, ZBC_ERR_SOLVE_FAIL, in->op, 0);
                }
                L->n_solved = nk;
                if (ev_mask(L) & ZBC_EV_SOLVE) ev_solve_op(L, pid, seed, pairs, nwb, 1);
                L->pc++;
                break;
            }
            if (p->prob_len) {
                /* Real solve: bound the blob, validate slots, then drive dv-solve. */
                if (!L->img->sprob ||
                    (uint64_t)p->prob_off + p->prob_len > L->img->sprob_count) {
                    return halt(thread, L, ZBC_ERR_BAD_SOLVE, in->op, 0);
                }
                if (L->obj) {
                    for (uint32_t i = 0; i < nwb; i++) {
                        if ((uint64_t)L->base + pairs[2 * i] >= L->obj->n) {
                            return halt(thread, L, ZBC_ERR_OOB_FIELD, in->op, 0);
                        }
                    }
                    /* The entry frame keeps to its caller's arguments (F2.3b). */
                    uint32_t pin_var[ZBC_CALL_MAX_ARGS + ZBC_SOLVE_MAX_INPUTS];
                    int64_t pin_val[ZBC_CALL_MAX_ARGS + ZBC_SOLVE_MAX_INPUTS];
                    uint32_t npin = 0;
                    if (nin > ZBC_SOLVE_MAX_INPUTS) {
                        return halt(thread, L, ZBC_ERR_BAD_SOLVE, in->op, 0);
                    }
                    for (uint32_t i = 0; L->is_entry && L->host && i < nwb
                            && npin < L->host->n_pins && npin < ZBC_CALL_MAX_ARGS; i++) {
                        uint64_t v;
                        if (entry_pin(L, L->base + pairs[2 * i], &v)) {
                            pin_var[npin] = pairs[2 * i + 1];
                            pin_val[npin++] = (int64_t)v;
                        }
                    }
                    /* Non-rand fields a constraint reads hold their values (F3.7b2). */
                    for (uint32_t i = nwb; i < nwb + nin; i++) {
                        uint64_t slot = (uint64_t)L->base + pairs[2 * i];
                        if (slot >= L->obj->n) {
                            return halt(thread, L, ZBC_ERR_OOB_FIELD, in->op, 0);
                        }
                        pin_var[npin] = pairs[2 * i + 1];
                        pin_val[npin++] = (int64_t)L->obj->slots[slot];
                    }
                    /* Writeback slots are relative to the frame's base. */
                    int sr = zbc_solver_run_pinned(L->img->sprob + p->prob_off, seed,
                                                   pairs, nwb, L->obj->slots + L->base,
                                                   pin_var, pin_val, npin);
                    if (sr == ZBC_SOLVER_UNSAT) {
                        note_unsat(L, pid, pin_var, pin_val, npin);
                        return halt(thread, L, ZBC_ERR_SOLVE_UNSAT, in->op, 0);
                    }
                    if (sr != ZBC_SOLVER_OK) {
                        return halt(thread, L, ZBC_ERR_SOLVE_FAIL, in->op, 0);
                    }
                }
            } else if (L->obj) {
                for (uint32_t i = 0; i < nwb; i++) {
                    uint64_t slot = (uint64_t)L->base + pairs[2 * i];
                    uint32_t var_id = pairs[2 * i + 1];
                    if (slot >= L->obj->n) {
                        return halt(thread, L, ZBC_ERR_OOB_FIELD, in->op, 0);
                    }
                    L->obj->slots[slot] = seed + var_id;
                }
            }
            if (ev_mask(L) & ZBC_EV_SOLVE) ev_solve_op(L, pid, seed, pairs, nwb, 0);
            if (L->ar && L->node < L->act->n_nodes) {       /* act.commit */
                L->ar->committed[L->node] = 1;
                L->ar->by_site[L->node] = L->ar->site_of[L->node];
            }
            L->pc++;
            break;
        }

        case ZBC_OP_SOLVE_PIN: {
            /* Stage input var a0 = reg a1 for the frame's next SOLVE (F3.7b);
             * a later pin of the same var replaces it. */
            uint32_t k = 0;
            while (k < L->n_pins && L->pin_var[k] != a0) k++;
            if (k == ZBC_SOLVE_MAX_INPUTS) {
                return halt(thread, L, ZBC_ERR_BAD_SOLVE, in->op, 0);
            }
            if (k == L->n_pins) L->n_pins++;
            L->pin_var[k] = a0;
            L->pin_val[k] = (int64_t)L->regs[a1];
            L->pc++;
            break;
        }

        case ZBC_OP_SOLVE_GET: {
            if (a1 >= L->n_solved) {   /* no procedural SOLVE kept it */
                return halt(thread, L, ZBC_ERR_BAD_SOLVE, in->op, 0);
            }
            L->regs[a0] = L->solved[a1];
            L->pc++;
            break;
        }

        case ZBC_OP_IMPORT: {
            /* The interpreter's window to the outside world. The instruction fully
             * encodes the call (fn_id=arg0, ret reg=arg1 or 0xFFFFFFFF void, arg
             * regs=arg2/arg3, or imm = n > 0 arguments staged by ARG as for
             * CALL, consumed once the call completes), so we just record it in
             * the host log and read a per-fn_id return value. Synchronous in M1
             * (even a BLOCKING import completes inline), matching the oracle's
             * _op_import -> CONTINUE. */
            uint32_t fn_id = a0;
            uint32_t ret_slot = a1;
            uint64_t argv[ZBC_IMPORT_MAX_ARGS];
            uint32_t nval;
            uint32_t n_res = (uint32_t)(in->imm >> 8) & 0xFFu;
            if ((in->imm & 0xFF) > 0) {
                nval = (uint32_t)in->imm & 0xFFu;
                for (uint32_t i = 0; i < nval; i++)
                    argv[i] = i < L->n_staged ? L->staged[i] : 0;
            } else {
                nval = (in->nargs > 2) ? (in->nargs - 2) : 0;
                if (nval > 0) argv[0] = L->regs[a2];
                if (nval > 1) argv[1] = L->regs[in->arg3];
            }

            /* P4.3b: a pssvm call's host answers anything but the message
             * builtins out of the run. The first visit posts the request and
             * blocks here (pc stays on the IMPORT); the host's answer
             * reschedules the thread, which comes back and takes it. */
            int have_answer = 0;
            uint64_t answer = 0;
            if (L->host && L->host->yield && fn_id != ZBC_BUILTIN_ERROR
                    && fn_id != ZBC_BUILTIN_MESSAGE && fn_id != ZBC_BUILTIN_ERROR_MSG
                    && fn_id != ZBC_BUILTIN_FATAL_MSG && fn_id != ZBC_BUILTIN_PRINT
                    && (fn_id < ZBC_BUILTIN_FILE_OPEN || fn_id > ZBC_BUILTIN_URANDOM_RANGE)) {
                zbc_yield_t *y = L->host->yield;
                if (y->state == ZBC_YIELD_DONE && y->frame == L) {
                    answer = y->value;
                    have_answer = 1;
                    /* A struct result: its leaves, for LD_RES (F6.4b2). */
                    for (uint32_t i = 0; i < n_res; i++) L->results[i] = y->values[i];
                    y->state = ZBC_YIELD_NONE;
                    y->frame = NULL;
                    y->thread = NULL;
                } else {
                    if (y->state == ZBC_YIELD_NONE) {
                        y->fn_id = fn_id;
                        y->n_args = nval;
                        for (uint32_t i = 0; i < nval; i++) y->args[i] = argv[i];
                        y->flags = in->flags & (ZBC_F_BLOCKING | ZBC_F_HAS_RET);
                        if (ret_slot == 0xFFFFFFFFu && n_res == 0)
                            y->flags &= ~(uint32_t)ZBC_F_HAS_RET;
                        y->n_ret = n_res ? n_res : ((y->flags & ZBC_F_HAS_RET) ? 1u : 0u);
                        if (fn_id >= ZBC_BUILTIN_MEM_FIRST && fn_id <= ZBC_BUILTIN_MEM_LAST) {
                            uint32_t k = fn_id - ZBC_BUILTIN_MEM_FIRST;
                            uint32_t nb = 1u << (k & 3u);
                            uint64_t m = (nb == 8) ? ~(uint64_t)0 : (((uint64_t)1 << (8 * nb)) - 1);
                            y->kind = ZBC_YIELD_ACCESS;
                            y->is_write = (k >= 4);
                            y->addr = nval > 0 ? argv[0] : 0;
                            y->size = nb;
                            y->data = (y->is_write && nval > 1) ? (argv[1] & m) : 0;
                        } else {
                            y->kind = ZBC_YIELD_IMPORT;
                            y->is_write = 0;
                            y->addr = 0;
                            y->size = 0;
                            y->data = 0;
                        }
                        y->value = 0;
                        y->thread = thread;
                        y->frame = L;
                        y->executor = L->executor;
                        y->pc = L->coro->code_start + L->pc;
                        y->state = ZBC_YIELD_PENDING;
                    }
                    /* Off the ready queue until the answer (or another
                     * thread's request is still open: wait behind it). */
                    if (y->frame == L) thread->flags |= ZSP_THREAD_FLAGS_BLOCKED;
                    else zsp_timebase_yield(thread);
                    L->ev_skip_pc = L->pc;   /* the IMPORT runs again */
                    return ret;
                }
            }

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
            if (fn_id == ZBC_BUILTIN_ERROR) {
                /* arg0 = a run string id: the host gets its text. The oracle
                 * raises; never run on past it. */
                const zbc_msgtab *mt = L->img->msgtab;
                if (mt && nval > 0 && argv[0] < mt->n_model_strings
                        && L->host && L->host->message) {
                    const char *txt = L->img->msgstrb + L->img->msgstr_off[argv[0]];
                    L->host->message(L->host->msg_ctx, ZBC_MSG_SEV_RUNTIME, 0, txt,
                                     (uint32_t)strlen(txt));
                }
                return halt(thread, L, ZBC_ERR_RUNTIME, in->op, 0);
            }
            if (fn_id == ZBC_BUILTIN_URANDOM || fn_id == ZBC_BUILTIN_URANDOM_RANGE) {
                /* urandom()/urandom_range() (24.4): this frame's seed stream,
                 * one draw, as determinism.py urandom/urandom_range. */
                L->seed_state = lcg_next(L->seed_state);
                uint64_t urv;
                if (fn_id == ZBC_BUILTIN_URANDOM) {
                    urv = L->seed_state >> 32;
                } else {
                    uint64_t lo = (nval > 0 ? argv[0] : 0) & 0xFFFFFFFFu;
                    uint64_t hi = (nval > 1 ? argv[1] : 0) & 0xFFFFFFFFu;
                    if (lo > hi) { uint64_t t = lo; lo = hi; hi = t; }
                    urv = lo + L->seed_state % (hi - lo + 1);
                }
                if ((in->flags & ZBC_F_HAS_RET) && ret_slot != 0xFFFFFFFFu)
                    L->regs[ret_slot] = urv;
                L->pc++;
                break;
            }
            if (fn_id >= ZBC_BUILTIN_FILE_OPEN && fn_id <= ZBC_BUILTIN_FILE_EXISTS) {
                /* file_open/close/exists (24.2); names are model strings. */
                const zbc_msgtab *mt = L->img->msgtab;
                const char *name = (fn_id != ZBC_BUILTIN_FILE_CLOSE && mt && nval > 0
                                    && argv[0] < mt->n_model_strings)
                    ? L->img->msgstrb + L->img->msgstr_off[argv[0]] : NULL;
                uint64_t frv = 0;
                if (fn_id == ZBC_BUILTIN_FILE_EXISTS) {
                    FILE *f = name ? fopen(name, "r") : NULL;
                    if (f) { fclose(f); frv = 1; }
                } else if (fn_id == ZBC_BUILTIN_FILE_OPEN) {
                    frv = name && nval > 1 ? file_open(name, argv[1]) : 0;
                } else if (!file_close(nval > 0 ? argv[0] : 0)) {
                    char txt[64];
                    int n = snprintf(txt, sizeof(txt), "file handle %llu: not an open file",
                                     (unsigned long long)(nval > 0 ? argv[0] : 0));
                    if (L->host && L->host->message)
                        L->host->message(L->host->msg_ctx, ZBC_MSG_SEV_RUNTIME, 0, txt, (uint32_t)n);
                    return halt(thread, L, ZBC_ERR_RUNTIME, in->op, 0);
                }
                if ((in->flags & ZBC_F_HAS_RET) && ret_slot != 0xFFFFFFFFu)
                    L->regs[ret_slot] = frv;
                L->pc++;
                break;
            }
            if (fn_id == ZBC_BUILTIN_FILE_WRITE) {
                /* file_write(handle, fmt, ...): the text as formatted, no
                 * newline (24.2); slot0 holds the handle. */
                const zbc_msgtab *mt = L->img->msgtab;
                uint32_t mi = mt && nval > 0 && argv[0] < mt->n_msgs ? (uint32_t)argv[0] : 0xFFFFFFFFu;
                if (mi == 0xFFFFFFFFu) return halt(thread, L, ZBC_ERR_RUNTIME, in->op, 0);
                char txt[ZBC_MSG_TEXT_MAX];
                uint64_t h = 0;
                int n = zbc_format_message(L->img, mi, L->locals, txt, sizeof(txt), &h);
                if (n < 0) return halt(thread, L, ZBC_ERR_RUNTIME, in->op, 0);
                FILE *f = file_get(h);
                if (f == NULL || f_modes[h - 1] == 2) {
                    char e[96];
                    int en = snprintf(e, sizeof(e), f ? "file handle %llu: opened for reading, not writing"
                                                      : "file handle %llu: not an open file",
                                      (unsigned long long)h);
                    if (L->host && L->host->message)
                        L->host->message(L->host->msg_ctx, ZBC_MSG_SEV_RUNTIME, 0, e, (uint32_t)en);
                    return halt(thread, L, ZBC_ERR_RUNTIME, in->op, 0);
                }
                fwrite(txt, 1, (size_t)n, f);
                fflush(f);
                L->pc++;
                break;
            }
            if (fn_id == ZBC_BUILTIN_MESSAGE || fn_id == ZBC_BUILTIN_ERROR_MSG
                    || fn_id == ZBC_BUILTIN_FATAL_MSG || fn_id == ZBC_BUILTIN_PRINT) {
                /* print() is a message() at any verbosity, level 0. */
                int info = fn_id == ZBC_BUILTIN_MESSAGE || fn_id == ZBC_BUILTIN_PRINT;
                /* arg0 = the message entry (the host also has the call in its
                 * log). With a MSG table the text is formatted and handed to
                 * the host; error()/fatal() then stop the run, as the oracle
                 * raises. A message() above the run's verbosity is ignored. */
                if (L->img->msgtab) {
                    const zbc_msgtab *mt = L->img->msgtab;
                    uint32_t mi = nval > 0 && argv[0] < mt->n_msgs ? (uint32_t)argv[0] : 0xFFFFFFFFu;
                    if (mi == 0xFFFFFFFFu) return halt(thread, L, ZBC_ERR_RUNTIME, in->op, 0);
                    uint32_t lvl_slot = L->img->msgslots[L->img->msgs[mi].slot0];
                    uint64_t lvl = lvl_slot < L->nlocals ? L->locals[lvl_slot] : 0;
                    uint32_t verb = L->host ? L->host->verbosity : 0;
                    if (fn_id != ZBC_BUILTIN_MESSAGE || lvl <= verb) {
                        char txt[ZBC_MSG_TEXT_MAX];
                        int n = zbc_format_message(L->img, mi, L->locals, txt,
                                                   sizeof(txt), &lvl);
                        if (n < 0) return halt(thread, L, ZBC_ERR_RUNTIME, in->op, 0);
                        if (evm & ZBC_EV_MESSAGE)
                            ev_message(L, info ? 0
                                       : fn_id == ZBC_BUILTIN_ERROR_MSG ? 1 : 2, lvl, txt, n);
                        if (L->host && L->host->message)
                            L->host->message(L->host->msg_ctx,
                                info ? ZBC_MSG_SEV_INFO
                                : fn_id == ZBC_BUILTIN_ERROR_MSG ? ZBC_MSG_SEV_ERROR
                                : ZBC_MSG_SEV_FATAL,
                                fn_id == ZBC_BUILTIN_ERROR_MSG ? 0 : lvl, txt, (uint32_t)n);
                        zbc_yield_t *ey = L->host ? L->host->yield : NULL;
                        if (!info && ey && !ey->err_text[0]) {
                            if (fn_id == ZBC_BUILTIN_ERROR_MSG)
                                snprintf(ey->err_text, sizeof(ey->err_text), "error: %s", txt);
                            else
                                snprintf(ey->err_text, sizeof(ey->err_text),
                                         "fatal (status %llu): %s", (unsigned long long)lvl, txt);
                        }
                    }
                }
                if (!info)
                    return halt(thread, L, ZBC_ERR_RUNTIME, in->op, 0);
                L->pc++;
                break;
            }

            uint64_t rv = 0;
            if (fn_id >= ZBC_BUILTIN_MEM_FIRST && fn_id <= ZBC_BUILTIN_MEM_LAST) {
                /* read8..64 (+0..3), write8..64 (+4..7): the oracle's
                 * vm.memory.read/write. zbc_run refused the image if the host
                 * has no mem_access, so it is there. */
                uint32_t k = fn_id - ZBC_BUILTIN_MEM_FIRST;
                uint32_t nbytes = 1u << (k & 3u);
                uint64_t mask = (nbytes == 8) ? ~(uint64_t)0 : (((uint64_t)1 << (8 * nbytes)) - 1);
                int is_write = (k >= 4);
                uint64_t data = (is_write && nval > 1) ? (argv[1] & mask) : 0;
                rv = have_answer ? answer
                   : L->host->mem_access(L->host->mem_ctx, is_write,
                                         nval > 0 ? argv[0] : 0, nbytes, data);
                if (!is_write && (in->flags & ZBC_F_HAS_RET) && ret_slot != 0xFFFFFFFFu)
                    L->regs[ret_slot] = rv & mask;
                if (evm & ZBC_EV_ACCESS)
                    ev_access(L, is_write, nbytes, nval > 0 ? argv[0] : 0,
                              is_write ? data : (rv & mask));
                if (L->host->dbg && L->host->dbg->n_watches)
                    dbg_access(L, is_write, nbytes, nval > 0 ? argv[0] : 0,
                               is_write ? data : (rv & mask));
                L->pc++;
                break;
            }
            if (have_answer) {
                rv = answer;
            } else if (L->host && L->host->import_returns) {
                const zbc_import_returns_t *rt = L->host->import_returns;
                for (uint32_t i = 0; i < rt->count; i++) {
                    if (rt->fn_ids[i] == fn_id) { rv = rt->values[i]; break; }
                }
            }
            if ((in->flags & ZBC_F_HAS_RET) && ret_slot != 0xFFFFFFFFu) {
                L->regs[ret_slot] = rv;
            }
            if (evm & ZBC_EV_IMPORT)
                ev_import(L, fn_id, argv, nval, (in->flags & ZBC_F_BLOCKING) != 0,
                          (in->flags & ZBC_F_HAS_RET) && ret_slot != 0xFFFFFFFFu, rv);
            if (!have_answer)   /* no host: a struct result reads 0s */
                for (uint32_t i = 0; i < n_res; i++) L->results[i] = 0;
            if ((in->imm & 0xFF) > 0) L->n_staged = 0;   /* staged args consumed */
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
                    if (g >= L->nregs) {
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
            L->invoke_yield = 1;          /* the oracle readies it as an INVOKE */
            return zsp_timebase_call(thread, &zbc_interp_task,
                                     L->img, (int)target, (zbc_result_t *)0,
                                     L->obj, L->base, L->spawn_budget, L->host,
                                     child_seed(L, target),
                                     (const uint64_t *)0, (uint32_t)0, L->run, (uint32_t)0,
                L->act, L->node, L->comp, L->ar);
        }

        case ZBC_OP_ARG:
            L->staged[a1] = L->regs[a0];
            if (a1 + 1 > L->n_staged) L->n_staged = a1 + 1;
            L->pc++;
            break;
        case ZBC_OP_LD_ARG: L->regs[a0] = L->call_args[a1]; L->pc++; break;
        case ZBC_OP_LD_RES: L->regs[a0] = L->results[a1]; L->pc++; break;

        /* COV_SAMPLE (F4.6b): covergroup a0 sampled with the a1 values staged
         * by ARG (consumed). Binning is the host's, from the `cov` record. */
        /* EXEC_SET (F5.4a): the frame's executor is now a0's value (an
         * EXEC row id); the requests it issues carry it. */
        case ZBC_OP_EXEC_SET:
            L->executor = (uint32_t)L->regs[a0];
            L->pc++;
            break;

        /* EXEC_GET (F5.4c): a0 = the frame's executor (0xFFFFFFFF = none:
         * `executor()` is null). */
        case ZBC_OP_EXEC_GET:
            L->regs[a0] = L->executor;
            L->pc++;
            break;

        case ZBC_OP_COV_SAMPLE: {
            if (evm & ZBC_EV_COV) {
                zbc_ev_sink_t *s = L->host->events;
                zbc_ev_begin(s, "cov", L->ev_id,
                             L->img->code[L->coro->code_start + L->pc].src_ref);
                zbc_ev_map(s, 2);
                zbc_ev_key(s, "covg"); zbc_ev_uint(s, a0);
                zbc_ev_key(s, "values");
                zbc_ev_list(s, a1);
                for (uint32_t i = 0; i < a1; i++)
                    zbc_ev_uint(s, i < L->n_staged ? L->staged[i] : 0);
                zbc_ev_end(s);
            }
            L->n_staged = 0;
            L->pc++;
            break;
        }

        case ZBC_OP_CALL: {
            /* A called function (B-D5): nested on this thread like a blocking
             * INVOKE, so it runs at once and we resume when it returns. It
             * shares our object, base and seed state, and forks no seed (a
             * function draws nothing; the oracle's call forks none either). */
            uint32_t target = a0;
            if (target >= L->img->coro_count) {
                return halt(thread, L, ZBC_ERR_BAD_TARGET, in->op, 0);
            }
            if (L->depth >= ZBC_CALL_MAX_DEPTH) {
                return halt(thread, L, ZBC_ERR_CALL_DEPTH, in->op, 0);
            }
            if (L->host && L->host->bound && L->host->bound[target] && L->host->yield) {
                /* P4.8c2: a host-bound function (a mock). The host answers
                 * its result in place of the body, as an IMPORT is answered
                 * (pc stays here until then); `call`/`return` carry
                 * `mocked`, from the caller's frame, as the Python VM's do. */
                zbc_yield_t *y = L->host->yield;
                const zbc_coro *c = &L->img->coros[target];
                int evc = (zbc_ev_mask(L->host->events, target) & ZBC_EV_CALL) != 0;
                if (y->state == ZBC_YIELD_DONE && y->frame == L) {
                    uint64_t rv = y->value;
                    y->state = ZBC_YIELD_NONE;
                    y->frame = NULL;
                    y->thread = NULL;
                    if (a1 != 0xFFFFFFFFu) L->regs[a1] = rv;
                    if (evc) {
                        zbc_ev_sink_t *s = L->host->events;
                        zbc_ev_begin(s, "return", L->ev_id, in->src_ref);
                        zbc_ev_map(s, a1 != 0xFFFFFFFFu ? 4 : 3);
                        zbc_ev_key(s, "depth");
                        zbc_ev_uint(s, L->depth + 1);
                        ev_fn(s, L->img, c);
                        zbc_ev_key(s, "mocked");
                        zbc_ev_bool(s, 1);
                        if (a1 != 0xFFFFFFFFu) { zbc_ev_key(s, "retval"); zbc_ev_uint(s, rv); }
                        zbc_ev_end(s);
                    }
                    L->n_staged = 0;
                    L->pc++;
                    break;
                }
                if (y->state == ZBC_YIELD_NONE) {
                    if (evc) {
                        zbc_ev_sink_t *s = L->host->events;
                        zbc_ev_begin(s, "call", L->ev_id, in->src_ref);
                        zbc_ev_map(s, 4);
                        zbc_ev_key(s, "args");
                        zbc_ev_list(s, L->n_staged);
                        for (uint32_t i = 0; i < L->n_staged; i++) zbc_ev_uint(s, L->staged[i]);
                        zbc_ev_key(s, "depth");
                        zbc_ev_uint(s, L->depth + 1);
                        ev_fn(s, L->img, c);
                        zbc_ev_key(s, "mocked");
                        zbc_ev_bool(s, 1);
                        zbc_ev_end(s);
                    }
                    y->kind = ZBC_YIELD_BOUND;
                    y->fn_id = target;
                    y->n_args = L->n_staged;
                    for (uint32_t i = 0; i < L->n_staged; i++) y->args[i] = L->staged[i];
                    y->flags = (a1 != 0xFFFFFFFFu) ? ZBC_F_HAS_RET : 0;
                    y->is_write = 0;
                    y->addr = 0;
                    y->size = 0;
                    y->data = 0;
                    y->value = 0;
                    y->thread = thread;
                    y->frame = L;
                    y->executor = L->executor;
                    y->pc = L->coro->code_start + L->pc;
                    y->state = ZBC_YIELD_PENDING;
                }
                if (y->frame == L) thread->flags |= ZSP_THREAD_FLAGS_BLOCKED;
                else zsp_timebase_yield(thread);
                L->ev_skip_pc = L->pc;   /* the CALL runs again */
                return ret;
            }
            if (L->host && (zbc_ev_mask(L->host->events, target) & ZBC_EV_CALL)) {
                /* The callee's `call`, before it runs; it takes the next id. */
                zbc_ev_sink_t *s = L->host->events;
                const zbc_coro *c = &L->img->coros[target];
                zbc_ev_begin(s, "call", s->next_id, c->src_ref);
                zbc_ev_map(s, 3);
                zbc_ev_key(s, "args");
                zbc_ev_list(s, L->n_staged);
                for (uint32_t i = 0; i < L->n_staged; i++) zbc_ev_uint(s, L->staged[i]);
                zbc_ev_key(s, "depth");
                zbc_ev_uint(s, L->depth + 1);
                ev_fn(s, L->img, c);
                zbc_ev_end(s);
            }
            L->n_staged = 0;
            L->pc++;
            L->call_ret_reg = (a1 == 0xFFFFFFFFu) ? -1 : (int)a1;
            L->resuming_call = 1;
            L->sync_call = 1;
            zsp_frame_t *cr = zsp_timebase_call(thread, &zbc_interp_task,
                                     L->img, (int)target, (zbc_result_t *)0,
                                     L->obj, L->base, L->spawn_budget, L->host,
                                     L->seed_state, (const uint64_t *)L->staged,
                                     L->depth + 1, L->run, (uint32_t)0,
                                     L->act, L->node, L->comp, L->ar);
            L->sync_call = 0;
            if (thread->leaf != ret || (thread->flags & ZSP_THREAD_FLAGS_BLOCKED))
                return cr;   /* the callee suspended: the scheduler resumes it */
            /* The callee completed: resume here, as zsp_timebase_return would. */
            thread->flags &= ~ZSP_THREAD_FLAGS_SUSPEND;
            goto resume;
        }

        case ZBC_OP_RET: {
            uint64_t rv = (in->nargs > 0) ? L->regs[a0] : 0;
            if ((evm & ZBC_EV_CALL) && L->depth) ev_return(L, in->nargs > 0, rv);
            if (L->called && L->n_staged) {
                /* F6.4a: a struct result's leaves and the struct parameters'
                 * copy-out, staged by ARG, go to the caller (LD_RES). */
                memcpy(zsp_frame_locals(ret->prev, interp_locals_t)->results,
                       L->staged, sizeof(L->staged));
            }
            return halt(thread, L, ZBC_OK, 0, rv);
        }

        default:
            return halt(thread, L, ZBC_ERR_UNSUPPORTED_OP, in->op, 0);
        }
    }
}
