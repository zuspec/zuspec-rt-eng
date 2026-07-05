"""P3 SOLVE (real): the native engine drives the dv-solve constraint solver.

Unlike the minimal randomizer (``slot = seed + var_id``), this path carries a
relocatable dv-solve ``SolveProblem`` blob in the image's SPROB pool. The engine
compiles + solves it with the frame's drawn seed and writes
``solver_get_value(var_id)`` back to each object slot.

The differential holds because *both* sides drive the identical solver on the
identical problem bytes with the identical seed:

* native -- engine links libdv_solve, ``zbc_solver_run`` compiles + solves;
* oracle -- ``run_model`` with a backend that drives the same ``SolveCtx`` on
  ``problem.problem_bytes`` and returns ``{var_name: get_value(var_id)}``.

The seed contract is the one already proven for the minimal path: fixed ->
``seed_value``; inherit -> the frame's next raw draw (LCG, matching
``be.bc.determinism``), forked for spawned children. Same solver + same bytes +
same seed => identical fields.

Both the native link and the oracle backend need libdv_solve; the ``dv`` fixture
builds it (session-scoped) and skips the module when the toolchain is absent.
"""

import ctypes
import os

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc.model import ZbcModel, CoroDescriptor, Instr, Op, SolveProblem
from zuspec.be.bc.interp import run_model, Obj
from zuspec.be.bc.interp.extern import SolveBackend

from conftest import run_image


# --- ops ------------------------------------------------------------------ #

def SOLVE(pid):  return Instr(Op.SOLVE, args=(pid,))
def SP(target):  return Instr(Op.SPAWN, args=(target,))
def RET(r=None): return Instr(Op.RET) if r is None else Instr(Op.RET, args=(r,))
JOIN = Instr(Op.JOIN, imm=0)


@pytest.fixture(autouse=True)
def _bind_eng(eng):
    global _eng
    _eng = eng
    yield


@pytest.fixture
def dv(dvsolve):
    """dv-solve (problem, ctx) modules bound to the session-built libdv_solve."""
    if dvsolve is None:
        pytest.skip("libdv_solve unavailable (cmake / C toolchain missing)")
    # Point the Python wrapper at the *same* build the engine linked, so oracle and
    # native are byte-for-byte the same solver.
    os.environ["ZSP_SOLVER_PATH"] = str(dvsolve)
    problem = pytest.importorskip("dv_solve.problem")
    builder = pytest.importorskip("dv_solve.builder")
    cx = pytest.importorskip("dv_solve.ctx")
    from dv_solve.lib import _load_lib
    if _load_lib() is None:
        pytest.skip("libdv_solve failed to load from the session build")
    return problem, cx, builder


class _BlobBackend(SolveBackend):
    """Oracle SOLVE backend: drive the real SolveCtx on the problem blob."""

    def __init__(self, cx):
        self._cx = cx

    def randomize(self, obj, problem, seed):
        blob = problem.problem_bytes
        raw = (ctypes.c_uint8 * len(blob)).from_buffer_copy(blob)
        ctx = self._cx.SolveCtx(raw)
        try:
            rc = ctx.solve(seed=seed)
            if rc != self._cx.SOLVE_OK:
                raise RuntimeError("oracle solve failed rc=%d" % rc)
            vids = sorted(set(problem.writeback.values()))
            return {problem.var_names[v]: ctx.get_value(v) for v in vids}
        finally:
            ctx.destroy()


# --- model assembly ------------------------------------------------------- #

def _problem(blob: bytes, writeback_slots, seed_kind="inherit", seed_value=0):
    """Build a SolveProblem carrying ``blob`` + both writeback keyings.

    ``writeback_slots`` is {obj_slot: var_id}. The oracle keys write-back by field
    name; we name var ``v<var_id>`` and field ``f<slot>`` so both agree. var_names
    is indexed by var_id (the backend's return key). Defaults to ``inherit`` so the
    frame's seed stream drives the solve unless a fixed seed is requested.
    """
    max_vid = max(writeback_slots.values())
    var_names = ["v%d" % i for i in range(max_vid + 1)]
    writeback = {"f%d" % slot: vid for slot, vid in writeback_slots.items()}
    return SolveProblem(var_names=var_names, writeback=writeback,
                        writeback_slots=dict(writeback_slots),
                        seed_kind=seed_kind, seed_value=seed_value,
                        problem_bytes=blob)


def _diff(dv, coros, problems, fields):
    """Run oracle (real backend) + native engine; return (oracle_fields, native)."""
    _, cx, _ = dv
    model = ZbcModel(coros=[CoroDescriptor(name=n, code=c, blocks=[], frame_locals=[])
                            for (n, c) in coros], entry_coro=0)
    model.problems = problems
    obj = Obj(field_names=["f%d" % i for i in range(len(fields))], values=list(fields))
    run_model(model, obj=obj, seed=0, solve_backend=_BlobBackend(cx))
    o_fields = list(obj.values)

    nf = list(fields)
    res = run_image(_eng, model.to_bytes(), fields=nf)
    assert res.status == 0, "native status %d" % res.status
    return o_fields, nf


# --- problem builders ----------------------------------------------------- #

def _p_single_range(dv, lo, hi):
    problem, _, builder = dv
    sp = builder.SolveProblemBuilder()
    sp.add_var(0, 32, False, lo, hi)
    return sp.finalize_bytes()


def _p_sum(dv):
    """v0 in [0,100], v1 in [0,100], v0 + v1 == 42, v0 >= 10."""
    problem, _, builder = dv
    sp = builder.SolveProblemBuilder()
    sp.add_var(0, 32, False, 0, 100)
    sp.add_var(1, 32, False, 0, 100)
    sp.add_constraint(sp.expr_binary(problem.BIN_EQ,
        sp.expr_binary(problem.BIN_ADD, sp.expr_var(0), sp.expr_var(1)),
        sp.expr_const(42)))
    sp.add_constraint(sp.expr_binary(problem.BIN_GTE, sp.expr_var(0), sp.expr_const(10)))
    return sp.finalize_bytes()


def _p_unsat(dv):
    """v0 in [0,5] AND v0 > 10 -- unsatisfiable."""
    problem, _, builder = dv
    sp = builder.SolveProblemBuilder()
    sp.add_var(0, 32, False, 0, 5)
    sp.add_constraint(sp.expr_binary(problem.BIN_GT, sp.expr_var(0), sp.expr_const(10)))
    return sp.finalize_bytes()


# --- tests ---------------------------------------------------------------- #

def test_real_solve_single_var_in_range(dv):
    of, nf = _diff(dv, [("main", [SOLVE(0), RET()])],
                   [_problem(_p_single_range(dv, 10, 90), {0: 0},
                             seed_kind="fixed", seed_value=1234)],
                   fields=[0, 7])
    assert nf == of                     # oracle and engine agree exactly
    assert 10 <= nf[0] <= 90            # constraint (range) satisfied
    assert nf[1] == 7                   # unwritten slot untouched


def test_real_solve_sum_constraint_fixed_seed(dv):
    blob = _p_sum(dv)
    of, nf = _diff(dv, [("main", [SOLVE(0), RET()])],
                   [_problem(blob, {0: 0, 1: 1}, seed_kind="fixed", seed_value=7)],
                   fields=[0, 0])
    assert nf == of
    assert nf[0] + nf[1] == 42 and nf[0] >= 10     # constraints hold
    # Also pin against a standalone solve of the same bytes + seed (real values).
    _, cx, _ = dv
    raw = (ctypes.c_uint8 * len(blob)).from_buffer_copy(blob)
    ctx = cx.SolveCtx(raw)
    assert ctx.solve(seed=7) == cx.SOLVE_OK
    assert [ctx.get_value(0), ctx.get_value(1)] == nf
    ctx.destroy()


def test_real_solve_inherit_seed_matches_oracle(dv):
    # inherit -> the frame draws its next raw seed off the root stream; oracle and
    # engine must draw the same seed and hence solve to the same assignment.
    of, nf = _diff(dv, [("main", [SOLVE(0), RET()])],
                   [_problem(_p_sum(dv), {0: 0, 1: 1})],   # seed_kind="inherit"
                   fields=[0, 0])
    assert nf == of
    assert nf[0] + nf[1] == 42 and nf[0] >= 10


def test_real_solve_two_solves_advance_stream(dv):
    # Two inherit solves of the same one-var range draw different seeds -> (almost
    # surely) different values; oracle and engine advance the stream identically.
    of, nf = _diff(dv,
                   [("main", [SOLVE(0), SOLVE(1), RET()])],
                   [_problem(_p_single_range(dv, 0, 1_000_000), {0: 0}),
                    _problem(_p_single_range(dv, 0, 1_000_000), {1: 0})],
                   fields=[0, 0])
    assert nf == of
    assert nf[0] != nf[1]              # distinct draws -> stream advanced


def test_real_solve_inside_spawned_child(dv):
    # A spawned child runs the SOLVE; its seed is fork_seed(parent, idx). This proves
    # the native fork rule feeds the solver the same seed as the oracle for a forked
    # stream, not just the root.
    of, nf = _diff(dv,
                   [("main", [SP(1), JOIN, RET()]),
                    ("child", [SOLVE(0), RET()])],
                   [_problem(_p_sum(dv), {0: 0, 1: 1})],
                   fields=[0, 0])
    assert nf == of
    assert nf[0] + nf[1] == 42 and nf[0] >= 10


def test_real_solve_unsat_is_rejected(dv):
    # An unsatisfiable problem -> engine reports ZBC_ERR_SOLVE_UNSAT (-21). (The
    # oracle backend would raise, so this is an engine-only assertion, like bad-pid.)
    _, cx, _ = dv
    blob = _p_unsat(dv)
    raw = (ctypes.c_uint8 * len(blob)).from_buffer_copy(blob)
    # dv-solve detects this at compile time (bound tightening empties the domain),
    # which the Python wrapper surfaces as CompileUnsatError from SolveCtx().
    with pytest.raises(cx.CompileUnsatError):
        cx.SolveCtx(raw)

    # The engine sees solver_compile() return -2 and reports ZBC_ERR_SOLVE_UNSAT.
    model = ZbcModel(coros=[CoroDescriptor(name="main", code=[SOLVE(0), RET()],
                                           blocks=[], frame_locals=[])], entry_coro=0)
    model.problems = [_problem(blob, {0: 0}, seed_kind="fixed", seed_value=1)]
    res = run_image(_eng, model.to_bytes(), fields=[0])
    assert res.status == -21                        # ZBC_ERR_SOLVE_UNSAT
