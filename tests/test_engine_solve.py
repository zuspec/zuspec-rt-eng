"""P3 SOLVE (minimal): randomize object fields from the determinism stream.

A real constraint solver is out of scope; this iteration matches the oracle's
default ``FixedSolveBackend`` (base 0), whose reproducible mapping is
``field_slot = seed + var_id``. That is enough to prove the *serialization* + the
*seed policy* end-to-end: the SOLVE descriptor (seed kind/value + slot writeback)
now travels in the ``.zbc`` (SEC_SOLVE + shared OPLIST), and the native seed draw
matches ``be.bc.determinism``, so oracle and engine write identical field values.

The oracle keys write-back by field *name* (resolved against the live object);
the engine has only slots, so ``SolveProblem.writeback_slots`` carries the same
mapping in slot form. The tests set both consistently.
"""

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc.model import ZbcModel, CoroDescriptor, Instr, Op, SolveProblem
from zuspec.be.bc.interp import run_model, Obj

from conftest import run_image


def SOLVE(pid): return Instr(Op.SOLVE, args=(pid,))
def RET(r=None): return Instr(Op.RET) if r is None else Instr(Op.RET, args=(r,))


@pytest.fixture(autouse=True)
def _bind_eng(eng):
    global _eng
    _eng = eng
    yield


def _diff(coros, problems, fields):
    """Run oracle (FixedSolveBackend) + engine; return (oracle_fields, native_fields)."""
    model = ZbcModel(coros=[CoroDescriptor(name=n, code=c, blocks=[], frame_locals=[])
                            for (n, c) in coros], entry_coro=0)
    model.problems = problems
    obj = Obj(field_names=["f%d" % i for i in range(len(fields))], values=list(fields))
    run_model(model, obj=obj, seed=0)          # default solve_backend = FixedSolveBackend(0)
    o_fields = list(obj.values)

    nf = list(fields)
    res = run_image(_eng, model.to_bytes(), fields=nf)
    assert res.status == 0
    return o_fields, nf


def test_solve_fixed_seed_two_vars(eng):
    # fixed seed 1000; f0 = seed + var_id(0), f1 = seed + var_id(1).
    of, nf = _diff(
        [("main", [SOLVE(0), RET()])],
        [SolveProblem(var_names=["f0", "f1"], writeback={"f0": 0, "f1": 1},
                      writeback_slots={0: 0, 1: 1},
                      seed_kind="fixed", seed_value=1000)],
        fields=[0, 0])
    assert nf == of == [1000, 1001]


def test_solve_var_id_offset(eng):
    # var_id gates the per-field offset: f1's var_id is 3, so f1 = seed + 3.
    of, nf = _diff(
        [("main", [SOLVE(0), RET()])],
        [SolveProblem(var_names=["f0", "x", "y", "f1"], writeback={"f0": 0, "f1": 3},
                      writeback_slots={0: 0, 1: 3},
                      seed_kind="fixed", seed_value=10)],
        fields=[0, 0])
    assert nf == of == [10, 13]


def test_solve_inherit_seed_matches_oracle(eng):
    # inherit -> the frame draws its next raw seed (LCG from root seed 0); the exact
    # value is whatever be.bc.determinism produces, but oracle and engine must agree.
    of, nf = _diff(
        [("main", [SOLVE(0), RET()])],
        [SolveProblem(var_names=["f0", "f1"], writeback={"f0": 0, "f1": 1},
                      writeback_slots={0: 0, 1: 1})],   # seed_kind="inherit"
        fields=[0, 0])
    assert nf == of
    assert nf[0] != 0                      # a draw happened
    assert nf[1] == nf[0] + 1              # var_id offset


def test_solve_two_inherit_solves_advance_seed(eng):
    # Two inherit SOLVEs in a row draw *different* seeds (the stream advances), so
    # f0 and f1 differ; oracle and engine advance identically.
    of, nf = _diff(
        [("main", [SOLVE(0), SOLVE(1), RET()])],
        [SolveProblem(var_names=["f0"], writeback={"f0": 0}, writeback_slots={0: 0}),
         SolveProblem(var_names=["f1"], writeback={"f1": 0}, writeback_slots={1: 0})],
        fields=[0, 0])
    assert nf == of
    assert nf[0] != nf[1]                   # distinct draws -> stream advanced


def test_solve_single_field(eng):
    of, nf = _diff(
        [("main", [SOLVE(0), RET()])],
        [SolveProblem(var_names=["f0"], writeback={"f0": 0}, writeback_slots={0: 0},
                      seed_kind="fixed", seed_value=42)],
        fields=[0, 7])
    assert nf == of == [42, 7]             # only f0 written; f1 untouched


def test_solve_bad_pid_is_rejected(eng):
    # SOLVE referencing a non-existent descriptor -> engine-only BAD_SOLVE (-20).
    model = ZbcModel(coros=[CoroDescriptor(name="main", code=[SOLVE(3), RET()],
                                           blocks=[], frame_locals=[])], entry_coro=0)
    model.problems = [SolveProblem(writeback_slots={0: 0}, seed_kind="fixed", seed_value=1)]
    res = run_image(eng, model.to_bytes(), fields=[0])
    assert res.status == -20
