"""P3 SELECT: weighted choice drawn from the frame's determinism stream.

SELECT is the first op whose behaviour depends on the *seed stream*, so these
tests are the real proof that the native engine reproduces be.bc.determinism
bit-for-bit: because oracle and engine draw from identical LCG streams (root seed
0, children forked by fork_seed), they pick the **same** branch every time, so the
differential can assert exact field/retval equality -- not just cardinality.

The SELECT table is now serialized into the ``.zbc`` image (OPLIST + SELECT
sections), so the engine reads it from bytes just like CODE/CORO; nothing is
side-channelled the way the M1 oracle did it.
"""

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc.model import ZbcModel, CoroDescriptor, Instr, Op, SelectTable
from zuspec.be.bc.interp import run_model, Obj

from conftest import run_image, ZbcResult


def C(rd, v):    return Instr(Op.CONST, args=(rd,), imm=v)
def STF(rs, sl): return Instr(Op.ST_FIELD, args=(rs, sl))
def SEL(sid):    return Instr(Op.SELECT, args=(sid,))
def SP(target):  return Instr(Op.SPAWN, args=(target,))
def RET(r=None): return Instr(Op.RET) if r is None else Instr(Op.RET, args=(r,))
JOIN = Instr(Op.JOIN, imm=0)


def _build(coros, selects, fields):
    model = ZbcModel(coros=[CoroDescriptor(name=n, code=c, blocks=[], frame_locals=[])
                            for (n, c) in coros], entry_coro=0)
    model.selects = selects
    return model


def _diff(coros, selects, fields):
    """Run both oracle and engine; return (oracle_tuple, native_result, native_fields).

    oracle_tuple = (retval, now, fields-list). The engine mutates its own copy of
    ``fields`` in place. Callers assert the two agree exactly.
    """
    model = _build(coros, selects, fields)
    obj = Obj(field_names=["f%d" % i for i in range(len(fields))], values=list(fields))
    o = run_model(model, obj=obj, seed=0)
    oracle = (o.retval or 0, o.now, list(obj.values))

    nf = list(fields)
    native = run_image(_eng, model.to_bytes(), fields=nf)
    return oracle, native, nf


# The `eng` fixture is function-scoped; capture it for the helper via a fixture shim.
@pytest.fixture(autouse=True)
def _bind_eng(eng):
    global _eng
    _eng = eng
    yield


def test_select_matches_oracle_branch(eng):
    # SELECT { (w=1) f0=10 ; (w=3) f1=20 } -- both runtimes draw seed-0 identically
    # and MUST land on the same branch, so exactly one field is written to match.
    oracle, native, fields = _diff(
        [("main", [SEL(0), RET()]),
         ("b0", [C(0, 10), STF(0, 0), RET()]),
         ("b1", [C(0, 20), STF(0, 1), RET()])],
        [SelectTable(branches=[1, 2], weights=[1, 3], guards=[], allow_none=False)],
        fields=[0, 0])
    assert native.status == 0
    assert fields == oracle[2]
    # Exactly one branch ran (the other field stays 0).
    assert (fields[0] != 0) ^ (fields[1] != 0)


def test_select_three_branches(eng):
    oracle, native, fields = _diff(
        [("main", [SEL(0), RET()]),
         ("b0", [C(0, 1), STF(0, 0), RET()]),
         ("b1", [C(0, 1), STF(0, 1), RET()]),
         ("b2", [C(0, 1), STF(0, 2), RET()])],
        [SelectTable(branches=[1, 2, 3], weights=[5, 7, 11], guards=[], allow_none=False)],
        fields=[0, 0, 0])
    assert native.status == 0
    assert fields == oracle[2]
    assert sum(fields) == 1               # exactly one branch fired


def test_select_guard_forces_branch(eng):
    # r0 is a guard: main sets r0=0 so branch 0 is ineligible; only branch 1 is
    # eligible -> it must run regardless of the draw. Both runtimes agree.
    oracle, native, fields = _diff(
        [("main", [C(0, 0), SEL(0), RET()]),   # r0 = 0 (disables branch 0)
         ("b0", [C(0, 10), STF(0, 0), RET()]),
         ("b1", [C(0, 20), STF(0, 1), RET()])],
        [SelectTable(branches=[1, 2], weights=[1, 1], guards=[0, -1], allow_none=False)],
        fields=[0, 0])
    assert native.status == 0
    assert fields == oracle[2] == [0, 20]


def test_select_guard_enables_branch(eng):
    # r0=1 enables the guarded branch 0; with branch 1 weight 0-eligible... use a
    # guard on branch 1 that is false, leaving only branch 0 eligible.
    oracle, native, fields = _diff(
        [("main", [C(0, 1), C(1, 0), SEL(0), RET()]),  # r0=1 (enable b0), r1=0 (disable b1)
         ("b0", [C(0, 10), STF(0, 0), RET()]),
         ("b1", [C(0, 20), STF(0, 1), RET()])],
        [SelectTable(branches=[1, 2], weights=[1, 1], guards=[0, 1], allow_none=False)],
        fields=[0, 0])
    assert native.status == 0
    assert fields == oracle[2] == [10, 0]


def test_select_allow_none_runs_nothing(eng):
    # All branches guarded-off; allow_none -> the SELECT is a no-op, nothing runs.
    oracle, native, fields = _diff(
        [("main", [C(0, 0), SEL(0), C(1, 99), STF(1, 0), RET()]),  # r0=0 disables both
         ("b0", [C(0, 10), STF(0, 1), RET()]),
         ("b1", [C(0, 20), STF(0, 1), RET()])],
        [SelectTable(branches=[1, 2], weights=[1, 1], guards=[0, 0], allow_none=True)],
        fields=[0, 0])
    assert native.status == 0
    # main continued past the SELECT and wrote f0=99; no branch touched f1.
    assert fields == oracle[2] == [99, 0]


def test_select_no_eligible_is_rejected(eng):
    # All branches guarded-off and allow_none is false -> the engine reports
    # ZBC_ERR_SELECT_NONE (-18). (The oracle raises VMError here, so this is an
    # engine-only assertion, matching the invoke-bad-target precedent.)
    model = _build(
        [("main", [C(0, 0), SEL(0), RET()]),
         ("b0", [C(0, 10), STF(0, 0), RET()]),
         ("b1", [C(0, 20), STF(0, 1), RET()])],
        [SelectTable(branches=[1, 2], weights=[1, 1], guards=[0, 0], allow_none=False)],
        fields=[0, 0])
    res = run_image(eng, model.to_bytes(), fields=[0, 0])
    assert res.status == -18


def test_select_inside_spawned_child(eng):
    # A spawned child does the SELECT: its seed is fork_seed(parent, idx), so this
    # proves the native fork rule aligns with the oracle for a *forked* stream, not
    # just the root. main spawns A (coro 1) and joins; A selects among b0/b1.
    oracle, native, fields = _diff(
        [("main", [SP(1), JOIN, RET()]),
         ("A",    [SEL(0), RET()]),
         ("b0",   [C(0, 7), STF(0, 0), RET()]),
         ("b1",   [C(0, 9), STF(0, 1), RET()])],
        [SelectTable(branches=[2, 3], weights=[2, 5], guards=[], allow_none=False)],
        fields=[0, 0])
    assert native.status == 0
    assert fields == oracle[2]
    assert (fields[0] != 0) ^ (fields[1] != 0)


def test_select_branch_may_wait(eng):
    # The chosen branch itself WAITs, so the SELECT-as-blocking-call must suspend
    # and resume across time -- and `now` must match the oracle's.
    oracle, native, fields = _diff(
        [("main", [SEL(0), RET()]),
         ("b0", [Instr(Op.WAIT, imm=4), C(0, 1), STF(0, 0), RET()]),
         ("b1", [Instr(Op.WAIT, imm=9), C(0, 2), STF(0, 1), RET()])],
        [SelectTable(branches=[1, 2], weights=[1, 1], guards=[], allow_none=False)],
        fields=[0, 0])
    assert native.status == 0
    assert fields == oracle[2]
    assert native.now == oracle[1]
