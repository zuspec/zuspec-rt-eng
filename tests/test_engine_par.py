"""P3 orchestration (increment 2): SPAWN + JOIN-ALL (concurrent PAR).

SPAWN forks a child coroutine (its own frame, the shared object) as a new
scheduler thread; the parent continues. JOIN (imm==0) blocks the parent until
every spawned child completes, then resumes. Each child, on completion,
decrements the parent's pending count and re-schedules it at zero. Differential-
matched against the oracle (fields written, resume time = slowest branch).

FIRST(n) with surplus cancellation (imm>0) is a later increment.
"""

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc.model import ZbcModel, CoroDescriptor, Instr, Op
from zuspec.be.bc.interp import run_model, Obj

from conftest import run_image


def C(rd, v):    return Instr(Op.CONST, args=(rd,), imm=v)
def SP(target):  return Instr(Op.SPAWN, args=(target,))
def STF(rs, sl): return Instr(Op.ST_FIELD, args=(rs, sl))
def LDF(rd, sl): return Instr(Op.LD_FIELD, args=(rd, sl))
def W(t):        return Instr(Op.WAIT, imm=t)
def ADD(d, a, b): return Instr(Op.ADD, args=(d, a, b))
def RET(r=None): return Instr(Op.RET) if r is None else Instr(Op.RET, args=(r,))
JOIN = Instr(Op.JOIN, imm=0)


def _run(eng, coros, fields=None):
    model = ZbcModel(coros=[CoroDescriptor(name=n, code=c, blocks=[], frame_locals=[])
                            for (n, c) in coros], entry_coro=0)
    obj = Obj(field_names=["f%d" % i for i in range(len(fields))],
              values=list(fields)) if fields else None
    o = run_model(model, obj=obj, seed=0)
    oracle = (o.retval or 0, o.now, list(o.obj.values) if obj else None)
    nf = list(fields) if fields else None
    native = run_image(eng, model.to_bytes(), fields=nf)
    return oracle, native, nf


def test_par_all_branches_run(eng):
    # parallel { f0 = 11; f1 = 22 }
    oracle, native, fields = _run(eng, [
        ("main", [SP(1), SP(2), JOIN, RET()]),
        ("b0", [C(0, 11), STF(0, 0), RET()]),
        ("b1", [C(0, 22), STF(0, 1), RET()]),
    ], fields=[0, 0])
    assert native.status == 0
    assert fields == oracle[2] == [11, 22]


def test_par_join_waits_for_slowest_branch(eng):
    # parallel { wait 3; wait 7 } -> parent resumes at t=7
    oracle, native, _ = _run(eng, [
        ("main", [SP(1), SP(2), JOIN, RET()]),
        ("w0", [W(3), RET()]),
        ("w1", [W(7), RET()]),
    ])
    assert native.status == 0
    assert native.now == oracle[1] == 7


def test_par_result_visible_after_join(eng):
    # branches write f0=5, f1=6; after JOIN the parent returns f0+f1 = 11.
    oracle, native, fields = _run(eng, [
        ("main", [SP(1), SP(2), JOIN,
                  LDF(0, 0), LDF(1, 1), ADD(2, 0, 1), RET(2)]),
        ("b0", [C(0, 5), STF(0, 0), RET()]),
        ("b1", [C(0, 6), STF(0, 1), RET()]),
    ], fields=[0, 0])
    assert native.status == 0
    assert (native.retval, fields) == (oracle[0], oracle[2]) == (11, [5, 6])


def test_par_three_branches(eng):
    oracle, native, fields = _run(eng, [
        ("main", [SP(1), SP(2), SP(3), JOIN, RET()]),
        ("b0", [C(0, 1), STF(0, 0), RET()]),
        ("b1", [C(0, 2), STF(0, 1), RET()]),
        ("b2", [C(0, 3), STF(0, 2), RET()]),
    ], fields=[0, 0, 0])
    assert native.status == 0
    assert fields == oracle[2] == [1, 2, 3]


def test_nested_par(eng):
    # main parallel { A ; b2=f2 } where A is itself parallel { f0 ; f1 }.
    # Exercises independent join bookkeeping at two nesting levels.
    oracle, native, fields = _run(eng, [
        ("main", [SP(1), SP(4), JOIN, RET()]),   # spawn A(1) and b2(4)
        ("A",    [SP(2), SP(3), JOIN, RET()]),   # A spawns b0(2), b1(3)
        ("b0",   [C(0, 1), STF(0, 0), RET()]),
        ("b1",   [C(0, 2), STF(0, 1), RET()]),
        ("b2",   [C(0, 3), STF(0, 2), RET()]),
    ], fields=[0, 0, 0])
    assert native.status == 0
    assert fields == oracle[2] == [1, 2, 3]


def JOINn(n):      return Instr(Op.JOIN, imm=n)


def test_join_first_cancels_surplus(eng):
    # FIRST(1) { (wait 1; f0=1) ; (wait 10; f1=2) } -- branch 0 wins at t=1;
    # branch 1 is cancelled, so f1 stays 0 and its wait-10 never advances `now`.
    oracle, native, fields = _run(eng, [
        ("main", [SP(1), SP(2), JOINn(1), RET()]),
        ("b0", [W(1), C(0, 1), STF(0, 0), RET()]),
        ("b1", [W(10), C(0, 2), STF(0, 1), RET()]),
    ], fields=[0, 0])
    assert native.status == 0
    assert (native.now, fields) == (oracle[1], oracle[2]) == (1, [1, 0])


def test_join_first_n_resumes_after_n_complete(eng):
    # FIRST(2) of waits {1,5,20}, then wait 100 -> resume at t=5, end at 105;
    # the wait-20 surplus is cancelled.
    oracle, native, _ = _run(eng, [
        ("main", [SP(1), SP(2), SP(3), JOINn(2), W(100), RET()]),
        ("w1", [W(1), RET()]),
        ("w5", [W(5), RET()]),
        ("w20", [W(20), RET()]),
    ])
    assert native.status == 0
    assert native.now == oracle[1] == 105


def NBINV(target): return Instr(Op.INVOKE, args=(target,), flags=0)  # non-blocking


def test_non_blocking_invoke_is_detached(eng):
    # main fires sub without waiting (returns at t=0); the detached sub writes
    # f0=42 later in the drain. counted==0 -> no use-after-free on the freed parent.
    oracle, native, fields = _run(eng, [
        ("main", [NBINV(1), RET()]),
        ("sub", [C(0, 42), STF(0, 0), RET()]),
    ], fields=[0])
    assert native.status == 0
    assert (native.now, fields) == (oracle[1], oracle[2]) == (0, [42])


def test_spawn_without_join_detaches(eng):
    # SPAWN with no following JOIN (NONE policy): parent returns immediately; the
    # child runs in the drain (wait 5, write f0=7) -> now advances to 5.
    oracle, native, fields = _run(eng, [
        ("main", [SP(1), RET()]),
        ("c", [W(5), C(0, 7), STF(0, 0), RET()]),
    ], fields=[0])
    assert native.status == 0
    assert (native.now, fields) == (oracle[1], oracle[2]) == (5, [7])


def test_par_nested_waits(eng):
    # main parallel { (wait 5) ; A } ; A parallel { wait 2 ; wait 8 } -> now = 8
    oracle, native, _ = _run(eng, [
        ("main", [SP(1), SP(2), JOIN, RET()]),
        ("w5",   [W(5), RET()]),
        ("A",    [SP(3), SP(4), JOIN, RET()]),
        ("w2",   [W(2), RET()]),
        ("w8",   [W(8), RET()]),
    ])
    assert native.status == 0
    assert native.now == oracle[1] == 8
