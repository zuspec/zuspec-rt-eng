"""P3 orchestration (increment 1): blocking INVOKE == a sequential `do Sub`.

A blocking INVOKE runs the callee coroutine as a NESTED interpreted coroutine on
the caller's frame stack (`zsp_timebase_call`) -- the interpreter-as-coroutine
design across multiple frames. The callee shares the caller's object, may suspend
(WAIT) mid-call, and returns a value the caller receives. Every case is
differential-matched against the Python oracle (which models the same INVOKE as
spawn-child + parent-suspend -- same observable result).
"""

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc.model import (
    ZbcModel, CoroDescriptor, Instr, Op, INSTR_F_BLOCKING, INSTR_F_HAS_RET,
)
from zuspec.be.bc.interp import run_model, Obj

from conftest import run_image

BL, HR = INSTR_F_BLOCKING, INSTR_F_HAS_RET


def C(rd, v):          return Instr(Op.CONST, args=(rd,), imm=v)
def RET(r=None):       return Instr(Op.RET) if r is None else Instr(Op.RET, args=(r,))
def CALL(target, rd):  return Instr(Op.INVOKE, args=(target, rd), flags=BL | HR)
def CALLV(target):     return Instr(Op.INVOKE, args=(target,), flags=BL)  # void call
def ADD(d, a, b):      return Instr(Op.ADD, args=(d, a, b))


def _model(coros):
    """coros: list of (name, code, frame_locals). Entry is coro 0."""
    return ZbcModel(
        coros=[CoroDescriptor(name=n, code=c, blocks=[], frame_locals=list(fl))
               for (n, c, fl) in coros],
        entry_coro=0)


def _run(eng, coros, fields=None):
    model = _model(coros)
    obj = Obj(field_names=["f%d" % i for i in range(len(fields))],
              values=list(fields)) if fields else None
    o = run_model(model, obj=obj, seed=0)
    oracle = (o.retval or 0, o.now, list(o.obj.values) if obj else None)

    nf = list(fields) if fields else None
    native = run_image(eng, model.to_bytes(), fields=nf)
    return oracle, native, nf


def test_invoke_returns_callee_value(eng):
    # main: r0 = sub(); RET r0    sub: RET 42
    oracle, native, _ = _run(eng, [
        ("main", [CALL(1, 0), RET(0)], []),
        ("sub",  [C(0, 42), RET(0)], []),
    ])
    assert native.status == 0
    assert (native.retval, native.now) == oracle[:2] == (42, 0)


def test_invoke_callee_wait_advances_time(eng):
    # sub waits 5 then returns 7 -> the nested call suspends the caller too.
    oracle, native, _ = _run(eng, [
        ("main", [CALL(1, 0), RET(0)], []),
        ("sub",  [Instr(Op.WAIT, imm=5), C(0, 7), RET(0)], []),
    ])
    assert native.status == 0
    assert (native.retval, native.now) == oracle[:2] == (7, 5)


def test_void_invoke_shares_object(eng):
    # sub writes field0 = 99 through the shared object; void (no return).
    oracle, native, fields = _run(eng, [
        ("main", [CALLV(1), RET()], []),
        ("sub",  [C(0, 99), Instr(Op.ST_FIELD, args=(0, 0)), RET()], []),
    ], fields=[0])
    assert native.status == 0
    assert fields == oracle[2] == [99]


def test_nested_invoke(eng):
    # main -> a -> b : b returns 5, a returns b()+10=15, main returns a()+100=115
    oracle, native, _ = _run(eng, [
        ("main", [CALL(1, 0), C(1, 100), ADD(0, 0, 1), RET(0)], []),
        ("a",    [CALL(2, 0), C(1, 10), ADD(0, 0, 1), RET(0)], []),
        ("b",    [C(0, 5), RET(0)], []),
    ])
    assert native.status == 0
    assert (native.retval, native.now) == oracle[:2] == (115, 0)


def test_invoke_in_loop_accumulates(eng):
    # main calls sub() three times, summing the results; sub returns 4 each time.
    # r0=sum, r1=i, r2=limit; loop calls sub -> r3, adds to sum.
    oracle, native, _ = _run(eng, [
        ("main", [
            C(0, 0), C(1, 0), C(2, 3),
            Instr(Op.CMP_LT, args=(4, 1, 2)),      # @3 head
            Instr(Op.BRZ, args=(4, 10)),           # exit -> @10 (RET)
            CALL(1, 3),                            # r3 = sub()
            ADD(0, 0, 3),                          # sum += r3
            C(5, 1), ADD(1, 1, 5),                 # i += 1
            Instr(Op.BR, args=(3,)),
            RET(0),                                # @10
        ], []),
        ("sub", [C(0, 4), RET(0)], []),
    ])
    assert native.status == 0
    assert (native.retval, native.now) == oracle[:2] == (12, 0)


def test_invoke_bad_target_is_rejected(eng):
    # target coro index out of range -> clean error (engine-only: the oracle
    # raises IndexError for the same condition).
    model = _model([("main", [Instr(Op.INVOKE, args=(9, 0), flags=BL | HR),
                              RET(0)], [])])
    native = run_image(eng, model.to_bytes())
    assert native.status == -12   # ZBC_ERR_BAD_TARGET
