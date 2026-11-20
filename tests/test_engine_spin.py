"""A channel's blocking wait: "while not ready: YIELD" with the SPIN flag
(bc procedural gaps B-D4), and the deadlock check around it.

A SPIN yield reached again from its own resume made no progress. When every
ready thread is in that state, only time can change anything: the run
advances to the next timed thread, or, with none, stops as a deadlock (the
oracle raises). The engine and the oracle must agree on the values, the end
time and the failure.
"""

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc.model import ZbcModel, CoroDescriptor, Instr, Op, INSTR_F_SPIN
from zuspec.be.bc.interp import run_model, Obj
from zuspec.be.bc.interp.vm import VMError

from conftest import run_image

ZBC_ERR_DEADLOCK = -27


def C(rd, v):    return Instr(Op.CONST, args=(rd,), imm=v)
def SP(target):  return Instr(Op.SPAWN, args=(target,))
def STF(rs, sl): return Instr(Op.ST_FIELD, args=(rs, sl))
def LDF(rd, sl): return Instr(Op.LD_FIELD, args=(rd, sl))
def W(t):        return Instr(Op.WAIT, imm=t)
def RET(r=None): return Instr(Op.RET) if r is None else Instr(Op.RET, args=(r,))
JOIN = Instr(Op.JOIN, imm=0)
YIELD = Instr(Op.YIELD)


def get(src, dst):
    """Spin until field `src` is non-zero, then copy it to field `dst`."""
    return [LDF(0, src),                              # @0
            Instr(Op.BRZ, args=(0, 3)),               # empty -> wait
            Instr(Op.BR, args=(5,)),                  # ready -> take
            Instr(Op.YIELD, flags=INSTR_F_SPIN),      # @3
            Instr(Op.BR, args=(0,)),
            STF(0, dst), RET()]                       # @5


def _model(coros):
    return ZbcModel(coros=[CoroDescriptor(name=n, code=c, blocks=[], frame_locals=[])
                           for (n, c) in coros], entry_coro=0)


def _run(eng, model, nfields):
    obj = Obj(field_names=["f%d" % i for i in range(nfields)], values=[0] * nfields)
    o = run_model(model, obj=obj, seed=0)
    fields = [0] * nfields
    native = run_image(eng, model.to_bytes(), fields=fields)
    return o, native, fields


def test_a_wait_on_a_timed_put_advances_time(eng):
    # parallel { get f0 -> f1; { wait 5; f0 = 7 } }
    model = _model([("main", [SP(1), SP(2), JOIN, RET()]),
                    ("get", get(0, 1)),
                    ("put", [W(5), C(0, 7), STF(0, 0), RET()])])
    o, native, fields = _run(eng, model, 2)
    assert native.status == 0
    assert fields == list(o.obj.values) == [7, 7]
    assert native.now == o.now == 5


def test_two_waiters_and_a_ready_producer(eng):
    # The producer yields (not SPIN) twice before it puts: no deadlock yet.
    model = _model([("main", [SP(1), SP(2), SP(3), JOIN, RET()]),
                    ("get1", get(0, 1)),
                    ("get2", get(0, 2)),
                    ("put", [YIELD, YIELD, C(0, 9), STF(0, 0), RET()])])
    o, native, fields = _run(eng, model, 3)
    assert native.status == 0
    assert fields == list(o.obj.values) == [9, 9, 9]
    assert native.now == o.now == 0


def test_a_wait_nothing_can_satisfy_is_a_deadlock(eng):
    model = _model([("main", [SP(1), SP(2), JOIN, RET()]),
                    ("get", get(0, 1)),
                    ("idle", [W(3), RET()])])
    with pytest.raises(VMError, match="deadlock"):
        run_model(model, obj=Obj(field_names=["f0", "f1"], values=[0, 0]), seed=0)
    fields = [0, 0]
    native = run_image(eng, model.to_bytes(), fields=fields)
    assert native.status == ZBC_ERR_DEADLOCK
    assert native.halted_op == int(Op.YIELD)
    assert native.now == 3
    assert fields == [0, 0]
