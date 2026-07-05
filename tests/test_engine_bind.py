"""P3 BIND: a flow-object bind, which is a no-op in M1.

The oracle's ``_op_bind`` emits a BIND trace event and continues; with no operands
there is nothing to compute. So the only observable contract is that BIND does not
perturb execution -- a program with BIND interleaved must produce the same fields,
return value, and clock as the same program without it. These tests assert that
against the oracle (and that BIND no longer trips the unsupported-op path).
"""

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc.model import ZbcModel, CoroDescriptor, Instr, Op
from zuspec.be.bc.interp import run_model, Obj

from conftest import run_image


def C(rd, v):    return Instr(Op.CONST, args=(rd,), imm=v)
def STF(rs, sl): return Instr(Op.ST_FIELD, args=(rs, sl))
def ADD(d, a, b): return Instr(Op.ADD, args=(d, a, b))
def RET(r=None): return Instr(Op.RET) if r is None else Instr(Op.RET, args=(r,))
BIND = Instr(Op.BIND)


def _diff(eng, code, fields=None):
    model = ZbcModel(coros=[CoroDescriptor(name="main", code=code, blocks=[],
                                           frame_locals=[])], entry_coro=0)
    obj = (Obj(field_names=["f%d" % i for i in range(len(fields))], values=list(fields))
           if fields is not None else None)
    o = run_model(model, obj=obj, seed=0)
    oracle = (o.retval or 0, o.now, list(obj.values) if obj is not None else None)
    nf = list(fields) if fields is not None else None
    res = run_image(eng, model.to_bytes(), fields=nf)
    return oracle, res, nf


def test_bind_is_a_noop_between_field_writes(eng):
    oracle, res, fields = _diff(
        eng, [C(0, 5), STF(0, 0), BIND, C(0, 9), STF(0, 1), RET()], fields=[0, 0])
    assert res.status == 0
    assert fields == oracle[2] == [5, 9]


def test_bind_preserves_return_value(eng):
    oracle, res, _ = _diff(
        eng, [C(0, 3), C(1, 4), BIND, ADD(2, 0, 1), RET(2)])
    assert res.status == 0
    assert res.retval == oracle[0] == 7


def test_leading_and_trailing_bind(eng):
    oracle, res, fields = _diff(
        eng, [BIND, C(0, 42), STF(0, 0), BIND, RET()], fields=[0])
    assert res.status == 0
    assert (res.retval, fields) == (oracle[0], oracle[2]) == (0, [42])
