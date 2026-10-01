"""P1.4: an activation is one object (P1-D1), and its solve scope is refused.

A traversal of a node of the activation is an INVOKE with ``INSTR_F_NODE``: the
callee runs on the caller's object, ``imm`` slots past the caller's base, so
every field access and SOLVE write-back is relative to the frame's base. The
oracle and the engine must agree on that operand -- they used to disagree on
INVOKE's object altogether (the oracle gave a callee a fresh one).

``SCOPE_ENTER`` / ``SOLVE_NODE`` (the cone solve, LRM 13.4.9) and an INVOKE
that starts its callee past its initial values (``INSTR_F_INITED``, traversal
initializers, 11.3.1 b) run on the oracle only until P8: the engine refuses an
image that uses them before running any of it, naming the opcode (P1-D6),
instead of running it with the cone constraints or initializers dropped.
"""

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc.model import (
    ZbcModel, CoroDescriptor, Instr, Op, INSTR_F_BLOCKING, INSTR_F_NODE,
    INSTR_F_INITED, INSTR_F_SPIN,
)
from zuspec.be.bc.interp import run_model, Obj

from conftest import run_image

ZBC_ERR_UNSUPPORTED_OP = -8


def C(rd, v):
    return Instr(Op.CONST, args=(rd,), imm=v)


def ST(rs, slot):
    return Instr(Op.ST_FIELD, args=(rs, slot))


def LD(rd, slot):
    return Instr(Op.LD_FIELD, args=(rd, slot))


def NODE(target, child_base, site=0):
    return Instr(Op.INVOKE, args=(target, 0, site), imm=child_base,
                 flags=INSTR_F_BLOCKING | INSTR_F_NODE)


def RET():
    return Instr(Op.RET)


def _model(coros):
    return ZbcModel(
        coros=[CoroDescriptor(name=n, code=c, blocks=[], frame_locals=[])
               for (n, c) in coros],
        entry_coro=0)


def test_a_node_runs_at_its_base_on_the_callers_object(eng):
    # root: field 0 = 1; traverse a child at +2; the child writes its field 1
    # (slot 3) and traverses a grandchild at +1 (slot 3 + ...): the grandchild
    # copies its field 0 (slot 3) to its field 1 (slot 4).
    model = _model([
        ("root",  [C(0, 1), ST(0, 0), NODE(1, 2), RET()]),
        ("child", [C(0, 7), ST(0, 1), NODE(2, 1), RET()]),
        ("grand", [LD(0, 0), ST(0, 1), RET()]),
    ])
    fields = [0] * 5
    o = run_model(model, obj=Obj(field_names=["f%d" % i for i in range(5)]), seed=0)
    native = run_image(eng, model.to_bytes(), fields=fields)
    assert native.status == 0
    assert fields == list(o.obj.values) == [1, 0, 0, 7, 7]


@pytest.mark.parametrize("op", [Op.SCOPE_ENTER, Op.SOLVE_NODE])
def test_the_activation_solve_scope_is_refused_before_anything_runs(eng, op):
    ins = Instr(op, imm=0) if op == Op.SCOPE_ENTER else Instr(op, args=(0xFFFFFFFF,))
    model = _model([("root", [C(0, 9), ST(0, 0), ins, RET()])])
    fields = [0]
    res = run_image(eng, model.to_bytes(), fields=fields)
    assert res.status == ZBC_ERR_UNSUPPORTED_OP
    assert res.halted_op == int(op)
    assert fields == [0]          # refused at load: the store never ran


def test_an_initialized_traversal_is_refused_before_anything_runs(eng):
    inited = Instr(Op.INVOKE, args=(1, 0, 0, 0), imm=0,
                   flags=INSTR_F_BLOCKING | INSTR_F_NODE | INSTR_F_INITED)
    model = _model([("root", [C(0, 9), ST(0, 0), inited, RET()]),
                    ("child", [RET()])])
    fields = [0]
    res = run_image(eng, model.to_bytes(), fields=fields)
    assert res.status == ZBC_ERR_UNSUPPORTED_OP
    assert res.halted_op == int(Op.INVOKE)
    assert fields == [0]


def test_a_spin_yield_is_refused_before_anything_runs(eng):
    """A blocking channel wait (bc procedural gaps B-D4): its deadlock check is
    the oracle's, so the engine refuses it rather than risk spinning."""
    model = _model([("root", [C(0, 9), ST(0, 0),
                              Instr(Op.YIELD, flags=INSTR_F_SPIN), RET()])])
    fields = [0]
    res = run_image(eng, model.to_bytes(), fields=fields)
    assert res.status == ZBC_ERR_UNSUPPORTED_OP
    assert res.halted_op == int(Op.YIELD)
    assert fields == [0]
