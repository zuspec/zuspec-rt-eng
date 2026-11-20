"""P1.4: an activation is one object (P1-D1), and its solve scope runs.

A traversal of a node of the activation is an INVOKE with ``INSTR_F_NODE``: the
callee runs on the caller's object, ``imm`` slots past the caller's base, so
every field access and SOLVE write-back is relative to the frame's base. The
oracle and the engine must agree on that operand -- they used to disagree on
INVOKE's object altogether (the oracle gave a callee a fresh one).

An INVOKE that starts its callee past its initial values (``INSTR_F_INITED``,
traversal initializers, 11.3.1 b) runs as on the oracle: the caller has
written the initializers into the callee's slots.

``SCOPE_ENTER`` / ``SOLVE_NODE`` (the cone solve, LRM 13.4.9) run on the engine
since P4.10d1; without an activation table there is no cone, so a SOLVE_NODE
with no problem only commits and the code after it runs.
"""

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc.model import (
    ZbcModel, CoroDescriptor, Instr, Op, INSTR_F_BLOCKING, INSTR_F_NODE,
    INSTR_F_INITED,
)
from zuspec.be.bc.interp import run_model, Obj

from conftest import run_image

ZBC_ERR_UNSUPPORTED_OP = -8
ZBC_ERR_BAD_TARGET = -12


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
def test_the_activation_solve_scope_runs_without_an_activation_table(eng, op):
    ins = Instr(op, imm=0) if op == Op.SCOPE_ENTER else Instr(op, args=(0xFFFFFFFF,))
    model = _model([("root", [C(0, 9), ST(0, 0), ins, RET()])])
    fields = [0]
    res = run_image(eng, model.to_bytes(), fields=fields)
    assert res.status == 0
    assert fields == [9]


def _inited(target, child_base, start, blocking=True):
    flags = INSTR_F_NODE | INSTR_F_INITED | (INSTR_F_BLOCKING if blocking else 0)
    return Instr(Op.INVOKE, args=(target, 0, 0, start), imm=child_base, flags=flags)


# child: its default (field 0 = 5) at pc 0-1, then field 1 = field 0.
_CHILD = ("child", [C(0, 5), ST(0, 0), LD(0, 0), ST(0, 1), RET()])


@pytest.mark.parametrize("blocking", [True, False])
def test_an_initialized_traversal_starts_past_its_defaults(eng, blocking):
    # root writes the initializer 9 into the child's field 0 (slot 2) and
    # traverses it from pc 2, so the default 5 is never stored.
    tail = [RET()] if blocking else [Instr(Op.JOIN, imm=0), RET()]
    model = _model([("root", [C(0, 9), ST(0, 2), _inited(1, 2, 2, blocking)] + tail),
                    _CHILD])
    fields = [0] * 4
    o = run_model(model, obj=Obj(field_names=["f%d" % i for i in range(4)]), seed=0)
    native = run_image(eng, model.to_bytes(), fields=fields)
    assert native.status == 0
    assert fields == list(o.obj.values) == [0, 0, 9, 9]


def test_an_uninitialized_traversal_keeps_its_defaults(eng):
    model = _model([("root", [C(0, 9), ST(0, 2), NODE(1, 2), RET()]), _CHILD])
    fields = [0] * 4
    o = run_model(model, obj=Obj(field_names=["f%d" % i for i in range(4)]), seed=0)
    native = run_image(eng, model.to_bytes(), fields=fields)
    assert native.status == 0
    assert fields == list(o.obj.values) == [0, 0, 5, 5]


def test_a_start_past_the_callee_halts(eng):
    model = _model([("root", [_inited(1, 0, 99), RET()]), _CHILD])
    res = run_image(eng, model.to_bytes(), fields=[0] * 4)
    assert res.status == ZBC_ERR_BAD_TARGET
