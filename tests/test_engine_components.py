"""P1.5: the component tree is refused by the engine until P8 (P1-D6).

Component attributes live in a second object, the component object, read and
written by ``LD_COMP`` / ``ST_COMP`` relative to the frame's component
instance, and a coroutine constructs the tree (initial values, ``init_down``,
``init_up``) before the entry runs. The engine implements neither: it refuses
an image that uses the ops, naming the opcode, and an image that constructs a
component tree (header flag ``ZBC_HDR_COMP_INIT``) -- even one whose init
blocks only call imports, so their side effects are never silently lost.
"""

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc.model import ZbcModel, CoroDescriptor, Instr, Op

from conftest import run_image

ZBC_ERR_UNSUPPORTED_OP = -8
ZBC_ERR_COMP_INIT = -23


def C(rd, v):
    return Instr(Op.CONST, args=(rd,), imm=v)


def ST(rs, slot):
    return Instr(Op.ST_FIELD, args=(rs, slot))


def _model(coros, comp_init=False):
    return ZbcModel(
        coros=[CoroDescriptor(name=n, code=c, blocks=[], frame_locals=[])
               for (n, c) in coros],
        entry_coro=0, comp_init=comp_init)


@pytest.mark.parametrize("op", [Op.LD_COMP, Op.ST_COMP])
def test_a_component_attribute_access_is_refused_before_anything_runs(eng, op):
    model = _model([("root", [C(0, 9), ST(0, 0), Instr(op, args=(0, 0)),
                              Instr(Op.RET)])])
    fields = [0]
    res = run_image(eng, model.to_bytes(), fields=fields)
    assert res.status == ZBC_ERR_UNSUPPORTED_OP
    assert res.halted_op == int(op)
    assert fields == [0]


def test_an_image_constructing_a_component_tree_is_refused(eng):
    model = _model([("root", [C(0, 9), ST(0, 0), Instr(Op.RET)]),
                    ("$comp_init", [Instr(Op.RET)])], comp_init=True)
    data = model.to_bytes()
    assert ZbcModel.from_bytes(data).comp_init
    fields = [0]
    res = run_image(eng, data, fields=fields)
    assert res.status == ZBC_ERR_COMP_INIT
    assert fields == [0]
