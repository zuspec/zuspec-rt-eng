"""P1.5 / P4.2a: the component object and its construction in the engine.

Component attributes live in a second object, the component object, read and
written by ``LD_COMP`` / ``ST_COMP`` relative to the frame's component
instance, and a coroutine constructs the tree (initial values, ``init_down``,
``init_up``) before the entry runs. The image's COMP section carries the
object's size, that coroutine and each instance's base; the engine runs the
coroutine to completion before the entry and matches the oracle. Without a
COMP section it refuses the ops (naming the opcode) and an image that
constructs a tree (header flag ``ZBC_HDR_COMP_INIT``), so an init block's side
effects are never silently lost; so it does when an activation node runs in an
instance other than instance 0 (``ZBC_COMP_F_NODE_INST``), until frames carry
their instance.
"""

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc.model import ZbcModel, CoroDescriptor, Instr, Op

from zuspec.be.bc.format import spec
from zuspec.be.bc.format.emit_dataclass import CLASSES as REC
from zuspec.be.bc.interp import run_model
from zuspec.be.bc.interp.components import CompTable

from conftest import run_image

ZBC_ERR_UNSUPPORTED_OP = -8
ZBC_ERR_COMP_INIT = -23
ZBC_ERR_OOB_COMP = -26


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


def _acts(comp, comp_slot=None):
    """A two-node activation: the root, and a child that runs in the
    instances *comp* (``comp_slot`` holding the choice when more than one),
    traversed from the root's site 0."""
    from zuspec.be.bc.interp.activation import ActivationTable
    from zuspec.ir.core import scenario as SC
    tree = SC.ScActionTree(root="T", type_qname="T", size=8, nodes=[
        SC.ScActionNode(id=0, type_qname="T", size=1, children=[1]),
        SC.ScActionNode(id=1, path="c", type_qname="C", base=1, size=1, parent=0,
                        comp=list(comp), comp_slot=comp_slot)],
        scopes=[SC.ScActivityScope(id=0, kind=SC.ScopeKind.ACTIVITY, node=0)],
        sites=[SC.ScTraversalSite(id=0, owner=0, target=1, scope=0)])
    return ActivationTable(tree, [""] * 8, {})


def _comps(n_slots, bases, init_coro):
    t = CompTable.__new__(CompTable)
    t.names = [f"a{i}" for i in range(n_slots)]
    t.bases, t.init_coro = list(bases), init_coro
    t.paths = [""] * len(bases)
    t.types = [""] * len(bases)
    return t


def _with_comps(coros, n_slots=4, bases=(0, 2), init=True):
    model = _model(coros, comp_init=init)
    model.components = _comps(n_slots, bases, 1 if init else None)
    return model


def _counter():
    """$comp_init sets a2 = 7; root: a0 = a2 + 5, returns a0 (12)."""
    return _with_comps([
        ("root", [Instr(Op.LD_COMP, args=(0, 2)), C(1, 5),
                  Instr(Op.ADD, args=(2, 0, 1)), Instr(Op.ST_COMP, args=(2, 0)),
                  Instr(Op.LD_COMP, args=(3, 0)), Instr(Op.RET, args=(3,))]),
        ("$comp_init", [C(0, 7), Instr(Op.ST_COMP, args=(0, 2)), Instr(Op.RET)]),
    ])


def test_the_comp_section_carries_size_construction_and_bases():
    data = _counter().to_bytes()
    from zuspec.be.bc.format.reader import read_image
    sec = [s for s in read_image(data).sections
           if s.kind == spec.sec_kind("ZBC_SEC_COMP")]
    assert len(sec) == 1
    rec = REC["zbc_comp"].from_bytes(sec[0].payload)
    assert (rec.n_slots, rec.init_coro, rec.n_inst, rec.flags) == (4, 1, 2, 0)
    assert sec[0].payload[16:24] == bytes([0, 0, 0, 0, 2, 0, 0, 0])


def test_construction_runs_before_the_entry_and_matches_the_oracle(eng):
    model = _counter()
    res = run_image(eng, model.to_bytes())
    assert res.status == 0
    assert res.retval == run_model(model).retval == 12


def test_component_attributes_without_construction(eng):
    model = _with_comps([("root", [C(0, 3), Instr(Op.ST_COMP, args=(0, 3)),
                                   Instr(Op.LD_COMP, args=(1, 3)),
                                   Instr(Op.ADD, args=(2, 1, 1)),
                                   Instr(Op.RET, args=(2,))])], init=False)
    res = run_image(eng, model.to_bytes())
    assert res.status == 0
    assert res.retval == run_model(model).retval == 6


def test_a_slot_past_the_component_object_halts(eng):
    model = _with_comps([("root", [Instr(Op.LD_COMP, args=(0, 4)),
                                   Instr(Op.RET)])], init=False)
    res = run_image(eng, model.to_bytes())
    assert res.status == ZBC_ERR_OOB_COMP
    assert res.halted_op == int(Op.LD_COMP)


def test_a_node_in_another_instance_runs_there(eng):
    """P4.10c4: the activity table says which instance a node runs in; the
    child (traversed from the root's site 0) writes a0 of instance 1 (slot
    2), as on the Python VM."""
    from zuspec.be.bc.model import INSTR_F_BLOCKING, INSTR_F_NODE
    model = _with_comps([
        ("root", [Instr(Op.INVOKE, args=(2, 0, 0, 0), imm=1,
                        flags=INSTR_F_BLOCKING | INSTR_F_NODE),
                  Instr(Op.LD_COMP, args=(3, 2)), Instr(Op.RET, args=(3,))]),
        ("$comp_init", [C(0, 7), Instr(Op.ST_COMP, args=(0, 2)), Instr(Op.RET)]),
        ("C", [C(0, 9), Instr(Op.ST_COMP, args=(0, 0)), Instr(Op.RET)]),
    ])
    model.activations = {0: _acts([1])}
    res = run_image(eng, model.to_bytes())
    assert res.status == 0
    assert res.retval == run_model(model).retval == 9


def test_a_node_in_another_instance_needs_the_activity_table(eng):
    """Without an ACT section the engine cannot say which instance runs a
    node (ZBC_COMP_F_NODE_INST set), so the image is refused."""
    data = _counter().to_bytes()
    from zuspec.be.bc.format.reader import read_image
    p = [s.payload for s in read_image(data).sections
         if s.kind == spec.sec_kind("ZBC_SEC_COMP")][0]
    rec = REC["zbc_comp"].from_bytes(p)
    rec.flags |= spec.flag_value("zbc_comp_flags", "ZBC_COMP_F_NODE_INST")
    at = data.index(bytes(p))
    data = data[:at] + rec.to_bytes() + data[at + REC["zbc_comp"].size():]
    assert run_image(eng, data).status == ZBC_ERR_COMP_INIT
