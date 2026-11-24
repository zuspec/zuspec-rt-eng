"""Functional coverage (F4.4, F4.6b): COV_SAMPLE takes the values staged by
ARG (consumed) and, in a watched coroutine, writes a ``cov`` trace record
{covg, values}; the host bins it. Both engines write the same record."""
import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc.model import ZbcModel, CoroDescriptor, Instr, Op
from zuspec.be.bc.interp.oracle import Obj
from zuspec.be.bc.trace import events as ev

from conftest import run_image
from test_events import c_events, py_events, _norm

CP = {"width": 4, "signed": False, "iff": False, "bins": []}
COVG = {"name": "A::cs", "instance": "cs", "crosses": [],
        "coverpoints": [dict(CP, name=f"cp_{i}") for i in range(4)]}


def _model():
    """root: stage 1..4 with ARG, sample covergroup 0 with them, then store
    7 to field 0 (the run goes on after the sample)."""
    code = []
    for i in range(4):
        code += [Instr(Op.CONST, args=(i,), imm=i + 1), Instr(Op.ARG, args=(i, i))]
    code += [Instr(Op.COV_SAMPLE, args=(0, 4)),
             Instr(Op.CONST, args=(4,), imm=7), Instr(Op.ST_FIELD, args=(4, 0)),
             Instr(Op.RET)]
    return ZbcModel(coros=[CoroDescriptor(name="root", code=code, blocks=[],
                                          frame_locals=[])],
                    entry_coro=0, covgs=[COVG])


def test_an_image_sampling_a_covergroup_runs(eng):
    fields = [0]
    res = run_image(eng, _model().to_bytes(), fields=fields)
    assert res.status == 0
    assert fields == [7]


def test_cov_events_match_the_python_vm(eng):
    model = _model()
    want = py_events(model, ev.EV_COV, obj=Obj(field_names=["f0"], values=[0]))
    res, got = c_events(eng, model, ev.EV_COV, fields=[0])
    assert res.status == 0
    assert [r["kind"] for r in got] == [ev.COV]
    assert got[0]["detail"] == {"covg": 0, "values": [1, 2, 3, 4]}
    assert _norm(got) == _norm(want)


def test_unwatched_samples_write_nothing(eng):
    res, got = c_events(eng, _model(), 0, fields=[0])
    assert res.status == 0 and got == []
