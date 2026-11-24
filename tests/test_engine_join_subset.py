"""join_select / join_branch (JOIN with INSTR_F_SUBSET, F8 M8b1) are the
Python engine's alone until M14: the C engine refuses the image before
running any of it, naming JOIN."""

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.ir.core import scenario as SC
from zuspec.ir.core import expr as E
from zuspec.ir.core.activity import JoinSpec, JoinKind
from zuspec.be.bc.lower import lower_scenario
from zuspec.be.bc.model import Op

from conftest import run_image

ZBC_ERR_UNSUPPORTED_OP = -8


def _wait(t):
    return SC.ScWait(time=E.ExprConstant(value=t))


@pytest.mark.parametrize("spec,branches", [
    (JoinSpec(kind=JoinKind.SELECT, count=E.ExprConstant(value=1)), []),
    (JoinSpec(kind=JoinKind.BRANCH, branch_labels=["L1"]), [0]),
])
def test_engine_refuses_subset_join(eng, spec, branches):
    coro = SC.ScCoroutine(name="root", body=[
        SC.ScPar(branches=[_wait(1), _wait(2)], join_spec=spec, join_branches=branches)])
    native = run_image(eng, lower_scenario([coro]).to_bytes())
    assert native.status == ZBC_ERR_UNSUPPORTED_OP
    assert native.halted_op == int(Op.JOIN)


def test_engine_still_runs_join_all(eng):
    coro = SC.ScCoroutine(name="root", body=[SC.ScPar(branches=[_wait(1), _wait(2)])])
    assert run_image(eng, lower_scenario([coro]).to_bytes()).status == 0
