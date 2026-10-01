"""CALL / ARG / LD_ARG: a recursive function, called rather than inlined
(bc procedural gaps B-D5).

The caller stages each argument with ARG, CALL runs the callee nested on the
caller's thread (it shares the caller's object and base, and forks no seed),
and the callee reads its arguments with LD_ARG; RET's value lands in CALL's
result register. The oracle and the engine must agree, including on the depth
limit.
"""

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc.model import (ZbcModel, CoroDescriptor, Instr, Op,
                                CALL_MAX_DEPTH)
from zuspec.be.bc.interp import run_model
from zuspec.be.bc.interp.vm import VMError

from conftest import run_image

ZBC_ERR_CALL_DEPTH = -24
VOID = 0xFFFFFFFF


def C(rd, v):
    return Instr(Op.CONST, args=(rd,), imm=v)


def _model(coros):
    return ZbcModel(
        coros=[CoroDescriptor(name=n, code=c, blocks=[], frame_locals=[])
               for (n, c) in coros],
        entry_coro=0)


def _fact(n):
    """root: fact(n); fact(k) = k <= 1 ? 1 : k * fact(k - 1)."""
    return _model([
        ("root", [C(0, n), Instr(Op.ARG, args=(0, 0)), Instr(Op.CALL, args=(1, 1)),
                  Instr(Op.RET, args=(1,))]),
        ("fact", [Instr(Op.LD_ARG, args=(0, 0)), C(1, 1),
                  Instr(Op.CMP_LE, args=(2, 0, 1)), Instr(Op.BRZ, args=(2, 5)),
                  Instr(Op.RET, args=(1,)),
                  Instr(Op.SUB, args=(3, 0, 1)), Instr(Op.ARG, args=(3, 0)),
                  Instr(Op.CALL, args=(1, 4)), Instr(Op.MUL, args=(5, 0, 4)),
                  Instr(Op.RET, args=(5,))]),
    ])


@pytest.mark.parametrize("n,want", [(1, 1), (5, 120), (12, 479001600)])
def test_a_recursive_call_matches_the_oracle(eng, n, want):
    model = _fact(n)
    native = run_image(eng, model.to_bytes())
    assert native.status == 0
    assert native.retval == run_model(model).retval == want


def _deep():
    """deep(k) = k == 0 ? 0 : 1 + deep(k - 1); arguments 0 and 1 staged."""
    return [Instr(Op.LD_ARG, args=(0, 0)), Instr(Op.LD_ARG, args=(6, 1)), C(1, 0),
            Instr(Op.CMP_EQ, args=(2, 0, 1)), Instr(Op.BRZ, args=(2, 6)),
            Instr(Op.RET, args=(1,)),
            C(7, 1), Instr(Op.SUB, args=(3, 0, 7)), Instr(Op.ARG, args=(3, 0)),
            Instr(Op.ARG, args=(6, 1)),
            Instr(Op.CALL, args=(1, 4)), Instr(Op.ADD, args=(5, 4, 7)),
            Instr(Op.RET, args=(5,))]


def _deep_model(n):
    return _model([
        ("root", [C(0, n), C(1, 99), Instr(Op.ARG, args=(0, 0)),
                  Instr(Op.ARG, args=(1, 1)), Instr(Op.CALL, args=(1, 2)),
                  Instr(Op.RET, args=(2,))]),
        ("deep", _deep()),
    ])


def test_the_depth_limit_is_the_same_in_both_engines(eng):
    ok = _deep_model(CALL_MAX_DEPTH - 1)
    native = run_image(eng, ok.to_bytes())
    assert native.status == 0
    assert native.retval == run_model(ok).retval == CALL_MAX_DEPTH - 1

    too_deep = _deep_model(CALL_MAX_DEPTH)
    native = run_image(eng, too_deep.to_bytes())
    assert native.status == ZBC_ERR_CALL_DEPTH
    assert native.halted_op == int(Op.CALL)
    with pytest.raises(VMError, match="nested deeper"):
        run_model(too_deep)


def test_a_void_call_writes_no_register(eng):
    model = _model([
        ("root", [C(0, 7), Instr(Op.CALL, args=(1, VOID)), Instr(Op.RET, args=(0,))]),
        ("f", [C(0, 1), Instr(Op.RET)]),
    ])
    native = run_image(eng, model.to_bytes())
    assert native.status == 0
    assert native.retval == run_model(model).retval == 7


ZBC_ERR_DIV_ZERO = -14


@pytest.mark.parametrize("op,flags", [(Op.CALL, 0), (Op.INVOKE, 0x02)],
                         ids=["call", "blocking_invoke"])
def test_an_error_in_a_nested_callee_is_the_runs(eng, op, flags):
    """It used to be lost: the callee had no result to write, its caller
    resumed with 0, and the run reported success."""
    call = (Instr(Op.CALL, args=(1, 1)) if op == Op.CALL
            else Instr(Op.INVOKE, args=(1, 1), flags=flags | 0x04))
    model = _model([
        ("root", [call, C(2, 5), Instr(Op.RET, args=(2,))]),
        ("bad", [C(0, 1), C(1, 0), Instr(Op.DIV, args=(2, 0, 1)), Instr(Op.RET, args=(2,))]),
    ])
    native = run_image(eng, model.to_bytes())
    assert native.status == ZBC_ERR_DIV_ZERO
    assert native.halted_op == int(Op.DIV)


def test_a_memory_builtin_is_refused_before_anything_runs(eng):
    """The engine has no platform memory to answer from (B-D6)."""
    from zuspec.be.bc.model import BUILTIN_READ, INSTR_F_HAS_RET
    model = _model([("root", [C(0, 9), Instr(Op.ST_FIELD, args=(0, 0)),
                              Instr(Op.IMPORT, args=(BUILTIN_READ[32], 1, 0),
                                    flags=INSTR_F_HAS_RET), Instr(Op.RET)])])
    fields = [0]
    res = run_image(eng, model.to_bytes(), fields=fields)
    assert res.status == -8                     # ZBC_ERR_UNSUPPORTED_OP
    assert res.halted_op == int(Op.IMPORT)
    assert fields == [0]


def test_a_builtin_error_stops_the_run(eng):
    """It was recorded as an import and the run went on (the oracle raises)."""
    from zuspec.be.bc.model import BUILTIN_ERROR
    model = _model([("root", [C(0, 0), Instr(Op.IMPORT, args=(BUILTIN_ERROR, VOID, 0)),
                              C(1, 5), Instr(Op.RET, args=(1,))])])
    model.strings = ["boom"]
    res = run_image(eng, model.to_bytes())
    assert res.status == -25                    # ZBC_ERR_RUNTIME
    with pytest.raises(VMError, match="boom"):
        run_model(model)
