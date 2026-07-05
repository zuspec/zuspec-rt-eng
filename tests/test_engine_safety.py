"""Engine robustness: the watchdog + operand verifier turn malformed / runaway
images into clean error codes instead of hangs or memory corruption.

These are engine-only (no oracle differential): the oracle raises Python
exceptions for the same conditions, whereas the native engine reports a negative
status -- both reject, by different mechanisms.
"""

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc.model import ZbcModel, CoroDescriptor, Instr, Op

from conftest import run_image

# Error codes (mirror zbc_reader.h).
ZBC_ERR_UNSUPPORTED_OP = -8
ZBC_ERR_OOB_REG        = -10
ZBC_ERR_BAD_TARGET     = -12
ZBC_ERR_STEP_LIMIT     = -13
ZBC_ERR_DIV_ZERO       = -14
ZBC_ERR_NO_OBJ         = -15
ZBC_ERR_OOB_FIELD      = -16


def _run(eng, code, frame_locals=(), fields=None):
    model = ZbcModel(coros=[CoroDescriptor(name="main", code=code, blocks=[],
                                           frame_locals=list(frame_locals))],
                     entry_coro=0)
    return run_image(eng, model.to_bytes(), fields=fields)


def test_runaway_loop_hits_step_limit(eng):
    # `BR 0` branches to itself forever -> the watchdog trips instead of hanging.
    res = _run(eng, [Instr(Op.BR, args=(0,))])
    assert res.status == ZBC_ERR_STEP_LIMIT


def test_out_of_range_register_is_rejected(eng):
    # register index far beyond ZBC_MAX_REGS -> verifier rejects before executing.
    res = _run(eng, [Instr(Op.CONST, args=(9999,), imm=1),
                     Instr(Op.RET, args=(9999,))])
    assert res.status == ZBC_ERR_OOB_REG


def test_branch_target_out_of_range_is_rejected(eng):
    res = _run(eng, [Instr(Op.BR, args=(99,))])   # target beyond the coro
    assert res.status == ZBC_ERR_BAD_TARGET


def test_division_by_zero_is_a_clean_error(eng):
    res = _run(eng, [Instr(Op.CONST, args=(0,), imm=5),
                     Instr(Op.CONST, args=(1,), imm=0),
                     Instr(Op.DIV, args=(2, 0, 1)),
                     Instr(Op.RET, args=(2,))])
    assert res.status == ZBC_ERR_DIV_ZERO


def test_unsupported_op_reports_the_opcode(eng):
    # PAR -> UNSUPPORTED_OP, halted_op reports the opcode. PAR is desugared to
    # SPAWN/JOIN at lowering, so the engine never sees it in real images; a
    # hand-authored one is the last op with no native handler (all other M1 ops --
    # incl. BIND now -- are implemented).
    res = _run(eng, [Instr(Op.PAR, imm=0)])
    assert res.status == ZBC_ERR_UNSUPPORTED_OP
    assert res.halted_op == int(Op.PAR)


def test_field_access_without_object_is_rejected(eng):
    # LD_FIELD but no object was provided -> NO_OBJ.
    res = _run(eng, [Instr(Op.LD_FIELD, args=(0, 0)), Instr(Op.RET, args=(0,))])
    assert res.status == ZBC_ERR_NO_OBJ


def test_field_slot_out_of_range_is_rejected(eng):
    # object has 1 field; writing slot 5 -> OOB_FIELD.
    res = _run(eng, [Instr(Op.CONST, args=(0,), imm=1),
                     Instr(Op.ST_FIELD, args=(0, 5)),
                     Instr(Op.RET, args=(0,))],
               fields=[0])
    assert res.status == ZBC_ERR_OOB_FIELD
