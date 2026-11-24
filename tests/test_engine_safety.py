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


def _count_down(n):
    """main: i = n; while (i != 0) i -= 1; return 7 -- about 4n steps."""
    return [Instr(Op.CONST, args=(0,), imm=n), Instr(Op.CONST, args=(1,), imm=1),
            Instr(Op.CONST, args=(2,), imm=0),
            Instr(Op.CMP_EQ, args=(3, 0, 2)),                  # 3: loop
            Instr(Op.BRZ, args=(3, 6)),
            Instr(Op.BR, args=(8,)),
            Instr(Op.SUB, args=(0, 0, 1)),                     # 6: body
            Instr(Op.BR, args=(3,)),
            Instr(Op.CONST, args=(4,), imm=7),                 # 8: done
            Instr(Op.RET, args=(4,))]


def test_a_host_sets_the_step_limit(eng):
    # zbc_host_t.step_limit: the budget a bounded loop of ~4000 steps runs in.
    from conftest import ZbcHost
    model = ZbcModel(coros=[CoroDescriptor(name="main", code=_count_down(1000),
                                           blocks=[])], entry_coro=0)
    host = ZbcHost()
    host.step_limit = 100
    assert run_image(eng, model.to_bytes(), host=host).status == ZBC_ERR_STEP_LIMIT
    host.step_limit = 2 ** 64 - 1                      # ZBC_STEP_UNLIMITED
    res = run_image(eng, model.to_bytes(), host=host)
    assert res.status == 0 and res.retval == 7
    host.step_limit = 0                                # the default
    res = run_image(eng, model.to_bytes(), host=host)
    assert res.status == 0 and res.retval == 7


def test_out_of_range_register_is_rejected(eng):
    # register index far beyond ZBC_MAX_REGS -> verifier rejects before executing.
    res = _run(eng, [Instr(Op.CONST, args=(99999,), imm=1),
                     Instr(Op.RET, args=(99999,))])
    assert res.status == ZBC_ERR_OOB_REG


def test_a_frame_holds_the_registers_and_locals_its_code_uses(eng):
    # P4.8d: a frame is sized for its coroutine (was a fixed 64 regs / 32 locals);
    # the compiler uses about one register per instruction.
    res = _run(eng, [Instr(Op.CONST, args=(300,), imm=7),
                     Instr(Op.ST_LOCAL, args=(300, 200)),
                     Instr(Op.LD_LOCAL, args=(299, 200)),
                     Instr(Op.RET, args=(299,))])
    assert res.status == 0 and res.retval == 7


def test_a_frame_bigger_than_a_stack_block_runs(eng):
    # P4.8d2: a frame over the 8 KiB stack block gets a block of its own
    # (WB DMA's routed arb_a); operands stay bounded by ZBC_MAX_REGS/LOCALS.
    res = _run(eng, [Instr(Op.CONST, args=(1000,), imm=5),
                     Instr(Op.ST_LOCAL, args=(1000, 1000)),
                     Instr(Op.LD_LOCAL, args=(999, 1000)),
                     Instr(Op.RET, args=(999,))])
    assert res.status == 0 and res.retval == 5


def test_a_body_of_more_than_a_thousand_registers_runs(eng):
    # P4.8d2: WB DMA's routed arb body uses ~1500 registers (ZBC_MAX_REGS 65536).
    res = _run(eng, [Instr(Op.CONST, args=(1500,), imm=9),
                     Instr(Op.MOV, args=(3000, 1500)),
                     Instr(Op.RET, args=(3000,))])
    assert res.status == 0 and res.retval == 9


def test_branch_target_out_of_range_is_rejected(eng):
    res = _run(eng, [Instr(Op.BR, args=(99,))])   # target beyond the coro
    assert res.status == ZBC_ERR_BAD_TARGET


def test_a_branch_to_the_end_of_the_coro_completes_it(eng):
    # P4.10f2: `repeat`/`if` lowering branches to len(code) as the coro's exit.
    res = _run(eng, [Instr(Op.CONST, args=(0,), imm=0),
                     Instr(Op.BRZ, args=(0, 3)),
                     Instr(Op.BR, args=(0,))])
    assert res.status == 0


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


def _patched(code, index, op):
    """The image of ``code`` with instruction ``index``'s opcode set to ``op``,
    which the model itself would refuse to build (an opcode from a newer format)."""
    from zuspec.be.bc.format import spec
    image = ZbcModel(coros=[CoroDescriptor(name="main", code=code, blocks=[])],
                     entry_coro=0).to_container()
    sec = next(s for s in image.sections if s.kind == spec.sec_kind("ZBC_SEC_CODE"))
    payload = bytearray(sec.payload)
    payload[32 * index:32 * index + 2] = op.to_bytes(2, "little")   # zbc_instr.op (u16)
    sec.payload = bytes(payload)
    return image


def test_unknown_opcode_is_refused_before_anything_runs(eng):
    # The IMPORT before it never reaches the host: the image is checked first.
    from zuspec.be.bc.format.writer import write_image
    from conftest import make_import_host
    imp = Instr(Op.IMPORT, args=(0, 0xFFFFFFFF))
    image = _patched([imp, Instr(Op.NOP), Instr(Op.RET)], 1, 0xEE)
    host, read_calls = make_import_host()
    res = run_image(eng, write_image(image), host=host)
    assert res.status == ZBC_ERR_UNSUPPORTED_OP
    assert res.halted_op == 0xEE
    assert list(read_calls()) == []


def test_an_unknown_section_is_skipped(eng):
    from zuspec.be.bc.format.writer import Section, write_image
    code = [Instr(Op.CONST, args=(0,), imm=7), Instr(Op.RET, args=(0,))]
    image = ZbcModel(coros=[CoroDescriptor(name="main", code=code, blocks=[])],
                     entry_coro=0).to_container()
    image.sections.append(Section(kind=0x7F00, payload=b"from a newer format"))
    res = run_image(eng, write_image(image))
    assert res.status == 0
    assert res.retval == 7


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
