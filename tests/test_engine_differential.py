"""P3 differential: the native engine must match the Python oracle.

The engine's correctness contract is the oracle (`zuspec.be.bc.interp`): the same
`.zbc` image executed by both must produce the same result. Here we hand-author
ZBC at the instruction level (this exercises the engine's reader + interpreter
directly, independent of the frontend), serialize it with `ZbcModel.to_bytes()`,
and assert `native == oracle == expected` for `(retval, now)`.

Skeleton scope: procedural ops (CONST/MOV/arith/logic/compare), BR/BRZ (incl.
register-only loops), WAIT (sim time), RET. Locals/fields/orchestration land in
later slices.
"""

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc.model import ZbcModel, CoroDescriptor, Instr, Op
from zuspec.be.bc.interp import run_model, Obj

from conftest import run_image


def _model(code, frame_locals=()):
    return ZbcModel(coros=[CoroDescriptor(name="main", code=code, blocks=[],
                                          frame_locals=list(frame_locals))],
                    entry_coro=0)


def _oracle(model):
    r = run_model(model, obj=None, seed=0)
    return (r.retval or 0, r.now)     # a RET with no value -> None; normalize to 0


def C(rd, v):        return Instr(Op.CONST, args=(rd,), imm=v)
def BIN(op, d, a, b): return Instr(op, args=(d, a, b))
def RET(r):          return Instr(Op.RET, args=(r,))


# (name, code, expected (retval, now))
PROGRAMS = [
    ("add",   [C(0, 7), C(1, 5), BIN(Op.ADD, 2, 0, 1), RET(2)], (12, 0)),
    ("sub",   [C(0, 20), C(1, 8), BIN(Op.SUB, 2, 0, 1), RET(2)], (12, 0)),
    ("mul",   [C(0, 6), C(1, 7), BIN(Op.MUL, 2, 0, 1), RET(2)], (42, 0)),
    ("div",   [C(0, 40), C(1, 5), BIN(Op.DIV, 2, 0, 1), RET(2)], (8, 0)),
    ("mod",   [C(0, 43), C(1, 5), BIN(Op.MOD, 2, 0, 1), RET(2)], (3, 0)),
    ("and",   [C(0, 0b1100), C(1, 0b1010), BIN(Op.AND, 2, 0, 1), RET(2)], (0b1000, 0)),
    ("or",    [C(0, 0b1100), C(1, 0b1010), BIN(Op.OR, 2, 0, 1), RET(2)], (0b1110, 0)),
    ("xor",   [C(0, 0b1100), C(1, 0b1010), BIN(Op.XOR, 2, 0, 1), RET(2)], (0b0110, 0)),
    ("shl",   [C(0, 1), C(1, 4), BIN(Op.SHL, 2, 0, 1), RET(2)], (16, 0)),
    ("shr",   [C(0, 64), C(1, 2), BIN(Op.SHR, 2, 0, 1), RET(2)], (16, 0)),
    ("cmp_lt_true",  [C(0, 3), C(1, 5), BIN(Op.CMP_LT, 2, 0, 1), RET(2)], (1, 0)),
    ("cmp_lt_false", [C(0, 5), C(1, 3), BIN(Op.CMP_LT, 2, 0, 1), RET(2)], (0, 0)),
    ("cmp_eq",       [C(0, 9), C(1, 9), BIN(Op.CMP_EQ, 2, 0, 1), RET(2)], (1, 0)),
    ("mov",   [C(0, 99), Instr(Op.MOV, args=(1, 0)), RET(1)], (99, 0)),
    ("not",   [C(0, 0), Instr(Op.NOT, args=(1, 0)), RET(1)], ((1 << 64) - 1, 0)),
    # arithmetic wraps mod 2**64 (unsigned bit patterns)
    ("wrap",  [C(0, (1 << 64) - 1), C(1, 2), BIN(Op.ADD, 2, 0, 1), RET(2)], (1, 0)),
    # WAIT accumulates sim time; RET with no value -> 0
    ("wait",  [Instr(Op.WAIT, imm=5), Instr(Op.WAIT, imm=7), Instr(Op.RET)], (0, 12)),
    # register-only loop: sum 0..4 == 10 (induction var persists across the back-edge)
    ("loop_sum", [
        C(0, 0), C(1, 0), C(2, 5),
        BIN(Op.CMP_LT, 3, 1, 2),            # @3 head: r3 = i<5
        Instr(Op.BRZ, args=(3, 9)),         # exit -> @9
        BIN(Op.ADD, 0, 0, 1),               # sum += i
        C(4, 1), BIN(Op.ADD, 1, 1, 4),      # i += 1
        Instr(Op.BR, args=(3,)),            # -> head
        RET(0),                             # @9
    ], (10, 0)),
    # if/else via BRZ + BR (registers only)
    ("branch", [
        C(0, 1), Instr(Op.BRZ, args=(0, 5)),
        C(1, 10), Instr(Op.BR, args=(6,)),
        Instr(Op.NOP), C(1, 20),
        RET(1),
    ], (10, 0)),
    # fall off the end without RET -> completes, retval 0
    ("fallthrough", [C(0, 5)], (0, 0)),
]


@pytest.mark.parametrize("name,code,expected", PROGRAMS, ids=[p[0] for p in PROGRAMS])
def test_engine_matches_oracle(eng, name, code, expected):
    model = _model(code)
    oracle = _oracle(model)
    native = run_image(eng, model.to_bytes())
    assert native.status == 0, "engine halted: status=%d op=0x%x" % (
        native.status, native.halted_op)
    assert (native.retval, native.now) == oracle == expected


def LDL(rd, slot): return Instr(Op.LD_LOCAL, args=(rd, slot))
def STL(rs, slot): return Instr(Op.ST_LOCAL, args=(rs, slot))


# Programs that exercise frame locals (slot store/load). frame_locals gives the
# slot names; the count sizes the oracle's locals list.
LOCAL_PROGRAMS = [
    ("local_roundtrip", ["a"],
     [C(0, 77), STL(0, 0), C(0, 0), LDL(1, 0), RET(1)], (77, 0)),
    # loop with induction var + accumulator held in locals: sum 0..4 == 10
    ("local_loop_sum", ["sum", "i"], [
        C(0, 0), STL(0, 0),               # sum = 0
        C(0, 0), STL(0, 1),               # i = 0
        LDL(0, 1), C(1, 5), BIN(Op.CMP_LT, 2, 0, 1),  # @4 head: i<5
        Instr(Op.BRZ, args=(2, 17)),      # exit -> @17
        LDL(0, 0), LDL(1, 1), BIN(Op.ADD, 0, 0, 1), STL(0, 0),   # sum += i
        LDL(0, 1), C(1, 1), BIN(Op.ADD, 0, 0, 1), STL(0, 1),     # i += 1
        Instr(Op.BR, args=(4,)),          # -> head
        LDL(0, 0), RET(0),                # @17
    ], (10, 0)),
]


@pytest.mark.parametrize("name,flocals,code,expected", LOCAL_PROGRAMS,
                         ids=[p[0] for p in LOCAL_PROGRAMS])
def test_engine_matches_oracle_with_locals(eng, name, flocals, code, expected):
    model = _model(code, frame_locals=flocals)
    oracle = _oracle(model)
    native = run_image(eng, model.to_bytes())
    assert native.status == 0, "engine halted: status=%d op=0x%x" % (
        native.status, native.halted_op)
    assert (native.retval, native.now) == oracle == expected


def LDF(rd, slot): return Instr(Op.LD_FIELD, args=(rd, slot))
def STF(rs, slot): return Instr(Op.ST_FIELD, args=(rs, slot))


# Programs that read/write the action object's field slots. Each entry gives the
# field names (slot order), the initial field values, the code, and the expected
# (final fields, retval, now).
FIELD_PROGRAMS = [
    # field0 += 5; return field1  (field1 untouched)
    ("field_rw", ["a", "b"], [10, 99], [
        LDF(0, 0), C(1, 5), BIN(Op.ADD, 0, 0, 1), STF(0, 0),
        LDF(2, 1), RET(2),
    ], ([15, 99], 99, 0)),
    # copy field0 -> field1; return field0
    ("field_copy", ["a", "b"], [7, 0], [
        LDF(0, 0), STF(0, 1), RET(0),
    ], ([7, 7], 7, 0)),
    # accumulate field0 into field1 across a register loop: f1 += f0 three times
    ("field_accumulate", ["src", "acc"], [4, 0], [
        C(0, 0), C(1, 3),                          # i=0, limit=3
        BIN(Op.CMP_LT, 2, 0, 1),                   # @2 head
        Instr(Op.BRZ, args=(2, 11)),               # exit -> @11
        LDF(3, 1), LDF(4, 0), BIN(Op.ADD, 3, 3, 4), STF(3, 1),  # acc += src
        C(5, 1), BIN(Op.ADD, 0, 0, 5),             # i += 1
        Instr(Op.BR, args=(2,)),
        LDF(6, 1), RET(6),                         # @11
    ], ([4, 12], 12, 0)),
]


@pytest.mark.parametrize("name,fnames,init,code,expected", FIELD_PROGRAMS,
                         ids=[p[0] for p in FIELD_PROGRAMS])
def test_engine_matches_oracle_with_fields(eng, name, fnames, init, code, expected):
    exp_fields, exp_ret, exp_now = expected
    model = _model(code)

    # oracle: run over an Obj seeded with the initial field values
    r = run_model(model, obj=Obj(field_names=fnames, values=list(init)), seed=0)
    oracle_fields = list(r.obj.values)

    # native: fields mutated in place
    native_fields = list(init)
    native = run_image(eng, model.to_bytes(), fields=native_fields)

    assert native.status == 0, "engine halted: status=%d op=0x%x" % (
        native.status, native.halted_op)
    assert native_fields == oracle_fields == exp_fields
    assert (native.retval, native.now) == (r.retval or 0, r.now) == (exp_ret, exp_now)
