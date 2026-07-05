"""P3 IMPORT: the interpreter's window to the outside world.

IMPORT is fully encoded in the instruction (fn_id, ret reg, arg regs), so unlike
SELECT it needs no format extension -- only a native *host seam* that records each
call and supplies a per-fn_id return value, mirroring the oracle's
``RecordingImportProvider``. These tests run both runtimes with matching record +
returns tables and assert the **call sequence** (fn_id + arg values, in order), the
**returned values** (via their field effects), and that imports fire from spawned
children too (host is threaded like the spawn budget).

M1 semantics: an IMPORT completes synchronously (even a BLOCKING one), so it never
suspends -- it is procedural-with-a-side-effect, matching ``_op_import -> CONTINUE``.
"""

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc.model import (
    ZbcModel, CoroDescriptor, Instr, Op,
    INSTR_F_HAS_RET, INSTR_F_BLOCKING,
)
from zuspec.be.bc.interp import run_model, Obj, RecordingImportProvider

from conftest import run_image, make_import_host

_VOID = 0xFFFFFFFF


def C(rd, v):    return Instr(Op.CONST, args=(rd,), imm=v)
def STF(rs, sl): return Instr(Op.ST_FIELD, args=(rs, sl))
def ADD(d, a, b): return Instr(Op.ADD, args=(d, a, b))
def SP(target):  return Instr(Op.SPAWN, args=(target,))
def RET(r=None): return Instr(Op.RET) if r is None else Instr(Op.RET, args=(r,))
JOIN = Instr(Op.JOIN, imm=0)


def IMP(fn_id, *arg_regs, ret=None, blocking=False):
    flags = INSTR_F_BLOCKING if blocking else 0
    if ret is not None:
        flags |= INSTR_F_HAS_RET
    slot = ret if ret is not None else _VOID
    return Instr(Op.IMPORT, args=(fn_id, slot, *arg_regs), flags=flags)


def _oracle_calls(provider):
    return [(c["fn_id"], list(c["args"])) for c in provider.calls]


def _diff(coros, fields=None, returns=None):
    """Run oracle + engine with matching import record/returns; return everything.

    Returns (oracle_calls, native_calls, oracle_fields, native_fields, native_res).
    """
    model = ZbcModel(coros=[CoroDescriptor(name=n, code=c, blocks=[], frame_locals=[])
                            for (n, c) in coros], entry_coro=0)
    obj = (Obj(field_names=["f%d" % i for i in range(len(fields))], values=list(fields))
           if fields is not None else None)

    provider = RecordingImportProvider(returns=dict(returns) if returns else None)
    run_model(model, obj=obj, seed=0, import_provider=provider)
    o_calls = _oracle_calls(provider)
    o_fields = list(obj.values) if obj is not None else None

    host, read_calls = make_import_host(returns=returns)
    nf = list(fields) if fields is not None else None
    res = run_image(_eng, model.to_bytes(), fields=nf, host=host)
    return o_calls, read_calls(), o_fields, nf, res


@pytest.fixture(autouse=True)
def _bind_eng(eng):
    global _eng
    _eng = eng
    yield


def test_void_import_records_the_call(eng):
    # mark(5): a void, argless-return import -- recorded, no field touched.
    o, n, of, nf, res = _diff(
        [("main", [C(0, 5), IMP(1, 0), RET()])])
    assert res.status == 0
    assert n == o == [(1, [5])]


def test_import_return_value_is_written(eng):
    # r1 = getval(7); f0 = r1. Return table says fn 2 -> 42, so f0 == 42 on both.
    o, n, of, nf, res = _diff(
        [("main", [C(0, 7), IMP(2, 0, ret=1), STF(1, 0), RET()])],
        fields=[0], returns={2: 42})
    assert res.status == 0
    assert n == o == [(2, [7])]
    assert nf == of == [42]


def test_import_default_return_is_zero(eng):
    # No returns table -> fn returns 0 (matches RecordingImportProvider default).
    o, n, of, nf, res = _diff(
        [("main", [C(0, 1), IMP(9, 0, ret=1), STF(1, 0), RET()])],
        fields=[7])
    assert res.status == 0
    assert n == o == [(9, [1])]
    assert nf == of == [0]


def test_import_sequence_order(eng):
    # Three imports in a row: the recorded order must match exactly.
    o, n, of, nf, res = _diff(
        [("main", [C(0, 10), IMP(1, 0),
                   C(0, 20), IMP(2, 0),
                   C(0, 30), IMP(1, 0), RET()])])
    assert res.status == 0
    assert n == o == [(1, [10]), (2, [20]), (1, [30])]


def test_import_two_args(eng):
    o, n, of, nf, res = _diff(
        [("main", [C(0, 3), C(1, 4), IMP(5, 0, 1), RET()])])
    assert res.status == 0
    assert n == o == [(5, [3, 4])]


def test_import_in_loop_records_each_iteration(eng):
    # for i in 0..3: mark(i). Loop is register-only (BR/BRZ), imports 3 times.
    def BRZ(cond, tgt): return Instr(Op.BRZ, args=(cond, tgt))
    def BR(tgt):        return Instr(Op.BR, args=(tgt,))
    def CMP_LT(d, a, b): return Instr(Op.CMP_LT, args=(d, a, b))
    # r0=i=0, r1=limit=3, r2=1
    code = [
        C(0, 0), C(1, 3), C(2, 1),        # 0,1,2
        CMP_LT(3, 0, 1),                  # 3: r3 = i < 3
        BRZ(3, 9),                        # 4: exit if !(i<3)
        IMP(7, 0),                        # 5: mark(i)
        ADD(0, 0, 2),                     # 6: i += 1
        BR(3),                            # 7: loop
        RET(),                            # 8 (unreached fallthrough guard)
        RET(),                            # 9: exit
    ]
    o, n, of, nf, res = _diff([("main", code)])
    assert res.status == 0
    assert n == o == [(7, [0]), (7, [1]), (7, [2])]


def test_import_fires_from_spawned_child(eng):
    # main spawns A and B; each marks a distinct fn. Host is threaded to children,
    # so both calls are recorded. Order follows cooperative scheduling (A before B),
    # which the oracle produces too -> exact match.
    o, n, of, nf, res = _diff(
        [("main", [SP(1), SP(2), JOIN, RET()]),
         ("A", [C(0, 100), IMP(1, 0), RET()]),
         ("B", [C(0, 200), IMP(2, 0), RET()])])
    assert res.status == 0
    assert n == o == [(1, [100]), (2, [200])]


def test_blocking_import_is_synchronous(eng):
    # A BLOCKING import still completes inline in M1 (no suspend): it returns its
    # value and time does not advance.
    o, n, of, nf, res = _diff(
        [("main", [C(0, 8), IMP(3, 0, ret=1, blocking=True), STF(1, 0), RET()])],
        fields=[0], returns={3: 55})
    assert res.status == 0
    assert res.now == 0
    assert n == o == [(3, [8])]
    assert nf == of == [55]
