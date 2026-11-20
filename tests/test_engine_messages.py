"""error()/fatal() in the native engine (P4.2b).

``error(fmt, ...)`` and ``fatal(status, fmt, ...)`` lower to an IMPORT of
``BUILTIN_ERROR_MSG``/``BUILTIN_FATAL_MSG`` with the message entry's index as
its argument. The oracle formats the text and raises; the engine logs the
call, so the host can name the entry, then halts with ``ZBC_ERR_RUNTIME``.
"""
import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc.model import (ZbcModel, CoroDescriptor, Instr, Op,
                                BUILTIN_MESSAGE, BUILTIN_ERROR_MSG,
                                BUILTIN_FATAL_MSG)
from zuspec.be.bc.interp import run_model
from zuspec.be.bc.interp.vm import VMError
from zuspec.be.bc.interp.oracle import Obj

from conftest import run_image, make_import_host

ZBC_ERR_RUNTIME = -25
VOID = 0xFFFFFFFF
U32 = {"kind": "int", "width": 32, "signed": False}


def C(rd, v):
    return Instr(Op.CONST, args=(rd,), imm=v)


def _model(fn_id, status, after=()):
    """root: a message entry 0 ("got %d", value 7) through ``fn_id``, then
    ``after`` (instructions), then RET 5."""
    code = [C(0, status), Instr(Op.ST_LOCAL, args=(0, 0)),
            C(1, 7), Instr(Op.ST_LOCAL, args=(1, 1)),
            C(2, 0), Instr(Op.IMPORT, args=(fn_id, VOID, 2)),
            *after,
            C(3, 5), Instr(Op.ST_FIELD, args=(3, 0)), Instr(Op.RET, args=(3,))]
    m = ZbcModel(coros=[CoroDescriptor(name="root", code=code, blocks=[],
                                       frame_locals=["$msg0", "$msg1"])],
                 entry_coro=0)
    m.messages = [{"fmt": "got %d", "args": [U32], "slots": [0, 1]}]
    return m


@pytest.mark.parametrize("fn_id,status,want", [
    (BUILTIN_ERROR_MSG, 0, "error: got 7"),
    (BUILTIN_FATAL_MSG, 3, r"fatal \(status 3\): got 7"),
])
def test_error_and_fatal_stop_the_run_in_both_engines(eng, fn_id, status, want):
    model = _model(fn_id, status)
    with pytest.raises(VMError, match=want):
        run_model(model)
    host, calls = make_import_host()
    fields = [0]
    res = run_image(eng, model.to_bytes(), fields=fields, host=host)
    assert res.status == ZBC_ERR_RUNTIME
    assert res.halted_op == int(Op.IMPORT)
    assert fields == [0]                        # nothing after the call ran
    assert calls() == [(fn_id, [0])]            # the host can name the entry


def test_message_does_not_stop_the_run(eng):
    model = _model(BUILTIN_MESSAGE, 0)
    lines = []
    o = run_model(model, obj=Obj(field_names=["f0"], values=[0]), out=lines.append)
    assert lines == ["got 7"] and o.fields == {"f0": 5}
    host, calls = make_import_host()
    fields = [0]
    res = run_image(eng, model.to_bytes(), fields=fields, host=host)
    assert res.status == 0
    assert fields == [5]
    assert calls() == [(BUILTIN_MESSAGE, [0])]


# --- P4.2g: the text, formatted in C from the image's MSG table ----------- #

import ctypes

from conftest import MESSAGE_FN

ENUM = {"kind": "enum", "width": 8, "signed": True, "items": [["NEG", -2], ["ONE", 1]]}
I8 = {"kind": "int", "width": 8, "signed": True}
BOOL = {"kind": "bool", "width": 1, "signed": False}
STR = {"kind": "string", "width": 64, "signed": False}


def _texts(host):
    got = []
    cb = MESSAGE_FN(lambda ctx, sev, lvl, txt, n: got.append((sev, lvl, txt[:n].decode())))
    host.message = ctypes.cast(cb, ctypes.c_void_p)
    host.verbosity = 2
    return got, cb


def _fmt_model(fmt, args, vals, level=0, fn_id=BUILTIN_MESSAGE):
    code = []
    for i, v in enumerate([level, *vals]):
        code += [C(0, v & 0xFFFFFFFFFFFFFFFF), Instr(Op.ST_LOCAL, args=(0, i))]
    code += [C(2, 0), Instr(Op.IMPORT, args=(fn_id, VOID, 2)),
             C(3, 5), Instr(Op.ST_FIELD, args=(3, 0)), Instr(Op.RET, args=(3,))]
    m = ZbcModel(coros=[CoroDescriptor(name="root", code=code, blocks=[],
                                       frame_locals=[f"$m{i}" for i in range(len(vals) + 1)])],
                 entry_coro=0, profile="runtime")
    m.strings = ["hello", "world"]
    m.messages = [{"fmt": fmt, "args": args, "slots": list(range(len(vals) + 1))}]
    return m


@pytest.mark.parametrize("fmt,args,vals", [
    ("v=%d|%5d|%-5d|%05d|%+d|% d", [I8] * 6, [-3, 42, 42, -42, 7, 7]),
    ("%u %x %X %#x %#08x %o %#o %b %B %#b", [U32] * 10, [7, 255, 255, 255, 255, 8, 8, 5, 5, 5]),
    ("%.3d|%.0d|%8.3x|%d", [I8, I8, U32, I8], [5, 0, 10, -128]),
    ("%n %n %n %-6n|", [ENUM, ENUM, BOOL, BOOL], [-2, 1, 1, 0]),
    ("%s %.3s %8s %-8s| 100%%", [STR] * 4, [0, 1, 0, 1]),
    ("%d %x", [BOOL, {"kind": "int", "width": 64, "signed": True}], [1, -1]),
])
def test_text_matches_the_python_vm(eng, fmt, args, vals):
    model = _fmt_model(fmt, args, vals)
    lines = []
    run_model(model, obj=Obj(field_names=["f0"], values=[0]), out=lines.append)
    host, _ = make_import_host()
    got, _cb = _texts(host)
    res = run_image(eng, model.to_bytes(), fields=[0], host=host)
    assert res.status == 0
    assert got == [(0, 0, lines[0])]


def test_message_above_verbosity_is_not_delivered(eng):
    model = _fmt_model("x %d", [I8], [1], level=3)
    host, _ = make_import_host()
    got, _cb = _texts(host)
    assert run_image(eng, model.to_bytes(), fields=[0], host=host).status == 0
    assert got == []


@pytest.mark.parametrize("fn_id,sev,lvl", [(BUILTIN_ERROR_MSG, 1, 0), (BUILTIN_FATAL_MSG, 2, 4)])
def test_error_and_fatal_text_reach_the_host(eng, fn_id, sev, lvl):
    model = _fmt_model("bad %s=%d", [STR, I8], [1, -1], level=lvl, fn_id=fn_id)
    host, _ = make_import_host()
    got, _cb = _texts(host)
    res = run_image(eng, model.to_bytes(), fields=[0], host=host)
    assert res.status == ZBC_ERR_RUNTIME
    assert got == [(sev, lvl, "bad world=-1")]


def test_unformattable_value_stops_the_run(eng):
    model = _fmt_model("%n", [ENUM], [5])            # not an item
    with pytest.raises(VMError):
        run_model(model, obj=Obj(field_names=["f0"], values=[0]), out=lambda s: None)
    host, _ = make_import_host()
    got, _cb = _texts(host)
    assert run_image(eng, model.to_bytes(), fields=[0], host=host).status == ZBC_ERR_RUNTIME
    assert got == []
