"""P4.3a: the host ABI in C (be-bc docs/spec/host-abi.md), load / start / run.

A host loads an image, starts an entry by its ``ENTRY`` name (or the image's
entry coroutine for ``""``) and runs it to DONE; the result is the one
``zbc_run`` gives for the same coroutine. Component state lives as long as the
engine, so it carries from call to call. A bad entry is ``PSSVM_E_ARGS`` and a
bad image is NULL, each with a JSON ``pssvm_error``.
"""

import ctypes
import json
import struct

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc.model import ZbcModel, EntryPoint, Instr, Op
from zuspec.be.bc.interp import run_model

from conftest import run_image
from test_engine_call import _fact, _deep_model
from test_engine_components import _counter, _with_comps, C

PSSVM_DONE, PSSVM_ERROR = 0, -1
PSSVM_E_ARGS, PSSVM_E_IMAGE = -3, -5
ZBC_ERR_CALL_DEPTH = -24

_U64 = {"kind": "int", "width": 64, "signed": False}


class PssvmReq(ctypes.Structure):
    """Mirror of pssvm_req_t."""
    _fields_ = [
        ("status", ctypes.c_int32), ("kind", ctypes.c_uint32),
        ("addr", ctypes.c_uint64), ("size", ctypes.c_uint32),
        ("data", ctypes.c_uint64), ("reg_id", ctypes.c_uint32),
        ("src_ref", ctypes.c_uint32), ("fn_id", ctypes.c_uint32),
        ("name", ctypes.c_char_p), ("args", ctypes.POINTER(ctypes.c_uint8)),
        ("args_len", ctypes.c_size_t), ("blocking", ctypes.c_uint32),
        ("has_ret", ctypes.c_uint32), ("on", ctypes.c_uint32),
        ("delay", ctypes.c_uint64), ("bound", ctypes.c_uint32),
    ]


@pytest.fixture()
def vm(_rawlib):
    lib = _rawlib
    vp, sz, u8p = ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p
    sigs = {
        "pssvm_abi_version": ([], ctypes.c_int),
        "pssvm_load": ([u8p, sz, ctypes.c_char_p], vp),
        "pssvm_construct": ([vp, ctypes.c_char_p, u8p, sz], ctypes.c_int),
        "pssvm_call_start": ([vp, ctypes.c_char_p, ctypes.c_char_p, u8p, sz,
                              ctypes.c_uint64], vp),
        "pssvm_run": ([vp], ctypes.c_int),
        "pssvm_result": ([vp, ctypes.c_void_p, sz], sz),
        "pssvm_call_end": ([vp], None),
        "pssvm_error": ([vp, vp], ctypes.c_char_p),
        "pssvm_free": ([vp], None),
        "pssvm_call_status": ([vp, ctypes.POINTER(ctypes.c_int),
                               ctypes.POINTER(ctypes.c_uint64)], ctypes.c_int),
        "pssvm_request": ([vp], ctypes.POINTER(PssvmReq)),
        "pssvm_complete": ([vp, u8p, sz], ctypes.c_int),
    }
    for name, (args, res) in sigs.items():
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = args, res
    return lib


def _call(vm, e, entry="", args=(), comp=""):
    """Start and run one call; return (status, result or None, zbc status, now)."""
    a = b"".join(struct.pack("<Q", v) for v in args)
    h = vm.pssvm_call_start(e, entry.encode(), comp.encode(), a, len(a), 0)
    assert h, vm.pssvm_error(e, None)
    st = vm.pssvm_run(h)
    buf = (ctypes.c_uint8 * 8)()
    n = vm.pssvm_result(h, buf, 8)
    halted, now = ctypes.c_int(), ctypes.c_uint64()
    zst = vm.pssvm_call_status(h, ctypes.byref(halted), ctypes.byref(now))
    vm.pssvm_call_end(h)
    return st, (struct.unpack("<Q", bytes(buf))[0] if n == 8 else None), zst, now.value


def _load(vm, model):
    data = model.to_bytes()
    e = vm.pssvm_load(data, len(data), None)
    assert e, vm.pssvm_error(None, None)
    return e


def test_the_abi_version_is_1(vm):
    assert vm.pssvm_abi_version() == 1


@pytest.mark.parametrize("model", [_fact(5), _fact(12), _counter()],
                         ids=["fact5", "fact12", "counter"])
def test_the_default_entry_gives_what_zbc_run_gives(vm, eng, model):
    ref = run_image(eng, model.to_bytes())
    e = _load(vm, model)
    st, ret, zst, now = _call(vm, e)
    vm.pssvm_free(e)
    assert (st, ret, zst, now) == (PSSVM_DONE, ref.retval, ref.status, ref.now)


def test_an_engine_error_is_a_located_json_error(vm, eng):
    from test_engine_call import CALL_MAX_DEPTH
    model = _deep_model(CALL_MAX_DEPTH + 5)
    assert run_image(eng, model.to_bytes()).status == ZBC_ERR_CALL_DEPTH
    e = _load(vm, model)
    h = vm.pssvm_call_start(e, b"", b"", None, 0, 0)
    assert vm.pssvm_run(h) == PSSVM_ERROR
    err = json.loads(vm.pssvm_error(e, h))
    assert "call depth" in err["message"]
    # P4.3c: located at the frame that failed; P4.4b: no PROV, so no source.
    assert err["call"] == "" and isinstance(err["coro"], int) and isinstance(err["pc"], int)
    assert err["line"] is None and err["src_ref"] is None
    assert vm.pssvm_result(h, None, 0) == 0
    vm.pssvm_call_end(h)
    # The engine stays usable after an error.
    st, _, _, _ = _call(vm, e)
    assert st == PSSVM_ERROR
    vm.pssvm_free(e)


def _with_fact_entry(n):
    model = _fact(n)
    model.entries = {"fact": EntryPoint(coro=1, kind="function",
                                        params=[("k", _U64)], returns=_U64)}
    return model


@pytest.mark.parametrize("k,want", [(1, 1), (5, 120), (10, 3628800)])
def test_an_entry_by_name_takes_its_arguments(vm, k, want):
    e = _load(vm, _with_fact_entry(3))
    assert _call(vm, e, "fact", [k])[:2] == (PSSVM_DONE, want)
    assert _call(vm, e, "", [])[:2] == (PSSVM_DONE, 6)
    vm.pssvm_free(e)


def test_an_entry_without_a_result_returns_none(vm):
    model = _fact(3)
    model.entries = {"root": EntryPoint(coro=0, kind="action")}
    e = _load(vm, model)
    assert _call(vm, e, "root")[:2] == (PSSVM_DONE, None)
    vm.pssvm_free(e)


def test_component_state_carries_from_call_to_call(vm):
    """bump: a0 = a0 + a2 ($comp_init sets a2 = 7), returns a0."""
    model = _with_comps([
        ("bump", [Instr(Op.LD_COMP, args=(0, 0)), Instr(Op.LD_COMP, args=(1, 2)),
                  Instr(Op.ADD, args=(2, 0, 1)), Instr(Op.ST_COMP, args=(2, 0)),
                  Instr(Op.RET, args=(2,))]),
        ("$comp_init", [C(0, 7), Instr(Op.ST_COMP, args=(0, 2)), Instr(Op.RET)]),
    ])
    assert run_model(model).retval == 7
    e = _load(vm, model)
    assert vm.pssvm_construct(e, None, None, 0) == 0
    assert [_call(vm, e)[1] for _ in range(3)] == [7, 14, 21]
    vm.pssvm_free(e)


@pytest.mark.parametrize("entry,comp_path,nargs", [
    (b"nope", b"", 0), (b"fact", b"top.x", 0), (b"fact", b"", 33)])
def test_a_bad_entry_path_or_argument_size_is_refused(vm, entry, comp_path, nargs):
    e = _load(vm, _with_fact_entry(3))
    a = bytes(8 * nargs)
    assert not vm.pssvm_call_start(e, entry, comp_path, a, len(a), 0)
    err = json.loads(vm.pssvm_error(e, None))
    assert err["status"] == PSSVM_E_ARGS
    assert not vm.pssvm_call_start(e, b"fact", b"", b"\0" * 5, 5, 0)
    vm.pssvm_free(e)


@pytest.mark.parametrize("data", [b"", b"ZBC?" + bytes(60)], ids=["empty", "magic"])
def test_a_bad_image_is_null_with_an_error(vm, data):
    assert not vm.pssvm_load(data, len(data), None)
    err = json.loads(vm.pssvm_error(None, None))
    assert err["status"] == PSSVM_E_IMAGE
    assert err["message"].startswith("bad image")


def test_a_debug_image_with_identity_and_entries_loads(vm):
    model = _with_fact_entry(4)
    model.profile = "debug"
    model.api_hash, model.generation = 0x1234, 3
    e = _load(vm, model)
    assert _call(vm, e, "fact", [4])[:2] == (PSSVM_DONE, 24)
    vm.pssvm_free(e)


# --- P4.3b: bus accesses and imports yield to the host ----------------------

PSSVM_ACCESS, PSSVM_IMPORT, PSSVM_E_STATE = 1, 2, -2
_VOID = 0xFFFFFFFF


def _code_model(code):
    from zuspec.be.bc.model import CoroDescriptor
    return ZbcModel(coros=[CoroDescriptor(name="root", code=code, blocks=[],
                                          frame_locals=[])], entry_coro=0)


def _req(vm, h):
    r = vm.pssvm_request(h)
    assert r, "no request"
    r = r.contents
    args = struct.unpack("<%dQ" % (r.args_len // 8), bytes(r.args[:r.args_len]))
    return r, args


def test_an_import_stops_the_run_until_the_host_answers(vm):
    from zuspec.be.bc.model import INSTR_F_BLOCKING, INSTR_F_HAS_RET
    e = _load(vm, _code_model([
        C(1, 5), C(2, 7),
        Instr(Op.IMPORT, args=(42, 3, 1, 2), flags=INSTR_F_BLOCKING | INSTR_F_HAS_RET),
        Instr(Op.ADD, args=(4, 3, 1)), Instr(Op.RET, args=(4,))]))
    h = vm.pssvm_call_start(e, b"", b"", None, 0, 0)
    assert vm.pssvm_request(h) is None or not vm.pssvm_request(h)
    assert vm.pssvm_run(h) == PSSVM_IMPORT
    r, args = _req(vm, h)
    assert (r.status, r.fn_id, args, r.blocking, r.has_ret) == (PSSVM_IMPORT, 42, (5, 7), 1, 1)
    assert vm.pssvm_run(h) == PSSVM_IMPORT          # unanswered: still waiting
    assert vm.pssvm_complete(h, b"", 0) == PSSVM_E_STATE   # wants 8 bytes
    assert vm.pssvm_complete(h, struct.pack("<Q", 100), 8) == 0
    assert vm.pssvm_complete(h, struct.pack("<Q", 100), 8) == PSSVM_E_STATE
    assert vm.pssvm_run(h) == PSSVM_DONE
    buf = (ctypes.c_uint8 * 8)()
    assert vm.pssvm_result(h, buf, 8) == 8
    assert struct.unpack("<Q", bytes(buf))[0] == 105
    vm.pssvm_call_end(h)
    vm.pssvm_free(e)


def test_bus_writes_and_reads_stop_the_run_with_their_access(vm):
    from zuspec.be.bc.model import BUILTIN_READ, BUILTIN_WRITE, INSTR_F_HAS_RET
    e = _load(vm, _code_model([
        C(1, 0x1000), C(2, 0x1234ABCD),
        Instr(Op.IMPORT, args=(BUILTIN_WRITE[16], _VOID, 1, 2)),
        Instr(Op.IMPORT, args=(BUILTIN_READ[32], 3, 1), flags=INSTR_F_HAS_RET),
        Instr(Op.RET, args=(3,))]))
    h = vm.pssvm_call_start(e, b"", b"", None, 0, 0)
    assert vm.pssvm_run(h) == PSSVM_ACCESS
    r, _ = _req(vm, h)
    assert (r.kind, r.addr, r.size, r.data) == (1, 0x1000, 2, 0xABCD)
    assert vm.pssvm_complete(h, struct.pack("<Q", 1), 8) == PSSVM_E_STATE  # a write takes nothing
    assert vm.pssvm_complete(h, None, 0) == 0
    assert vm.pssvm_run(h) == PSSVM_ACCESS
    r, _ = _req(vm, h)
    assert (r.kind, r.addr, r.size) == (0, 0x1000, 4)
    assert vm.pssvm_complete(h, struct.pack("<I", 0xFEEDF00D), 4) == 0
    assert vm.pssvm_run(h) == PSSVM_DONE
    buf = (ctypes.c_uint8 * 8)()
    vm.pssvm_result(h, buf, 8)
    assert struct.unpack("<Q", bytes(buf))[0] == 0xFEEDF00D
    vm.pssvm_call_end(h)
    vm.pssvm_free(e)


def test_completing_with_nothing_pending_is_a_state_error(vm):
    e = _load(vm, _fact(3))
    h = vm.pssvm_call_start(e, b"", b"", None, 0, 0)
    assert vm.pssvm_complete(h, None, 0) == PSSVM_E_STATE
    assert vm.pssvm_run(h) == PSSVM_DONE
    assert vm.pssvm_complete(h, None, 0) == PSSVM_E_STATE
    vm.pssvm_call_end(h)
    vm.pssvm_free(e)


def test_a_call_ended_while_it_waits_is_dropped(vm):
    e = _load(vm, _code_model([
        C(1, 9), Instr(Op.IMPORT, args=(7, _VOID, 1)), Instr(Op.RET, args=(1,))]))
    h = vm.pssvm_call_start(e, b"", b"", None, 0, 0)
    assert vm.pssvm_run(h) == PSSVM_IMPORT
    vm.pssvm_call_end(h)
    h = vm.pssvm_call_start(e, b"", b"", None, 0, 0)
    assert vm.pssvm_run(h) == PSSVM_IMPORT
    assert vm.pssvm_complete(h, None, 0) == 0
    assert vm.pssvm_run(h) == PSSVM_DONE
    vm.pssvm_call_end(h)
    vm.pssvm_free(e)


def test_spawned_threads_ask_one_at_a_time_in_scheduling_order(vm):
    # main spawns A and B; each makes two imports. A request suspends the
    # whole call: B does not ask before A's first is answered, and an
    # answered thread runs on first, as with inline answers (zbc_run).
    from zuspec.be.bc.model import CoroDescriptor
    SP = lambda t: Instr(Op.SPAWN, args=(t,))
    coros = [("main", [SP(1), SP(2), Instr(Op.JOIN, imm=0), Instr(Op.RET)]),
             ("A", [C(0, 100), Instr(Op.IMPORT, args=(1, _VOID, 0)),
                    Instr(Op.IMPORT, args=(3, _VOID, 0)), Instr(Op.RET)]),
             ("B", [C(0, 200), Instr(Op.IMPORT, args=(2, _VOID, 0)),
                    Instr(Op.RET)])]
    e = _load(vm, ZbcModel(coros=[CoroDescriptor(name=n, code=c, blocks=[], frame_locals=[])
                                  for n, c in coros], entry_coro=0))
    h = vm.pssvm_call_start(e, b"", b"", None, 0, 0)
    seen = []
    while (st := vm.pssvm_run(h)) == PSSVM_IMPORT:
        r, args = _req(vm, h)
        seen.append((r.fn_id, args))
        assert vm.pssvm_complete(h, None, 0) == 0
    assert st == PSSVM_DONE
    assert seen == [(1, (100,)), (3, (100,)), (2, (200,))]
    vm.pssvm_call_end(h)
    vm.pssvm_free(e)


# --- P4.3c: a call waits on time through the host ----------------------------

PSSVM_WAIT, PSSVM_ON_TIME = 3, 1


def _waits(vm, h):
    """Run `h` to its end, answering each WAIT at once; the delays seen."""
    delays = []
    while (st := vm.pssvm_run(h)) == PSSVM_WAIT:
        r, _ = _req(vm, h)
        assert (r.status, r.on) == (PSSVM_WAIT, PSSVM_ON_TIME)
        assert vm.pssvm_complete(h, None, 0) == PSSVM_E_STATE   # a WAIT takes no answer
        delays.append(r.delay)
    return st, delays


def test_a_timed_wait_returns_wait_with_its_delay(vm, eng):
    model = _code_model([Instr(Op.WAIT, imm=5), Instr(Op.WAIT, imm=7),
                         C(1, 3), Instr(Op.RET, args=(1,))])
    ref = run_image(eng, model.to_bytes())
    e = _load(vm, model)
    h = vm.pssvm_call_start(e, b"", b"", None, 0, 0)
    st, delays = _waits(vm, h)
    halted, now = ctypes.c_int(), ctypes.c_uint64()
    vm.pssvm_call_status(h, ctypes.byref(halted), ctypes.byref(now))
    assert (st, delays, now.value) == (PSSVM_DONE, [5, 7], ref.now)
    vm.pssvm_call_end(h)
    vm.pssvm_free(e)


def test_parallel_waits_give_the_gaps_between_wake_times(vm, eng):
    from zuspec.be.bc.model import CoroDescriptor
    SP = lambda t: Instr(Op.SPAWN, args=(t,))
    coros = [("main", [SP(1), SP(2), Instr(Op.JOIN, imm=0), Instr(Op.RET)]),
             ("A", [Instr(Op.WAIT, imm=4), Instr(Op.IMPORT, args=(1, _VOID)), Instr(Op.RET)]),
             ("B", [Instr(Op.WAIT, imm=9), Instr(Op.RET)])]
    model = ZbcModel(coros=[CoroDescriptor(name=n, code=c, blocks=[], frame_locals=[])
                            for n, c in coros], entry_coro=0)
    e = _load(vm, model)
    h = vm.pssvm_call_start(e, b"", b"", None, 0, 0)
    assert vm.pssvm_run(h) == PSSVM_WAIT and _req(vm, h)[0].delay == 4
    assert vm.pssvm_run(h) == PSSVM_IMPORT              # A, woken at 4
    assert vm.pssvm_complete(h, None, 0) == 0
    assert vm.pssvm_run(h) == PSSVM_WAIT and _req(vm, h)[0].delay == 5
    assert vm.pssvm_run(h) == PSSVM_DONE
    halted, now = ctypes.c_int(), ctypes.c_uint64()
    vm.pssvm_call_status(h, ctypes.byref(halted), ctypes.byref(now))
    assert now.value == 9
    vm.pssvm_call_end(h)
    vm.pssvm_free(e)


@pytest.mark.parametrize("model", [_fact(5), _counter()], ids=["fact5", "counter"])
def test_a_call_without_timed_waits_never_waits(vm, model):
    e = _load(vm, model)
    h = vm.pssvm_call_start(e, b"", b"", None, 0, 0)
    assert _waits(vm, h) == (PSSVM_DONE, [])
    vm.pssvm_call_end(h)
    vm.pssvm_free(e)


def test_a_call_by_instance_path_reads_that_instances_fields(vm):
    """`comp_path` picks the instance (pssc.native `inst` lines, in the
    image's instance order): its fields are at that instance's base."""
    from zuspec.be.bc.model import EntryPoint
    from test_engine_components import _with_comps
    model = _with_comps([
        ("get", [Instr(Op.LD_COMP, args=(0, 0)), Instr(Op.RET, args=(0,))]),
        ("$comp_init", [C(0, 11), Instr(Op.ST_COMP, args=(0, 0)),
                        C(0, 22), Instr(Op.ST_COMP, args=(0, 2)), Instr(Op.RET)]),
    ])
    model.entries = {"sub_c::get": EntryPoint(coro=0, kind="function", returns=_U64)}
    model.profile = "debug"   # META is written in debug images only
    model.meta["pssc.native"] ="inst\t\ninst\tch[0]\n"
    e = _load(vm, model)
    assert _call(vm, e, "sub_c::get")[:2] == (PSSVM_DONE, 11)
    assert _call(vm, e, "sub_c::get", comp="ch[0]")[:2] == (PSSVM_DONE, 22)
    h = vm.pssvm_call_start(e, b"sub_c::get", b"ch[1]", b"", 0, 0)
    assert not h
    assert "no component instance 'ch[1]'" in json.loads(vm.pssvm_error(e, None))["message"]
    vm.pssvm_free(e)
