"""P4.5c1: the debug stub over the C engine (``debug.NativeStub``) passes the
Python VM stub's scripted cases (be-bc tests/unit/interp/test_debug_stub.py
``CASES``), with the C engine's known differences as overrides."""
import importlib.util
import json
from pathlib import Path

import pytest

pytest.importorskip("zuspec.be.bc")
from zuspec.be.bc.interp.extern import Memory
from zuspec.be.bc.interp.stub_socket import SocketStub, serve_stub
from zuspec.be.bc.model import CoroDescriptor, Instr, Op, ZbcModel
from zuspec.rt.eng import host as nhost
from zuspec.rt.eng.debug import NativeStub
from test_debug_stop import par_model

_SRC = (Path(__file__).resolve().parents[2] / "zuspec-be-bc" / "tests" / "unit" / "interp"
        / "test_debug_stub.py")
if not _SRC.is_file():
    pytest.skip("be-bc's stub cases are not beside this package", allow_module_level=True)
_spec = importlib.util.spec_from_file_location("_bebc_stub_cases", _SRC)
cases = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cases)

ATTACH_C = ({"cmd": "attach", "args": {"version": 1}},
            {"body": {"version": 1, "engine": "c", "image": {"coros": None},
                      "capabilities": ["access_watch", "backdoor_read"]}}, [])


def comp_model():
    # cases.comp_model with a constructor coroutine for the slot values
    # (the C engine builds the tree itself; pyvm's setup writes the values)
    m = cases.comp_model()
    m.coros.append(CoroDescriptor(name="$comp_init", code=[
        Instr(Op.CONST, args=(0,), imm=1), Instr(Op.ST_COMP, args=(0, 0)),
        Instr(Op.CONST, args=(0,), imm=2), Instr(Op.ST_COMP, args=(0, 1)),
        Instr(Op.CONST, args=(0,), imm=3), Instr(Op.ST_COMP, args=(0, 2)),
        Instr(Op.RET)]))
    m.comp_init = True
    m.components.init_coro = len(m.coros) - 1
    return m


# par: the same coroutines and statements, writing a local (be-bc's writes
# fields of the action object, which the C run has none of)
MODELS = dict(cases.MODELS, comp=comp_model, par=par_model)


def _c_script(name, script):
    """The case's script with the C engine's differences."""
    out = []
    for req, exp, events in script:
        if req is cases.ATTACH[0]:
            req, exp, events = ATTACH_C
        elif req.get("cmd") == "set_stop_on" and exp.get("body"):
            exp = {"body": {"kinds": ["error"]}}     # C knows no check stops
        elif req.get("cmd") == "read_frame" and name == "read_locals_comp_memory":
            exp = {"body": dict(exp["body"], this=None)}
        out.append((req, exp, events))
    return out


def run_case(model, script, transport="direct"):
    """Play ``script`` on a NativeStub (``transport`` "socket": served as
    line JSON on a socket pair, driven through a ``SocketStub``, P4.5c2);
    returns the NativeStub and the transcript."""
    import socket
    eng = nhost.Engine(nhost.bind(_LIB[0]), model.to_bytes())
    mem = Memory()
    mem.write(0x100, 4, 0xDEADBEEF)
    real = NativeStub(eng, model, memory=mem)
    stub, server = real, None
    if transport == "socket":
        a, b = socket.socketpair()
        server = serve_stub(real, a)
        stub = SocketStub(b, timeout=10.0)
    ids, lines = {}, []
    try:
        for seq, (req, exp, events) in enumerate(script):
            rep = stub.request(dict(cases._subst(req, ids), seq=seq))
            if req.get("cmd") == "attach" and rep["ok"] and real.root_thread is not None:
                ids["root"] = real.root_thread
            lines.append(json.dumps(rep, sort_keys=True, separators=(",", ":")))
            assert rep["seq"] == seq
            if "error" in exp:
                assert not rep["ok"] and rep["error"]["code"] == exp["error"], rep
            else:
                assert rep["ok"], rep
                cases._match(rep["body"], cases._subst(exp["body"], ids), f"reply {seq}")
            for e in events:
                got = stub.next_event()
                assert got is not None, f"no event after request {seq}"
                lines.append(json.dumps(got, sort_keys=True, separators=(",", ":")))
                cases._match(got, cases._subst(e, ids), f"event after {seq}")
                if got["event"] == "stopped":
                    ids["thread"] = got["body"]["thread"]
        stub.join()
        assert stub.next_event(timeout=0.05) is None
    finally:
        if server is not None:
            stub.close()
            server.join(5.0)
        real.join()
        eng.free()
    return real, lines


_LIB = []


@pytest.fixture(autouse=True)
def _lib(_rawlib):
    _LIB[:] = [_rawlib]


@pytest.mark.parametrize("transport", ["direct", "socket"])
@pytest.mark.parametrize("name", sorted(n for n in cases.CASES if n != "exec_snippet"))
def test_scripted(name, transport):
    model, script = cases.CASES[name]
    stub, _ = run_case(MODELS[model](), _c_script(name, script), transport)
    assert stub.state == ("exited" if name != "detach_runs_unobserved" else "detached") \
        or stub.state == "exited"


def test_transcript_is_deterministic():
    s = _c_script("step_into_and_out", cases.CASES["step_into_and_out"][1])
    assert run_case(cases.call_model(), s)[1] == run_case(cases.call_model(), s)[1]


def test_socket_transcript_is_the_direct_one():
    # P4.5c2: line JSON on a socket changes nothing a debugger sees.
    for name in ("step_into_and_out", "threads_of_a_parallel"):
        model, script = cases.CASES[name]
        s = _c_script(name, script)
        assert run_case(MODELS[model](), s)[1] == run_case(MODELS[model](), s, "socket")[1], name


def test_exec_snippet_is_unsupported():
    run_case(cases.loop_model(), [
        ATTACH_C,
        ({"cmd": "exec_snippet", "args": {"frame": 1, "nregs": 1, "code": []}},
         {"error": "unsupported"}, []),
        cases.CONT_EXIT])


def test_stop_while_running_and_errors():
    # pause lands on the next instruction; an engine error stops (on by
    # default), then any resume ends the run with it
    m = ZbcModel(coros=[CoroDescriptor(name="root", code=[
        Instr(Op.CONST, args=(0,), imm=1), Instr(Op.CONST, args=(1,), imm=0),
        Instr(Op.DIV, args=(2, 0, 1)), Instr(Op.RET, args=(2,))])], entry_coro=0)
    eng = nhost.Engine(nhost.bind(_LIB[0]), m.to_bytes())
    try:
        stub = NativeStub(eng, m)
        assert stub.request({"seq": 0, "cmd": "attach"})["ok"]
        assert stub.request({"seq": 1, "cmd": "continue"})["ok"]
        ev = stub.next_event()
        assert ev["event"] == "stopped" and ev["body"]["reason"] == "error", ev
        assert ev["body"]["pc"] == 2 and "error" in ev["body"]["detail"]
        assert stub.request({"seq": 2, "cmd": "frames",
                             "args": {"thread": ev["body"]["thread"]}})["ok"]
        stub.request({"seq": 3, "cmd": "continue"})
        ev = stub.next_event()
        assert ev["event"] == "exited" and ev["body"]["status"] == "error", ev
        stub.join()
    finally:
        eng.free()


def test_terminate_while_running_ends_the_run():
    eng = nhost.Engine(nhost.bind(_LIB[0]), cases.loop_model().to_bytes())
    try:
        stub = NativeStub(eng, cases.loop_model(),
                          run=lambda on_stop: [nhost.run_sync(eng.call(), on_stop=on_stop)
                                               for _ in range(1000)])
        assert stub.request({"seq": 0, "cmd": "attach", "args": {"entry": False}})["ok"]
        assert stub.request({"seq": 1, "cmd": "terminate"})["ok"]
        assert stub.next_event()["body"] == {"status": "terminated"}
        stub.join()
    finally:
        eng.free()
