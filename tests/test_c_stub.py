"""The debug stub in C (pssvm_stub.c, ``host.CStub``) passes the scripted
cases test_native_stub.py plays on NativeStub, with the C stub's own
differences: read_comp is ``no_comp`` (the image names no components)."""
import json
import socket

import pytest

pytest.importorskip("zuspec.be.bc")
from zuspec.be.bc.interp.extern import Memory
from zuspec.be.bc.interp.stub_socket import SocketStub, serve_stub
from zuspec.be.bc.model import CoroDescriptor, Instr, Op, ZbcModel
from zuspec.rt.eng import host as nhost
import test_native_stub as tns
from test_native_stub import ATTACH_C, MODELS, _c_script, cases

_LIB = []


@pytest.fixture(autouse=True)
def _lib(_rawlib):
    _LIB[:] = [_rawlib]


def _cc_script(name, script):
    out = []
    for req, exp, events in _c_script(name, script):
        if req.get("cmd") == "read_comp" and "body" in exp:
            exp = {"error": "no_comp"}
        out.append((req, exp, events))
    return out


def run_case(model, script, transport="direct", runs=1):
    eng = nhost.Engine(nhost.bind(_LIB[0]), model.to_bytes())
    mem = Memory()
    mem.write(0x100, 4, 0xDEADBEEF)
    real = eng.stub(memory=mem, runs=runs)
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
        state = real.state
        real.free()
        eng.free()
    return state, lines


@pytest.mark.parametrize("transport", ["direct", "socket"])
@pytest.mark.parametrize("name", sorted(n for n in cases.CASES if n != "exec_snippet"))
def test_c_stub_scripted(name, transport):
    model, script = cases.CASES[name]
    state, _ = run_case(MODELS[model](), _cc_script(name, script), transport)
    assert state in ("exited", "detached")


def test_c_stub_transcript_is_deterministic():
    s = _cc_script("step_into_and_out", cases.CASES["step_into_and_out"][1])
    assert run_case(cases.call_model(), s)[1] == run_case(cases.call_model(), s)[1]


def test_c_stub_transcript_is_the_native_stubs():
    # the C stub and NativeStub reply alike (but for the image sha256)
    for name in ("step_into_and_out", "threads_of_a_parallel", "breakpoint_every_iteration"):
        model, script = cases.CASES[name]
        s = _cc_script(name, script)
        tns._LIB[:] = _LIB
        py = [json.loads(x) for x in tns.run_case(MODELS[model](), s)[1]]
        for x in py:
            x.get("body", {}).get("image", {}).pop("sha256", None)
        assert [json.loads(x) for x in run_case(MODELS[model](), s)[1]] == py, name


def test_c_stub_named_locals():
    # the comp model's coroutine 0 names local slot 0 "acc" (LOCAL section)
    s = _cc_script("read_locals_comp_memory", cases.CASES["read_locals_comp_memory"][1])
    run_case(MODELS["comp"](), s)


def test_c_stub_exec_snippet_is_unsupported():
    run_case(cases.loop_model(), [
        ATTACH_C,
        ({"cmd": "exec_snippet", "args": {"frame": 1, "nregs": 1, "code": []}},
         {"error": "unsupported"}, []),
        cases.CONT_EXIT])


def test_c_stub_bad_json_and_seq_echo():
    eng = nhost.Engine(nhost.bind(_LIB[0]), cases.loop_model().to_bytes())
    st = eng.stub()
    try:
        rep = json.loads(eng.lib.pssvm_stub_request(st._h, b'{"seq": "a\\"b", "cmd": 1}'))
        assert rep == {"seq": 'a"b', "ok": False,
                       "error": {"code": "bad_request", "message": "a request needs a cmd"}}
        rep = json.loads(eng.lib.pssvm_stub_request(st._h, b'{"seq": 3, "cmd"'))
        assert rep["seq"] is None and rep["error"]["code"] == "bad_request"
        assert st.state == "detached"
    finally:
        st.free()
        eng.free()


def test_c_stub_stop_while_running_and_errors():
    m = ZbcModel(coros=[CoroDescriptor(name="root", code=[
        Instr(Op.CONST, args=(0,), imm=1), Instr(Op.CONST, args=(1,), imm=0),
        Instr(Op.DIV, args=(2, 0, 1)), Instr(Op.RET, args=(2,))])], entry_coro=0)
    eng = nhost.Engine(nhost.bind(_LIB[0]), m.to_bytes())
    stub = eng.stub()
    try:
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
        assert ev["body"].get("message")
        stub.join()
    finally:
        stub.free()
        eng.free()


def test_c_stub_terminate_while_running_ends_the_run():
    eng = nhost.Engine(nhost.bind(_LIB[0]), cases.loop_model().to_bytes())
    stub = eng.stub(runs=1000)
    try:
        assert stub.request({"seq": 0, "cmd": "attach", "args": {"entry": False}})["ok"]
        assert stub.request({"seq": 1, "cmd": "terminate"})["ok"]
        assert stub.next_event()["body"] == {"status": "terminated"}
        stub.join()
        assert stub.state == "exited"
    finally:
        stub.free()
        eng.free()
