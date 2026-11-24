"""P4.5a: the C engine stops at breakpoints, on pause and after a step, and
resumes. A stop is a host yield: ``pssvm_run`` returns ``PSSVM_STOP`` and
``pssvm_dbg_stop`` says where (be-bc debug.py ``Stub`` is the reference).
The models are be-bc tests/unit/interp/test_debug_stub.py's."""
import pytest

pytest.importorskip("zuspec.be.bc")
from zuspec.ir.core import expr as E
from zuspec.ir.core import scenario as SC
from zuspec.ir.core import stmt as S
from zuspec.be.bc.lower import lower_scenario
from zuspec.be.bc.model import CoroDescriptor, Instr, Op, ZbcModel, INSTR_F_BLOCKING, INSTR_F_HAS_RET
from zuspec.rt.eng import host as nhost
from test_engine_components import C
from test_pssvm_host import _code_model


def loop_model():
    # acc = 0; repeat 5: acc = acc + 1; return acc
    # statements: pc 0 (src 1), the loop body's ADD pc 10 (src 2), RET pc 18 (src 3)
    def assign(v):
        return SC.ScExecBlock(kind="body", stmts=[S.StmtAssign(
            targets=[E.ExprRefLocal(name="acc")], value=v)])
    coro = SC.ScCoroutine(name="root", frame_locals=["acc"], body=[
        assign(E.ExprConstant(value=0)),
        SC.ScLoop(kind="repeat", count=E.ExprConstant(value=5), body=[
            assign(E.ExprBin(lhs=E.ExprRefLocal(name="acc"), op=E.BinOp.Add,
                             rhs=E.ExprConstant(value=1)))]),
        SC.ScExecBlock(kind="body", stmts=[
            S.StmtReturn(value=E.ExprRefLocal(name="acc"))]),
    ])
    m = lower_scenario([coro])
    assert m.coros[0].code[10].op == Op.ADD and m.coros[0].code[18].op == Op.RET
    m.coros[0].stmts = [(0, 1), (10, 2), (18, 3)]
    return m


def call_model():
    # f() { return 7; }  root: f(); return   (root stmts pc 0, 1; f's pc 0)
    f = CoroDescriptor(name="f", src_ref=0, code=[
        Instr(Op.CONST, args=(0,), imm=7), Instr(Op.RET, args=(0,))],
        stmts=[(0, 5)])
    root = CoroDescriptor(name="root", code=[
        Instr(Op.CALL, args=(1, 0xFFFFFFFF)), Instr(Op.RET)],
        stmts=[(0, 1), (1, 2)])
    return ZbcModel(coros=[root, f], entry_coro=0)


def par_model():
    # parallel { acc = 1; acc = 2 }; return 3  (root stmts pc 0, 3; branches pc 0)
    def body(v):
        return SC.ScExecBlock(kind="body", stmts=[S.StmtAssign(
            targets=[E.ExprRefLocal(name="acc")], value=E.ExprConstant(value=v))])
    coro = SC.ScCoroutine(name="root", frame_locals=["acc"], body=[
        SC.ScPar(branches=[body(1), body(2)]),
        SC.ScExecBlock(kind="body", stmts=[S.StmtReturn(value=E.ExprConstant(value=3))]),
    ])
    m = lower_scenario([coro])
    assert [i.op for i in m.coros[0].code][:3] == [Op.SPAWN, Op.SPAWN, Op.JOIN]
    m.coros[0].stmts = [(0, 1), (3, 4)]
    m.coros[1].stmts = [(0, 11)]
    m.coros[2].stmts = [(0, 12)]
    return m


def _stops(call, resume=nhost.RESUME):
    """Run ``call`` to its end, resuming each stop with ``resume``; the stops."""
    out = []
    while True:
        r = call.run()
        if r.status == nhost.DONE:
            return out, call.result
        assert r.status == nhost.STOP, r
        st = call.dbg_stop()
        assert st["src_ref"] == r.src_ref
        out.append(st)
        call.dbg_resume(resume)


def _engine(lib, model, breaks=(), on=True):
    eng = nhost.Engine(lib, model.to_bytes())
    eng.dbg_enable(on)
    if breaks:
        assert all(eng.dbg_set_breaks(list(breaks)))
    return eng


def test_debugging_on_without_stops_runs_as_before(_rawlib):
    for on in (False, True):
        with _engine(_rawlib, loop_model(), on=on) as eng:
            assert _stops(eng.call()) == ([], 5)


def test_breakpoints_off_do_not_stop(_rawlib):
    with _engine(_rawlib, loop_model(), [(7, 0, 10)], on=False) as eng:
        assert _stops(eng.call()) == ([], 5)


def test_a_breakpoint_in_a_loop_stops_each_time(_rawlib):
    with _engine(_rawlib, loop_model(), [(7, 0, 10), (8, 0, 10)]) as eng:
        stops, res = _stops(eng.call())
    assert res == 5 and len(stops) == 5
    s = stops[0]
    assert (s["reason"], s["coro"], s["pc"], s["src_ref"], s["hits"]) == \
        ("breakpoint", 0, 10, 2, [7, 8])
    assert s["depth"] == 1 and s["thread"] == s["frame"] != 0


def test_breakpoints_are_verified(_rawlib):
    with nhost.Engine(_rawlib, loop_model().to_bytes()) as eng:
        assert eng.dbg_set_breaks([(1, 0, 10), (2, 0, 999), (3, 5, 0)]) == [True, False, False]


def test_pause_stops_at_the_next_instruction(_rawlib):
    with _engine(_rawlib, loop_model()) as eng:
        eng.dbg_pause()
        stops, res = _stops(eng.call())
    assert res == 5 and [(s["reason"], s["pc"], s["src_ref"]) for s in stops] == [("pause", 0, 1)]


def test_step_over_stops_at_each_statement(_rawlib):
    with _engine(_rawlib, loop_model()) as eng:
        eng.dbg_pause()
        stops, res = _stops(eng.call(), nhost.STEP_STMT)
    assert res == 5
    assert [s["pc"] for s in stops] == [0] + [10] * 5 + [18]
    assert [s["reason"] for s in stops] == ["pause"] + ["step"] * 6


def test_step_into_out_and_over_a_call(_rawlib):
    with _engine(_rawlib, call_model(), [(1, 0, 0)]) as eng:
        call = eng.call()
        assert call.run().status == nhost.STOP
        call.dbg_resume(nhost.STEP_INTO)
        assert call.run().status == nhost.STOP
        s = call.dbg_stop()
        assert (s["coro"], s["pc"], s["depth"], s["src_ref"]) == (1, 0, 2, 5)
        assert s["thread"] != s["frame"]
        call.dbg_resume(nhost.STEP_OUT)
        assert call.run().status == nhost.STOP
        assert (call.dbg_stop()["coro"], call.dbg_stop()["pc"]) == (0, 1)
        call.dbg_resume(nhost.STEP_OUT)
        assert call.run().status == nhost.DONE
        # over: the callee's statement is not a stop
        call = eng.call()
        assert call.run().status == nhost.STOP
        call.dbg_resume(nhost.STEP_STMT)
        assert call.run().status == nhost.STOP
        s = call.dbg_stop()
        assert (s["coro"], s["pc"], s["depth"]) == (0, 1, 1)


def test_parallel_branches_stop_in_their_own_threads(_rawlib):
    with _engine(_rawlib, par_model(), [(1, 1, 0), (2, 2, 0)]) as eng:
        stops, res = _stops(eng.call())
    assert res == 3
    assert sorted(s["hits"][0] for s in stops) == [1, 2]
    assert len({s["thread"] for s in stops}) == 2


def test_a_step_past_the_end_of_its_thread_stops_in_another(_rawlib):
    with _engine(_rawlib, par_model(), [(1, 1, 0)]) as eng:
        call = eng.call()
        assert call.run().status == nhost.STOP
        first = call.dbg_stop()["thread"]
        call.dbg_resume(nhost.STEP_STMT)
        assert call.run().status == nhost.STOP
        s = call.dbg_stop()
        assert s["reason"] == "step" and s["thread"] != first
        call.dbg_resume()
        assert call.run().status == nhost.DONE and call.result == 3


def test_a_breakpoint_on_a_blocking_import_stops_once(_rawlib):
    code = [C(1, 5),
            Instr(Op.IMPORT, args=(42, 2, 1), flags=INSTR_F_BLOCKING | INSTR_F_HAS_RET),
            Instr(Op.WAIT, imm=3),
            Instr(Op.RET, args=(2,))]
    with _engine(_rawlib, _code_model(code), [(1, 0, 1), (2, 0, 2)]) as eng:
        call = eng.call()
        seen = []
        while True:
            r = call.run()
            if r.status == nhost.DONE:
                seen.append(r.status_name)
                break
            if r.status == nhost.REQS:
                q = call.take()
                seen.append((r.status_name, q.api, q.fn))
                call.complete(q.req_id, q.args[0] + 1000)
            else:
                seen.append(r.status_name)
    assert seen == ["STOP", ("REQS", nhost.API_USER, 42), "STOP", "WAIT", "DONE"]
    assert call.result == 1005


def test_resume_needs_a_stop(_rawlib):
    with _engine(_rawlib, loop_model()) as eng:
        call = eng.call()
        assert call.dbg_stop() is None
        with pytest.raises(nhost.HostStateError):
            call.dbg_resume()


# P4.5b: a stopped call's threads, frames and frame contents.

def test_a_stopped_call_shows_its_thread_frame_and_locals(_rawlib):
    with _engine(_rawlib, loop_model(), [(7, 0, 10)]) as eng:
        call = eng.call()
        assert call.dbg_threads() == []          # not stopped
        accs = []
        while call.run().status == nhost.STOP:
            s = call.dbg_stop()
            assert call.dbg_threads() == [{"id": s["thread"], "coro": 0, "state": "running"}]
            frames = call.dbg_frames(s["thread"])
            assert [(f["id"], f["coro"], f["pc"], f["depth"]) for f in frames] == \
                [(s["frame"], 0, 10, 1)]
            f = call.dbg_read_frame(s["frame"])
            assert len(f["regs"]) == 64 and len(f["locals"]) == 32 and len(f["args"]) == 32
            accs.append(f["locals"][0])
            call.dbg_resume()
        assert call.result == 5 and accs == [0, 1, 2, 3, 4]
        assert call.dbg_threads() == [] and call.dbg_read_frame(1) is None


def test_a_stopped_call_shows_the_callers_frame(_rawlib):
    with _engine(_rawlib, call_model(), [(1, 1, 1)]) as eng:
        call = eng.call()
        assert call.run().status == nhost.STOP
        s = call.dbg_stop()
        frames = call.dbg_frames(s["thread"])
        assert [(f["coro"], f["pc"], f["depth"], f["call_depth"]) for f in frames] == \
            [(1, 1, 2, 1), (0, 1, 1, 0)]   # the caller: past its CALL, as pyvm
        assert frames[0]["id"] == s["frame"] and frames[1]["id"] == s["thread"]
        assert call.dbg_read_frame(s["frame"])["regs"][0] == 7
        assert call.dbg_frames(12345) == [] and call.dbg_read_frame(12345) is None
        call.dbg_resume()
        assert call.run().status == nhost.DONE


def test_a_stopped_call_shows_every_live_thread(_rawlib):
    with _engine(_rawlib, par_model(), [(1, 1, 0)]) as eng:
        call = eng.call()
        assert call.run().status == nhost.STOP
        s = call.dbg_stop()
        threads = call.dbg_threads()
        assert [t["coro"] for t in threads] == [0, 1, 2]
        assert [t["id"] for t in threads] == sorted(t["id"] for t in threads)
        by_coro = {t["coro"]: t for t in threads}
        assert by_coro[1] == {"id": s["thread"], "coro": 1, "state": "running"}
        assert by_coro[0]["state"] == "waiting" and by_coro[2]["state"] != "running"
        call.dbg_resume()
        assert call.run().status == nhost.DONE and call.result == 3


# P4.5b2: access watches and stop-on-error.

def _bus_model():
    from zuspec.be.bc.model import BUILTIN_READ, BUILTIN_WRITE
    return _code_model([
        C(1, 0x1000), C(2, 0x1234ABCD),
        Instr(Op.IMPORT, args=(BUILTIN_WRITE[16], 0xFFFFFFFF, 1, 2)),
        Instr(Op.IMPORT, args=(BUILTIN_READ[32], 3, 1), flags=INSTR_F_HAS_RET),
        Instr(Op.RET, args=(3,))])


def _run_bus(call):
    """Run ``call`` answering reads with 0xFEEDF00D; the stops it made."""
    stops = []
    while True:
        r = call.run()
        if r.status == nhost.DONE:
            return stops
        if r.status == nhost.STOP:
            stops.append(call.dbg_stop())
            call.dbg_resume()
        else:
            assert r.status == nhost.REQS, r
            q = call.take()
            assert q.api == nhost.API_MEM, q
            call.complete(q.req_id, None if q.kind == "w" else 0xFEEDF00D)


def test_a_watched_write_stops_after_the_access(_rawlib):
    with _engine(_rawlib, _bus_model()) as eng:
        assert eng.dbg_set_watches([{"id": 5, "addr": 0x1001, "size": 1, "rw": "w"},
                                    {"id": 6, "addr": 0x2000, "size": 4},
                                    {"id": 7, "addr": 0x1000, "size": 0}]) == [True, True, False]
        call = eng.call()
        stops = _run_bus(call)
    assert [(s["reason"], s["hits"], s["pc"], s["detail"]) for s in stops] == [
        ("watch", [5], 3, {"rw": "w", "width": 16, "addr": 0x1000, "data": 0xABCD})]
    assert call.result == 0xFEEDF00D


def test_a_read_watch_sees_the_value_and_matches_it(_rawlib):
    for value, n in ((0xF00D, 1), (0x1234, 0)):
        with _engine(_rawlib, _bus_model()) as eng:
            eng.dbg_set_watches([{"id": 1, "addr": 0x1000, "size": 4, "rw": "r",
                                  "value": value, "mask": 0xFFFF}])
            stops = _run_bus(eng.call())
        assert len(stops) == n
        if n:
            assert stops[0]["detail"]["data"] == 0xFEEDF00D and stops[0]["pc"] == 4


def test_watches_cleared_do_not_stop(_rawlib):
    with _engine(_rawlib, _bus_model()) as eng:
        eng.dbg_set_watches([{"id": 1, "addr": 0x1000, "size": 4}])
        eng.dbg_set_watches([])
        assert _run_bus(eng.call()) == []


def _div0_model():
    return _code_model([C(1, 7), C(2, 0), Instr(Op.DIV, args=(3, 1, 2)),
                        Instr(Op.RET, args=(3,))])


def test_an_error_stops_where_it_happened_when_asked(_rawlib):
    with _engine(_rawlib, _div0_model()) as eng:
        assert eng.dbg_set_stop_on(["error", "check"]) == ["error"]
        call = eng.call()
        r = call.run()
        assert r.status == nhost.STOP
        st = call.dbg_stop()
        assert (st["reason"], st["pc"]) == ("error", 2)
        assert "DIV" in st["detail"]["error"].upper()
        f = call.dbg_read_frame(st["frame"])
        assert f["regs"][1] == 7          # the frame is still live
        call.dbg_resume()
        r = call.run()
        assert r.status == nhost.ERROR


def test_an_error_without_stop_on_ends_the_run(_rawlib):
    with _engine(_rawlib, _div0_model()) as eng:
        r = eng.call().run()
        assert r.status == nhost.ERROR
