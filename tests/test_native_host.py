"""P4.3d: the C engine driven from Python like the Python VM.

``zuspec.rt.eng.host`` has be-bc's ``HostCall`` / ``run_sync`` shape over
``pssvm_*``, so the same Python memory and import mocks answer both engines
and give the same result and the same sequence of host calls.
"""

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc.interp import host as pyhost
from zuspec.be.bc.interp.extern import Memory, ImportProvider
from zuspec.be.bc.interp.vm import VM
from zuspec.be.bc.model import (BUILTIN_READ, BUILTIN_WRITE, INSTR_F_BLOCKING,
                                INSTR_F_HAS_RET, Instr, Op)

from zuspec.rt.eng import host as nhost
from test_engine_call import _fact
from test_engine_components import C
from test_pssvm_host import _code_model, _with_fact_entry, _VOID


class _LogMemory:
    def __init__(self, log):
        self.mem = Memory()
        self.log = log

    def read(self, addr, n):
        v = self.mem.read(addr, n)
        self.log.append(("r", addr, n, v))
        return v

    def write(self, addr, n, value):
        self.log.append(("w", addr, n, value))
        self.mem.write(addr, n, value)


class _Mock(ImportProvider):
    """A Python mock: fn 42 adds 1000 to its first argument, others log."""

    def __init__(self, log):
        self.log = log

    def call(self, fn_id, args):
        self.log.append(("i", fn_id, tuple(args)))
        if fn_id == 99:
            raise ValueError("mock refused")
        return args[0] + 1000 if fn_id == 42 else None


def _both(lib, model, entry="", args=()):
    """(result or exception type, host log) on pyvm and on the C engine."""
    out = []
    for engine in ("py", "c"):
        log = []
        mem, prov = _LogMemory(log), _Mock(log)
        try:
            if engine == "py":
                vm = VM(model, memory=mem, import_provider=prov, out=lambda l: None)
                coro = model.entries[entry].coro if entry else model.entry_coro
                root = vm.root_frame(coro, 0)
                root.args = list(args)
                res = pyhost.run_sync(pyhost.HostCall(vm, root), mem, prov)
            else:
                with nhost.Engine(lib, model.to_bytes()) as eng:
                    res = nhost.run_sync(eng.call(entry, args), mem, prov)
        except Exception as e:      # noqa: BLE001 - compared by type
            res = type(e)
        out.append((res, log))
    return out


_IO = [C(1, 0x1000), C(2, 0x1234ABCD),
       Instr(Op.IMPORT, args=(BUILTIN_WRITE[32], _VOID, 1, 2)),
       Instr(Op.IMPORT, args=(BUILTIN_READ[16], 3, 1), flags=INSTR_F_HAS_RET),
       Instr(Op.IMPORT, args=(42, 4, 3), flags=INSTR_F_BLOCKING | INSTR_F_HAS_RET),
       Instr(Op.WAIT, imm=5),
       Instr(Op.IMPORT, args=(7, _VOID, 4)),
       Instr(Op.RET, args=(4,))]


def test_python_mocks_answer_both_engines_alike(_rawlib):
    py, c = _both(_rawlib, _code_model(_IO))
    assert py == c
    assert c[0] == 0xABCD + 1000
    assert [e[0] for e in c[1]] == ["w", "r", "i", "i"]


def test_an_entry_with_arguments_runs_alike(_rawlib):
    py, c = _both(_rawlib, _with_fact_entry(3), "fact", [6])
    assert py == c and c[0] == 720


def test_a_failing_mock_is_an_error_on_both(_rawlib):
    code = [C(1, 5), Instr(Op.IMPORT, args=(99, _VOID, 1)), Instr(Op.RET, args=(1,))]
    py, c = _both(_rawlib, _code_model(code))
    assert py[0] is ValueError and c[0] is ValueError
    assert py[1] == c[1] == [("i", 99, (5,))]


def test_an_engine_error_raises_a_located_native_error(_rawlib):
    from test_engine_call import CALL_MAX_DEPTH, _deep_model
    with nhost.Engine(_rawlib, _deep_model(CALL_MAX_DEPTH + 5).to_bytes()) as eng:
        with pytest.raises(nhost.NativeError) as ei:
            nhost.run_sync(eng.call())
    assert "call depth" in str(ei.value) and isinstance(ei.value.error["pc"], int)


def test_the_call_reports_each_request_like_hostcall(_rawlib):
    with nhost.Engine(_rawlib, _code_model(_IO).to_bytes()) as eng:
        call = eng.call()
        seen = []
        while (r := call.run()).status != nhost.DONE:
            if r.status != nhost.REQS:
                seen.append((r.status_name, None, "", 0, r.on, r.delay))
                continue
            q = call.take()
            assert call.take() is None            # one request at a time
            seen.append((q.status_name, q.api, q.kind, q.fn, q.on, q.delay))
            if q.api == nhost.API_MEM:
                w = call.run()                    # taken, unanswered: waits on it
                assert (w.status, w.on) == (nhost.WAIT, "REQS")
                call.complete(q.req_id, 0xBEEF if q.kind == "r" else None)
            else:
                call.complete(q.req_id, 1 if q.has_ret else None)
        assert call.result == 1 and call.over
        call.end()
    M, U = nhost.API_MEM, nhost.API_USER
    assert seen == [("REQS", M, "w", nhost.FN_WRITE, "", 0),
                    ("REQS", M, "r", nhost.FN_READ, "", 0),
                    ("REQS", U, "", 42, "", 0), ("WAIT", None, "", 0, "TIME", 5),
                    ("REQS", U, "", 7, "", 0)]


def test_a_taken_request_waits_until_it_is_answered_by_its_id(_rawlib):
    code = [C(1, 5), Instr(Op.IMPORT, args=(42, 2, 1),
                           flags=INSTR_F_BLOCKING | INSTR_F_HAS_RET),
            Instr(Op.RET, args=(2,))]
    with nhost.Engine(_rawlib, _code_model(code).to_bytes()) as eng:
        call = eng.call()
        assert call.run().status == nhost.REQS
        q = call.take()
        assert (q.api, q.fn, q.args) == (nhost.API_USER, 42, [5])
        assert call.take() is None
        for _ in range(2):                         # taken, unanswered
            r = call.run()
            assert (r.status, r.on) == (nhost.WAIT, "REQS")
        with pytest.raises(nhost.HostStateError):
            call.complete(q.req_id + 1, 7)         # not outstanding
        with pytest.raises(nhost.HostStateError):
            call.fail(q.req_id + 1, ValueError())
        call.complete(q.req_id, 1005)
        with pytest.raises(nhost.HostStateError):
            call.complete(q.req_id, 1005)          # answered already
        assert call.run().status == nhost.DONE
        assert call.result == 1005
        call.end()


def test_a_bad_image_or_entry_is_a_native_error(_rawlib):
    with pytest.raises(nhost.NativeError):
        nhost.Engine(_rawlib, b"not an image")
    with nhost.Engine(_rawlib, _fact(3).to_bytes()) as eng:
        with pytest.raises(nhost.NativeError):
            eng.call("nope")


# P4.4e: WAIT EVENT and pssvm_notify. root spins until a0 is set, which
# only the interrupt handler `irq` does (a0 = a2 + 5); it returns a0.
def _irq_model():
    from zuspec.be.bc.model import INSTR_F_SPIN, EntryPoint
    from test_engine_components import _with_comps
    model = _with_comps([
        ("root", [Instr(Op.LD_COMP, args=(0, 0)),            # @0
                  Instr(Op.BRZ, args=(0, 3)),
                  Instr(Op.RET, args=(0,)),
                  Instr(Op.YIELD, flags=INSTR_F_SPIN),        # @3
                  Instr(Op.BR, args=(0,))]),
        ("$comp_init", [C(0, 7), Instr(Op.ST_COMP, args=(0, 2)), Instr(Op.RET)]),
        ("irq", [Instr(Op.LD_COMP, args=(0, 2)), C(1, 5),
                 Instr(Op.ADD, args=(2, 0, 1)), Instr(Op.ST_COMP, args=(2, 0)),
                 Instr(Op.RET)]),
    ])
    model.entries = {"irq": EntryPoint(coro=2, kind="function")}
    return model


def _steps(call):
    """Run `call` to its end: each status, and a notify at the first WAIT EVENT."""
    seen = []
    while True:
        r = call.run()
        seen.append((r.status_name, r.on if r.status == nhost.WAIT else None))
        if r.status == nhost.WAIT and r.on == "EVENT" and len(seen) == 1:
            call.notify(nhost.N_IRQ, 3)
            continue
        if r.status != nhost.WAIT:
            return seen, (call.result if r.status == nhost.DONE else r.error)


def test_an_irq_wakes_a_call_waiting_on_an_event_alike(_rawlib):
    model = _irq_model()
    vm = VM(model, out=lambda l: None)
    py = pyhost.HostCall(vm, vm.root_frame(model.entry_coro, 0), irq_entry=2)
    want = _steps(py)
    py.end()
    assert want == ([("WAIT", "EVENT"), ("DONE", None)], 12)
    with nhost.Engine(_rawlib, model.to_bytes()) as eng:
        eng.set_irq("irq")
        call = eng.call()
        got = _steps(call)
        call.end()
    assert got == want


def test_a_call_waiting_on_an_event_with_no_notify_stays_waiting(_rawlib):
    with nhost.Engine(_rawlib, _irq_model().to_bytes()) as eng:
        call = eng.call()
        assert [(call.run().status_name, call.request.on) for _ in range(2)] \
            == [("WAIT", "EVENT")] * 2
        call.end()
        with pytest.raises(nhost.NativeError, match="deadlock"):
            nhost.run_sync(eng.call(), None, None)


def test_an_irq_without_a_handler_or_a_bad_handler_is_an_error(_rawlib):
    with nhost.Engine(_rawlib, _irq_model().to_bytes()) as eng:
        with pytest.raises(nhost.NativeError, match="no entry named"):
            eng.set_irq("nope")
        call = eng.call()
        assert call.run().status_name == "WAIT"
        with pytest.raises(nhost.HostStateError, match="no host-fed channel 1"):
            call.notify(nhost.N_CHAN, 1, 9)    # F5.5b: no EVENT row 1
        call.notify(7, 1, 9)
        r = call.run()
        assert r.status_name == "ERROR"
        assert "notify kind 7 has no handler" in r.error["message"]
        call.end()


def _platform(engine, lib, model, drive, mem=None, prov=None, irq=None):
    """The platform side (be-bc ``events.platform_side``) of a run of
    `model` on `engine`, recorded under the ``platform`` mask; `drive`
    runs the call."""
    from zuspec.be.bc.trace import binary, events as ev
    from zuspec.be.bc.trace.sink import MemorySink
    if engine == "py":
        sink = MemorySink()
        vm = VM(model, memory=mem, import_provider=prov, out=lambda l: None,
                events=sink)
        vm.watch(ev.EV_PLATFORM)
        call = pyhost.HostCall(vm, vm.root_frame(model.entry_coro, 0),
                               irq_entry=irq)
        drive(call)
        return ev.platform_side(sink.events)
    buf = []
    with nhost.Engine(lib, model.to_bytes()) as eng:
        eng.trace(buf.append, ev.EV_PLATFORM)
        if irq is not None:
            eng.set_irq("irq")
        drive(eng.call())
    return ev.platform_side(binary.read(b"".join(buf))[2])


def test_both_engines_record_the_same_platform_side(_rawlib):
    """P4.4f: read data, import returns and notifications are in the
    trace, the same on both engines, and nothing else is."""
    model = _code_model(_IO)
    sides = []
    for engine in ("py", "c"):
        log = []
        mem, prov = _LogMemory(log), _Mock(log)

        def drive(call):
            (pyhost if engine == "py" else nhost).run_sync(call, mem, prov)
        sides.append(_platform(engine, _rawlib, model, drive, mem, prov))
    assert sides[0] == sides[1]
    assert [s[0] for s in sides[0]] == ["read", "import", "import"]
    assert sides[0][0] == ("read", 0x1000, 16, 0xABCD)
    assert sides[0][1] == ("import", 42, 0xABCD + 1000)
    assert sides[0][2] == ("import", 7, None)

    irq = []
    for engine in ("py", "c"):
        def drive(call):
            _steps(call)
            call.end()
        irq.append(_platform(engine, _rawlib, _irq_model(), drive, irq=2))
    assert irq[0] == irq[1] == [
        ("notify", {"irq": 3, "value": 0, "delivered": True})]


def test_a_notification_with_no_handler_is_recorded_undelivered(_rawlib):
    def drive(call):
        assert call.run().status_name == "WAIT"
        call.notify(7, 1, 9)
        try:
            call.run()
        except Exception:   # noqa: BLE001 - pyvm raises, C returns ERROR
            pass
        call.end()
    sides = [_platform(e, _rawlib, _irq_model(), drive) for e in ("py", "c")]
    assert sides[0] == sides[1] == [
        ("notify", {"kind": 7, "value": 9, "delivered": False})]


def test_an_action_entry_reads_and_writes_its_own_object(_rawlib):
    # P4.8d2: an action entry runs on an object of its fields
    # (pssvm_call_start_obj), as pyvm's root_frame(coro, obj=...) does.
    from zuspec.be.bc.model import EntryPoint
    model = _code_model([Instr(Op.LD_FIELD, args=(0, 1)),
                         Instr(Op.CONST, args=(1,), imm=10),
                         Instr(Op.ADD, args=(2, 0, 1)),
                         Instr(Op.ST_FIELD, args=(2, 0)),
                         Instr(Op.RET)])
    model.entries = {"act": EntryPoint(coro=0, kind="action")}
    with nhost.Engine(_rawlib, model.to_bytes()) as eng:
        call = eng.call("act", obj_slots=2)
        nhost.run_sync(call)
        assert call.obj == [10, 0]
        with pytest.raises(nhost.NativeError):
            nhost.run_sync(eng.call("act"))       # no object: LD_FIELD fails
