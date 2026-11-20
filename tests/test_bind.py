"""Host-bound functions on the C engine (P4.8c2): ``Engine.bind`` makes each
CALL of a coroutine a request the host answers in place of its body, as
be-bc's ``VM.bind`` does on the Python VM (pssc's mocks)."""
import pytest

from zuspec.be.bc.interp import host as pyhost
from zuspec.be.bc.interp.vm import VM
from zuspec.be.bc.trace import binary
from zuspec.be.bc.trace import events as ev
from zuspec.be.bc.trace.sink import MemorySink
from zuspec.rt.eng import host as nhost
from test_engine_call import _fact
from test_events import _norm


def _run(engine, lib, model, fn, mask=0):
    """(result, calls of ``fn``, trace records) with coroutine 1 (``fact``)
    bound to ``fn`` (None: not bound)."""
    calls = []

    def mock(*args):
        calls.append(tuple(args))
        return fn(*args)

    if engine == "py":
        sink = MemorySink()
        vm = VM(model, events=sink, out=lambda l: None)
        if mask:
            vm.watch(mask)
        if fn is not None:
            vm.bindings[1] = ("fact", mock)
        res = pyhost.run_sync(pyhost.HostCall(vm, vm.root_frame(model.entry_coro, 0)))
        return res, calls, [e.to_dict() for e in sink.events]
    data = bytearray()
    with nhost.Engine(lib, model.to_bytes()) as eng:
        if mask:
            eng.trace(data.extend, mask)
        if fn is not None:
            eng.bind(1)
        res = nhost.run_sync(eng.call(), bound={1: mock})
    recs = binary.read(bytes(data))[2] if data else []
    return res, calls, recs


def test_a_bound_function_is_answered_by_the_host_alike(_rawlib):
    model = _fact(5)
    py = _run("py", _rawlib, model, lambda k: k * 100)
    c = _run("c", _rawlib, model, lambda k: k * 100)
    assert py[:2] == c[:2] == (500, [(5,)])


def test_a_bound_call_traces_call_and_return_as_mocked_alike(_rawlib):
    model = _fact(4)
    mask = ev.EV_STMT | ev.EV_CALL
    py = _run("py", _rawlib, model, lambda k: None, mask)
    c = _run("c", _rawlib, model, lambda k: None, mask)
    assert c[0] == py[0] == 0
    assert _norm(c[2]) == _norm(py[2])
    calls = [r for r in c[2] if r["kind"] in (ev.CALL, ev.RETURN)]
    assert [r["detail"]["mocked"] for r in calls] == [True, True]
    assert calls[0]["detail"]["args"] == [4]


def test_an_unbound_function_runs_its_body(_rawlib):
    model = _fact(5)
    with nhost.Engine(_rawlib, model.to_bytes()) as eng:
        eng.bind(1)
        eng.bind(1, False)
        assert nhost.run_sync(eng.call()) == 120
        with pytest.raises(nhost.NativeError, match="no coroutine"):
            eng.bind(99)


def test_a_bound_call_with_no_host_function_is_an_error(_rawlib):
    with nhost.Engine(_rawlib, _fact(5).to_bytes()) as eng:
        eng.bind(1)
        with pytest.raises(nhost.NativeError, match="no host function"):
            nhost.run_sync(eng.call())
