"""Debug events from the native engine (P4.4c c2, c3).

The engine writes events into a ``zbc_ev_sink_t`` in the binary trace form
(be-bc ``trace/binary.py``); here they are read back and compared with the
events the Python VM raises for the same model and mask.
"""
import ctypes

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc.model import (ZbcModel, CoroDescriptor, Instr, Op,
                                BUILTIN_MESSAGE, BUILTIN_READ, BUILTIN_WRITE,
                                INSTR_F_BLOCKING, INSTR_F_HAS_RET)
from zuspec.be.bc.interp import run_model
from zuspec.be.bc.interp.oracle import Obj
from zuspec.be.bc.interp.extern import Memory, RecordingImportProvider
from zuspec.be.bc.trace import binary, events as ev
from zuspec.be.bc.trace.sink import MemorySink

from conftest import run_image, make_import_host, ZbcHost, MEM_ACCESS_FN

VOID = 0xFFFFFFFF
U32 = {"kind": "int", "width": 32, "signed": False}

#: C ``zbc_ev_out_f``: (ctx, bytes, len); host.py's, so both set the same
#: argtypes on the shared library.
from zuspec.rt.eng.host import EV_OUT_FN  # noqa: E402


def C(rd, v):
    return Instr(Op.CONST, args=(rd,), imm=v)


def _setup(lib):
    lib.zbc_ev_new.argtypes = [EV_OUT_FN, ctypes.c_void_p]
    lib.zbc_ev_new.restype = ctypes.c_void_p
    lib.zbc_ev_delete.argtypes = [ctypes.c_void_p]
    lib.zbc_ev_watch.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32]


def c_events(eng, model, mask, fields=None, host=None):
    """Run ``model`` on the native engine with ``mask`` watched in every
    coroutine; return (result, decoded records)."""
    _setup(eng)
    data = bytearray()

    @EV_OUT_FN
    def out(_ctx, p, n):
        data.extend(ctypes.string_at(p, n))

    sink = eng.zbc_ev_new(out, None)
    assert sink
    try:
        eng.zbc_ev_watch(sink, mask, -1)
        if host is None:
            host = ZbcHost()
        host.events = sink
        res = run_image(eng, model.to_bytes(), fields=fields, host=host)
    finally:
        eng.zbc_ev_delete(sink)
    if not data:
        return res, []
    _, _, recs = binary.read(bytes(data))
    return res, recs


def py_events(model, mask, **kw):
    sink = MemorySink()
    run_model(model, events=sink, watch=mask, **kw)
    return [e.to_dict() for e in sink.events]


def _norm(recs):
    """Drop what only one engine knows: ``seq`` (the Python VM's sink also
    counts the trace's own events) and the stmt ``path``/``scope`` (from the
    COV table, which these models have none of)."""
    out = []
    for r in recs:
        d = dict(r.get("detail") or {})
        if r["kind"] == ev.STMT:
            d.pop("path", None)
            d.pop("scope", None)
        out.append((r["kind"], r.get("coro", 0), r.get("src_ref", 0), d))
    return out


def _model(coros, entry=0):
    return ZbcModel(coros=coros, entry_coro=entry)


def _fact_model(n, store=True):
    """root: fact(n) (stored in field 0 when ``store``); fact(k) = k <= 1 ? 1
    : k * fact(k - 1); statements at the call in root and at the test and
    the recursion in fact."""
    st = Instr(Op.ST_FIELD, args=(1, 0)) if store else Instr(Op.MOV, args=(2, 1))
    root = CoroDescriptor(
        name="root", code=[C(0, n), Instr(Op.ARG, args=(0, 0)),
                           Instr(Op.CALL, args=(1, 1)), st,
                           Instr(Op.RET, args=(1,))],
        blocks=[], frame_locals=[], src_ref=1)
    root.stmts = [(0, 11), (3, 12)]
    fact = CoroDescriptor(
        name="fact", code=[Instr(Op.LD_ARG, args=(0, 0)), C(1, 1),
                           Instr(Op.CMP_LE, args=(2, 0, 1)), Instr(Op.BRZ, args=(2, 5)),
                           Instr(Op.RET, args=(1,)),
                           Instr(Op.SUB, args=(3, 0, 1)), Instr(Op.ARG, args=(3, 0)),
                           Instr(Op.CALL, args=(1, 4)), Instr(Op.MUL, args=(5, 0, 4)),
                           Instr(Op.RET, args=(5,))],
        blocks=[], frame_locals=[], src_ref=2)
    fact.stmts = [(0, 21), (5, 22)]
    return _model([root, fact])


def _msg_model():
    code = [C(0, 0), Instr(Op.ST_LOCAL, args=(0, 0)),
            C(1, 7), Instr(Op.ST_LOCAL, args=(1, 1)),
            C(2, 0), Instr(Op.IMPORT, args=(BUILTIN_MESSAGE, VOID, 2)),
            C(3, 5), Instr(Op.ST_FIELD, args=(3, 0)), Instr(Op.RET, args=(3,))]
    root = CoroDescriptor(name="root", code=code, blocks=[],
                          frame_locals=["$msg0", "$msg1"])
    root.stmts = [(0, 31), (6, 32)]
    m = _model([root])
    m.messages = [{"fmt": "got %d", "args": [U32], "slots": [0, 1]}]
    return m


def _import_model():
    """root: r0 = imp7(3, 4) (blocking, returns); imp9(r0) (void)."""
    code = [C(0, 3), C(1, 4),
            Instr(Op.IMPORT, args=(7, 2, 0, 1), flags=INSTR_F_BLOCKING | INSTR_F_HAS_RET),
            Instr(Op.IMPORT, args=(9, VOID, 2)),
            Instr(Op.ST_FIELD, args=(2, 0)), Instr(Op.RET, args=(2,))]
    root = CoroDescriptor(name="root", code=code, blocks=[], frame_locals=[])
    root.stmts = [(0, 41), (3, 42)]
    return _model([root])


def _mem_model(regs=(), discards=()):
    """root: write32(0x1000, 0xAB); r3 = read32(0x1000); read8(0x1000)
    (value dropped); the debug tables name registers at ``regs``."""
    code = [C(0, 0x1000), C(1, 0xAB),
            Instr(Op.IMPORT, args=(BUILTIN_WRITE[32], VOID, 0, 1)),
            Instr(Op.IMPORT, args=(BUILTIN_READ[32], 3, 0), flags=INSTR_F_HAS_RET),
            Instr(Op.IMPORT, args=(BUILTIN_READ[8], 4, 0), flags=INSTR_F_HAS_RET),
            Instr(Op.ST_FIELD, args=(3, 0)), Instr(Op.RET, args=(3,))]
    root = CoroDescriptor(name="root", code=code, blocks=[], frame_locals=[])
    root.stmts = [(0, 51), (3, 52)]
    root.regs = list(regs)
    root.discards = list(discards)
    return _model([root])


def _mem_host(mem):
    host, _calls = make_import_host()

    def access(_ctx, is_write, addr, nbytes, data):
        if is_write:
            mem.write(addr, nbytes, data)
            return 0
        return mem.read(addr, nbytes)

    cb = MEM_ACCESS_FN(access)
    host.mem_access = ctypes.cast(cb, ctypes.c_void_p)
    return host, cb


def test_import_events_match_the_python_vm(eng):
    model = _import_model()
    mask = ev.EV_IMPORT | ev.EV_STMT
    want = py_events(model, mask, obj=Obj(field_names=["f0"], values=[0]),
                     import_provider=RecordingImportProvider({7: 0x55}))
    host, _calls = make_import_host(returns={7: 0x55})
    fields = [0]
    res, got = c_events(eng, model, mask, fields=fields, host=host)
    assert res.status == 0 and fields == [0x55]
    imps = [r["detail"] for r in want if r["kind"] == ev.IMPORT]
    assert [d.get("ret") for d in imps] == [0x55, None]
    assert _norm(got) == _norm(want)


@pytest.mark.parametrize("tables", [{}, {"regs": [(2, 3), (3, 3), (4, 5)], "discards": [4]}],
                         ids=["plain", "registers"])
def test_access_events_match_the_python_vm(eng, tables):
    model = _mem_model(**tables)
    mask = ev.EV_ACCESS | ev.EV_IMPORT
    want = py_events(model, mask, obj=Obj(field_names=["f0"], values=[0]),
                     memory=Memory())
    host, _keep = _mem_host(Memory())
    fields = [0]
    res, got = c_events(eng, model, mask, fields=fields, host=host)
    assert res.status == 0 and fields == [0xAB]
    assert [r["kind"] for r in want] == [ev.ACCESS] * 3
    if tables:
        assert want[2]["detail"].get("discarded") is True
    assert _norm(got) == _norm(want)


@pytest.mark.parametrize("mask", [ev.EV_STMT, ev.EV_CALL, ev.EV_STMT | ev.EV_CALL])
def test_stmt_call_and_return_events_match_the_python_vm(eng, mask):
    model = _fact_model(3)
    want = py_events(model, mask, obj=Obj(field_names=["f0"], values=[0]))
    fields = [0]
    res, got = c_events(eng, model, mask, fields=fields)
    assert res.status == 0 and fields == [6]
    assert want, "the Python VM raised no events"
    assert _norm(got) == _norm(want)


@pytest.mark.parametrize("mask", [ev.EV_STMT, ev.EV_BRANCH, ev.EV_STMT | ev.EV_BRANCH])
def test_coverage_events_match_the_python_vm(eng, mask):
    """P4.7: with a COV table, stmt events carry path/scope and the arms
    taken raise branch events, as on the Python VM (the coverage sink)."""
    model = _fact_model(3)
    root, fact = model.coros
    root.cov = [("stmt", 0, "", "0", 11, False), ("stmt", 3, "", "1", 12, False)]
    fact.cov = [("stmt", 0, "T::fact", "0", 21, False),
                ("arm", 4, "T::fact", "0/then", 23, False),
                ("stmt", 5, "T::fact", "1", 22, False),
                ("arm", 5, "T::fact", "0/else", 24, True)]
    want = py_events(model, mask, obj=Obj(field_names=["f0"], values=[0]))
    fields = [0]
    res, got = c_events(eng, model, mask, fields=fields)
    assert res.status == 0 and fields == [6]
    if mask & ev.EV_BRANCH:
        arms = [r["detail"] for r in want if r["kind"] == ev.BRANCH]
        assert {"pc": 5, "branch": "0", "arm": "else", "scope": "T::fact",
                "implicit": True} in arms and len(arms) == 3
    if mask & ev.EV_STMT:
        assert any(r["detail"].get("path") == "1" for r in want if r["kind"] == ev.STMT)
    strip = [(r["kind"], r.get("coro", 0), r.get("src_ref", 0), r.get("detail"))
             for r in got]
    assert strip == [(r["kind"], r.get("coro", 0), r.get("src_ref", 0), r.get("detail"))
                     for r in want]


def test_message_events_match_the_python_vm(eng):
    model = _msg_model()
    mask = ev.EV_MESSAGE | ev.EV_STMT
    want = py_events(model, mask, obj=Obj(field_names=["f0"], values=[0]),
                     out=lambda _l: None)
    host, _calls = make_import_host()
    res, got = c_events(eng, model, mask, fields=[0], host=host)
    assert res.status == 0
    assert [r["kind"] for r in want].count(ev.MESSAGE) == 1
    assert _norm(got) == _norm(want)


def test_no_mask_no_events(eng):
    res, got = c_events(eng, _fact_model(3), 0, fields=[0])
    assert res.status == 0 and got == []


def test_a_coroutine_mask_limits_the_events_to_it(eng):
    _setup(eng)
    model = _fact_model(2)
    _, all_recs = c_events(eng, model, ev.EV_STMT, fields=[0])
    # only root's statements: watch fact with 0
    data = bytearray()

    @EV_OUT_FN
    def out(_ctx, p, n):
        data.extend(ctypes.string_at(p, n))

    sink = eng.zbc_ev_new(out, None)
    try:
        eng.zbc_ev_watch(sink, ev.EV_STMT, -1)
        eng.zbc_ev_watch(sink, 0, 1)
        host = ZbcHost()
        host.events = sink
        run_image(eng, model.to_bytes(), fields=[0], host=host)
    finally:
        eng.zbc_ev_delete(sink)
    _, _, recs = binary.read(bytes(data))
    assert [r["src_ref"] for r in recs] == [11, 12]
    assert len(all_recs) > len(recs)


def test_pssvm_calls_raise_events_into_the_engines_sink(_rawlib):
    """pssvm_set_events: a pssvm call raises the same events as zbc_run."""
    lib = _rawlib
    _setup(lib)
    vp = ctypes.c_void_p
    lib.pssvm_load.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    lib.pssvm_load.restype = vp
    lib.pssvm_set_events.argtypes = [vp, vp]
    lib.pssvm_call_start.argtypes = [vp, ctypes.c_char_p, ctypes.c_char_p,
                                     ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint64]
    lib.pssvm_call_start.restype = vp
    lib.pssvm_run.argtypes = [vp]
    lib.pssvm_call_end.argtypes = [vp]
    lib.pssvm_free.argtypes = [vp]
    model = _fact_model(3, store=False)
    mask = ev.EV_STMT | ev.EV_CALL
    want = py_events(model, mask)
    data = bytearray()

    @EV_OUT_FN
    def out(_ctx, p, n):
        data.extend(ctypes.string_at(p, n))

    img = model.to_bytes()
    e = lib.pssvm_load(img, len(img), None)
    sink = lib.zbc_ev_new(out, None)
    try:
        lib.zbc_ev_watch(sink, mask, -1)
        lib.pssvm_set_events(e, sink)
        h = lib.pssvm_call_start(e, b"", b"", None, 0, 0)
        assert h
        lib.pssvm_error.argtypes = [vp, vp]
        lib.pssvm_error.restype = ctypes.c_char_p
        assert lib.pssvm_run(h) == 0, lib.pssvm_error(e, h)   # PSSVM_DONE
        lib.pssvm_call_end(h)
    finally:
        lib.pssvm_free(e)
        lib.zbc_ev_delete(sink)
    _, _, got = binary.read(bytes(data))
    assert _norm(got) == _norm(want)


def test_the_host_engine_writes_a_trace(_rawlib):
    """host.Engine.trace: a call's events go to ``out`` as a binary trace,
    with the header given; the same events as the Python VM's."""
    from zuspec.rt.eng.host import Engine, HostStateError
    model = _fact_model(3, store=False)
    mask = ev.EV_STMT | ev.EV_CALL
    data = bytearray()
    with Engine(_rawlib, model.to_bytes()) as e:
        e.trace(data.extend, mask, header={"test": "t", "image": "m.zbc"})
        with pytest.raises(HostStateError):
            e.trace(data.extend)
        call = e.call()
        assert call.run().status_name == "DONE"
        call.end()
    _, header, got = binary.read(bytes(data))
    assert header == {"image": "m.zbc", "test": "t"}
    assert _norm(got) == _norm(py_events(model, mask))


def test_pssvm_answers_raise_access_and_import_events(_rawlib):
    """A pssvm call's bus accesses and imports raise their events when the
    host answers them, as the Python VM does after its answer."""
    lib = _rawlib
    _setup(lib)
    vp, sz = ctypes.c_void_p, ctypes.c_size_t
    lib.pssvm_load.argtypes = [ctypes.c_char_p, sz, ctypes.c_char_p]
    lib.pssvm_load.restype = vp
    lib.pssvm_set_events.argtypes = [vp, vp]
    lib.pssvm_call_start.argtypes = [vp, ctypes.c_char_p, ctypes.c_char_p,
                                     ctypes.c_char_p, sz, ctypes.c_uint64]
    lib.pssvm_call_start.restype = vp
    lib.pssvm_run.argtypes = [vp]
    lib.pssvm_complete.argtypes = [vp, ctypes.c_char_p, sz]
    lib.pssvm_call_end.argtypes = [vp]
    lib.pssvm_free.argtypes = [vp]
    m = _mem_model(regs=[(2, 3), (3, 3)])
    root = m.coros[0]
    # then imp7(r3) -> r2 (returns 0x55); no component to store into
    root.code[-2:-1] = [Instr(Op.IMPORT, args=(7, 2, 3), flags=INSTR_F_HAS_RET),
                        Instr(Op.MOV, args=(5, 3))]
    mask = ev.EV_ACCESS | ev.EV_IMPORT | ev.EV_STMT
    want = py_events(m, mask, memory=Memory(), import_provider=RecordingImportProvider({7: 0x55}))
    data = bytearray()

    @EV_OUT_FN
    def out(_ctx, p, n):
        data.extend(ctypes.string_at(p, n))

    img = m.to_bytes()
    e = lib.pssvm_load(img, len(img), None)
    sink = lib.zbc_ev_new(out, None)
    try:
        lib.zbc_ev_watch(sink, mask, -1)
        lib.pssvm_set_events(e, sink)
        h = lib.pssvm_call_start(e, b"", b"", None, 0, 0)
        # write, read32, read8, imp7: an answer is its request's size
        for a in [None, (0xAB, 4), (0xAB, 1), (0x55, 8)]:
            assert lib.pssvm_run(h) in (1, 2)       # PSSVM_ACCESS / PSSVM_IMPORT
            if a is None:
                assert lib.pssvm_complete(h, None, 0) == 0
            else:
                assert lib.pssvm_complete(h, a[0].to_bytes(a[1], "little"), a[1]) == 0
        lib.pssvm_error.argtypes = [vp, vp]
        lib.pssvm_error.restype = ctypes.c_char_p
        assert lib.pssvm_run(h) == 0, lib.pssvm_error(e, h)
        lib.pssvm_call_end(h)
    finally:
        lib.pssvm_free(e)
        lib.zbc_ev_delete(sink)
    _, _, got = binary.read(bytes(data))
    assert [r["kind"] for r in want].count(ev.ACCESS) == 3
    assert _norm(got) == _norm(want)


def test_chan_events_match_the_python_vm(eng):
    """chan at each CHAN table NOP: a put (value), a try_get that got one
    (ok, value) and one that did not (ok false, no value)."""
    model = _chan_model()
    mask = ev.EV_CHAN | ev.EV_STMT
    want = py_events(model, mask)
    res, got = c_events(eng, model, mask)
    assert res.status == 0
    chans = [r["detail"] for r in want if r["kind"] == ev.CHAN]
    assert chans == [{"channel": "c0", "op": "put", "value": 9},
                     {"channel": "c0", "op": "try_get", "ok": True, "value": 9},
                     {"channel": "c1", "op": "try_get", "ok": False}]
    assert _norm(got) == _norm(want)


#: Every kind the native engine raises (P4.4c c2).
C_KINDS = (ev.EV_STMT | ev.EV_CALL | ev.EV_ACCESS | ev.EV_IMPORT
           | ev.EV_MESSAGE | ev.EV_CHAN)


def _canon(recs):
    """The binary form of ``recs`` after dropping what only one engine knows
    (see :func:`_norm`): ``seq`` renumbered from 0, stmt ``path``/``scope``
    gone, and no header."""
    import io

    buf = io.BytesIO()
    w = binary.Writer(buf)
    for i, r in enumerate(recs):
        d = dict(r, seq=i, detail=dict(r.get("detail") or {}))
        if d["kind"] == ev.STMT:
            d["detail"].pop("path", None)
            d["detail"].pop("scope", None)
        w.write(d)
    return buf.getvalue()


def _chan_model():
    """chan at each CHAN table NOP: put 9 on c0, try_get c0, try_get c1."""
    code = [C(0, 9), Instr(Op.NOP), C(1, 1), Instr(Op.NOP),
            C(1, 0), Instr(Op.NOP), Instr(Op.RET, args=(0,))]
    root = CoroDescriptor(name="root", code=code, blocks=[], frame_locals=[])
    root.stmts = [(0, 61)]
    root.chans = [(1, 71, "c0", "put", 0, -1), (3, 72, "c0", "try_get", 0, 1),
                  (5, 73, "c1", "try_get", 0, 1)]
    return _model([root])


def _f0():
    return Obj(field_names=["f0"], values=[0])


#: name -> (model, Python VM run_model kwargs, native host factory).
DIFF_CASES = {
    "fact": (lambda: _fact_model(3), lambda: {"obj": _f0()}, lambda: (None, None)),
    "message": (_msg_model, lambda: {"obj": _f0(), "out": lambda _l: None},
                lambda: make_import_host()),
    "import": (_import_model,
               lambda: {"obj": _f0(),
                        "import_provider": RecordingImportProvider({7: 0x55})},
               lambda: make_import_host(returns={7: 0x55})),
    "access": (_mem_model, lambda: {"obj": _f0(), "memory": Memory()},
               lambda: _mem_host(Memory())),
    "registers": (lambda: _mem_model(regs=[(2, 3), (3, 3), (4, 5)], discards=[4]),
                  lambda: {"obj": _f0(), "memory": Memory()},
                  lambda: _mem_host(Memory())),
    "chan": (_chan_model, lambda: {}, lambda: (None, None)),
}


@pytest.mark.parametrize("case", sorted(DIFF_CASES))
def test_both_engines_write_the_same_trace(eng, case):
    """P4.4c c3: every kind the C engine raises, at once; the Python VM's
    trace goes through :class:`binary.BinarySink`, the C engine's is its own
    bytes; both are byte-equal once :func:`_canon` has dropped seq and the
    stmt path/scope."""
    import io

    mk_model, py_kw, mk_host = DIFF_CASES[case]
    buf = io.BytesIO()
    run_model(mk_model(), events=binary.BinarySink(buf), watch=C_KINDS, **py_kw())
    _, _, want = binary.read(buf.getvalue())
    host, _keep = mk_host()
    res, got = c_events(eng, mk_model(), C_KINDS, fields=[0], host=host)
    assert res.status == 0
    assert want, "the Python VM raised no events"
    assert _canon(got) == _canon(want), (binary.to_ndjson(_canon(got)),
                                         binary.to_ndjson(_canon(want)))
