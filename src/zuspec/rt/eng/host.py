"""The C engine's host ABI from Python (``pssvm.h``, P4.3d).

The same shape as be-bc's ``zuspec.be.bc.interp.host``: a call runs until it
needs its host and hands it a :class:`Request` (a memory access, a user
import, or a wait); the host answers with :meth:`NativeCall.complete` and
runs the call on with :meth:`NativeCall.run`::

    eng = Engine(lib, image)
    call = eng.call("entry", [arg])
    value = run_sync(call, memory, import_provider)

so a Python memory or import mock written for the Python VM answers the C
engine too. ``lib`` is the engine library (a ``ctypes.CDLL`` or its path),
built with :func:`zuspec.rt.eng.build.build_shared_lib`.

A call whose threads all wait on something only the host can change returns
WAIT on ``"EVENT"``; :meth:`NativeCall.notify` (an interrupt, started as the
handler :meth:`Engine.set_irq` names) lets it go on (P4.4e). Not here yet:
host-fed channels (``N_CHAN`` has no handler) and constructing a root other
than the image's own.
"""
from __future__ import annotations

import ctypes
import json
import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Union

#: run status (``pssvm_run``), as be-bc's host.py
DONE, ACCESS, IMPORT, WAIT, STOP, ERROR = 0, 1, 2, 3, 4, -1
STATUS_NAMES = {DONE: "DONE", ACCESS: "ACCESS", IMPORT: "IMPORT", WAIT: "WAIT",
                STOP: "STOP", ERROR: "ERROR"}

PSSVM_OK, PSSVM_E_STATE = 0, -2
#: notify kinds (``pssvm_notify``), as be-bc's host.py
N_IRQ, N_CHAN = 1, 2
_ON = {1: "TIME", 2: "EVENT"}
_NONE32 = 0xFFFFFFFF


class HostStateError(RuntimeError):
    """A call made in the wrong state (``PSSVM_E_STATE``)."""


class NativeError(RuntimeError):
    """An engine error; ``error`` is the ``pssvm_error`` JSON."""

    def __init__(self, error: dict):
        super().__init__(error.get("message", "engine error"))
        self.error = error


@dataclass
class Request:
    """What :meth:`NativeCall.run` returned: ``status`` and its fields (the
    fields of be-bc's ``host.Request``)."""
    status: int
    kind: str = ""
    addr: int = 0
    size: int = 0
    data: Optional[int] = None
    reg_id: Optional[int] = None
    src_ref: int = 0
    fn_id: int = 0
    name: Optional[str] = None
    args: List[int] = field(default_factory=list)
    blocking: bool = False
    has_ret: bool = False
    on: str = ""
    delay: int = 0
    error: Optional[dict] = None
    exc: Optional[BaseException] = None
    bound: bool = False   # IMPORT: a call of an Engine.bind function (fn_id: its coroutine)

    @property
    def status_name(self) -> str:
        return STATUS_NAMES[self.status]


class _Req(ctypes.Structure):
    """Mirror of ``pssvm_req_t``."""
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


#: C ``zbc_ev_out_f``: (ctx, bytes, len), a binary trace's next bytes.
EV_OUT_FN = ctypes.CFUNCTYPE(None, ctypes.c_void_p,
                             ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)


#: pssvm_dbg_stop's reasons and pssvm_dbg_resume's kinds (pssvm.h)
STOP_REASONS = {1: "pause", 2: "step", 3: "breakpoint", 4: "watch", 5: "error"}
RESUME, STEP_STMT, STEP_INTO, STEP_OUT = 0, 1, 2, 3


class _Stop(ctypes.Structure):
    """pssvm_stop_t (zbc_interp.h zbc_dbg_stop_t)."""
    _fields_ = [(n, ctypes.c_uint32) for n in
                ("reason", "thread_id", "frame_id", "coro", "pc", "src_ref",
                 "depth", "n_hits")] + [
        ("hits", ctypes.c_uint32 * 16), ("thread", ctypes.c_void_p),
        ("frame", ctypes.c_void_p), ("is_write", ctypes.c_uint32),
        ("size", ctypes.c_uint32), ("addr", ctypes.c_uint64),
        ("data", ctypes.c_uint64), ("status", ctypes.c_int32),
        ("op", ctypes.c_int32), ("message", ctypes.c_char_p)]


def _stop_detail(s) -> dict:
    """A stop's detail, as the debug stub's ``stopped`` event has it."""
    if s.reason == 4:
        return {"rw": "w" if s.is_write else "r", "width": 8 * s.size,
                "addr": s.addr, "data": s.data}
    if s.reason == 5:
        name = (s.message or b"error").decode()
        return {"error": f"{name} ({s.status})", "status": s.status,
                "halted_op": s.op}
    return {}


class _Watch(ctypes.Structure):
    """pssvm_watch_t (zbc_interp.h zbc_dbg_watch_t)."""
    _fields_ = [("id", ctypes.c_uint32), ("rw", ctypes.c_uint32),
                ("addr", ctypes.c_uint64), ("size", ctypes.c_uint64),
                ("has_value", ctypes.c_uint32), ("value", ctypes.c_uint64),
                ("mask", ctypes.c_uint64)]


#: pssvm_dbg_set_watches' rw (pssvm.h PSSVM_WATCH_*)
_WATCH_RW = {"r": 1, "w": 2, "rw": 3}


#: pssvm_frame_t's thread states (zbc_interp.h ZBC_DBG_RUNNING..WAITING)
THREAD_STATES = {0: "running", 1: "ready", 2: "waiting"}
#: zbc_interp.h ZBC_CALL_MAX_ARGS (a frame carries its nregs / nlocals)
_N_ARGS = 32


class _Frame(ctypes.Structure):
    """pssvm_frame_t (zbc_interp.h zbc_dbg_frame_t)."""
    _fields_ = [(n, ctypes.c_uint32) for n in
                ("id", "thread_id", "coro", "pc", "depth", "call_depth",
                 "state", "base")] + [
        ("regs", ctypes.POINTER(ctypes.c_uint64)),
        ("locals", ctypes.POINTER(ctypes.c_uint64)),
        ("args", ctypes.POINTER(ctypes.c_uint64)),
        ("frame", ctypes.c_void_p), ("thread", ctypes.c_void_p),
        ("nregs", ctypes.c_uint32), ("nlocals", ctypes.c_uint32)]

    def info(self) -> dict:
        return {"id": self.id, "thread": self.thread_id, "coro": self.coro,
                "pc": self.pc, "depth": self.depth, "call_depth": self.call_depth,
                "state": THREAD_STATES.get(self.state, str(self.state))}


def bind(lib) -> ctypes.CDLL:
    """Set the ``pssvm_*`` signatures on ``lib`` (a CDLL or a path)."""
    if not isinstance(lib, ctypes.CDLL):
        lib = ctypes.CDLL(str(lib))
    if getattr(lib, "_pssvm_bound", False):
        return lib
    vp, sz, u8p = ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p
    sigs = {
        "pssvm_abi_version": ([], ctypes.c_int),
        "pssvm_load": ([u8p, sz, ctypes.c_char_p], vp),
        "pssvm_construct": ([vp, ctypes.c_char_p, u8p, sz], ctypes.c_int),
        "pssvm_call_start": ([vp, ctypes.c_char_p, ctypes.c_char_p, u8p, sz,
                              ctypes.c_uint64], vp),
        "pssvm_call_start_obj": ([vp, ctypes.c_char_p, ctypes.c_char_p, u8p, sz,
                                  ctypes.c_uint64, vp, ctypes.c_uint32], vp),
        "pssvm_run": ([vp], ctypes.c_int),
        "pssvm_result": ([vp, vp, sz], sz),
        "pssvm_call_end": ([vp], None),
        "pssvm_error": ([vp, vp], ctypes.c_char_p),
        "pssvm_free": ([vp], None),
        "pssvm_call_status": ([vp, ctypes.POINTER(ctypes.c_int),
                               ctypes.POINTER(ctypes.c_uint64)], ctypes.c_int),
        "pssvm_request": ([vp], ctypes.POINTER(_Req)),
        "pssvm_complete": ([vp, u8p, sz], ctypes.c_int),
        "pssvm_comp_read": ([vp, vp, sz], sz),
        "pssvm_comp_write": ([vp, vp, sz], sz),
        "pssvm_reload": ([vp, u8p, sz, ctypes.c_uint32], ctypes.c_int),
        "pssvm_generation": ([vp], ctypes.c_uint64),
        "pssvm_set_events": ([vp, vp], None),
        "pssvm_notify": ([vp, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint64],
                         ctypes.c_int),
        "pssvm_set_irq": ([vp, ctypes.c_char_p], ctypes.c_int),
        "pssvm_bind": ([vp, ctypes.c_uint32, ctypes.c_int], ctypes.c_int),
        "pssvm_dbg_enable": ([vp, ctypes.c_int], ctypes.c_int),
        "pssvm_dbg_set_breaks": ([vp, vp, ctypes.c_uint32, vp], ctypes.c_int),
        "pssvm_dbg_pause": ([vp], ctypes.c_int),
        "pssvm_dbg_set_watches": ([vp, vp, ctypes.c_uint32], ctypes.c_int),
        "pssvm_dbg_set_stop_on": ([vp, ctypes.c_uint32], ctypes.c_int),
        "pssvm_dbg_resume": ([vp, ctypes.c_int], ctypes.c_int),
        "pssvm_dbg_stop": ([vp], ctypes.POINTER(_Stop)),
        "pssvm_dbg_threads": ([vp, vp, ctypes.c_uint32], ctypes.c_uint32),
        "pssvm_dbg_frames": ([vp, ctypes.c_uint32, vp, ctypes.c_uint32],
                             ctypes.c_uint32),
        "pssvm_dbg_frame": ([vp, ctypes.c_uint32, ctypes.POINTER(_Frame)],
                            ctypes.c_int),
        "pssvm_stub_new": ([vp], vp),
        "pssvm_stub_free": ([vp], None),
        "pssvm_stub_request": ([vp, ctypes.c_char_p], ctypes.c_char_p),
        "pssvm_stub_wait_attached": ([vp, ctypes.c_int], ctypes.c_int),
        "pssvm_stub_on_stop": ([vp, vp], ctypes.c_int),
        "pssvm_stub_exited": ([vp, ctypes.c_char_p, ctypes.c_char_p], None),
        "pssvm_stub_next_event": ([vp, ctypes.c_int], ctypes.c_char_p),
        "pssvm_stub_state": ([vp], ctypes.c_char_p),
        "pssvm_stub_set_backdoor": ([vp, PEEK_FN, vp], None),
        "zbc_ev_new": ([EV_OUT_FN, vp], vp),
        "zbc_ev_delete": ([vp], None),
        "zbc_ev_watch": ([vp, ctypes.c_uint32, ctypes.c_int32], None),
        "zbc_ev_header": ([vp, ctypes.POINTER(ctypes.c_char_p),
                           ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint32],
                          ctypes.c_int),
    }
    for name, (args, res) in sigs.items():
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = args, res
    lib._pssvm_bound = True
    return lib


def _error(lib, e, h) -> dict:
    raw = lib.pssvm_error(e, h)
    try:
        return json.loads(raw) if raw else {"message": "engine error"}
    except ValueError:
        return {"message": raw.decode(errors="replace")}


#: pssvm_peek_f: (ctx, addr, n, *out) -> 0 / non-zero
PEEK_FN = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_uint64,
                           ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint64))


class CStub:
    """The debug stub in C (pssvm_stub.c) on ``engine``: requests and events
    as dicts, NativeStub's interface. A successful ``attach`` starts the run
    thread: ``runs`` calls of the image's entry under :func:`run_sync` with
    ``memory`` and ``import_provider`` (``memory`` also serves
    ``backdoor_read``), stops going to ``pssvm_stub_on_stop``."""

    def __init__(self, engine: "Engine", memory=None, import_provider=None, runs: int = 1):
        import threading
        self.engine, self.lib = engine, engine.lib
        self._h = self.lib.pssvm_stub_new(engine._h)
        if not self._h:
            raise NativeError({"message": "pssvm_stub_new failed"})
        self.memory, self.import_provider, self.runs = memory, import_provider, runs
        self._thread: Optional["threading.Thread"] = None
        self.root_thread: Optional[int] = None
        self._peek = None
        if memory is not None:
            from .debug import backdoor_read

            def _peek(_ctx, addr, n, out):
                try:
                    out[0] = backdoor_read(memory, addr, n) & (2**64 - 1)
                    return 0
                except Exception:
                    return 1
            self._peek = PEEK_FN(_peek)
            self.lib.pssvm_stub_set_backdoor(self._h, self._peek, None)

    @property
    def state(self) -> str:
        return self.lib.pssvm_stub_state(self._h).decode()

    def request(self, msg: dict) -> dict:
        import json
        import threading
        start = (isinstance(msg, dict) and msg.get("cmd") == "attach"
                 and self._thread is None and self.state == "detached")
        if start:       # the run thread waits for the attach, then runs
            self._thread = threading.Thread(target=self._main, name="pssvm-cstub",
                                            daemon=True)
            self._thread.start()
        rep = json.loads(self.lib.pssvm_stub_request(
            self._h, json.dumps(msg, separators=(",", ":")).encode()))
        if start and rep.get("ok"):
            self.root_thread = self._root()
        return rep

    def _root(self):
        """The entry's thread (the only one at the entry stop), or None."""
        import json
        if self.state != "stopped":
            return None
        rep = json.loads(self.lib.pssvm_stub_request(self._h, b'{"cmd":"threads"}'))
        ts = rep.get("body", {}).get("threads", []) if rep.get("ok") else []
        return ts[0]["id"] if ts else None

    def next_event(self, timeout: Optional[float] = 5.0) -> Optional[dict]:
        import json
        ms = -1 if timeout is None else int(timeout * 1000)
        p = self.lib.pssvm_stub_next_event(self._h, ms)
        return None if p is None else json.loads(p)

    def join(self, timeout: Optional[float] = 5.0) -> None:
        if self._thread is not None:
            self._thread.join(timeout)

    def free(self) -> None:
        if self._h:
            self.join()
            self.lib.pssvm_stub_free(self._h)
            self._h = None

    def _on_stop(self, call) -> None:
        from .debug import Terminated
        if self.lib.pssvm_stub_on_stop(self._h, call._h) == 1:
            raise Terminated()

    def _main(self):
        from .debug import Terminated
        if self.lib.pssvm_stub_wait_attached(self._h, 10000) != 1:
            self._thread = None
            return
        status, message = "ok", None
        try:
            for _ in range(self.runs):
                run_sync(self.engine.call(), self.memory, self.import_provider,
                         on_stop=self._on_stop)
        except Terminated:
            status = "terminated"
        except Exception as e:
            err = getattr(e, "error", None)
            status = "error"
            message = err.get("message") if isinstance(err, dict) and err.get("message") \
                else f"{type(e).__name__}: {e}"
        self.lib.pssvm_stub_exited(self._h, status.encode(),
                                   message.encode() if message else None)


class Engine:
    """A loaded image (``pssvm_load``); its component tree is built at the
    first call and lives as long as the engine."""

    def __init__(self, lib: Union[ctypes.CDLL, str], image: bytes,
                 opts: Optional[str] = None):
        self.lib = bind(lib)
        self._image = bytes(image)    # the engine may keep pointers into it
        self._h = self.lib.pssvm_load(self._image, len(self._image),
                                      opts.encode() if opts else None)
        if not self._h:
            raise NativeError(_error(self.lib, None, None))
        self._sink = None
        self._out = None

    def trace(self, out: Callable[[bytes], None], mask: Optional[int] = None,
              header: Optional[Dict[str, str]] = None) -> None:
        """Write the debug events ``mask`` selects (all, by default) of
        every later call as a binary trace (be-bc ``trace/binary.py``),
        passing its bytes to ``out`` as they come; ``header``: the trace
        header's keys (string values: a test's name, the image's path)."""
        if not self._h:
            raise HostStateError("the engine is freed")
        if self._sink is not None:
            raise HostStateError("the engine already writes a trace")
        if mask is None:
            from zuspec.be.bc.trace.events import EV_ALL
            mask = EV_ALL

        @EV_OUT_FN
        def _out(_ctx, p, n):
            out(ctypes.string_at(p, n))

        self._out = _out              # keep the callback alive
        self._sink = self.lib.zbc_ev_new(_out, None)
        if not self._sink:
            raise NativeError({"message": "out of memory (event sink)"})
        self.lib.zbc_ev_watch(self._sink, mask & 0xFFFFFFFF, -1)
        if header:
            ks = sorted(header)
            keys = (ctypes.c_char_p * len(ks))(*(k.encode() for k in ks))
            vals = (ctypes.c_char_p * len(ks))(
                *(str(header[k]).encode() for k in ks))
            self.lib.zbc_ev_header(self._sink, keys, vals, len(ks))
        self.lib.pssvm_set_events(self._h, self._sink)

    def call(self, entry: str = "", args: Sequence[int] = (),
             comp_path: str = "", seed: int = 0,
             obj_slots: int = 0) -> "NativeCall":
        """Start a call of ``entry`` (``""``: the image's entry coroutine)
        with u64 ``args``; ``obj_slots``: an action entry's object of that
        many fields, zeroed (``NativeCall.obj`` after the run)."""
        if not self._h:
            raise HostStateError("the engine is freed")
        a = b"".join(struct.pack("<Q", int(v) & (2**64 - 1)) for v in args)
        slots = (ctypes.c_uint64 * obj_slots)() if obj_slots else None
        h = self.lib.pssvm_call_start_obj(self._h, entry.encode(), comp_path.encode(),
                                          a, len(a), seed, slots, obj_slots)
        if not h:
            raise NativeError(_error(self.lib, self._h, None))
        call = NativeCall(self, h)
        call._slots = slots
        return call

    def set_irq(self, entry: Optional[str]) -> None:
        """The function entry an ``N_IRQ`` notification starts, in the root
        component (None: none)."""
        if not self._h:
            raise HostStateError("the engine is freed")
        if self.lib.pssvm_set_irq(self._h, (entry or "").encode()) != PSSVM_OK:
            raise NativeError(_error(self.lib, self._h, None))

    def bind(self, coro: int, on: bool = True) -> None:
        """From the next call on, each CALL of coroutine ``coro`` is an
        IMPORT request with ``bound`` set (``fn_id``: ``coro``, ``args``: the
        call's), answered with the function's result in place of its body,
        as be-bc's ``VM.bind`` does; ``on=False`` unbinds it."""
        if not self._h:
            raise HostStateError("the engine is freed")
        if self.lib.pssvm_bind(self._h, int(coro), 1 if on else 0) != PSSVM_OK:
            raise NativeError(_error(self.lib, self._h, None))

    def notify(self, kind: int, id: int = 0, value: int = 0) -> None:
        """A host event; the next :meth:`NativeCall.run` of any call takes it."""
        if not self._h:
            raise HostStateError("the engine is freed")
        if self.lib.pssvm_notify(self._h, kind, id, value & (2**64 - 1)) != PSSVM_OK:
            raise HostStateError(_error(self.lib, self._h, None)
                                 .get("message", "pssvm_notify refused"))

    def stub(self, memory=None, import_provider=None, runs: int = 1) -> CStub:
        """A debug session on this engine served by the C stub (pssvm_stub.c)."""
        return CStub(self, memory, import_provider, runs)

    def dbg_enable(self, on: bool = True) -> None:
        """Debug stops (breakpoints, pause, steps) in later calls."""
        self.lib.pssvm_dbg_enable(self._h, 1 if on else 0)

    def dbg_set_breaks(self, breaks) -> List[bool]:
        """Replace the breakpoints with ``breaks``, (id, coro, pc) triples
        (pc in the coroutine); returns whether each names an instruction."""
        n = len(breaks)
        flat = (ctypes.c_uint32 * max(3 * n, 1))(*[v for b in breaks for v in b])
        ok = (ctypes.c_uint8 * max(n, 1))()
        if self.lib.pssvm_dbg_set_breaks(self._h, flat, n, ok) != PSSVM_OK:
            raise NativeError(_error(self.lib, self._h, None))
        return [bool(v) for v in ok[:n]]

    def dbg_set_watches(self, watches) -> List[bool]:
        """Replace the access watches with ``watches``, dicts as the debug
        stub's ``set_access_watch`` (id, addr, size, rw "r"/"w"/"rw",
        optional value and mask); returns whether each is valid (only those
        are set)."""
        ok, good = [], []
        for w in watches:
            rw = _WATCH_RW.get(w.get("rw", "rw"))
            v = (isinstance(w.get("id"), int) and isinstance(w.get("addr"), int)
                 and isinstance(w.get("size"), int) and w["size"] > 0 and rw)
            ok.append(bool(v))
            if v:
                value = w.get("value")
                good.append(_Watch(w["id"], rw, w["addr"], w["size"],
                                   value is not None, (value or 0) & (2**64 - 1),
                                   w.get("mask", 2**64 - 1) & (2**64 - 1)))
        arr = (_Watch * max(len(good), 1))(*good)
        if self.lib.pssvm_dbg_set_watches(self._h, arr, len(good)) != PSSVM_OK:
            raise NativeError(_error(self.lib, self._h, None))
        return ok

    def dbg_set_stop_on(self, kinds) -> List[str]:
        """Stop on these kinds (the C engine knows "error"); returns those set."""
        on = sorted(k for k in kinds if k == "error")
        self.lib.pssvm_dbg_set_stop_on(self._h, 1 if on else 0)
        return on

    def dbg_pause(self) -> None:
        """The next instruction of any thread stops (STOP, reason pause)."""
        self.lib.pssvm_dbg_pause(self._h)

    def comp_slots(self) -> List[int]:
        """The component object's slots (field i of the image's component
        tree), as left by the last call; [] before the first."""
        if not self._h:
            raise HostStateError("the engine is freed")
        n = self.lib.pssvm_comp_read(self._h, None, 0)
        buf = (ctypes.c_uint64 * max(n, 1))()
        self.lib.pssvm_comp_read(self._h, buf, n)
        return list(buf[:n])

    def construct(self) -> None:
        """Build the component tree now (``pssvm_construct``) rather than at
        the first call. Construction must not need the host: a memory access
        or import there raises :class:`NativeError` (message
        ``construct-yield: ...``) and leaves no tree."""
        if not self._h:
            raise HostStateError("the engine is freed")
        if self.lib.pssvm_construct(self._h, None, None, 0) != PSSVM_OK:
            raise NativeError(_error(self.lib, self._h, None))

    def comp_write(self, slots: Sequence[int]) -> int:
        """Overwrite the constructed component object's first ``len(slots)``
        slots (``pssvm_comp_write``, for a reload's migration); returns the
        number written, 0 before construction. Call with no call live."""
        if not self._h:
            raise HostStateError("the engine is freed")
        buf = (ctypes.c_uint64 * max(len(slots), 1))(
            *[int(v) & (2**64 - 1) for v in slots])
        return self.lib.pssvm_comp_write(self._h, buf, len(slots))

    def reload(self, image: bytes, strict: bool = False) -> None:
        """Load ``image`` as the next generation in place, in C
        (``pssvm_reload``; call with no call live). A refusal raises
        :class:`NativeError` whose message starts with the reason (``api``,
        ``structure``, ``bus``, ``construct``) and leaves this generation."""
        if not self._h:
            raise HostStateError("the engine is freed")
        if self.lib.pssvm_reload(self._h, bytes(image), len(image), 1 if strict else 0) != PSSVM_OK:
            raise NativeError(_error(self.lib, self._h, None))

    @property
    def generation(self) -> int:
        """1 at load, one more for each :meth:`reload`."""
        return int(self.lib.pssvm_generation(self._h)) if self._h else 0

    def free(self) -> None:
        if self._h:
            self.lib.pssvm_free(self._h)
            self._h = None
        if self._sink is not None:
            self.lib.zbc_ev_delete(self._sink)
            self._sink = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.free()


class NativeCall:
    """One call on the C engine, with be-bc's ``HostCall`` interface."""

    def __init__(self, engine: Engine, h):
        self.engine = engine
        self.lib = engine.lib
        self._h = h
        self._pending: Optional[Request] = None
        self._failed: Optional[BaseException] = None
        self._last: Optional[Request] = None
        self._result: Optional[int] = None
        self._slots = None                 # the action object's fields (Engine.call)
        self.over = False

    def run(self) -> Request:
        """Run the call until it needs the host; the request says why."""
        if self.over:
            raise HostStateError("the call is over")
        if self._failed is not None:
            # the host's answer was an error: the call ends with it
            exc, self._failed = self._failed, None
            r = Request(ERROR, error={"message": str(exc)}, exc=exc)
            self._finish(r)
            return r
        if self._pending is not None:
            raise HostStateError(f"the {self._pending.status_name} is not answered")
        st = self.lib.pssvm_run(self._h)
        if st == DONE:
            buf = (ctypes.c_uint8 * 8)()
            n = self.lib.pssvm_result(self._h, buf, 8)
            self._result = struct.unpack("<Q", bytes(buf))[0] if n == 8 else None
            r = Request(DONE)
            self._finish(r)
        elif st == ERROR:
            err = _error(self.lib, self.engine._h, self._h)
            r = Request(ERROR, error=err, exc=NativeError(err))
            self._finish(r)
        elif st == STOP:
            r = Request(STOP, src_ref=self.lib.pssvm_request(self._h).contents.src_ref)
        elif st in (ACCESS, IMPORT, WAIT):
            r = self._request(st)
            if st != WAIT:
                self._pending = r
        else:
            raise HostStateError(f"pssvm_run gave {st}")
        self._last = r
        return r

    def dbg_stop(self) -> Optional[dict]:
        """Where the call is stopped (after a STOP), or None."""
        p = self.lib.pssvm_dbg_stop(self._h)
        if not p:
            return None
        s = p.contents
        return {"reason": STOP_REASONS.get(s.reason, str(s.reason)),
                "thread": s.thread_id, "frame": s.frame_id, "coro": s.coro,
                "pc": s.pc, "src_ref": s.src_ref, "depth": s.depth,
                "hits": list(s.hits[:s.n_hits]), "detail": _stop_detail(s)}

    def dbg_threads(self) -> List[dict]:
        """The live threads of a stopped call (ids ascending): ``id`` (its
        bottom frame's), ``coro``, ``state`` running/ready/waiting."""
        n = self.lib.pssvm_dbg_threads(self._h, None, 0)
        ids = (ctypes.c_uint32 * max(n, 1))()
        n = min(n, self.lib.pssvm_dbg_threads(self._h, ids, n))
        out = []
        for tid in ids[:n]:
            f = self.dbg_frames(tid)
            if f:
                out.append({"id": tid, "coro": f[-1]["coro"], "state": f[-1]["state"]})
        return out

    def dbg_frames(self, thread: int) -> List[dict]:
        """A stopped call's thread's frames, innermost first ([] if none):
        ``id``, ``coro``, ``pc``, ``depth`` (on the thread), ``call_depth``."""
        n = self.lib.pssvm_dbg_frames(self._h, thread, None, 0)
        if n == 0:
            return []
        buf = (_Frame * n)()
        n = min(n, self.lib.pssvm_dbg_frames(self._h, thread, buf, n))
        return [buf[i].info() for i in range(n)]

    def dbg_read_frame(self, frame: int) -> Optional[dict]:
        """A stopped call's frame (None if not live): :meth:`dbg_frames`'s
        keys plus its ``regs``, ``locals`` (the slots) and call ``args``."""
        f = _Frame()
        if self.lib.pssvm_dbg_frame(self._h, frame, ctypes.byref(f)) != PSSVM_OK:
            return None
        d = f.info()
        d["base"] = f.base
        d["regs"] = list(f.regs[:f.nregs])
        d["locals"] = list(f.locals[:f.nlocals])
        d["args"] = list(f.args[:_N_ARGS])
        return d

    def dbg_resume(self, kind: int = RESUME) -> None:
        """Resume a stopped call: continue, or step (STEP_STMT/INTO/OUT) the
        stopped thread; the next :meth:`run` runs it."""
        if self.lib.pssvm_dbg_resume(self._h, kind) != PSSVM_OK:
            raise HostStateError("the call is not stopped")

    def _request(self, st: int) -> Request:
        q = self.lib.pssvm_request(self._h).contents
        if st == ACCESS:
            return Request(ACCESS, kind="w" if q.kind else "r", addr=q.addr,
                           size=q.size, data=q.data if q.kind else None,
                           reg_id=None if q.reg_id == _NONE32 else q.reg_id,
                           src_ref=0 if q.src_ref == _NONE32 else q.src_ref)
        if st == IMPORT:
            raw = bytes(q.args[:q.args_len]) if q.args_len else b""
            return Request(IMPORT, fn_id=q.fn_id,
                           name=q.name.decode() if q.name else None,
                           args=list(struct.unpack("<%dQ" % (len(raw) // 8), raw)),
                           blocking=bool(q.blocking), has_ret=bool(q.has_ret),
                           bound=bool(q.bound),
                           src_ref=0 if q.src_ref == _NONE32 else q.src_ref)
        return Request(WAIT, on=_ON.get(q.on, ""), delay=q.delay)

    def complete(self, value: Optional[int] = None) -> None:
        """Answer the pending access or import: the read value, the import's
        result (None: none), nothing for a write."""
        r = self._pending
        if r is None:
            raise HostStateError("nothing to complete")
        if r.status == ACCESS:
            if r.kind == "r":
                if value is None:
                    raise HostStateError("a read completes with its value")
                data = (int(value) & ((1 << (8 * r.size)) - 1)).to_bytes(r.size, "little")
            elif value is not None:
                raise HostStateError("a write completes with no value")
            else:
                data = b""
        else:
            # an import without a result drops what the mock returned
            data = (struct.pack("<Q", int(value or 0) & (2**64 - 1))
                    if r.has_ret else b"")
        if self.lib.pssvm_complete(self._h, data or None, len(data)) != PSSVM_OK:
            raise HostStateError(_error(self.lib, self.engine._h, self._h)
                                 .get("message", "pssvm_complete refused"))
        self._pending = None

    def fail(self, exc: BaseException) -> None:
        """Answer the pending access or import with an error: the next
        :meth:`run` is ERROR with ``exc`` (the C engine cannot raise it where
        the access was made, so a model cannot catch it)."""
        if self._pending is None:
            raise HostStateError("nothing to fail")
        self._pending = None
        self._failed = exc

    def notify(self, kind: int, id: int = 0, value: int = 0) -> None:
        """A host event; it takes effect at the next :meth:`run`."""
        self.engine.notify(kind, id, value)

    @property
    def request(self) -> Optional[Request]:
        return self._last

    @property
    def obj(self) -> List[int]:
        """The action object's fields as the call left them (Engine.call
        ``obj_slots``; empty: none)."""
        return list(self._slots) if self._slots is not None else []

    @property
    def result(self):
        """The entry's return value after DONE (None: none)."""
        if self._last is None or self._last.status != DONE:
            raise HostStateError("the call is not DONE")
        return self._result

    def status(self):
        """(ZBC status, halting op, engine time) of the call."""
        halted, now = ctypes.c_int(), ctypes.c_uint64()
        st = self.lib.pssvm_call_status(self._h, ctypes.byref(halted),
                                        ctypes.byref(now))
        return st, halted.value, now.value

    def _finish(self, r: Request) -> None:
        self._last = r
        self.over = True

    def end(self) -> None:
        """Free the call; one not DONE is dropped."""
        if self._h:
            self.lib.pssvm_call_end(self._h)
            self._h = None
        self.over = True


def run_sync(call: NativeCall, memory=None, import_provider=None,
             on_stop: Optional[Callable[[NativeCall], None]] = None,
             bound: Optional[Dict[int, Callable]] = None):
    """Run ``call`` to DONE, answering from ``memory`` (``read(addr, n)``,
    ``write(addr, n, value)``) and ``import_provider`` (``call(fn_id,
    args)``), as be-bc's ``host.run_sync`` does, with no clock: a WAIT TIME
    runs on at once. A debug STOP goes to ``on_stop(call)``, which returns
    once it has resumed the call (none: the call resumes at once). Returns
    the entry's return value; an engine error or an error from ``memory`` /
    ``import_provider`` is raised. The call is ended either way. A
    ``memory`` with ``note_access(reg_id, src_ref)`` (pssc's register fake)
    is told each access's register and statement first, as the Python VM
    tells it. ``bound`` answers the calls of :meth:`Engine.bind` functions:
    ``bound[coro](*args)`` is the result (None: 0)."""
    note = getattr(memory, "note_access", None)
    try:
        while True:
            r = call.run()
            if r.status == DONE:
                return call.result
            if r.status in (ACCESS, IMPORT):
                try:
                    if r.status == IMPORT and r.bound:
                        fn = (bound or {}).get(r.fn_id)
                        if fn is None:
                            raise NativeError({"message": f"no host function bound to coroutine {r.fn_id}"})
                        v = fn(*r.args)
                    elif r.status == IMPORT:
                        if import_provider is None:
                            raise NativeError({"message": f"no import provider for fn {r.fn_id}"})
                        v = import_provider.call(r.fn_id, r.args)
                    elif memory is None:
                        raise NativeError({"message": f"no memory for access at {r.addr:#x}"})
                    else:
                        if note is not None:
                            note(r.reg_id, r.src_ref)
                        if r.kind == "r":
                            v = memory.read(r.addr, r.size)
                        else:
                            memory.write(r.addr, r.size, r.data)
                            v = None
                except BaseException as e:
                    call.fail(e)
                    continue
                call.complete(v)
            elif r.status == WAIT:
                if r.on == "EVENT":
                    raise NativeError({"message": "deadlock: the call waits on an "
                                       "event nothing here can notify"})
            elif r.status == STOP:
                if on_stop is not None:
                    on_stop(call)
                else:
                    call.dbg_resume(RESUME)
            elif r.status == ERROR:
                raise r.exc
            else:
                raise HostStateError(f"run_sync cannot serve {r.status_name}")
    finally:
        call.end()
