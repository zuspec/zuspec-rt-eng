"""The debug stub over the C engine (pssc P4.5c1): be-bc's ``interp.debug.Stub``
protocol (be-bc docs/spec/debug-stub.md) served from Python, with the stops
of :mod:`host` (``pssvm_dbg_*``). A stop is a host yield: the run thread's
:func:`host.run_sync` calls the stub's ``on_stop``, which blocks until a
request resumes the call.

Differences from the Python VM's stub: ``engine`` is ``"c"``; no
``exec_snippet`` (``unsupported``); ``set_stop_on`` knows only ``error``;
``read_frame``'s ``this`` is None (C frames keep no component); a frame's
``args`` are those up to the last non-zero one and, with no local table,
``regs`` the non-zero registers (C frames keep no counts); ``step`` steps
only the stopped thread (another: ``unsupported``)."""
from __future__ import annotations

import bisect
import hashlib
import queue
import threading
from typing import Any, Callable, Optional

from . import host as nhost

VERSION = 1
ENGINE = "c"
CAPABILITIES = ["access_watch", "backdoor_read"]
STOP_KINDS = ("check", "error", "sanitizer")

#: commands accepted while running (the rest reply ``not_stopped``)
_WHILE_RUNNING = {"stop", "set_pc_breaks", "set_access_watch", "set_stop_on",
                  "detach", "terminate"}
_STEPS = {"stmt": nhost.STEP_STMT, "into": nhost.STEP_INTO, "out": nhost.STEP_OUT}


class Terminated(BaseException):
    """Raised in the run thread by ``terminate`` (out of ``on_stop``) to end
    the run; :func:`host.run_sync` ends the call on the way out."""


class StubError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def backdoor_read(memory, addr: int, n: int) -> int:
    """``n`` bytes at ``addr`` with no bus access: the memory's ``peek(addr,
    n)`` if it has one, else its ``bytes`` dict (be-bc ``extern.Memory``)."""
    peek = getattr(memory, "peek", None)
    if peek is not None:
        return peek(addr, n)
    data = getattr(memory, "bytes", None)
    if not isinstance(data, dict):
        raise StubError("unsupported", "the platform memory has no back door")
    return sum((data.get(addr + i, 0) & 0xFF) << (8 * i) for i in range(n))


class NativeStub:
    """A debug session on runs of ``engine`` (a :class:`host.Engine` loaded
    from ``model``, the ZbcModel that gives names, statements and locals).
    ``run(on_stop)`` runs the calls (default: the image's entry under
    :func:`host.run_sync` with ``memory`` and ``import_provider``); it starts
    on ``attach`` and stops before its first instruction."""

    def __init__(self, engine, model, run: Optional[Callable[[Callable], Any]] = None,
                 memory=None, import_provider=None,
                 on_event: Optional[Callable[[dict], None]] = None):
        if run is None:
            run = lambda on_stop: nhost.run_sync(engine.call(), memory,
                                                 import_provider, on_stop=on_stop)
        self.engine = engine
        self.model = model
        self.memory = memory
        self._run = run
        self.on_event = on_event
        self.events: "queue.Queue[dict]" = queue.Queue()
        #: coroutine index -> {pc: first src_ref} / its statement pcs, ascending
        self._stmts, self._stmt_pcs = [], []
        for c in model.coros:
            pcs = {}
            for pc, sr in getattr(c, "stmts", None) or ():
                pcs.setdefault(pc, sr)
            self._stmts.append(pcs)
            self._stmt_pcs.append(sorted(pcs))
        self._cv = threading.Condition()
        self.state = "detached"     # detached|starting|stopped|running|exited
        self._thread: Optional[threading.Thread] = None
        self._observed = False
        self._terminate = False
        self._resumed = 0           # bumped by every resume, for on_stop's wait
        self._resume_kind = nhost.RESUME
        self._stop_on = {"error"}
        #: the stopped call and its stop (``NativeCall.dbg_stop``), or None
        self._call = None
        self.where: Optional[dict] = None
        #: the thread the run first stopped in (the entry's)
        self.root_thread: Optional[int] = None

    # -- the requests ----------------------------------------------------- #

    def request(self, msg: dict) -> dict:
        """Run one request; returns its reply."""
        seq = msg.get("seq") if isinstance(msg, dict) else None
        try:
            if not isinstance(msg, dict) or not isinstance(msg.get("cmd"), str):
                raise StubError("bad_request", "a request needs a cmd")
            args = msg.get("args") or {}
            if not isinstance(args, dict):
                raise StubError("bad_request", "args must be an object")
            fn = getattr(self, "_cmd_" + msg["cmd"], None)
            if fn is None:
                raise StubError("bad_request", f"unknown cmd {msg['cmd']!r}")
            with self._cv:
                if msg["cmd"] != "attach" and self.state == "detached":
                    raise StubError("bad_request", "not attached")
                if self.state == "exited" and msg["cmd"] not in ("detach", "terminate"):
                    raise StubError("not_stopped", "the run has ended")
                if self.state == "running" and msg["cmd"] not in _WHILE_RUNNING:
                    raise StubError("not_stopped", f"{msg['cmd']} needs a stopped run")
                body = fn(args)
            if msg["cmd"] == "attach":
                self._wait_started()
            return {"seq": seq, "ok": True, "body": body}
        except StubError as e:
            return {"seq": seq, "ok": False,
                    "error": {"code": e.code, "message": str(e)}}

    def next_event(self, timeout: Optional[float] = 5.0) -> Optional[dict]:
        """The next event, or None if none comes within ``timeout``."""
        try:
            return self.events.get(timeout=timeout)
        except queue.Empty:
            return None

    def join(self, timeout: Optional[float] = 5.0) -> None:
        if self._thread is not None:
            self._thread.join(timeout)

    def _cmd_attach(self, args):
        if self.state != "detached":
            raise StubError("bad_request", "already attached")
        if args.get("version", VERSION) != VERSION:
            raise StubError("bad_request", f"protocol version {VERSION} only")
        try:
            sha = hashlib.sha256(self.model.to_bytes()).hexdigest()
        except Exception:       # a hand-built model may not encode
            sha = ""
        # entry false: a run driven by its host: no stop before the first
        # instruction, the run is running
        hosted = not args.get("entry", True)
        self.state = "running" if hosted else "starting"
        self._observed = True
        eng = self.engine
        eng.dbg_enable(True)
        eng.dbg_set_stop_on(sorted(self._stop_on))     # the C default is off
        if not hosted:
            eng.dbg_pause()
        self._thread = threading.Thread(target=self._main, name="pssvm-debug",
                                        daemon=True)
        self._thread.start()
        return {"version": VERSION, "engine": ENGINE,
                "capabilities": list(CAPABILITIES),
                "image": {"coros": len(self.model.coros), "sha256": sha}}

    def _wait_started(self):
        with self._cv:
            while self.state == "starting":
                self._cv.wait()

    def _cmd_detach(self, args):
        eng = self.engine
        eng.dbg_set_breaks([])
        eng.dbg_set_watches([])
        eng.dbg_set_stop_on([])
        eng.dbg_enable(False)
        self._stop_on = set()
        self._observed = False
        self.on_event = None
        if self.state == "stopped":
            self._resume(nhost.RESUME)
        self.state = "detached" if self.state != "exited" else "exited"
        return {}

    def _cmd_terminate(self, args):
        if self.state == "exited":
            return {}
        self._terminate = True
        if self.state == "stopped":
            self._resume(nhost.RESUME)
        else:
            self.engine.dbg_pause()     # the next instruction stops, and ends
        return {}

    def _cmd_continue(self, args):
        self._resume(nhost.RESUME)
        return {}

    def _cmd_stop(self, args):
        if self.state != "running":
            raise StubError("not_running", "the run is already stopped")
        self.engine.dbg_pause()
        return {}

    def _cmd_step(self, args):
        kind = args.get("kind", "stmt")
        if kind not in _STEPS:
            raise StubError("bad_request", f"unknown step kind {kind!r}")
        tid = args.get("thread")
        if not isinstance(tid, int):
            raise StubError("bad_request", "step needs a thread")
        self._thread_by_id(tid)
        if tid != self.where["thread"]:
            raise StubError("unsupported", "the C engine steps the stopped thread only")
        self._resume(_STEPS[kind])
        return {}

    # -- inspection (stopped only) ----------------------------------------- #

    def _coro_name(self, coro):
        cs = self.model.coros
        return cs[coro].name if 0 <= coro < len(cs) else ""

    def _src_ref_at(self, coro, pc):
        """The statement containing ``pc``: the last start at or before it."""
        if not 0 <= coro < len(self._stmt_pcs):
            return 0
        pcs = self._stmt_pcs[coro]
        i = bisect.bisect_right(pcs, pc)
        return self._stmts[coro][pcs[i - 1]] if i else 0

    def _thread_by_id(self, tid):
        if not isinstance(tid, int):
            raise StubError("bad_request", "needs an int thread")
        frames = self._call.dbg_frames(tid) if tid >= 0 else []
        if not frames:
            raise StubError("no_thread", f"no live thread {tid}")
        return frames

    def _cmd_threads(self, args):
        return {"threads": [
            dict(t, name=self._coro_name(t["coro"])) for t in self._call.dbg_threads()]}

    def _cmd_frames(self, args):
        return {"frames": [
            {"id": f["id"], "coro": f["coro"], "name": self._coro_name(f["coro"]),
             "pc": f["pc"], "src_ref": self._src_ref_at(f["coro"], f["pc"]),
             "depth": f["call_depth"]}
            for f in self._thread_by_id(args.get("thread"))]}

    def _cmd_read_frame(self, args):
        fid = args.get("frame")
        if not isinstance(fid, int):
            raise StubError("bad_request", "needs an int frame")
        f = self._call.dbg_read_frame(fid) if fid >= 0 else None
        if f is None:
            raise StubError("no_frame", f"no live frame {fid}")
        coro, pc = f["coro"], f["pc"]
        lvars = (getattr(self.model.coros[coro], "locals", None) or ()
                 if 0 <= coro < len(self.model.coros) else ())
        locs = [{"name": v.name, "value": f["locals"][v.slot], "width": v.width,
                 "signed": v.signed, "kind": v.kind}
                for v in lvars
                if v.pc_start <= pc < v.pc_end and v.slot < len(f["locals"])]
        a = f["args"]
        n = max((i + 1 for i, v in enumerate(a) if v), default=0)
        body = {"locals": locs, "args": a[:n], "this": None}
        if not lvars:
            body["regs"] = {str(k): v for k, v in enumerate(f["regs"]) if v}
        return body

    def _cmd_read_comp(self, args):
        comps = getattr(self.model, "components", None)
        if comps is None:
            raise StubError("no_comp", "the image has no component tree")
        comp = args.get("comp")
        if comp is None and isinstance(args.get("path"), str):
            comp = comps.paths.index(args["path"]) if args["path"] in comps.paths else -1
        if not isinstance(comp, int) or not 0 <= comp < len(comps.paths):
            raise StubError("no_comp", f"no component {args.get('comp', args.get('path'))!r}")
        # an instance's fields: its slots up to the next instance's base
        lo = comps.bases[comp]
        hi = min([b for b in comps.bases if b > lo], default=len(comps.names))
        values = self.engine.comp_slots()
        fields = [{"name": comps.names[s], "value": values[s] if s < len(values) else 0,
                   "width": 64, "signed": False, "kind": "int"} for s in range(lo, hi)]
        return {"comp": comp, "path": comps.paths[comp], "fields": fields}

    def _cmd_backdoor_read(self, args):
        addr, width = args.get("addr"), args.get("width")
        if not isinstance(addr, int) or width not in (8, 16, 32, 64):
            raise StubError("bad_request", "backdoor_read needs int addr, width 8|16|32|64")
        if self.memory is None:
            raise StubError("unsupported", "the run has no host memory")
        return {"value": backdoor_read(self.memory, addr, width // 8)}

    def _cmd_exec_snippet(self, args):
        raise StubError("unsupported", "the C engine runs no snippets")

    def _cmd_set_access_watch(self, args):
        ws = args.get("watches")
        if not isinstance(ws, list):
            raise StubError("bad_request", "set_access_watch needs watches")
        for w in ws:
            if not isinstance(w, dict) or not isinstance(w.get("id"), int):
                raise StubError("bad_request", "a watch needs an int id")
        ok = self.engine.dbg_set_watches(ws)
        return {"watches": [{"id": w["id"], "verified": v} for w, v in zip(ws, ok)]}

    def _cmd_set_stop_on(self, args):
        kinds = args.get("kinds")
        if not isinstance(kinds, list) or not all(isinstance(k, str) for k in kinds):
            raise StubError("bad_request", "set_stop_on needs kinds [str]")
        self._stop_on = set(self.engine.dbg_set_stop_on(
            [k for k in kinds if k in STOP_KINDS]))
        return {"kinds": sorted(self._stop_on)}

    def _cmd_set_pc_breaks(self, args):
        breaks = args.get("breaks")
        if not isinstance(breaks, list):
            raise StubError("bad_request", "set_pc_breaks needs breaks")
        coros = self.model.coros
        table, out = [], []
        for b in breaks:
            if not isinstance(b, dict) or not all(
                    isinstance(b.get(k), int) for k in ("id", "coro", "pc")):
                raise StubError("bad_request", "a break needs int id, coro, pc")
            c, pc = b["coro"], b["pc"]
            if not 0 <= c < len(coros):
                out.append({"id": b["id"], "verified": False,
                            "message": f"no coroutine {c}"})
            elif not 0 <= pc < len(coros[c].code):
                out.append({"id": b["id"], "verified": False,
                            "message": f"pc {pc} out of range"})
            else:
                table.append((b["id"], c, pc))
                out.append({"id": b["id"], "verified": True})
        self.engine.dbg_set_breaks(table)
        return {"breaks": out}

    def _resume(self, kind):
        self.state = "running"
        self._resume_kind = kind
        self._resumed += 1
        self._cv.notify_all()

    # -- the run thread ---------------------------------------------------- #

    def _emit(self, event: str, body: dict) -> None:
        msg = {"event": event, "body": body}
        self.events.put(msg)
        if self.on_event is not None:
            self.on_event(msg)

    def on_stop(self, call) -> None:
        """A STOP of ``call`` (the run thread): show it, wait for a resume,
        then resume the call (or end the run on ``terminate``)."""
        with self._cv:
            if self._terminate:
                raise Terminated()
            st = call.dbg_stop()
            if not self._observed or st is None:     # detached meanwhile
                call.dbg_resume(nhost.RESUME)
                return
            self._call, self.where = call, st
            if self.root_thread is None:
                self.root_thread = st["thread"]
            starting = self.state == "starting"
            self.state = "stopped"
            self._cv.notify_all()
            if not starting:
                body = {k: st[k] for k in ("reason", "thread", "frame", "coro", "pc",
                                           "src_ref", "detail")}
                if st["hits"]:
                    body["hits"] = st["hits"]
                if st["reason"] == "step":
                    body["detail"] = {"kind": {v: k for k, v in _STEPS.items()}
                                      .get(self._resume_kind, "stmt")}
                self._emit("stopped", body)
            mark = self._resumed
            while self._resumed == mark:
                self._cv.wait()
            self._call = self.where = None
            if self._terminate:
                raise Terminated()
            call.dbg_resume(self._resume_kind)

    def _main(self):
        try:
            self._run(self.on_stop)
        except Terminated:
            self._exit({"status": "terminated"})
        except Exception as e:
            err = getattr(e, "error", None)
            msg = err.get("message") if isinstance(err, dict) and err.get("message") \
                else f"{type(e).__name__}: {e}"
            self._exit({"status": "error", "message": msg})
        else:
            self._exit({"status": "terminated" if self._terminate else "ok"})

    def _exit(self, body):
        with self._cv:
            observed = self._observed
            self.state = "exited"
            self._call = self.where = None
            self._cv.notify_all()
        if observed:
            self._emit("exited", body)
