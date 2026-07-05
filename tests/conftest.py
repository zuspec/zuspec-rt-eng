"""
rt-eng test harness: compile the engine (+ rt-core substrate) into a shared lib
once per session and hand tests a configured ``ctypes.CDLL``.

Native code is tested via pytest + ctypes (project convention); the build reuses
``zuspec.rt.eng.build`` (which wraps ``zuspec.rt.core.build``).
"""

import ctypes
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from zuspec.rt.eng import build as engbuild

# dv-solve package root: packages/zuspec-rt-eng/tests/conftest.py -> packages/dv-solve
_DV_SOLVE_DIR = Path(__file__).resolve().parents[2] / "dv-solve"


def _build_dv_solve(build_dir: Path):
    """CMake-build libdv_solve.so into ``build_dir``; return its directory or None.

    Returns None (rather than raising) when the toolchain or package is missing so
    the engine still builds -- the real-SOLVE tests then skip via ``dv_solve``.
    """
    if not _DV_SOLVE_DIR.is_dir() or not (_DV_SOLVE_DIR / "CMakeLists.txt").exists():
        return None
    if not shutil.which("cmake") or not (shutil.which("gcc") or shutil.which("cc")):
        return None
    build_dir.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(["cmake", str(_DV_SOLVE_DIR), "-DCMAKE_BUILD_TYPE=Release"],
                       cwd=build_dir, check=True, capture_output=True)
        subprocess.run(["cmake", "--build", str(build_dir), "--parallel"],
                       check=True, capture_output=True)
    except (subprocess.CalledProcessError, OSError):
        return None
    if not list(build_dir.glob("libdv_solve.so*")):
        return None
    return build_dir


@pytest.fixture(scope="session")
def dvsolve(tmp_path_factory):
    """Session-scoped libdv_solve build dir (or None). Real-SOLVE tests skip on None."""
    return _build_dv_solve(tmp_path_factory.mktemp("dvsolve"))


class ZbcResult(ctypes.Structure):
    """Mirror of C ``zbc_result_t`` (status, halted_op, retval, now)."""
    _fields_ = [
        ("status", ctypes.c_int),
        ("halted_op", ctypes.c_int),
        ("retval", ctypes.c_uint64),
        ("now", ctypes.c_uint64),
    ]


#: Must match ZBC_IMPORT_MAX_ARGS in zbc_interp.h.
IMPORT_MAX_ARGS = 4


class ZbcImportCall(ctypes.Structure):
    """Mirror of C ``zbc_import_call_t`` (one recorded IMPORT call)."""
    _fields_ = [
        ("fn_id", ctypes.c_uint32),
        ("n_args", ctypes.c_uint32),
        ("args", ctypes.c_uint64 * IMPORT_MAX_ARGS),
    ]


class ZbcImportLog(ctypes.Structure):
    _fields_ = [
        ("calls", ctypes.POINTER(ZbcImportCall)),
        ("capacity", ctypes.c_uint32),
        ("count", ctypes.c_uint32),
    ]


class ZbcImportReturns(ctypes.Structure):
    _fields_ = [
        ("fn_ids", ctypes.POINTER(ctypes.c_uint32)),
        ("values", ctypes.POINTER(ctypes.c_uint64)),
        ("count", ctypes.c_uint32),
    ]


class ZbcHost(ctypes.Structure):
    _fields_ = [
        ("import_log", ctypes.POINTER(ZbcImportLog)),
        ("import_returns", ctypes.POINTER(ZbcImportReturns)),
    ]


@pytest.fixture(scope="session")
def libpath(tmp_path_factory, dvsolve):
    out = tmp_path_factory.mktemp("rteng") / "libzsp_rteng_test.so"
    link_args = None
    if dvsolve is not None:
        # Link the real solver + bake an rpath so ctypes.CDLL resolves it at load.
        link_args = ["-L", str(dvsolve), "-ldv_solve",
                     "-Wl,-rpath," + str(dvsolve)]
    return engbuild.build_shared_lib(str(out), extra_link_args=link_args)


@pytest.fixture(scope="session")
def _rawlib(libpath):
    return ctypes.CDLL(libpath)


@pytest.fixture()
def eng(_rawlib):
    lib = _rawlib
    lib.zbc_run.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                            ctypes.POINTER(ctypes.c_uint64), ctypes.c_uint32,
                            ctypes.POINTER(ZbcHost), ctypes.POINTER(ZbcResult)]
    lib.zbc_run.restype = ctypes.c_int
    return lib


def run_image(eng, data: bytes, fields=None, host=None) -> ZbcResult:
    """Run a ``.zbc`` byte image through the native engine; return the result.

    ``fields`` is an optional list of initial 64-bit field values; if given, the
    list is mutated in place with the engine's final field values. ``host`` is an
    optional ``ZbcHost`` (IMPORT seam); pass ``None`` for none.
    """
    buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
    res = ZbcResult()
    hp = ctypes.byref(host) if host is not None else None
    if fields is None:
        eng.zbc_run(buf, len(data), None, 0, hp, ctypes.byref(res))
    else:
        arr = (ctypes.c_uint64 * len(fields))(*fields)
        eng.zbc_run(buf, len(data), arr, len(fields), hp, ctypes.byref(res))
        fields[:] = list(arr)
    return res


def make_import_host(returns=None, capacity=64):
    """Build a ``ZbcHost`` with a recording IMPORT log + optional returns table.

    ``returns`` maps ``fn_id -> value``. Returns ``(host, read_calls)`` where
    ``read_calls()`` yields the recorded calls as ``[(fn_id, [args...]), ...]``
    after a run. Keep the returned host referenced for the duration of the run so
    ctypes does not free the backing arrays.
    """
    calls = (ZbcImportCall * capacity)()
    log = ZbcImportLog(calls=calls, capacity=capacity, count=0)

    host = ZbcHost()
    host.import_log = ctypes.pointer(log)
    keepalive = [calls, log]

    if returns:
        ids = (ctypes.c_uint32 * len(returns))(*returns.keys())
        vals = (ctypes.c_uint64 * len(returns))(*returns.values())
        rt = ZbcImportReturns(fn_ids=ids, values=vals, count=len(returns))
        host.import_returns = ctypes.pointer(rt)
        keepalive += [ids, vals, rt]

    def read_calls():
        out = []
        n = min(log.count, capacity)
        for i in range(n):
            c = calls[i]
            out.append((c.fn_id, [c.args[j] for j in range(c.n_args)]))
        return out

    host._keepalive = keepalive  # pin backing arrays to the host's lifetime
    return host, read_calls
