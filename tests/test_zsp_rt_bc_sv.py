"""The C engine's variant of zsp_rt_bc_pkg (``share/sv/zsp_rt_bc_pkg.sv``;
pssc pssvm-plan step 7).

Both variants declare ``class zsp_rt_bc extends zsp_rt_bc_base`` from one
method list (zuspec-be-bc ``share/rt_bc_api.py``): what a variant does not
serve is the base's refusal. So the two expose the same methods with the
same signatures; here each method the C variant declares is checked against
the list and against the pyvm variant's, and the C variant lints under
Verilator with be-bc's shared ``.svh`` files.
"""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from zuspec.rt.eng import sv_dir

rt_bc_api = pytest.importorskip("zuspec.be.bc.share.rt_bc_api")

C_PKG = Path(sv_dir()) / "zsp_rt_bc_pkg.sv"
PY_PKG = rt_bc_api.sv_dir() / "zsp_rt_bc_pkg.sv"
#: what a variant adds to the list: its loader and its name for messages
EXTRA = {"load", "impl"}


def _methods(path: Path) -> dict:
    """``name -> signature`` of class zsp_rt_bc's functions in ``path``."""
    m = re.search(r"\bclass zsp_rt_bc\b.*?\bendclass\b", path.read_text(), re.S)
    assert m, path
    out = {}
    for f in re.finditer(r"\b(?:protected\s+)?(?:virtual|static)\s+function\s+"
                         r"([^;(]*?)\s*\(([^)]*)\)\s*;", m.group(0), re.S):
        head = " ".join(f.group(1).split())
        params = ", ".join(" ".join(p.split()) for p in f.group(2).split(",")
                           if p.strip())
        out[head.split()[-1]] = f"function {head}({params})"
    return out


def test_c_variant_declares_only_listed_methods_as_listed():
    want = {m.name: rt_bc_api.signature(m) for m in rt_bc_api.METHODS
            if m.impl == "engine"}
    got = _methods(C_PKG)
    for name, sig in got.items():
        if name in EXTRA or name == "opt_value":
            continue
        assert want.get(name) == sig, name


def test_both_variants_expose_the_same_methods():
    """Effective method sets (the base's defaults plus each variant's
    overrides) are the list in both; what they declare agrees wherever both
    declare it, and the loader is the same."""
    c, py = _methods(C_PKG), _methods(PY_PKG)
    for name in set(c) & set(py):
        assert c[name] == py[name], name
    assert c["load"] == py["load"] == \
        'function zsp_rt_bc load(string img, string opts = "")'
    listed = {m.name for m in rt_bc_api.METHODS}
    assert set(py) - EXTRA <= listed and set(c) - EXTRA - {"opt_value"} <= listed


def test_c_variant_refuses_the_step_6_surface():
    """The C engine is on hold: handles, links, step/pending and self-wait
    are the base's refusals, not missing symbols."""
    c = _methods(C_PKG)
    for name in ("new_obj", "sub", "call_obj", "release_obj", "field",
                 "api_id", "missing_links", "step", "pending", "next_time",
                 "call_inside", "progress", "fatal", "string_ret"):
        assert name not in c, name


def _verilator():
    v = shutil.which("verilator")
    if v:
        return v
    v = Path(__file__).resolve().parents[2] / "verilator" / "bin" / "verilator"
    return str(v) if v.exists() else None


@pytest.mark.skipif(_verilator() is None, reason="verilator not found")
def test_c_variant_lints():
    r = subprocess.run(
        [_verilator(), "--lint-only", "--timing", f"+incdir+{rt_bc_api.sv_dir()}",
         str(C_PKG)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "%Warning" not in r.stderr and "%Error" not in r.stderr, r.stderr
