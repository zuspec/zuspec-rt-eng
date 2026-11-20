"""P4.6a: hot reload of a C engine from a Python host (``generations.
reload_engine``) on be-bc's T3.6 component models
(tests/unit/interp/test_generations.py ``_comp_model``)."""
import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("zuspec.be.bc")
from zuspec.be.bc.interp.generations import ReloadRefused
from zuspec.rt.eng.generations import reload_engine
from zuspec.rt.eng.host import Engine, NativeError

_SRC = (Path(__file__).resolve().parents[2] / "zuspec-be-bc" / "tests" / "unit" / "interp"
        / "test_generations.py")
if not _SRC.is_file():
    pytest.skip("be-bc's generation cases are not beside this package",
                allow_module_level=True)
_spec = importlib.util.spec_from_file_location("_bebc_gen_cases", _SRC)
cases = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cases)

_TREE = cases._TREE
_NEW = [("top", "top_c", ["x", "y"]), ("top.ch", "chan_c", ["wake"]),
        ("top.dma", "dma_c", ["n"])]


def _model(insts, **kw):
    m = cases._comp_model(insts, **kw)
    m.comp_init = True
    return m


@pytest.fixture()
def n(libpath):
    m = _model(_TREE)
    eng = Engine(libpath, m.to_bytes())
    eng.construct()
    yield eng, m
    eng.free()


def test_construct_and_comp_write(n):
    eng, _ = n
    assert eng.comp_slots() == [1, 1, 1, 1]
    assert eng.comp_write([5, 6, 2, 3]) == 4
    assert eng.comp_slots() == [5, 6, 2, 3]


def test_state_migrates_by_path(n):
    eng, old = n
    eng.comp_write([5, 6, 2, 3])                 # N ran: fields and channel tokens moved
    eng2, r = reload_engine(eng, old, _model(_TREE, init=9))
    try:
        assert r["applied"] and r["new"] == 2
        assert r["structure"] == {"added": [], "removed": [], "changed": []}
        assert r["migrated"] == ["top", "top.ch"] and eng2.comp_slots() == [5, 6, 2, 3]
    finally:
        eng2.free()


def test_structural_change_new_parts_start_fresh(n):
    eng, old = n
    eng.comp_write([5, 6, 2, 3])
    eng2, r = reload_engine(eng, old, _model(_NEW, init=9))
    try:
        assert r["structure"] == {"added": ["top.dma"], "removed": [],
                                  "changed": ["top.ch"]}
        assert r["migrated"] == ["top"] and eng2.comp_slots() == [5, 6, 9, 9]
    finally:
        eng2.free()


def test_strict_refuses_a_structural_change(n):
    eng, old = n
    with pytest.raises(ReloadRefused) as ei:
        reload_engine(eng, old, _model(_TREE[:1]), strict=True)
    assert ei.value.reason == "structure" and "top.ch (removed)" in str(ei.value)
    eng2, r = reload_engine(eng, old, _model(_TREE, init=2), strict=True)
    eng2.free()


@pytest.mark.parametrize("touch", ["read", "import"])
def test_bus_during_construction_refuses(n, touch):
    eng, old = n
    eng.comp_write([5, 6, 2, 3])
    with pytest.raises(ReloadRefused) as ei:
        reload_engine(eng, old, _model(_TREE, touch=touch))
    assert ei.value.reason == "bus" and "generation 2" in str(ei.value)
    assert eng.comp_slots() == [5, 6, 2, 3]


def test_api_change_is_refused(n):
    from zuspec.be.bc.model import EntryPoint, api_hash_of
    eng, old = n
    new = _model(_TREE)
    new.entries = dict(new.entries, other_t=EntryPoint(coro=0, kind="action"))
    new.api_hash = api_hash_of(new.entries, {})
    with pytest.raises(ReloadRefused) as ei:
        reload_engine(eng, old, new)
    assert ei.value.reason == "api"


def test_no_tree_yet_builds_at_first_call(libpath):
    old = _model(_TREE)
    eng = Engine(libpath, old.to_bytes())
    try:
        eng2, r = reload_engine(eng, old, _model(_TREE, init=7))
        assert r["applied"] and r["migrated"] == [] and eng2.comp_slots() == []
        eng2.construct()
        assert eng2.comp_slots() == [7, 7, 7, 7]
        eng2.free()
    finally:
        eng.free()


# P4.9e1: the same reloads done by the C engine alone (``pssvm_reload``).

def test_c_reload_keeps_state_in_place(n):
    eng, _ = n
    eng.comp_write([5, 6, 2, 3])
    eng.reload(_model(_TREE, init=9).to_bytes())
    assert eng.generation == 2 and eng.comp_slots() == [5, 6, 2, 3]
    eng.reload(_model(_TREE, init=9).to_bytes(), strict=True)
    assert eng.generation == 3


@pytest.mark.parametrize("strict", [False, True])
def test_c_reload_refuses_a_layout_change(n, strict):
    eng, _ = n
    eng.comp_write([5, 6, 2, 3])
    with pytest.raises(NativeError) as ei:
        eng.reload(_model(_NEW).to_bytes(), strict=strict)
    assert ei.value.error["message"].startswith("structure:")
    assert eng.generation == 1 and eng.comp_slots() == [5, 6, 2, 3]


@pytest.mark.parametrize("touch", ["read", "import"])
def test_c_reload_bus_during_construction_refuses(n, touch):
    eng, _ = n
    eng.comp_write([5, 6, 2, 3])
    with pytest.raises(NativeError) as ei:
        eng.reload(_model(_TREE, touch=touch).to_bytes())
    msg = ei.value.error["message"]
    assert msg.startswith("bus:") and "generation 2" in msg
    assert eng.generation == 1 and eng.comp_slots() == [5, 6, 2, 3]


def _with_insts(m):
    """``m`` with the ``pssc.native`` inst lines pssc writes (migration by path)."""
    from zuspec.be.bc.interp.generations import native_inst_lines
    m.meta = dict(m.meta or {}, **{"pssc.native": "\n".join(native_inst_lines(m)) + "\n"})
    return m


@pytest.mark.parametrize("new", [_NEW, _TREE[:1] + [_NEW[2], _TREE[1]]])
def test_c_reload_migrates_by_path(libpath, new):
    # P4.9e2: non-strict, a changed tree keeps each unchanged instance's state
    # (wherever it now sits); changed and added ones start fresh
    eng = Engine(libpath, _with_insts(_model(_TREE)).to_bytes())
    try:
        eng.construct()
        eng.comp_write([5, 6, 2, 3])
        with pytest.raises(NativeError) as ei:
            eng.reload(_with_insts(_model(new, init=9)).to_bytes(), strict=True)
        assert ei.value.error["message"].startswith("structure:")
        eng.reload(_with_insts(_model(new, init=9)).to_bytes())
        want = [5, 6, 9, 9] if new is _NEW else [5, 6, 9, 2, 3]
        assert eng.generation == 2 and eng.comp_slots() == want
    finally:
        eng.free()


def test_c_reload_api_change_is_refused(n):
    from zuspec.be.bc.model import EntryPoint, api_hash_of
    eng, _ = n
    new = _model(_TREE)
    new.entries = dict(new.entries, other_t=EntryPoint(coro=0, kind="action"))
    new.api_hash = api_hash_of(new.entries, {})
    with pytest.raises(NativeError) as ei:
        eng.reload(new.to_bytes())
    assert ei.value.error["message"].startswith("api:") and eng.generation == 1


def test_c_reload_before_construction_builds_at_first_call(libpath):
    eng = Engine(libpath, _model(_TREE).to_bytes())
    try:
        eng.reload(_model(_TREE, init=7).to_bytes())
        assert eng.generation == 2 and eng.comp_slots() == []
        eng.construct()
        assert eng.comp_slots() == [7, 7, 7, 7]
    finally:
        eng.free()


def test_c_reload_bad_image(n):
    eng, _ = n
    with pytest.raises(NativeError):
        eng.reload(b"not an image")
    assert eng.generation == 1
