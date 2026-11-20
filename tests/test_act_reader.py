"""P4.10c2: the C reader parses the activity table (ACT) of an image.

The engine follows an activation's nodes, sites and writes from it (P4.10c3:
a node's state/buffer writes at its end; P4.10c4: a node's component). Here
the C view of a table -- per node its base, size, parent, children and
writes, per site its owner and target -- is the table the Python reader
(``ZbcModel.from_bytes``) gives, and a table whose ids point outside it is
refused when the image is opened.
"""

import ctypes
import struct

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc.model import ZbcModel
from zuspec.be.bc.format.emit_dataclass import CLASSES as REC

from test_native_host import _IO
from test_pssvm_host import _code_model

ZBC_ERR_BAD_SECTIONS = -5
_IMG_BYTES = 8192          # > sizeof(zbc_image_t)


def _table():
    """Four nodes (root, two children, a grandchild), two scopes, three sites,
    state and buffer writes, slot names and initial values."""
    from zuspec.be.bc.interp.activation import ActivationTable
    from zuspec.ir.core import scenario as SC
    W = SC.ScStateWrite
    tree = SC.ScActionTree(root="T", type_qname="P::T", size=12, nodes=[
        SC.ScActionNode(id=0, type_qname="P::T", size=2, children=[1, 2]),
        SC.ScActionNode(id=1, path="a", type_qname="P::A", base=2, size=3, parent=0,
                        decl_scope=0, children=[3],
                        state_writes=[W(ref="s", src=[3, 4], pools=[(0, 0)])]),
        SC.ScActionNode(id=2, path="b", type_qname="P::B", base=5, size=4, parent=0,
                        decl_scope=1,
                        buffer_writes=[W(ref="o", src=[6], pools=[(0, 1)])],
                        state_writes=[W(ref="t", src=[7, 8], pools=[(0, 0)])]),
        SC.ScActionNode(id=3, path="a.c", type_qname="P::C", base=9, size=3, parent=1)],
        scopes=[SC.ScActivityScope(id=0, kind=SC.ScopeKind.ACTIVITY, parent=None, node=0),
                SC.ScActivityScope(id=1, kind=SC.ScopeKind.SEQUENCE, parent=0, node=0)],
        sites=[SC.ScTraversalSite(id=0, owner=0, target=1, scope=0),
               SC.ScTraversalSite(id=1, owner=0, target=2, scope=1),
               SC.ScTraversalSite(id=2, owner=1, target=3, scope=0)])
    return ActivationTable(tree, [f"f{i}" for i in range(12)], {0: 7, 5: -3})


def _image():
    m = _code_model(list(_IO))
    m.activations = {0: _table()}
    return m.to_bytes()


class _Image:
    """zbc_image_open on *data*, kept alive with the record pointers."""

    def __init__(self, lib, data):
        for fn in ("zbc_image_act", "zbc_act_node", "zbc_act_scope", "zbc_act_site",
                   "zbc_act_write", "zbc_act_list", "zbc_image_act_str"):
            getattr(lib, fn).restype = ctypes.c_void_p
        lib.zbc_image_act.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        for fn in ("zbc_act_node", "zbc_act_scope", "zbc_act_site"):
            getattr(lib, fn).argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
        for fn in ("zbc_act_write", "zbc_act_list", "zbc_image_act_str"):
            getattr(lib, fn).argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.lib, self.data = lib, ctypes.create_string_buffer(data, len(data))
        self.img = ctypes.create_string_buffer(_IMG_BYTES)
        self.rc = lib.zbc_image_open(self.img, self.data, ctypes.c_size_t(len(data)))

    def rec(self, name, ptr):
        return REC[name].from_bytes(ctypes.string_at(ptr, REC[name].size()))

    def act(self, coro):
        p = self.lib.zbc_image_act(self.img, coro)
        return p, (self.rec("zbc_act", p) if p else None)

    def list(self, i, n):
        if not n:
            return []
        return list(struct.unpack(f"<{n}I", ctypes.string_at(self.lib.zbc_act_list(self.img, i), 4 * n)))

    def str(self, sid):
        return ctypes.string_at(self.lib.zbc_image_act_str(self.img, sid)).decode()

    def writes(self, i, n):
        out = []
        for k in range(n):
            w = self.rec("zbc_actwrite", self.lib.zbc_act_write(self.img, i + k))
            xs = self.list(w.pool0, 2 * w.n_pools)
            out.append((self.str(w.ref), self.list(w.src0, w.n_src), list(zip(xs[::2], xs[1::2]))))
        return out


def _none(x):
    return None if x == 0xFFFFFFFF else x


def test_the_c_reader_sees_the_table_python_reads(_rawlib):
    data = _image()
    py = ZbcModel.from_bytes(data).activations[0]
    im = _Image(_rawlib, data)
    assert im.rc == 0
    p, a = im.act(0)
    assert a.size == py.tree.size and a.n_nodes == len(py.tree.nodes)
    assert [im.str(x) for x in im.list(a.names0, a.n_names)] == py.names
    nodes = []
    for i in range(a.n_nodes):
        n = im.rec("zbc_actnode", _rawlib.zbc_act_node(im.img, p, i))
        nodes.append((im.str(n.path), im.str(n.type), n.base, n.size, _none(n.parent),
                      _none(n.decl_scope), im.list(n.child0, n.n_children),
                      im.writes(n.swrite0, n.n_swrites), im.writes(n.bwrite0, n.n_bwrites)))
    want = [(n.path, n.type_qname, n.base, n.size, n.parent, n.decl_scope, list(n.children),
             [(w.ref, list(w.src), [tuple(x) for x in w.pools]) for w in n.state_writes],
             [(w.ref, list(w.src), [tuple(x) for x in w.pools]) for w in n.buffer_writes])
            for n in py.tree.nodes]
    assert nodes == want
    sites = [im.rec("zbc_actsite", _rawlib.zbc_act_site(im.img, p, i)) for i in range(a.n_sites)]
    assert [(s.owner, s.target, s.scope) for s in sites] == \
        [(s.owner, s.target, s.scope) for s in py.tree.sites]
    scopes = [im.rec("zbc_actscope", _rawlib.zbc_act_scope(im.img, p, i)) for i in range(a.n_scopes)]
    assert [(_none(s.parent), s.node) for s in scopes] == \
        [(s.parent, s.node) for s in py.tree.scopes]


def test_a_coroutine_without_an_activity_has_none(_rawlib):
    im = _Image(_rawlib, _image())
    assert im.act(1) == (None, None)
    im = _Image(_rawlib, _code_model(list(_IO)).to_bytes())
    assert im.rc == 0 and im.act(0) == (None, None)


def _patched(data, rec, index, field, value):
    """*data* with field *field* of the *index*-th *rec* record of ACT set."""
    from zuspec.be.bc.format import spec
    m = ZbcModel.from_bytes(data)
    sec = [s for s in m.to_container().sections if s.kind == spec.sec_kind("ZBC_SEC_ACT")][0]
    p = bytes(sec.payload)
    hdr = REC["zbc_acttab"].from_bytes(p)
    order = ["zbc_actinit", "zbc_act", "zbc_actnode", "zbc_actscope", "zbc_actsite"]
    counts = [hdr.n_init, hdr.n_acts, hdr.n_nodes, hdr.n_scopes, hdr.n_sites]
    pos = REC["zbc_acttab"].size()
    for name, n in zip(order, counts):
        if name == rec:
            pos += index * REC[name].size()
            break
        pos += n * REC[name].size()
    r = REC[rec].from_bytes(p[pos:pos + REC[rec].size()])
    setattr(r, field, value)
    at = data.index(p)              # the payload is stored verbatim in the image
    return data[:at + pos] + r.to_bytes() + data[at + pos + REC[rec].size():]


@pytest.mark.parametrize("rec,index,field,value", [
    ("zbc_actnode", 1, "parent", 4),            # no node 4
    ("zbc_actnode", 3, "size", 9),              # past the object
    ("zbc_actsite", 2, "target", 7),
    ("zbc_actnode", 2, "n_swrites", 99),        # past the write records
    ("zbc_act", 0, "coro", 5),                  # no such coroutine
])
def test_a_table_pointing_outside_itself_is_refused(_rawlib, rec, index, field, value):
    data = _patched(_image(), rec, index, field, value)
    assert _Image(_rawlib, data).rc == ZBC_ERR_BAD_SECTIONS


def test_the_c_reader_finds_an_initial_value_by_slot(_rawlib):
    im = _Image(_rawlib, _image())
    p, a = im.act(0)
    _rawlib.zbc_act_init.restype = ctypes.c_void_p
    _rawlib.zbc_act_init.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
    got = {}
    for slot in range(a.size):
        r = _rawlib.zbc_act_init(im.img, p, slot)
        if r:
            rec = im.rec("zbc_actinit", r)
            got[rec.slot] = ctypes.c_int64(rec.value).value
    assert got == {0: 7, 5: -3}
