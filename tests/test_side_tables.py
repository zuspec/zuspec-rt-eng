"""P4.4a: the debug side tables (register accesses, channel operations) are in
the image, and the C engine reads them: a request names its register. P4.4b:
requests and errors name their source (src_ref, file, line, col)."""

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc.model import Instr, Op, ZbcModel

from zuspec.rt.eng import host as nhost
from test_engine_components import C
from test_native_host import _IO
from test_pssvm_host import _code_model


def _tabled(profile="codegen"):
    m = _code_model(list(_IO) + [])
    m.profile = profile
    c = m.coros[0]
    c.regs = [(2, 5), (3, 7)]           # the write and the read of _IO
    c.discards = [3]
    c.chans = [(4, 11, "ch", "put", 4, -1), (6, 12, "ch", "try_get", 4, 3)]
    c.cov = [("stmt", 0, "T::f", "0", 21, False), ("arm", 2, "T::f", "1/then", 22, False),
             ("arm", 4, "", "1/else", 0, True)]
    return m


def test_the_tables_survive_the_image():
    back = ZbcModel.from_bytes(_tabled().to_bytes()).coros[0]
    assert back.regs == [(2, 5), (3, 7)]
    assert back.discards == [3]
    assert back.chans == [(4, 11, "ch", "put", 4, -1), (6, 12, "ch", "try_get", 4, 3)]
    assert back.cov == _tabled().coros[0].cov


def test_the_runtime_profile_has_no_tables():
    from zuspec.be.bc.format import spec
    kinds = {s.kind for s in _tabled("runtime").to_container().sections}
    assert spec.sec_kind("ZBC_SEC_REG") not in kinds
    assert spec.sec_kind("ZBC_SEC_CHAN") not in kinds
    assert spec.sec_kind("ZBC_SEC_COV") not in kinds
    kinds = {s.kind for s in _tabled().to_container().sections}
    assert spec.sec_kind("ZBC_SEC_REG") in kinds


def test_a_c_request_names_its_register(_rawlib):
    ids = []
    with nhost.Engine(_rawlib, _tabled().to_bytes()) as eng:
        call = eng.call()
        while (r := call.run()).status != nhost.DONE:
            if r.status == nhost.REQS:
                q = call.take()
                ids.append((q.api, q.reg_id))
                call.complete(q.req_id, 0 if (q.api == nhost.API_MEM and q.kind == "r")
                              or q.has_ret else None)
        call.end()
    M, U = nhost.API_MEM, nhost.API_USER
    assert ids == [(M, 5), (M, 7), (U, None), (U, None)]


def test_without_tables_a_request_names_no_register(_rawlib):
    with nhost.Engine(_rawlib, _code_model(_IO).to_bytes()) as eng:
        call = eng.call()
        assert call.run().status == nhost.REQS
        q = call.take()
        assert q.api == nhost.API_MEM and q.kind == "w" and q.reg_id is None
        call.complete(q.req_id, None)
        while (r := call.run()).status != nhost.DONE:
            if r.status == nhost.REQS:
                q = call.take()
                call.complete(q.req_id, 0 if (q.api == nhost.API_MEM and q.kind == "r")
                              or q.has_ret else None)
        call.end()


# P4.4b: requests and errors say where in the PSS source they happened.

def _with_prov(m, src):
    """Give `m` the codegen profile, PROV records 1..n for `src` (file, line,
    col) and nothing else; the caller sets the instructions' src_ref."""
    from zuspec.be.bc.model import Prov
    m.profile = "codegen"
    for f, line, col in src:
        m.prov.add(Prov(file=f, line=line, col=col))
    return m


def test_a_c_request_names_its_source(_rawlib):
    m = _with_prov(_code_model(list(_IO)), [("a.pss", 10, 5), ("b.pss", 20, 9)])
    code = m.coros[0].code
    code[2].src_ref = 1                      # the write; the read has none
    code[4].src_ref = 2                      # the blocking import
    seen = []
    with nhost.Engine(_rawlib, m.to_bytes()) as eng:
        call = eng.call()
        while (r := call.run()).status != nhost.DONE:
            if r.status == nhost.REQS:
                q = call.take()
                seen.append(q.src_ref)
                call.complete(q.req_id, 0 if (q.api == nhost.API_MEM and q.kind == "r")
                              or q.has_ret else None)
        call.end()
    assert seen == [1, 0, 2, 0]


def test_a_c_error_names_its_file_and_line(_rawlib):
    from test_engine_call import CALL_MAX_DEPTH, _deep_model
    m = _with_prov(_deep_model(CALL_MAX_DEPTH + 5), [("deep.pss", 7, 3), ("root.pss", 1, 1)])
    for i in m.coros[1].code:
        i.src_ref = 1
    with nhost.Engine(_rawlib, m.to_bytes()) as eng:
        with pytest.raises(nhost.NativeError) as ei:
            nhost.run_sync(eng.call())
    err = ei.value.error
    assert (err["src_ref"], err["file"], err["line"], err["col"]) == (1, "deep.pss", 7, 3)


def test_a_c_error_falls_back_to_its_coroutine(_rawlib):
    from test_engine_call import CALL_MAX_DEPTH, _deep_model
    m = _with_prov(_deep_model(CALL_MAX_DEPTH + 5), [("deep.pss", 7, 3)])
    m.coros[1].src_ref = 1
    with nhost.Engine(_rawlib, m.to_bytes()) as eng:
        with pytest.raises(nhost.NativeError) as ei:
            nhost.run_sync(eng.call())
    assert ei.value.error["file"] == "deep.pss" and ei.value.error["line"] == 7
