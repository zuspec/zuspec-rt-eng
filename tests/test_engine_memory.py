"""Platform memory (read8..64 / write8..64 builtins, LRM 21.13.9) through the
host's ``mem_access`` callback.

The oracle answers these from ``vm.memory`` (``extern.Memory``: sparse,
little-endian bytes); the engine calls the host. With the same byte-backed
memory behind both, the accesses, their order and the values read must agree.
With no callback the image is still refused before it runs
(test_engine_call.py).
"""

import ctypes

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc.model import (ZbcModel, CoroDescriptor, Instr, Op,
                                BUILTIN_READ, BUILTIN_WRITE, INSTR_F_HAS_RET)
from zuspec.be.bc.interp import run_model
from zuspec.be.bc.interp.extern import Memory

from conftest import run_image, make_import_host, MEM_ACCESS_FN

VOID = 0xFFFFFFFF


def C(rd, v):
    return Instr(Op.CONST, args=(rd,), imm=v)


def W(width, addr_reg, data_reg):
    return Instr(Op.IMPORT, args=(BUILTIN_WRITE[width], VOID, addr_reg, data_reg))


def R(width, rd, addr_reg):
    return Instr(Op.IMPORT, args=(BUILTIN_READ[width], rd, addr_reg), flags=INSTR_F_HAS_RET)


def _model(code):
    return ZbcModel(coros=[CoroDescriptor(name="root", code=code, blocks=[],
                                          frame_locals=[])], entry_coro=0)


def _with_memory(mem):
    """A host whose mem_access is ``mem`` (an extern.Memory). Keep the
    returned tuple alive for the run."""
    host, _calls = make_import_host()

    def access(_ctx, is_write, addr, nbytes, data):
        if is_write:
            mem.write(addr, nbytes, data)
            return 0
        return mem.read(addr, nbytes)

    cb = MEM_ACCESS_FN(access)
    host.mem_access = ctypes.cast(cb, ctypes.c_void_p)
    return host, cb


def _both(eng, model):
    native_mem, oracle_mem = Memory(), Memory()
    host, _keep = _with_memory(native_mem)
    native = run_image(eng, model.to_bytes(), host=host)
    oracle = run_model(model, memory=oracle_mem)
    return native, oracle, native_mem, oracle_mem


def test_writes_and_reads_of_every_width_agree(eng):
    code = [C(0, 0x1000), C(1, 0x1122334455667788)]
    for i, w in enumerate((8, 16, 32, 64)):
        code += [C(2, 0x1000 + 0x10 * i), W(w, 2, 1)]
    code += [C(3, 0x1030), R(64, 4, 3),      # the 64-bit write, whole
             C(3, 0x1000), R(32, 5, 3),      # the 8-bit write: one byte, rest 0
             C(3, 0x1010), R(8, 6, 3),       # low byte of the 16-bit write
             C(3, 0x1021), R(16, 7, 3),      # straddles the 32-bit write
             Instr(Op.ADD, args=(8, 4, 5)), Instr(Op.XOR, args=(8, 8, 6)),
             Instr(Op.XOR, args=(8, 8, 7)), Instr(Op.RET, args=(8,))]
    native, oracle, nm, om = _both(eng, _model(code))
    assert native.status == 0
    assert nm.log == om.log
    assert nm.bytes == om.bytes
    assert native.retval == oracle.retval
    assert [e[3] for e in nm.log if e[0] == "r"] == [0x1122334455667788, 0x88, 0x88, 0x6677]


def test_a_write_is_masked_to_its_width(eng):
    code = [C(0, 0x40), C(1, 0xABCD), W(8, 0, 1), R(16, 2, 0), Instr(Op.RET, args=(2,))]
    native, oracle, nm, om = _both(eng, _model(code))
    assert nm.log == om.log == [("w", 0x40, 1, 0xCD), ("r", 0x40, 2, 0xCD)]
    assert native.retval == oracle.retval == 0xCD


def test_a_read_is_masked_even_if_the_host_returns_more(eng):
    host, _ = make_import_host()
    cb = MEM_ACCESS_FN(lambda _c, w, a, n, d: 0xFFFFFFFFFFFFFFFF)
    host.mem_access = ctypes.cast(cb, ctypes.c_void_p)
    model = _model([C(0, 0), R(16, 1, 0), Instr(Op.RET, args=(1,))])
    res = run_image(eng, model.to_bytes(), host=host)
    assert res.status == 0 and res.retval == 0xFFFF
