"""Drift guard: zbc_ops.h opcode/flag values must match zuspec.be.bc.model.

The engine hand-mirrors the ISA opcodes in `zbc_ops.h`; this parses that header
and asserts every `ZBC_OP_*` / `ZBC_F_*` value equals the Python enum / flag it
mirrors, so the two never silently diverge.
"""

import os
import re

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.be.bc import model as m
from zuspec.rt.eng import include_dir

_DEFINE = re.compile(r"#define\s+ZBC_(OP|F)_(\w+)\s+(0x[0-9a-fA-F]+|\d+)")


def _parse_ops_header():
    ops, flags = {}, {}
    with open(os.path.join(include_dir(), "zbc_ops.h")) as fp:
        for line in fp:
            mt = _DEFINE.match(line.strip())
            if not mt:
                continue
            kind, name, val = mt.groups()
            (ops if kind == "OP" else flags)[name] = int(val, 0)
    return ops, flags


def test_opcodes_match_model_enum():
    ops, _ = _parse_ops_header()
    py = {o.name: o.value for o in m.Op}
    # Every opcode named in the C header must exist in Op with the same value.
    for name, val in ops.items():
        assert name in py, "zbc_ops.h has ZBC_OP_%s not in model.Op" % name
        assert val == py[name], "ZBC_OP_%s=0x%x != model.Op.%s=0x%x" % (
            name, val, name, py[name])
    # And every model opcode must be mirrored in the header (no missing ops).
    assert set(ops) == set(py), "header/model opcode sets differ: %s" % (
        set(py) ^ set(ops))


def test_instr_flags_match_model():
    _, flags = _parse_ops_header()
    assert flags["FROM_POOL"] == m.INSTR_F_FROM_POOL
    assert flags["BLOCKING"] == m.INSTR_F_BLOCKING
    assert flags["HAS_RET"] == m.INSTR_F_HAS_RET
    assert flags["NODE"] == m.INSTR_F_NODE
    assert flags["INITED"] == m.INSTR_F_INITED
    assert flags["SPIN"] == m.INSTR_F_SPIN


# --- Native-engine gap audit (pssc-debug plan P4.1) ------------------------
#
# The opcodes, flags and builtins the Python VM runs that the C engine does
# not. Each entry is a known gap, with the plan item that closes it; when an
# item lands, its entry goes, and these tests say so. A new model opcode or
# builtin the engine lacks fails here instead of halting a run.

#: Opcodes with no case in zbc_interp.c. PAR is reserved: the oracle rejects
#: it too (lowering emits SPAWN/JOIN).
NATIVE_OP_GAPS = {
    "PAR": "reserved (oracle rejects)",
    "HEAP": "F6.9c heap ops; refused up front until M14",
}

#: Opcode/flag pairs the engine refuses up front (zbc_engine.c).
NATIVE_FLAG_GAPS = {}

#: model.BUILTIN_* imports with no ZBC_BUILTIN_* in zbc_ops.h; the engine
#: would log them as plain imports.
NATIVE_BUILTIN_GAPS = {}

_SHARE_RT = os.path.join(os.path.dirname(include_dir()), "rt")


def _read_rt(name):
    with open(os.path.join(_SHARE_RT, name)) as fp:
        return fp.read()


def _refusal_block():
    """The up-front refusal condition in zbc_run (zbc_engine.c)."""
    src = _read_rt("zbc_engine.c")
    start = src.index("uint32_t op = img->code[i].op;")
    return src[start:src.index("ZBC_ERR_UNSUPPORTED_OP", start)]


def test_native_opcode_gaps_are_the_audited_set():
    handled = set(re.findall(r"case\s+ZBC_OP_(\w+)\s*:", _read_rt("zbc_interp.c")))
    missing = {o.name for o in m.Op} - handled
    assert missing == set(NATIVE_OP_GAPS), (
        "engine opcode gaps changed: new %s, closed %s" % (
            sorted(missing - set(NATIVE_OP_GAPS)),
            sorted(set(NATIVE_OP_GAPS) - missing)))


def test_engine_refuses_gap_ops_before_running():
    block = _refusal_block()
    for name in NATIVE_OP_GAPS:
        if name == "PAR":
            continue
        assert "ZBC_OP_%s" % name in block, "%s not refused up front" % name
    for op, flag in NATIVE_FLAG_GAPS:
        assert re.search(r"ZBC_OP_%s\s*&&\s*\(img\.code\[i\]\.flags\s*&\s*ZBC_F_%s\)"
                         % (op, flag), block), "%s+%s not refused" % (op, flag)
    assert "ZBC_BUILTIN_MEM_FIRST" in block and "ZBC_BUILTIN_MEM_LAST" in block


def test_native_builtin_gaps_are_the_audited_set():
    with open(os.path.join(include_dir(), "zbc_ops.h")) as fp:
        hdr = fp.read()
    c_vals = {}
    for name, expr in re.findall(r"#define\s+ZBC_BUILTIN_(\w+)\s+\(ZBC_BUILTIN_BASE\s*\+\s*(\d+)\)", hdr):
        c_vals[int(expr)] = name
    mem = range(int(re.search(r"ZBC_BUILTIN_MEM_FIRST\s+\(ZBC_BUILTIN_BASE\s*\+\s*(\d+)", hdr).group(1)),
                int(re.search(r"ZBC_BUILTIN_MEM_LAST\s+\(ZBC_BUILTIN_BASE\s*\+\s*(\d+)", hdr).group(1)) + 1)
    py = {k[len("BUILTIN_"):]: v - m.BUILTIN_BASE for k, v in vars(m).items()
          if k.startswith("BUILTIN_") and k != "BUILTIN_BASE" and isinstance(v, int)}
    for off in list(m.BUILTIN_READ.values()) + list(m.BUILTIN_WRITE.values()):
        assert off - m.BUILTIN_BASE in mem, "memory builtin 0x%x outside MEM range" % off
    missing = {n for n, off in py.items() if off not in c_vals and off not in mem}
    assert missing == set(NATIVE_BUILTIN_GAPS), (
        "engine builtin gaps changed: new %s, closed %s" % (
            sorted(missing - set(NATIVE_BUILTIN_GAPS)),
            sorted(set(NATIVE_BUILTIN_GAPS) - missing)))
    for n, off in py.items():
        if off in c_vals:
            assert c_vals[off] == n, "ZBC_BUILTIN_%s != model.BUILTIN_%s" % (c_vals[off], n)
