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
