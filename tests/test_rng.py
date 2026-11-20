"""The C engine's MT19937 (zbc_rng.c) draws what Python's random.Random draws.

The Python VM picks buffer objects (and deals resource-pool instances) with
random.Random(seed).randrange(k, n); the C engine reproduces those draws, so
both engines pick the same objects for the same seed.
"""
import ctypes
import random

import pytest

U64 = ctypes.c_uint64

SEEDS = [0, 1, 2, 12345, 2**32 - 1, 2**32, 2**32 + 7, 2**63, 2**64 - 1]


def _ranges():
    # Narrow ranges (1-bit draws, many rejections), a lazy Fisher-Yates
    # sweep as the pick loop does, and widths across the 32-bit boundary.
    out = [(0, 1), (0, 2), (0, 3), (5, 6), (0, 1000)]
    out += [(k, 7) for k in range(7)]
    out += [(0, 2**31 + 1), (0, 2**32), (0, 2**32 + 1), (3, 2**40 + 3),
            (0, 2**63 + 5), (0, 2**64 - 1)]
    out += [(0, 17)] * 700   # past one 624-word refill
    return out


def _c_draws(lib, seed, ranges):
    n = len(ranges)
    lo = (U64 * n)(*[a for a, _ in ranges])
    hi = (U64 * n)(*[b for _, b in ranges])
    out = (U64 * n)()
    fn = lib.zbc_mt_test_draws
    fn.argtypes = [U64, ctypes.POINTER(U64), ctypes.POINTER(U64), ctypes.c_uint32,
                   ctypes.POINTER(U64)]
    fn.restype = ctypes.c_int
    assert fn(seed, lo, hi, n, out) == 0
    return list(out)


@pytest.mark.parametrize("seed", SEEDS)
def test_randrange_matches_python(_rawlib, seed):
    ranges = _ranges()
    rng = random.Random(seed)
    want = [rng.randrange(a, b) for a, b in ranges]
    assert _c_draws(_rawlib, seed, ranges) == want
