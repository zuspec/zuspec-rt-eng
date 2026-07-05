"""
zuspec.rt.eng -- the native ZBC engine (roadmap P3).

Loads a ``.zbc`` image and executes it with a bytecode interpreter over the
``zuspec-rt-core`` substrate. This Python package exposes the engine's C sources
+ include dir for downstream builds, and (via :mod:`zuspec.rt.eng.build`) a
helper that compiles the engine together with the rt-core substrate into a shared
library for the pytest+ctypes tests.
"""

import os
import glob

__version__ = "0.0.1"

SHARE_DIR = os.path.join(os.path.dirname(__file__), "share")


def include_dir() -> str:
    """Absolute path to the engine's C include directory."""
    return os.path.join(SHARE_DIR, "include")


def rt_dir() -> str:
    """Absolute path to the engine's C source directory."""
    return os.path.join(SHARE_DIR, "rt")


def source_files() -> list:
    """Absolute paths of the engine C sources (sorted, stable)."""
    return sorted(glob.glob(os.path.join(rt_dir(), "*.c")))
