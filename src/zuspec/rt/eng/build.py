"""
zuspec.rt.eng.build -- compile the engine (+ rt-core substrate) to a shared lib.

The engine links against the rt-core substrate (scheduler + arena) and the
generated ABI header. This wraps :func:`zuspec.rt.core.build.build_shared_lib`,
adding the engine's own sources + include dir, so both the ctypes tests and any
downstream consumer build the full native stack the same way.
"""

import os
from typing import Iterable, Optional

from zuspec.rt.core import build as core_build
from zuspec.rt.core import source_files as core_sources

from . import source_files, include_dir


def build_shared_lib(out_path: str,
                     extra_sources: Optional[Iterable[str]] = None,
                     extra_include_dirs: Optional[Iterable[str]] = None,
                     extra_link_args: Optional[Iterable[str]] = None,
                     cc: Optional[str] = None) -> str:
    """Compile rt-core substrate + engine (+ ``extra_sources``) into ``out_path``.

    ``extra_link_args`` pass through to the linker -- used to link the real
    constraint solver (libdv_solve) for the native SOLVE path.
    """
    srcs = list(source_files()) + list(extra_sources or [])
    incs = [include_dir()] + list(extra_include_dirs or [])
    # core_build.build_shared_lib prepends the rt-core substrate sources + include.
    return core_build.build_shared_lib(
        out_path, extra_sources=srcs, extra_include_dirs=incs,
        extra_link_args=extra_link_args, cc=cc)
