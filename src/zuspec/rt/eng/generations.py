"""Hot reload of a C engine from a Python host (P4.6a; be-bc
``docs/spec/generations.md``).

The checks and the migration are be-bc's (``interp/generations.py``), run on
the models; the engine builds generation N+1's tree and takes N's state::

    eng2, result = reload_engine(eng, old_model, new_model)
    eng.free()                      # N+1 is current: the host keeps eng2

N+1's construction is bus-isolated as the C engine's always is: an access or
import there refuses the reload (reason ``bus``). Quiescing is the host's: call
this with no call of N live (the result is applied at once). A reload that C
does alone, with no Python host (``pssvm_reload`` in host-abi.md), is P4.9's.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Optional, Tuple

from .host import Engine, NativeError


def reload_engine(engine: Engine, old, new, strict: bool = False,
                  number: int = 1,
                  opts: Optional[str] = None) -> Tuple[Engine, dict]:
    """Make ``new`` (a ``ZbcModel`` of the same sources as ``old``, the image
    ``engine`` runs as generation ``number``) generation ``number + 1``: a new
    engine on the same library. The API check comes first, then (``strict``)
    no change to the component tree; a refusal raises be-bc's
    ``ReloadRefused`` and leaves ``engine`` as it was. With N's tree built,
    N+1's is constructed and takes N's slots per unchanged instance path
    (``migrated``); else N+1 builds its tree at its first call. Returns the
    new engine and the result dict (``applied`` true); freeing ``engine`` is
    the caller's."""
    from zuspec.be.bc.interp.generations import (ReloadRefused, check_reload,
                                                 migrate)

    result = check_reload(old, new, strict, number)
    src = engine.comp_slots()
    eng = Engine(engine.lib, new.to_bytes(), opts)
    try:
        if src:
            try:
                eng.construct()
            except NativeError as e:
                if "construct-yield" not in str(e):
                    raise
                raise ReloadRefused(
                    "bus", f"reload refused: construction under generation "
                    f"{number + 1} made a bus access or import") from None
            a = SimpleNamespace(model=old, cobj=SimpleNamespace(values=src))
            b = SimpleNamespace(model=new, cobj=SimpleNamespace(
                values=eng.comp_slots()))
            result["migrated"] = migrate(a, b)
            eng.comp_write(b.cobj.values)
    except BaseException:
        eng.free()
        raise
    result["applied"] = True
    return eng, result
