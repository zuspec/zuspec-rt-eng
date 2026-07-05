# zuspec-rt-eng

The native ZBC execution engine (roadmap **P3**): loads a `.zbc` image and
executes it with a bytecode interpreter running over the `zuspec-rt-core`
substrate (scheduler + frame arena).

Per the "interpreter as a coroutine" design
(`zuspec-rt-core/docs/interp-as-coroutine.md`), the interpreter is a single
`zsp_task_func` (`zbc_interp_task`) whose frame-resident `pc` + register/local
file makes interpreted coroutines interoperate with compiled (AOT/JIT) ones under
one scheduler.

Its correctness contract is the **Python oracle** (`zuspec.be.bc.interp`): the
same `.zbc` + seed must produce matching results. Native code is tested via
pytest + ctypes (project convention), reusing `zuspec.rt.core.build`.

Status: **walking skeleton** — `.zbc` reader + procedural/`WAIT`/`RET` interpreter.
Orchestration (SPAWN/JOIN/INVOKE/SELECT), fields, SOLVE/IMPORT, and trace land
incrementally.
