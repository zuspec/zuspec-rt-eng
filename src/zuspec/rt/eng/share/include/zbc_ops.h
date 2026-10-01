/*
 * zbc_ops.h -- ZBC opcode + instruction-flag values.
 *
 * These MIRROR zuspec.be.bc.model.Op / INSTR_F_* (the single ISA authority). A
 * ctypes drift test (tests/test_ops_match_model.py) asserts these stay in sync
 * with the Python enum. (Later: generate this header from the same spec.)
 */
#ifndef ZUSPEC_ZBC_OPS_H
#define ZUSPEC_ZBC_OPS_H

/* Control */
#define ZBC_OP_NOP       0x00
#define ZBC_OP_RET       0x01

/* Data movement / materialization */
#define ZBC_OP_CONST     0x10
#define ZBC_OP_MOV       0x11
#define ZBC_OP_LD_LOCAL  0x12
#define ZBC_OP_ST_LOCAL  0x13
#define ZBC_OP_LD_FIELD  0x14
#define ZBC_OP_ST_FIELD  0x15
/* P1.5, component attributes: refused at load until P8. */
#define ZBC_OP_LD_COMP   0x16
#define ZBC_OP_ST_COMP   0x17
/* A called (recursive) function's arguments (bc procedural gaps B-D5). */
#define ZBC_OP_ARG       0x18   /* arg0 = rs; arg1 = i: stage argument i of the next CALL */
#define ZBC_OP_LD_ARG    0x19   /* arg0 = rd; arg1 = i: this frame's argument i */

/* Arithmetic / logic */
#define ZBC_OP_ADD       0x20
#define ZBC_OP_SUB       0x21
#define ZBC_OP_MUL       0x22
#define ZBC_OP_DIV       0x23
#define ZBC_OP_MOD       0x24
#define ZBC_OP_AND       0x25
#define ZBC_OP_OR        0x26
#define ZBC_OP_XOR       0x27
#define ZBC_OP_SHL       0x28
#define ZBC_OP_SHR       0x29
#define ZBC_OP_NEG       0x2a
#define ZBC_OP_NOT       0x2b

/* Compare (result is 0/1) */
#define ZBC_OP_CMP_EQ    0x30
#define ZBC_OP_CMP_NE    0x31
#define ZBC_OP_CMP_LT    0x32
#define ZBC_OP_CMP_LE    0x33
#define ZBC_OP_CMP_GT    0x34
#define ZBC_OP_CMP_GE    0x35

/* Branch (code-relative target within the coro) */
#define ZBC_OP_BR        0x38
#define ZBC_OP_BRZ       0x39

/* Orchestration */
#define ZBC_OP_SPAWN     0x40
#define ZBC_OP_INVOKE    0x41
#define ZBC_OP_PAR       0x42
#define ZBC_OP_JOIN      0x43
#define ZBC_OP_WAIT      0x44
#define ZBC_OP_SELECT    0x45
#define ZBC_OP_SOLVE     0x46
#define ZBC_OP_BIND      0x47
#define ZBC_OP_YIELD     0x48
#define ZBC_OP_IMPORT    0x49
/* P1.4 activation solve scope: NOT implemented natively until P8 -- an image
 * using either is refused before it runs (zbc_run). */
#define ZBC_OP_SCOPE_ENTER 0x4A
#define ZBC_OP_SOLVE_NODE  0x4B
/* A recursive function: call coroutine arg0 now, nested, in this frame's object
 * and base, with the staged arguments; its RET value lands in arg1
 * (0xFFFFFFFF: none). */
#define ZBC_OP_CALL        0x4C

/* IMPORT fn_ids at and above this are interpreter builtins (model.BUILTIN_*). */
#define ZBC_BUILTIN_BASE      0xFFFFFF00u
#define ZBC_BUILTIN_MESSAGE   (ZBC_BUILTIN_BASE + 0)
#define ZBC_BUILTIN_ERROR     (ZBC_BUILTIN_BASE + 1)   /* an LRM "shall" error: halts */
#define ZBC_BUILTIN_MEM_FIRST (ZBC_BUILTIN_BASE + 2)   /* read8..64, write8..64: refused */
#define ZBC_BUILTIN_MEM_LAST  (ZBC_BUILTIN_BASE + 9)

/* Instruction flags */
#define ZBC_F_FROM_POOL  0x01
#define ZBC_F_BLOCKING   0x02
#define ZBC_F_HAS_RET    0x04
#define ZBC_F_NODE       0x08   /* INVOKE: callee is a node at base + imm */
#define ZBC_F_INITED     0x10   /* INVOKE: callee starts at arg3 (P1.4; refused) */
#define ZBC_F_SPIN       0x20   /* YIELD: waiting on a condition (channel; refused) */

#endif /* ZUSPEC_ZBC_OPS_H */
