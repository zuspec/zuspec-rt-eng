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
/* A called (recursive) function's arguments (bc procedural gaps B-D5). */
#define ZBC_OP_ARG       0x18   /* arg0 = rs; arg1 = i: stage argument i of the next CALL */
#define ZBC_OP_LD_ARG    0x19   /* arg0 = rd; arg1 = i: this frame's argument i */
#define ZBC_OP_LD_RES    0x1A   /* arg0 = rd; arg1 = i: result i of this frame's last CALL */
/* F6.9c heap ops (be-bc heap.md): run-time strings, list/map/set; refused until M14. */
#define ZBC_OP_HEAP      0x1B

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

/* Float (registers hold binary64 bits; imm selects the operation) */
#define ZBC_OP_FARITH    0x2c   /* imm: 0 add 1 sub 2 mul 3 div 4 neg */
#define ZBC_OP_FCVT      0x2d   /* imm: 0 s2f 1 u2f 2 f2s 3 round to f32 */
#define ZBC_OP_FMATH     0x2e   /* imm: index in model FMATH_FNS (libm); 1-arg fns ignore arg2 */

/* Compare (result is 0/1) */
#define ZBC_OP_CMP_EQ    0x30
#define ZBC_OP_CMP_NE    0x31
#define ZBC_OP_CMP_LT    0x32
#define ZBC_OP_CMP_LE    0x33
#define ZBC_OP_CMP_GT    0x34
#define ZBC_OP_CMP_GE    0x35
#define ZBC_OP_FCMP      0x36   /* imm: 0 eq 1 ne 2 lt 3 le 4 gt 5 ge */

/* Float sub-ops (imm), mirroring zuspec.be.bc.model FARITH_* / FCVT_* / FCMP_* */
#define ZBC_FARITH_ADD 0
#define ZBC_FARITH_SUB 1
#define ZBC_FARITH_MUL 2
#define ZBC_FARITH_DIV 3
#define ZBC_FARITH_NEG 4
#define ZBC_FCVT_S2F   0
#define ZBC_FCVT_U2F   1
#define ZBC_FCVT_F2S   2
#define ZBC_FCVT_F32   3
#define ZBC_FCMP_EQ    0
#define ZBC_FCMP_NE    1
#define ZBC_FCMP_LT    2
#define ZBC_FCMP_LE    3
#define ZBC_FCMP_GT    4
#define ZBC_FCMP_GE    5

/* Branch (code-relative target within the coro) */
#define ZBC_OP_BR        0x38
#define ZBC_OP_BRZ       0x39

/* Orchestration */
#define ZBC_OP_SPAWN     0x40
#define ZBC_OP_INVOKE    0x41
#define ZBC_OP_PAR       0x42
#define ZBC_OP_JOIN      0x43
#define ZBC_OP_WAIT      0x44
#define ZBC_OP_SOLVE     0x46
#define ZBC_OP_BIND      0x47
#define ZBC_OP_YIELD     0x48
#define ZBC_OP_IMPORT    0x49
/* A recursive function: call coroutine arg0 now, nested, in this frame's object
 * and base, with the staged arguments; its RET value lands in arg1
 * (0xFFFFFFFF: none). */
#define ZBC_OP_CALL        0x4C
/* Procedural randomize (F3.7): SOLVE_PIN pins var arg0 of the frame's next
 * SOLVE to register arg1; SOLVE_GET reads var arg1 of the frame's last
 * procedural SOLVE (ZBC_SOLVE_PROCEDURAL) into register arg0. */
#define ZBC_OP_SOLVE_PIN   0x4D
#define ZBC_OP_SOLVE_GET   0x4E

/* The pss extension (0x80-0xBF; the image sets ZBC_HDR_EXT_PSS). */
#define ZBC_OP_SELECT      0x80
/* P1.4 activation solve scope. */
#define ZBC_OP_SCOPE_ENTER 0x81
#define ZBC_OP_SOLVE_NODE  0x82
/* Functional coverage (F4.4): sample covergroup arg0 (the image's COVG entry)
 * with the coverpoint values (and iff flags) in registers arg1... Not
 * implemented by this engine: an image using it is refused (M14). */
#define ZBC_OP_COV_SAMPLE  0x83
#define ZBC_OP_EXEC_SET    0x84   /* F5.4a: frame executor = EXEC row in a0 */
#define ZBC_OP_EXEC_GET    0x85   /* F5.4c: a0 = frame executor (~0 = none) */
/* P1.5, component attributes. */
#define ZBC_OP_LD_COMP     0x86
#define ZBC_OP_ST_COMP     0x87

/* The extensions this engine implements (zbc_format.h ZBC_HDR_EXT_*): an
 * image declaring another is refused at load (ZBC_ERR_BAD_PROFILE). */
#define ZBC_ENGINE_EXTENSIONS ZBC_HDR_EXT_PSS

/* IMPORT fn_ids at and above this are interpreter builtins (model.BUILTIN_*). */
#define ZBC_BUILTIN_BASE      0xFFFFFF00u
#define ZBC_BUILTIN_MESSAGE   (ZBC_BUILTIN_BASE + 0)
#define ZBC_BUILTIN_ERROR     (ZBC_BUILTIN_BASE + 1)   /* an LRM "shall" error: halts */
#define ZBC_BUILTIN_MEM_FIRST (ZBC_BUILTIN_BASE + 2)   /* read8..64, write8..64: host mem_access */
#define ZBC_BUILTIN_MEM_LAST  (ZBC_BUILTIN_BASE + 9)
#define ZBC_BUILTIN_ERROR_MSG (ZBC_BUILTIN_BASE + 10)  /* error(fmt, ...): logged, then halts */
#define ZBC_BUILTIN_FATAL_MSG (ZBC_BUILTIN_BASE + 11)  /* fatal(status, fmt, ...): logged, then halts */
#define ZBC_BUILTIN_PRINT     (ZBC_BUILTIN_BASE + 12)  /* print(fmt, ...): logged at any verbosity */
/* std_pkg file functions (24.2), served by the engine on its own machine:
 * open(name string, mode) -> handle (0 = nullfilehandle), close(handle),
 * exists(name string) -> bool, write(msg entry; slot0 = handle). */
#define ZBC_BUILTIN_FILE_OPEN   (ZBC_BUILTIN_BASE + 13)
#define ZBC_BUILTIN_FILE_CLOSE  (ZBC_BUILTIN_BASE + 14)
#define ZBC_BUILTIN_FILE_EXISTS (ZBC_BUILTIN_BASE + 15)
#define ZBC_BUILTIN_FILE_WRITE  (ZBC_BUILTIN_BASE + 16)
/* std_pkg urandom() / urandom_range(min, max) (24.4): a draw from the calling
 * frame's seed stream (as SELECT), so a seed gives the same numbers as the
 * Python engine. urandom: upper 32 bits of one draw; urandom_range: inclusive,
 * min > max swapped, min + draw % (max - min + 1). */
#define ZBC_BUILTIN_URANDOM       (ZBC_BUILTIN_BASE + 17)
#define ZBC_BUILTIN_URANDOM_RANGE (ZBC_BUILTIN_BASE + 18)
/* std_pkg file_read / file_read_lines / file_write_lines (24.2): they make
 * or read heap strings and lists, so an image calling them is refused up
 * front like one with HEAP ops (heap.md s.9) until M14. */
#define ZBC_BUILTIN_FILE_READ        (ZBC_BUILTIN_BASE + 19)
#define ZBC_BUILTIN_FILE_READ_LINES  (ZBC_BUILTIN_BASE + 20)
#define ZBC_BUILTIN_FILE_WRITE_LINES (ZBC_BUILTIN_BASE + 21)

/* Instruction flags */
#define ZBC_F_FROM_POOL  0x01
#define ZBC_F_BLOCKING   0x02
#define ZBC_F_HAS_RET    0x04
#define ZBC_F_NODE       0x08   /* INVOKE: callee is a node at base + imm */
#define ZBC_F_INITED     0x10   /* INVOKE: callee starts at arg3 (P1.4; refused) */
#define ZBC_F_SPIN       0x20   /* YIELD: waiting on a condition (channel get/put) */
#define ZBC_F_SUBSET     0x40   /* JOIN: join_select / join_branch (refused until M14) */

#endif /* ZUSPEC_ZBC_OPS_H */
