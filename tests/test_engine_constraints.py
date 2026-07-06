"""End-to-end PSS constraint lowering: IR constraints -> blob -> oracle == native.

This closes the loop from the scenario IR to the native engine:

    ScSolveProblem(vars + ConstraintExpr)         (ir-core)
        -> be-bc lower_scenario  (build_solve_blob -> problem_bytes)   (be-bc)
        -> ZbcModel.to_bytes()   (SPROB pool carries the dv-solve blob)
        -> native engine solves it            AND
        -> oracle solves the *same* blob (NativeBlobBackend)

Both sides drive the identical dv-solve solver on the identical lowered blob with
the identical drawn seed, so the solved fields must match exactly -- and satisfy
the original constraints. This is the payoff of lowering constraints properly:
the engine enforces the real constraint system, not the ``seed + var_id`` stub.

Requires libdv_solve (built + linked by the ``dvsolve`` fixture); skips otherwise.
"""

import os

import pytest

pytest.importorskip("zuspec.be.bc")

from zuspec.ir.core import scenario as SC
from zuspec.ir.core import expr as E
from zuspec.ir.core import constraint as C

from zuspec.be.bc.lower import lower_scenario
from zuspec.be.bc.interp import run_model, Obj

from conftest import run_image


@pytest.fixture(autouse=True)
def _bind_eng(eng):
    global _eng
    _eng = eng
    yield


@pytest.fixture
def dv(dvsolve):
    """Ensure libdv_solve is available to both the engine link and the oracle."""
    if dvsolve is None:
        pytest.skip("libdv_solve unavailable (cmake / C toolchain missing)")
    os.environ["ZSP_SOLVER_PATH"] = str(dvsolve)
    pytest.importorskip("dv_solve.builder")
    from dv_solve.lib import _load_lib
    if _load_lib() is None:
        pytest.skip("libdv_solve failed to load from the session build")
    return dvsolve


# --- IR builders ---------------------------------------------------------- #

def _var(i, width=32, signed=False):
    return SC.ScSolveVar(name="f%d" % i, var_id=i, width=width, signed=signed)

def FIELD(i):   return E.ExprRefField(base=E.TypeExprRefSelf(), index=i)
def K(n):       return E.ExprConstant(value=n)
def BIN(l, op, r): return E.ExprBin(lhs=l, op=op, rhs=r)


def _lower(vars_, constraints, seed=None):
    """Build a one-solve coroutine, lower it, and return the ZbcModel."""
    problem = SC.ScSolveProblem(
        vars=list(vars_),
        constraints=[C.ConstraintExpr(expr=c) for c in constraints],
        writeback={v.name: v.var_id for v in vars_},
        seed=(K(seed) if seed is not None else None))
    coro = SC.ScCoroutine(name="root", body=[problem], frame_locals=[])
    return lower_scenario([coro])


def _lower_items(vars_, items, arrays=None):
    """Lower a solve problem whose constraints are already Constraint objects."""
    problem = SC.ScSolveProblem(vars=list(vars_), constraints=list(items),
                                writeback={v.name: v.var_id for v in vars_},
                                arrays=dict(arrays or {}))
    return lower_scenario([SC.ScCoroutine(name="root", body=[problem], frame_locals=[])])


def _diff(model, nfields):
    """Run oracle (blob-solving) + native engine on the lowered model."""
    obj = Obj(field_names=["f%d" % i for i in range(nfields)], values=[0] * nfields)
    run_model(model, obj=obj, seed=0)            # _op_solve auto-selects the blob solver
    o_fields = list(obj.values)

    nf = [0] * nfields
    res = run_image(_eng, model.to_bytes(), fields=nf)
    assert res.status == 0, "native status %d" % res.status
    assert nf == o_fields, "oracle %r != native %r" % (o_fields, nf)
    return nf


# --- tests ---------------------------------------------------------------- #

def test_constraint_sum_and_bound(dv):
    # f0 + f1 == 42, f0 >= 10 (width 8 so the sum doesn't wrap).
    model = _lower(
        [_var(0, width=8), _var(1, width=8)],
        [BIN(BIN(FIELD(0), E.BinOp.Add, FIELD(1)), E.BinOp.Eq, K(42)),
         BIN(FIELD(0), E.BinOp.GtE, K(10))])
    # the blob actually rode along in the .zbc
    assert model.problems[0].problem_bytes
    f = _diff(model, 2)
    assert f[0] + f[1] == 42 and f[0] >= 10


def test_constraint_range(dv):
    # f0 in [10..20]
    model = _lower([_var(0)],
                   [E.ExprIn(value=FIELD(0), container=E.ExprRange(lower=K(10), upper=K(20)))])
    f = _diff(model, 1)
    assert 10 <= f[0] <= 20


def test_constraint_arithmetic_relation(dv):
    # f1 == f0 * 2, f0 in [1..10]
    model = _lower(
        [_var(0), _var(1)],
        [BIN(FIELD(1), E.BinOp.Eq, BIN(FIELD(0), E.BinOp.Mult, K(2))),
         E.ExprIn(value=FIELD(0), container=E.ExprRange(lower=K(1), upper=K(10)))])
    f = _diff(model, 2)
    assert f[1] == f[0] * 2 and 1 <= f[0] <= 10


def test_constraint_fixed_seed_is_reproducible(dv):
    # Same problem + fixed seed -> identical assignment across runs, oracle == native.
    def build():
        return _lower([_var(0, width=8), _var(1, width=8)],
                      [BIN(BIN(FIELD(0), E.BinOp.Add, FIELD(1)), E.BinOp.Eq, K(50))],
                      seed=99)
    f1 = _diff(build(), 2)
    f2 = _diff(build(), 2)
    assert f1 == f2                        # fixed seed -> deterministic
    assert f1[0] + f1[1] == 50


def test_constraint_boolean_or(dv):
    # (f0 == 3) OR (f0 == 8)
    model = _lower(
        [_var(0, width=8)],
        [E.ExprBool(op=E.BoolOp.Or, values=[
            BIN(FIELD(0), E.BinOp.Eq, K(3)),
            BIN(FIELD(0), E.BinOp.Eq, K(8))])])
    f = _diff(model, 1)
    assert f[0] in (3, 8)


def test_constraint_disjoint_range_union(dv):
    # f0 in {[0..3], [200..203]} -- a disjoint union solved identically by both sides.
    rl = E.ExprRangeList(ranges=[E.ExprRange(lower=K(0), upper=K(3)),
                                 E.ExprRange(lower=K(200), upper=K(203))])
    model = _lower([_var(0)], [E.ExprIn(value=FIELD(0), container=rl)])
    f = _diff(model, 1)
    assert f[0] in (0, 1, 2, 3, 200, 201, 202, 203)


def test_constraint_or_of_in_range(dv):
    # f0 in [0..10] || f0 in [200..210] -- a disjunction of ranges, solved identically
    # by oracle and native (reduced to EXPR_IN_RANGES during lowering).
    e = E.ExprBool(op=E.BoolOp.Or, values=[
        E.ExprIn(value=FIELD(0), container=E.ExprRange(lower=K(0), upper=K(10))),
        E.ExprIn(value=FIELD(0), container=E.ExprRange(lower=K(200), upper=K(210)))])
    model = _lower([_var(0)], [e])
    f = _diff(model, 1)
    assert 0 <= f[0] <= 10 or 200 <= f[0] <= 210


def test_constraint_dist(dv):
    # f0 dist { [0..3] := 1, [200..210] := 5 } -- value in the union, oracle == native.
    model = _lower_items(
        [_var(0)],
        [C.ConstraintDist(target=FIELD(0), weights=[
            C.DistWeight(rng=E.ExprRange(lower=K(0), upper=K(3))),
            C.DistWeight(rng=E.ExprRange(lower=K(200), upper=K(210)), weight=K(5))])])
    f = _diff(model, 1)
    assert 0 <= f[0] <= 3 or 200 <= f[0] <= 210


def test_constraint_cross_var_range_disjunction(dv):
    # f0 in [10..12] || f1 in [50..52] -- ranges over two vars, encoded with boolean
    # selector aux vars. The blob carries extra vars beyond f0/f1; the oracle and the
    # native engine must still agree and only write back the real fields.
    vs = [_var(0, width=8), _var(1, width=8)]
    disj = E.ExprBool(op=E.BoolOp.Or, values=[
        E.ExprIn(value=FIELD(0), container=E.ExprRange(lower=K(10), upper=K(12))),
        E.ExprIn(value=FIELD(1), container=E.ExprRange(lower=K(50), upper=K(52)))])
    model = _lower_items(vs, [C.ConstraintExpr(expr=disj)])
    assert model.problems[0].problem_bytes
    f = _diff(model, 2)
    assert (10 <= f[0] <= 12) or (50 <= f[1] <= 52)


def test_constraint_solve_before(dv):
    # `solve f0 before f1` is a distribution-only hint dv-solve can't honour; it
    # lowers to nothing, the hard constraint still holds, and oracle == native.
    vs = [_var(0, width=8), _var(1, width=8)]
    model = _lower_items(
        vs,
        [C.ConstraintExpr(expr=BIN(BIN(FIELD(0), E.BinOp.Add, FIELD(1)),
                                   E.BinOp.Eq, K(42))),
         C.ConstraintSolveBefore(before=[FIELD(0)], after=[FIELD(1)])])
    f = _diff(model, 2)
    assert f[0] + f[1] == 42


def test_constraint_unique(dv):
    # unique { f0, f1, f2 } over default 32-bit vars -- lowered to the native
    # add_all_different (its width-32/tier-1 unsoundness is now fixed). Oracle
    # solves the identical blob as the native engine, so they must agree.
    vs = [_var(0), _var(1), _var(2)]
    model = _lower_items(vs, [C.ConstraintUnique(items=[FIELD(0), FIELD(1), FIELD(2)])])
    assert model.problems[0].problem_bytes
    f = _diff(model, 3)
    assert len({f[0], f[1], f[2]}) == 3


def test_constraint_foreach_array(dv):
    # rand arr[4] (elements at slots 0..3, array base slot 10); foreach (arr[i])
    # arr[i] > 50 && arr[i] < 60. Unrolled per element, oracle == native.
    vs = [_var(0, width=8), _var(1, width=8), _var(2, width=8), _var(3, width=8)]
    arr_i = E.ExprSubscript(value=FIELD(10), slice=E.ExprRefLocal(name="i"))
    fe = C.ConstraintForeach(
        array=FIELD(10), index_var="i",
        body=[C.ConstraintExpr(expr=BIN(arr_i, E.BinOp.Gt, K(50))),
              C.ConstraintExpr(expr=BIN(arr_i, E.BinOp.Lt, K(60)))])
    model = _lower_items(vs, [fe], arrays={10: [0, 1, 2, 3]})
    assert model.problems[0].problem_bytes
    f = _diff(model, 4)
    assert all(50 < f[i] < 60 for i in range(4))


def test_constraint_soft_dropped(dv):
    # hard f0 >= 100 with a conflicting soft f0 == 5: the soft relaxes, the hard
    # holds, and oracle == native on the identical blob (deterministic relaxation).
    model = _lower_items(
        [_var(0, width=32)],
        [C.ConstraintExpr(expr=BIN(FIELD(0), E.BinOp.GtE, K(100))),
         C.ConstraintSoft(expr=BIN(FIELD(0), E.BinOp.Eq, K(5)))])
    assert model.problems[0].problem_bytes
    f = _diff(model, 1)
    assert f[0] >= 100                      # hard enforced, soft dropped, no hang


def test_constraint_soft_honored(dv):
    # soft f0 == 777 with no conflicting hard -> honored exactly on both sides.
    model = _lower_items(
        [_var(0, width=32)],
        [C.ConstraintSoft(expr=BIN(FIELD(0), E.BinOp.Eq, K(777)))])
    f = _diff(model, 1)
    assert f[0] == 777


def test_constraint_implies_range(dv):
    # (f0 == 1) -> (f1 in [50..55]), with f0 forced to 1. Oracle == native, f1 in range.
    eq1 = BIN(FIELD(0), E.BinOp.Eq, K(1))
    in_r = E.ExprIn(value=FIELD(1), container=E.ExprRange(lower=K(50), upper=K(55)))
    model = _lower_items(
        [_var(0, width=8), _var(1, width=8)],
        [C.ConstraintExpr(expr=eq1),
         C.ConstraintImplies(antecedent=eq1, body=[C.ConstraintExpr(expr=in_r)])])
    f = _diff(model, 2)
    assert f[0] == 1 and 50 <= f[1] <= 55


def test_constraint_if_else(dv):
    # if (f0 == 1) { f1 < 10 } else { f1 > 100 }, forcing f0 to 0 -> else branch.
    eq1 = BIN(FIELD(0), E.BinOp.Eq, K(1))
    model = _lower_items(
        [_var(0, width=8), _var(1, width=8)],
        [C.ConstraintExpr(expr=BIN(FIELD(0), E.BinOp.Eq, K(0))),
         C.ConstraintIfElse(cond=eq1,
                            then_body=[C.ConstraintExpr(expr=BIN(FIELD(1), E.BinOp.Lt, K(10)))],
                            else_body=[C.ConstraintExpr(expr=BIN(FIELD(1), E.BinOp.Gt, K(100)))])])
    f = _diff(model, 2)
    assert f[0] == 0 and f[1] > 100


def test_constraint_slot_differs_from_var_id(dv):
    # Object [f0 (non-rand pad), f1 (rand), f2 (rand)]: the rand vars live at slots
    # 1 and 2 but are solver var_ids 0 and 1, so writeback maps slot != var_id. The
    # constraint addresses fields by slot (1, 2); the non-rand slot 0 must be left
    # untouched by the solve.
    vx = SC.ScSolveVar(name="f1", var_id=0, slot=1, width=8)
    vy = SC.ScSolveVar(name="f2", var_id=1, slot=2, width=8)
    model = _lower(
        [vx, vy],
        [BIN(BIN(FIELD(1), E.BinOp.Add, FIELD(2)), E.BinOp.Eq, K(42)),
         BIN(FIELD(1), E.BinOp.GtE, K(10))])
    assert model.problems[0].writeback_slots == {1: 0, 2: 1}   # slot -> var_id

    # Seed a non-rand pad at slot 0 (=7) that the solve must not disturb.
    obj = Obj(field_names=["f0", "f1", "f2"], values=[7, 0, 0])
    run_model(model, obj=obj, seed=0)
    o = list(obj.values)

    nf = [7, 0, 0]
    res = run_image(_eng, model.to_bytes(), fields=nf)
    assert res.status == 0
    assert nf == o                          # oracle == native
    assert nf[0] == 7                        # non-rand slot untouched
    assert nf[1] + nf[2] == 42 and nf[1] >= 10
