"""
Unit tests for the symbolic expression and simplification system.

These tests can be run standalone (without IDA) to verify the expression
types and simplification logic work correctly.

Usage: python -m pytest test_symbolic.py
   or: python test_symbolic.py
"""
import sys
import os

# Add parent directory to path so we can import d810 modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from d810.Expr import (
    ExprInt, ExprId, ExprMem, ExprOp,
    ExprSlice, ExprCompose, ExprCond, walk_expr_iter
)
from d810.ExprSimplifier import simplify, unsigned_to_signed,signed_to_unsigned


def get_branch_constraints(expr_cond: ExprCond):
    cond = expr_cond.cond
    bit_one = ExprInt(1, cond.size)
    bit_zero = ExprInt(0, cond.size)

    # 条件为真：cond == 1
    cond_true = ExprOp("==", [cond, bit_one],4)
    # 条件为假：cond == 0
    cond_false = ExprOp("==", [cond, bit_zero],4)
    return cond_true, cond_false

def test_cond_jz_expr_replace():

    x29 = ExprId("x29", 8)
    c2 = ExprOp("==", [x29, ExprInt(0xDBE8A93F48D4BDC7, 8)], 4)
    e2 = ExprCond(c2, ExprInt(5, 4), ExprInt(21, 4))
    c_true, c_false = get_branch_constraints(e2)
    e3 = e2.replace({"x29": ExprInt(0xDBE8A93F48D4BDC7, 8)})
    assert simplify(e3).as_int() == 5

    # 方式2：用表达式对象替换
    e4 = e2.replace({x29: ExprInt(0x1234, 8)})
    assert simplify(e4).as_int() == 21
    print("  [PASS] test_cond_jz_expr_replace")


def test_cond_jz_expr_replace2():
    """测试多个表达式的批量替换"""
    # 构造多个表达式
    x29 = ExprId("x29", 8)
    x6 = ExprId("x6", 8)

    # 表达式列表
    exprs = [
        ExprOp("==", [x29, ExprInt(0xDBE8A93F48D4BDC7, 8)], 4),
        ExprOp(">s", [x6, ExprInt(0x9D60D6828D7CED1, 8)], 4),
        ExprOp("+", [x29, x6], 8),
    ]

    # 替换映射
    values = {
        x29: ExprInt(0xDBE8A93F48D4BDC7, 8),
        x6: ExprInt(0x1000000000000000, 8),
    }

    # 批量替换
    replaced = [e.replace(values) for e in exprs]
    simplified = [simplify(r) for r in replaced]

    # 验证结果
    assert simplified[0].is_int() and simplified[0].as_int() == 1  # x29 == 目标值 → True
    assert simplified[1].is_int() and simplified[1].as_int() == 1  # x6 > 目标值 → True
    assert simplified[2].is_int()  # x29 + x6 → 具体数值

    print("  [PASS] test_cond_jz_expr_replace2")


def test_walk_traverse():
    # 严格匹配构造参数顺序
    cmp1 = ExprOp(">", [ExprId("x", 4), ExprInt(1, 4)], 4)
    cmp2 = ExprOp("<", [ExprId("y", 4), ExprInt(10, 4)], 4)
    cond = ExprOp("&&", [cmp1, cmp2], 1)

    br_true = ExprInt(100, 8)
    br_false = ExprOp("+", [ExprId("a", 8), ExprId("b", 8)], 8)
    root = ExprCond(cond, br_true, br_false)

    nodes = list(walk_expr_iter(root))
    type_seq = [type(x).__name__ for x in nodes]

    expect = [
        "ExprCond",
        "ExprOp",
        "ExprOp",
        "ExprId",
        "ExprInt",
        "ExprOp",
        "ExprId",
        "ExprInt",
        "ExprInt",
        "ExprOp",
        "ExprId",
        "ExprId",
    ]

    assert type_seq == expect
    assert len(nodes) == 12

    vars_found = [x.name for x in nodes if x.is_id()]
    const_found = [x.value for x in nodes if x.is_int()]

    assert vars_found == ["x", "y", "a", "b"]
    assert const_found == [1, 10, 100]

    print("  [PASS] test_walk_traverse")


def test_replace_simple():
    """Test simple variable replacement."""
    x = ExprId("eax", 4)
    e = ExprOp('+', [x, ExprInt(5, 4)], 4)

    # Replace by variable name
    result = e.replace({"eax": ExprInt(10, 4)})
    simplified = simplify(result)
    assert simplified.is_int()
    assert simplified.as_int() == 15
    print("  [PASS] test_replace_simple")


def test_replace_multiple():
    """Test replacing multiple variables."""
    x = ExprId("x", 4)
    y = ExprId("y", 4)
    # (x + y) * 2
    e = ExprOp('*', [ExprOp('+', [x, y], 4), ExprInt(2, 4)], 4)

    # Replace both x and y
    result = e.replace({"x": ExprInt(3, 4), "y": ExprInt(4, 4)})
    simplified = simplify(result)

    assert simplified.is_int()
    assert simplified.as_int() == 14  # (3 + 4) * 2 = 14
    print("  [PASS] test_replace_multiple")


def test_replace_nested():
    """Test replacing in nested expressions."""
    x = ExprId("x", 4)
    # Cond expression: (x > 5 ? x + 1 : x - 1)
    cond = ExprOp('>u', [x, ExprInt(5, 4)], 4)
    true_branch = ExprOp('+', [x, ExprInt(1, 4)], 4)
    false_branch = ExprOp('-', [x, ExprInt(1, 4)], 4)
    e = ExprCond(cond, true_branch, false_branch)

    # Replace x with 10
    result = e.replace({"x": ExprInt(10, 4)})
    simplified = simplify(result)
    # 10 > 5 is true, so should get 10 + 1 = 11
    assert simplified.is_int()
    assert simplified.as_int() == 11
    print("  [PASS] test_replace_nested")


def test_replace_partial():
    """Test partial replacement (only some variables)."""
    x = ExprId("x", 4)
    y = ExprId("y", 4)
    e = ExprOp('+', [x, y], 4)

    # Only replace x, leave y symbolic
    result = e.replace({"x": ExprInt(5, 4)})
    # Should be (5 + y), still symbolic
    assert result.is_op()
    assert result.op == '+'
    assert result.args[0].is_int()
    assert result.args[0].as_int() == 5
    assert result.args[1] == y
    print("  [PASS] test_replace_partial")


def test_replace_subexpr():
    """Test replacing entire subexpressions."""
    x = ExprId("x", 4)
    y = ExprId("y", 4)
    subexpr = ExprOp('+', [x, y], 4)
    e = ExprOp('*', [subexpr, ExprInt(2, 4)], 4)

    # Replace the entire (x + y) subexpression
    result = e.replace({subexpr: ExprInt(10, 4)})
    simplified = simplify(result)
    assert simplified.is_int()
    assert simplified.as_int() == 20  # 10 * 2
    print("  [PASS] test_replace_subexpr")


def test_expr_int_basic():
    """Test ExprInt creation and properties."""
    e = ExprInt(42, 4)
    assert e.is_int()
    assert e.as_int() == 42
    assert e.size == 4
    assert e.bit_size == 32
    assert e.mask == 0xFFFFFFFF
    print("  [PASS] test_expr_int_basic")


def test_expr_int_truncation():
    """Test that integer values are masked to size."""
    e = ExprInt(0x1FFFFFFFF, 4)  # 5 bytes in a 4-byte int
    assert e.as_int() == 0xFFFFFFFF
    print("  [PASS] test_expr_int_truncation")

def test_expr_int_equal():
    e2 = ExprInt(0x7F, 1)  # 127 in signed 8-bit
    e1 = ExprInt(0x7F, 1)  # 127 in signed 8-bit
    assert e2 == e1
    print("  [PASS] test_expr_int_equal")


def test_expr_int_signed():
    """Test signed interpretation."""
    e = ExprInt(0xFF, 1)  # -1 in signed 8-bit
    assert e.signed_value() == -1

    e2 = ExprInt(0x7F, 1)  # 127 in signed 8-bit
    assert e2.signed_value() == 127
    print("  [PASS] test_expr_int_signed")


def test_expr_id():
    """Test ExprId creation."""
    e = ExprId("eax", 4)
    assert e.is_id()
    assert e.name == "eax"
    assert e.size == 4
    assert not e.is_int()
    assert e.as_int() is None
    print("  [PASS] test_expr_id")


def test_expr_equality():
    """Test expression equality."""
    a = ExprInt(5, 4)
    b = ExprInt(5, 4)
    c = ExprInt(5, 8)
    d = ExprInt(6, 4)

    assert a == b
    assert a != c  # different size
    assert a != d  # different value

    x = ExprId("eax", 4)
    y = ExprId("eax", 4)
    z = ExprId("ebx", 4)
    assert x == y
    assert x != z
    print("  [PASS] test_expr_equality")


def test_expr_hash():
    """Test expressions can be used as dict keys."""
    a = ExprInt(5, 4)
    b = ExprInt(5, 4)
    d = {a: "hello"}
    assert d[b] == "hello"

    x = ExprId("eax", 4)
    y = ExprId("eax", 4)
    d[x] = "world"
    assert d[y] == "world"
    print("  [PASS] test_expr_hash")


def test_expr_op():
    """Test ExprOp creation."""
    left = ExprId("eax", 4)
    right = ExprInt(5, 4)
    op = ExprOp('+', [left, right], 4)
    assert op.is_op()
    assert op.op == '+'
    assert len(op.args) == 2
    assert op.size == 4
    print("  [PASS] test_expr_op")


def test_expr_mem():
    """Test ExprMem creation."""
    addr = ExprId("rsp", 8)
    mem = ExprMem(addr, 4)
    assert mem.is_mem()
    assert mem.addr == addr
    assert mem.size == 4
    print("  [PASS] test_expr_mem")


def test_expr_slice():
    """Test ExprSlice creation."""
    e = ExprId("rax", 8)
    s = ExprSlice(e, 0, 32)
    assert s.is_slice()
    assert s.size == 4
    assert s.start == 0
    assert s.stop == 32
    print("  [PASS] test_expr_slice")


def test_expr_compose():
    """Test ExprCompose creation."""
    lo = ExprId("al", 1)
    hi = ExprId("ah", 1)
    c = ExprCompose([(lo, 0, 8), (hi, 8, 16)])
    assert c.is_compose()
    assert c.size == 2
    print("  [PASS] test_expr_compose")


def test_expr_cond():
    """Test ExprCond creation."""
    cond = ExprId("zf", 1)
    t = ExprInt(1, 4)
    f = ExprInt(0, 4)
    c = ExprCond(cond, t, f)
    assert c.is_cond()
    assert c.size == 4
    print("  [PASS] test_expr_cond")


# ============================================================
# Simplification tests
# ============================================================

def test_simplify_constant_folding_add():
    """Test constant folding: 3 + 5 = 8."""
    e = ExprOp('+', [ExprInt(3, 4), ExprInt(5, 4)], 4)
    result = simplify(e)
    assert result.is_int()
    assert result.as_int() == 8
    print("  [PASS] test_simplify_constant_folding_add")


def test_simplify_constant_folding_sub():
    """Test constant folding: 10 - 3 = 7."""
    e = ExprOp('-', [ExprInt(10, 4), ExprInt(3, 4)], 4)
    result = simplify(e)
    assert result.is_int()
    assert result.as_int() == 7
    print("  [PASS] test_simplify_constant_folding_sub")


def test_simplify_constant_folding_mul():
    """Test constant folding: 6 * 7 = 42."""
    e = ExprOp('*', [ExprInt(6, 4), ExprInt(7, 4)], 4)
    result = simplify(e)
    assert result.is_int()
    assert result.as_int() == 42
    print("  [PASS] test_simplify_constant_folding_mul")


def test_simplify_constant_folding_xor():
    """Test constant folding: 0xAA ^ 0x55 = 0xFF."""
    e = ExprOp('^', [ExprInt(0xAA, 1), ExprInt(0x55, 1)], 1)
    result = simplify(e)
    assert result.is_int()
    assert result.as_int() == 0xFF
    print("  [PASS] test_simplify_constant_folding_xor")


def test_simplify_constant_folding_shift():
    """Test constant folding: 1 << 4 = 16."""
    e = ExprOp('<<', [ExprInt(1, 4), ExprInt(4, 4)], 4)
    result = simplify(e)
    assert result.is_int()
    assert result.as_int() == 16
    print("  [PASS] test_simplify_constant_folding_shift")


def test_simplify_identity_add_zero():
    """Test identity: x + 0 = x."""
    x = ExprId("eax", 4)
    e = ExprOp('+', [x, ExprInt(0, 4)], 4)
    result = simplify(e)
    assert result == x
    print("  [PASS] test_simplify_identity_add_zero")


def test_simplify_identity_xor_zero():
    """Test identity: x ^ 0 = x."""
    x = ExprId("eax", 4)
    e = ExprOp('^', [x, ExprInt(0, 4)], 4)
    result = simplify(e)
    assert result == x
    print("  [PASS] test_simplify_identity_xor_zero")


def test_simplify_identity_and_mask():
    """Test identity: x & 0xFFFFFFFF = x (for 4-byte)."""
    x = ExprId("eax", 4)
    e = ExprOp('&', [x, ExprInt(0xFFFFFFFF, 4)], 4)
    result = simplify(e)
    assert result == x
    print("  [PASS] test_simplify_identity_and_mask")


def test_simplify_identity_or_zero():
    """Test identity: x | 0 = x."""
    x = ExprId("eax", 4)
    e = ExprOp('|', [x, ExprInt(0, 4)], 4)
    result = simplify(e)
    assert result == x
    print("  [PASS] test_simplify_identity_or_zero")


def test_simplify_identity_mul_one():
    """Test identity: x * 1 = x."""
    x = ExprId("eax", 4)
    e = ExprOp('*', [x, ExprInt(1, 4)], 4)
    result = simplify(e)
    assert result == x
    print("  [PASS] test_simplify_identity_mul_one")


def test_simplify_annihilation_mul_zero():
    """Test annihilation: x * 0 = 0."""
    x = ExprId("eax", 4)
    e = ExprOp('*', [x, ExprInt(0, 4)], 4)
    result = simplify(e)
    assert result.is_int()
    assert result.as_int() == 0
    print("  [PASS] test_simplify_annihilation_mul_zero")


def test_simplify_annihilation_and_zero():
    """Test annihilation: x & 0 = 0."""
    x = ExprId("eax", 4)
    e = ExprOp('&', [x, ExprInt(0, 4)], 4)
    result = simplify(e)
    assert result.is_int()
    assert result.as_int() == 0
    print("  [PASS] test_simplify_annihilation_and_zero")


def test_simplify_self_cancel_xor():
    """Test self-cancellation: x ^ x = 0."""
    x = ExprId("eax", 4)
    e = ExprOp('^', [x, x], 4)
    result = simplify(e)
    assert result.is_int()
    assert result.as_int() == 0
    print("  [PASS] test_simplify_self_cancel_xor")


def test_simplify_self_cancel_sub():
    """Test self-cancellation: x - x = 0."""
    x = ExprId("eax", 4)
    e = ExprOp('-', [x, x], 4)
    result = simplify(e)
    assert result.is_int()
    assert result.as_int() == 0
    print("  [PASS] test_simplify_self_cancel_sub")


def test_simplify_self_and():
    """Test self-AND: x & x = x."""
    x = ExprId("eax", 4)
    e = ExprOp('&', [x, x], 4)
    result = simplify(e)
    assert result == x
    print("  [PASS] test_simplify_self_and")


def test_simplify_self_or():
    """Test self-OR: x | x = x."""
    x = ExprId("eax", 4)
    e = ExprOp('|', [x, x], 4)
    result = simplify(e)
    assert result == x
    print("  [PASS] test_simplify_self_or")


def test_simplify_unary_neg_constant():
    """Test unary neg: neg(5) = -5 (as unsigned)."""
    e = ExprOp('neg', [ExprInt(5, 4)], 4)
    result = simplify(e)
    assert result.is_int()
    assert result.as_int() == ((-5) & 0xFFFFFFFF)
    print("  [PASS] test_simplify_unary_neg_constant")


def test_simplify_unary_bnot_constant():
    """Test unary bnot: ~0x0F = 0xFFFFFFF0 (4 bytes)."""
    e = ExprOp('~', [ExprInt(0x0F, 4)], 4)
    result = simplify(e)
    assert result.is_int()
    assert result.as_int() == 0xFFFFFFF0
    print("  [PASS] test_simplify_unary_bnot_constant")


def test_simplify_double_neg():
    """Test double negation: neg(neg(x)) = x."""
    x = ExprId("eax", 4)
    inner = ExprOp('neg', [x], 4)
    outer = ExprOp('neg', [inner], 4)
    result = simplify(outer)
    assert result == x
    print("  [PASS] test_simplify_double_neg")


def test_simplify_double_bnot():
    """Test double bitwise not: ~(~x) = x."""
    x = ExprId("eax", 4)
    inner = ExprOp('~', [x], 4)
    outer = ExprOp('~', [inner], 4)
    result = simplify(outer)
    assert result == x
    print("  [PASS] test_simplify_double_bnot")


def test_simplify_slice_of_int():
    """Test slice of integer: 0xAABBCCDD[0:16] = 0xCCDD."""
    e = ExprSlice(ExprInt(0xAABBCCDD, 4), 0, 16)
    result = simplify(e)
    assert result.is_int()
    assert result.as_int() == 0xCCDD
    print("  [PASS] test_simplify_slice_of_int")


def test_simplify_slice_identity():
    """Test slice covering entire expression is identity."""
    x = ExprId("eax", 4)
    e = ExprSlice(x, 0, 32)
    result = simplify(e)
    assert result == x
    print("  [PASS] test_simplify_slice_identity")


def test_simplify_cond_concrete_true():
    """Test concrete condition true: (1 ? a : b) = a."""
    a = ExprId("eax", 4)
    b = ExprId("ebx", 4)
    e = ExprCond(ExprInt(1, 1), a, b)
    result = simplify(e)
    assert result == a
    print("  [PASS] test_simplify_cond_concrete_true")


def test_simplify_cond_concrete_false():
    """Test concrete condition false: (0 ? a : b) = b."""
    a = ExprId("eax", 4)
    b = ExprId("ebx", 4)
    e = ExprCond(ExprInt(0, 1), a, b)
    result = simplify(e)
    assert result == b
    print("  [PASS] test_simplify_cond_concrete_false")


def test_simplify_cond_same_branches():
    """Test same branches: (c ? a : a) = a."""
    c = ExprId("zf", 1)
    a = ExprId("eax", 4)
    e = ExprCond(c, a, a)
    result = simplify(e)
    assert result == a
    print("  [PASS] test_simplify_cond_same_branches")


def test_simplify_compose_all_int():
    """Test compose of all integers folds into one integer."""
    # 0x12 at bits [0:8], 0x34 at bits [8:16]
    e = ExprCompose([(ExprInt(0x12, 1), 0, 8), (ExprInt(0x34, 1), 8, 16)])
    result = simplify(e)
    assert result.is_int()
    assert result.as_int() == 0x3412  # little-endian composition
    print("  [PASS] test_simplify_compose_all_int")


def test_simplify_comparison_equal():
    """Test comparison: 5 == 5 = 1."""
    e = ExprOp('==', [ExprInt(5, 4), ExprInt(5, 4)], 4)
    result = simplify(e)
    assert result.is_int()
    assert result.as_int() == 1
    print("  [PASS] test_simplify_comparison_equal")


def test_simplify_comparison_not_equal():
    """Test comparison: 5 != 3 = 1."""
    e = ExprOp('!=', [ExprInt(5, 4), ExprInt(3, 4)], 4)
    result = simplify(e)
    assert result.is_int()
    assert result.as_int() == 1
    print("  [PASS] test_simplify_comparison_not_equal")


def test_simplify_comparison_less_unsigned():
    """Test comparison: 3 <u 5 = 1."""
    e = ExprOp('<u', [ExprInt(3, 4), ExprInt(5, 4)], 4)
    result = simplify(e)
    assert result.is_int()
    assert result.as_int() == 1
    print("  [PASS] test_simplify_comparison_less_unsigned")


def test_simplify_comparison_greater_signed():
    """Test signed greater-than (>s), 对应汇编 jg 指令。"""
    # --- 基础用例：正数之间 ---
    # 5 >s 3 = 1
    e = ExprOp('>s', [ExprInt(5, 4), ExprInt(3, 4)], 4)
    assert simplify(e).as_int() == 1
    # 3 >s 5 = 0
    e = ExprOp('>s', [ExprInt(3, 4), ExprInt(5, 4)], 4)
    assert simplify(e).as_int() == 0

    # --- 有符号语义：负数 vs 正数 ---
    # -1 (0xFFFFFFFF) >s 1 = 0（负数不大于正数）
    e = ExprOp('>s', [ExprInt(0xFFFFFFFF, 4), ExprInt(1, 4)], 4)
    assert simplify(e).as_int() == 0
    # 1 >s -1 = 1
    e = ExprOp('>s', [ExprInt(1, 4), ExprInt(0xFFFFFFFF, 4)], 4)
    assert simplify(e).as_int() == 1

    # --- 与无符号对比：证明 >s 确实按有符号处理 ---
    # 无符号: 0xFFFFFFFF >u 1 = 1（因为无符号很大）
    e_u = ExprOp('>u', [ExprInt(0xFFFFFFFF, 4), ExprInt(1, 4)], 4)
    assert simplify(e_u).as_int() == 1
    # 有符号: 0xFFFFFFFF >s 1 = 0（因为是 -1）
    e_s = ExprOp('>s', [ExprInt(0xFFFFFFFF, 4), ExprInt(1, 4)], 4)
    assert simplify(e_s).as_int() == 0

    # --- 实际的 64 位 jg 场景 ---
    # jg x6, 0x9D60D6828D7CED1
    # x6 = 0xDBE8A93F48D4BDC7 (有符号为负), cmp 为正 → 不跳转
    x6 = ExprInt(0xDBE8A93F48D4BDC7, 8)
    cmp = ExprInt(0x9D60D6828D7CED1, 8)
    e = ExprOp('>s', [x6, cmp], 8)
    assert simplify(e).as_int() == 0  # jg 条件不满足

    # 相等时不大于: 5 >s 5 = 0
    e = ExprOp('>s', [ExprInt(5, 4), ExprInt(5, 4)], 4)
    assert simplify(e).as_int() == 0

    print("  [PASS] test_simplify_comparison_greater_signed")


def test_symbolic_propagation():
    """Test that symbolic values propagate through operations."""
    x = ExprId("eax", 4)
    five = ExprInt(5, 4)
    e = ExprOp('+', [x, five], 4)
    result = simplify(e)
    # Should remain symbolic since x is unknown
    assert not result.is_int()
    assert result.is_op()
    print("  [PASS] test_symbolic_propagation")


def test_nested_simplification():
    """Test nested constant folding: (3 + 5) * 2 = 16."""
    inner = ExprOp('+', [ExprInt(3, 4), ExprInt(5, 4)], 4)
    outer = ExprOp('*', [inner, ExprInt(2, 4)], 4)
    result = simplify(outer)
    assert result.is_int()
    assert result.as_int() == 16
    print("  [PASS] test_nested_simplification")


def test_mixed_symbolic_concrete():
    """Test mixed operations: (x + 0) ^ 0 = x."""
    x = ExprId("eax", 4)
    add_zero = ExprOp('+', [x, ExprInt(0, 4)], 4)
    xor_zero = ExprOp('^', [add_zero, ExprInt(0, 4)], 4)
    result = simplify(xor_zero)
    assert result == x
    print("  [PASS] test_mixed_symbolic_concrete")


def test_overflow_masking():
    """Test that overflow is properly masked: 0xFFFFFFFF + 1 = 0 (4 bytes)."""
    e = ExprOp('+', [ExprInt(0xFFFFFFFF, 4), ExprInt(1, 4)], 4)
    result = simplify(e)
    assert result.is_int()
    assert result.as_int() == 0
    print("  [PASS] test_overflow_masking")


def test_repr():
    """Test string representation."""
    a = ExprInt(42, 4)
    assert "42" in repr(a)

    b = ExprId("eax", 4)
    assert "eax" in repr(b)

    c = ExprOp('+', [b, a], 4)
    assert '+' in repr(c)

    d = ExprMem(b, 4)
    assert '@' in repr(d)
    print("  [PASS] test_repr")



def test_8bit():
    """测试 8 位有符号转换"""
    # 正数范围: 0 ~ 127
    assert unsigned_to_signed(0, 1) == 0
    assert unsigned_to_signed(1, 1) == 1
    assert unsigned_to_signed(127, 1) == 127

    # 负数范围: 128 ~ 255 → -128 ~ -1
    assert unsigned_to_signed(128, 1) == -128
    assert unsigned_to_signed(255, 1) == -1
    assert unsigned_to_signed(200, 1) == -56

    print("  [PASS] test_8bit")


def test_16bit():
    """测试 16 位有符号转换"""
    # 正数
    assert unsigned_to_signed(0x7FFF, 2) == 32767

    # 负数
    assert unsigned_to_signed(0x8000, 2) == -32768
    assert unsigned_to_signed(0xFFFF, 2) == -1

    print("  [PASS] test_16bit")


def test_32bit():
    """测试 32 位有符号转换"""
    # 正数
    assert unsigned_to_signed(0x7FFFFFFF, 4) == 2147483647

    # 负数
    assert unsigned_to_signed(0x80000000, 4) == -2147483648
    assert unsigned_to_signed(0xFFFFFFFF, 4) == -1

    print("  [PASS] test_32bit")


def test_64bit():
    """测试 64 位有符号转换"""
    # 正数
    assert unsigned_to_signed(0x7FFFFFFFFFFFFFFF, 8) == 9223372036854775807

    # 负数
    assert unsigned_to_signed(0x8000000000000000, 8) == -9223372036854775808
    assert unsigned_to_signed(0xFFFFFFFFFFFFFFFF, 8) == -1

    assert unsigned_to_signed(0xDBE8A93F48D4BDC7, 8)  == -2600642695536525881
    assert signed_to_unsigned(-2600642695536525881, 8) ==  0xDBE8A93F48D4BDC7

    print( hex(signed_to_unsigned(-0x241756C0B72B4239,8)))

    assert unsigned_to_signed(0x9D60D6828D7CED1, 8) == 708768732370423505

    print("  [PASS] test_64bit")


def test_jg_condition():
    """测试你的 jg 条件判断场景"""
    x6 = 0xDBE8A93F48D4BDC7
    cmp = 0x9D60D6828D7CED1

    # 0xDBE8A93F48D4BDC7
    # 0xDBE8A93F48D4BCC7
    x6_signed = unsigned_to_signed(x6, 8)
    cmp_signed = unsigned_to_signed(cmp, 8)

    # jg 是有符号 >，判断 x6 > cmp
    result = x6_signed > cmp_signed

    assert result == False

    print("  [PASS] test_jg_condition")





def run_all_tests():
    """Run all tests."""
    print("=" * 60)
    print("Running symbolic expression and simplification tests...")
    print("=" * 60)

    # Expression type tests
    print("\n--- Expression Type Tests ---")
    test_expr_int_basic()
    test_expr_int_truncation()
    test_expr_int_signed()
    test_expr_id()
    test_expr_equality()
    test_expr_hash()
    test_expr_op()
    test_expr_mem()
    test_expr_slice()
    test_expr_compose()
    test_expr_cond()

    # Simplification tests
    print("\n--- Simplification Tests ---")
    test_simplify_constant_folding_add()
    test_simplify_constant_folding_sub()
    test_simplify_constant_folding_mul()
    test_simplify_constant_folding_xor()
    test_simplify_constant_folding_shift()
    test_simplify_identity_add_zero()
    test_simplify_identity_xor_zero()
    test_simplify_identity_and_mask()
    test_simplify_identity_or_zero()
    test_simplify_identity_mul_one()
    test_simplify_annihilation_mul_zero()
    test_simplify_annihilation_and_zero()
    test_simplify_self_cancel_xor()
    test_simplify_self_cancel_sub()
    test_simplify_self_and()
    test_simplify_self_or()
    test_simplify_unary_neg_constant()
    test_simplify_unary_bnot_constant()
    test_simplify_double_neg()
    test_simplify_double_bnot()
    test_simplify_slice_of_int()
    test_simplify_slice_identity()
    test_simplify_cond_concrete_true()
    test_simplify_cond_concrete_false()
    test_simplify_cond_same_branches()
    test_simplify_compose_all_int()
    test_simplify_comparison_equal()
    test_simplify_comparison_not_equal()
    test_simplify_comparison_less_unsigned()
    test_simplify_symbolic_propagation()
    test_simplify_nested()
    test_simplify_mixed()
    test_simplify_overflow()
    test_repr()
    test_walk_traverse()

    test_replace_simple()
    test_replace_multiple()
    test_replace_nested()
    test_replace_partial()
    test_replace_subexpr()

    test_cond_jz_expr_replace()
    test_cond_jz_expr_replace2()

    test_8bit()
    test_16bit()
    test_32bit()
    test_64bit()
    test_jg_condition()

    test_simplify_comparison_greater_signed()

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED!")
    print("=" * 60)


# Aliases for the runner
test_simplify_symbolic_propagation = test_symbolic_propagation
test_simplify_nested = test_nested_simplification
test_simplify_mixed = test_mixed_symbolic_concrete
test_simplify_overflow = test_overflow_masking


if __name__ == "__main__":
    # run_all_tests()
    test_cond_jz_expr_replace()
    test_cond_jz_expr_replace2()
