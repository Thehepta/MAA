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

from d810.symbolic_expr import (
    Expr, ExprInt, ExprId, ExprMem, ExprOp,
    ExprSlice, ExprCompose, ExprCond, _size_mask,
    expr_int, expr_id, expr_op, expr_mem
)
from d810.symbolic_simplifier import simplify


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

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED!")
    print("=" * 60)


# Aliases for the runner
test_simplify_symbolic_propagation = test_symbolic_propagation
test_simplify_nested = test_nested_simplification
test_simplify_mixed = test_mixed_symbolic_concrete
test_simplify_overflow = test_overflow_masking


if __name__ == "__main__":
    run_all_tests()
