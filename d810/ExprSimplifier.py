"""
Expression simplifier for IDA microcode symbolic expressions.

Performs constant folding and basic algebraic simplifications on Expr trees.
Simplification is applied bottom-up: arguments are simplified before the operation.
"""
from __future__ import annotations
import logging
from typing import Optional

from d810.Expr import (
    Expr, ExprInt, ExprId, ExprMem, ExprOp,
    ExprSlice, ExprCompose, ExprCond, _size_mask
)

logger = logging.getLogger('D810.symbolic_simplifier')


def get_expr_index(searched_expr: Expr, expr_list) -> int:
    for i, expr in enumerate(expr_list):
        if expr == searched_expr:
            return i
    return -1


def append_expr_if_not_in_list(expr, expr_list) -> bool:
    mop_index = get_expr_index(expr, expr_list)
    if mop_index == -1:
        expr_list.append(expr)
        return True
    return False


def get_branch_condition(expr_cond: ExprCond, target_cond) -> Optional[Expr | None]:
    cond = expr_cond.cond
    bit_one = ExprInt(1, cond.size)
    bit_zero = ExprInt(0, cond.size)
    if expr_cond.src_true == target_cond:
        return ExprOp("==", [cond, bit_one], 4)
    elif expr_cond.src_false == target_cond:
        return ExprOp("==", [cond, bit_zero], 4)
    else:
        return None


def unsigned_to_signed(value: int, size: int) -> int:
    """Convert unsigned value to signed for given byte size."""
    bits = size * 8
    if value >= (1 << (bits - 1)):
        return value - (1 << bits)
    return value


def signed_to_unsigned(value: int, size: int) -> int:
    """Convert signed value to unsigned for given byte size."""
    if value < 0:
        return value + (1 << (size * 8))
    return value


def simplify(expr: Expr) -> Expr:
    """
    Simplify a symbolic expression.
    Performs constant folding, identity elimination, and algebraic simplification.
    Returns a simplified expression (may be the same object if no simplification applies).
    """
    if expr.is_int() or expr.is_id():
        return expr

    if expr.is_op():
        return _simplify_op(expr)
    elif expr.is_slice():
        return _simplify_slice(expr)
    elif expr.is_compose():
        return _simplify_compose(expr)
    elif expr.is_cond():
        return _simplify_cond(expr)
    elif expr.is_mem():
        return _simplify_mem(expr)

    return expr


def _simplify_mem(expr: ExprMem) -> Expr:
    """Simplify memory access expression."""
    addr = simplify(expr.addr)
    if addr is expr.addr:
        return expr
    return ExprMem(addr, expr.size)


def _simplify_cond(expr: ExprCond) -> Expr:
    """Simplify conditional expression."""
    cond = simplify(expr.cond)
    src_true = simplify(expr.src_true)
    src_false = simplify(expr.src_false)

    # If condition is concrete, select branch
    if cond.is_int():
        return src_true if cond.as_int() != 0 else src_false

    # If both branches are the same, condition doesn't matter
    if src_true == src_false:
        return src_true

    if cond is expr.cond and src_true is expr.src_true and src_false is expr.src_false:
        return expr
    return ExprCond(cond, src_true, src_false)


def _simplify_slice(expr: ExprSlice) -> Expr:
    """Simplify slice expression."""
    arg = simplify(expr.arg)

    # Slice of integer -> extract bits
    if arg.is_int():
        value = (arg.as_int() >> expr.start) & _size_mask(expr.size)
        return ExprInt(value, expr.size)

    # Slice that covers the entire expression -> identity
    if expr.start == 0 and expr.stop == arg.bit_size:
        return arg

    # Slice of a slice -> combined slice
    if arg.is_slice():
        inner = arg
        new_start = inner.start + expr.start
        new_stop = inner.start + expr.stop
        return simplify(ExprSlice(inner.arg, new_start, new_stop))

    if arg is expr.arg:
        return expr
    return ExprSlice(arg, expr.start, expr.stop)


def _simplify_compose(expr: ExprCompose) -> Expr:
    """Simplify compose expression."""
    parts = [(simplify(e), s, t) for e, s, t in expr.parts]

    # If all parts are integers, fold into single integer
    all_int = all(e.is_int() for e, _, _ in parts)
    if all_int:
        value = 0
        for e, start, stop in parts:
            value |= (e.as_int() & _size_mask((stop - start) // 8)) << start
        return ExprInt(value & expr.mask, expr.size)

    # Single part covering entire size -> just the expression
    if len(parts) == 1:
        e, s, t = parts[0]
        if s == 0 and t == expr.bit_size:
            return e

    return ExprCompose(parts)


def _simplify_op(expr: ExprOp) -> Expr:
    """Simplify operation expression."""
    # First, simplify all arguments
    args = [simplify(a) for a in expr.args]
    op = expr.op
    size = expr.size
    mask = _size_mask(size)

    # ---- Unary operations ----
    if len(args) == 1:
        return _simplify_unary(op, args[0], size, mask)

    # ---- Binary operations ----
    if len(args) == 2:
        return _simplify_binary(op, args[0], args[1], size, mask)

    # Fallback: if any arg changed, rebuild
    if any(a is not b for a, b in zip(args, expr.args)):
        return ExprOp(op, args, size)
    return expr


def _simplify_unary(op: str, arg: Expr, size: int, mask: int) -> Expr:
    """Simplify unary operation."""
    if arg.is_int():
        v = arg.as_int()
        if op == 'neg':
            return ExprInt((-v) & mask, size)
        elif op == '~':
            return ExprInt((v ^ mask) & mask, size)
        elif op == 'lnot':
            return ExprInt(1 if v == 0 else 0, size)

    # neg(neg(x)) = x
    if op == 'neg' and arg.is_op() and arg.op == 'neg':
        return arg.args[0]

    # ~(~x) = x
    if op == '~' and arg.is_op() and arg.op == '~':
        return arg.args[0]

    return ExprOp(op, [arg], size)


def _simplify_binary(op: str, left: Expr, right: Expr, size: int, mask: int) -> Expr:
    """Simplify binary operation."""

    # ---- Full constant folding ----
    if left.is_int() and right.is_int():
        result = _eval_concrete_binary(op, left.as_int(), left.size, right.as_int(), right.size, size, mask)
        if result is not None:
            return ExprInt(result, size)

    # ---- Identity and annihilation rules ----

    # Additive identity: x + 0 = x, x - 0 = x
    if op in ('+', '-') and right.is_int() and right.as_int() == 0:
        return _resize(left, size, mask)
    if op == '+' and left.is_int() and left.as_int() == 0:
        return _resize(right, size, mask)

    # Multiplicative identity: x * 1 = x
    if op == '*' and right.is_int() and right.as_int() == 1:
        return _resize(left, size, mask)
    if op == '*' and left.is_int() and left.as_int() == 1:
        return _resize(right, size, mask)

    # Multiplicative annihilation: x * 0 = 0
    if op == '*' and (left.is_int() and left.as_int() == 0):
        return ExprInt(0, size)
    if op == '*' and (right.is_int() and right.as_int() == 0):
        return ExprInt(0, size)

    # XOR identity: x ^ 0 = x
    if op == '^' and right.is_int() and right.as_int() == 0:
        return _resize(left, size, mask)
    if op == '^' and left.is_int() and left.as_int() == 0:
        return _resize(right, size, mask)

    # OR identity: x | 0 = x
    if op == '|' and right.is_int() and right.as_int() == 0:
        return _resize(left, size, mask)
    if op == '|' and left.is_int() and left.as_int() == 0:
        return _resize(right, size, mask)

    # AND identity: x & mask = x (full mask)
    if op == '&' and right.is_int() and right.as_int() == mask:
        return _resize(left, size, mask)
    if op == '&' and left.is_int() and left.as_int() == mask:
        return _resize(right, size, mask)

    # AND annihilation: x & 0 = 0
    if op == '&' and (right.is_int() and right.as_int() == 0):
        return ExprInt(0, size)
    if op == '&' and (left.is_int() and left.as_int() == 0):
        return ExprInt(0, size)

    # OR annihilation: x | mask = mask
    if op == '|' and right.is_int() and right.as_int() == mask:
        return ExprInt(mask, size)
    if op == '|' and left.is_int() and left.as_int() == mask:
        return ExprInt(mask, size)

    # Shift by 0: x << 0 = x, x >> 0 = x
    if op in ('<<', '>>', '>>a') and right.is_int() and right.as_int() == 0:
        return _resize(left, size, mask)

    # ---- Self-cancellation rules ----
    if left == right:
        # x ^ x = 0
        if op == '^':
            return ExprInt(0, size)
        # x - x = 0
        if op == '-':
            return ExprInt(0, size)
        # x & x = x
        if op == '&':
            return _resize(left, size, mask)
        # x | x = x
        if op == '|':
            return _resize(left, size, mask)
        # x == x = 1
        if op == '==':
            return ExprInt(1, size)
        # x != x = 0
        if op == '!=':
            return ExprInt(0, size)
        # x <u x = 0, x >u x = 0, x <s x = 0, x >s x = 0
        if op in ('<u', '>u', '<s', '>s'):
            return ExprInt(0, size)
        # x <=u x = 1, x >=u x = 1, x <=s x = 1, x >=s x = 1
        if op in ('<=u', '>=u', '<=s', '>=s'):
            return ExprInt(1, size)

    # No simplification applicable
    return ExprOp(op, [left, right], size)


def _resize(expr: Expr, size: int, mask: int) -> Expr:
    """Ensure expression has correct size (truncate if needed)."""
    if expr.size == size:
        return expr
    if expr.is_int():
        return ExprInt(expr.as_int() & mask, size)
    # For symbolic expressions with different sizes, use a slice
    if expr.size > size:
        return ExprSlice(expr, 0, size * 8)
    # Extend: zero-extend by composing
    return expr


def _eval_concrete_binary(op: str, left: int, left_size: int, right: int, right_size: int, size: int, mask: int) -> \
Optional[int]:
    """Evaluate a binary operation on two concrete values. Returns None if op is unsupported."""
    try:
        if op == '+':
            return (left + right) & mask
        elif op == '-':
            return (left - right) & mask
        elif op == '*':
            return (left * right) & mask
        elif op == '/':
            if right == 0:
                return None
            return (left // right) & mask
        elif op == '/s':
            if right == 0:
                return None
            left_s = unsigned_to_signed(left, left_size)
            right_s = unsigned_to_signed(right, right_size)
            result = int(left_s / right_s)  # truncate toward zero
            return signed_to_unsigned(result, size) & mask
        elif op == '%':
            if right == 0:
                return None
            return (left % right) & mask
        elif op == '%s':
            if right == 0:
                return None
            left_s = unsigned_to_signed(left, left_size)
            right_s = unsigned_to_signed(right, right_size)
            # Python's % has different sign behavior; use manual truncation
            result = left_s - int(left_s / right_s) * right_s
            return signed_to_unsigned(result, size) & mask
        elif op == '|':
            return (left | right) & mask
        elif op == '&':
            return (left & right) & mask
        elif op == '^':
            return (left ^ right) & mask
        elif op == '<<':
            return (left << right) & mask
        elif op == '>>':
            return (left >> right) & mask
        elif op == '>>a':
            # Arithmetic shift right
            left_s = unsigned_to_signed(left, left_size)
            result = left_s >> right
            return signed_to_unsigned(result, size) & mask
        elif op == '==':
            return 1 if left == right else 0
        elif op == '!=':
            return 1 if left != right else 0
        elif op == '<u':
            return 1 if left < right else 0
        elif op == '<=u':
            return 1 if left <= right else 0
        elif op == '>u':
            return 1 if left > right else 0
        elif op == '>=u':
            return 1 if left >= right else 0
        elif op == '<s':
            return 1 if unsigned_to_signed(left, left_size) < unsigned_to_signed(right, right_size) else 0
        elif op == '<=s':
            return 1 if unsigned_to_signed(left, left_size) <= unsigned_to_signed(right, right_size) else 0
        elif op == '>s':
            return 1 if unsigned_to_signed(left, left_size) > unsigned_to_signed(right, right_size) else 0
        elif op == '>=s':
            return 1 if unsigned_to_signed(left, left_size) >= unsigned_to_signed(right, right_size) else 0
        elif op == 'cfadd':
            result = left + right
            return 1 if result > mask else 0
        elif op == 'ofadd':
            bits = size * 8
            left_s = unsigned_to_signed(left, left_size)
            right_s = unsigned_to_signed(right, right_size)
            result_s = left_s + right_s
            max_val = (1 << (bits - 1)) - 1
            min_val = -(1 << (bits - 1))
            return 1 if (result_s > max_val or result_s < min_val) else 0
        elif op == 'sets':
            return 1 if unsigned_to_signed(left, left_size) < 0 else 0
        elif op == 'parity':
            # Parity of (left - right) lower byte
            diff = (left - right) & 0xFF
            return 1 if bin(diff).count('1') % 2 == 0 else 0
        elif op == 'ror':
            bits = size * 8
            right = right % bits
            return ((left >> right) | (left << (bits - right))) & mask
        elif op == 'seto':
            left_s = unsigned_to_signed(left, left_size)
            right_s = unsigned_to_signed(right, right_size)
            diff_s = left_s - right_s
            bits = size * 8
            max_val = (1 << (bits - 1)) - 1
            min_val = -(1 << (bits - 1))
            return 1 if (diff_s > max_val or diff_s < min_val) else 0
    except (OverflowError, ZeroDivisionError, ValueError):
        return None

    return None
