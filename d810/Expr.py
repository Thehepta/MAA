"""
Symbolic expression system for IDA microcode.

Provides symbolic expression types that represent computations over IDA microcode
operands. When a variable is undefined, it becomes a symbolic identifier that
propagates through operations and can potentially be simplified later.

Inspired by miasm's expression system, adapted for IDA microcode context.
All sizes are in BYTES (matching IDA mop_t.size convention).
"""
from __future__ import annotations
from typing import Optional, Tuple, List, Union
from functools import total_ordering


def _size_mask(size: int) -> int:
    """Return bitmask for given byte size."""
    return (1 << (size * 8)) - 1


def walk_expr_iter(root):
    stack = [root]
    while stack:
        cur = stack.pop()
        yield cur

        children = []
        if cur.is_cond():
            # ExprCond
            children = [cur.cond, cur.src_true, cur.src_false]
        elif cur.is_op():
            # ExprOp
            children = cur.args
        elif cur.is_mem():
            # ExprMem 只有地址子表达式
            children = [cur.addr]
        elif cur.is_slice():
            # ExprSlice
            children = [cur.arg]
        elif cur.is_compose():
            # ExprCompose 遍历每一段表达式
            children = [part[0] for part in cur.parts]

        # 逆序压栈，保持先序遍历顺序不变
        for child in reversed(children):
            stack.append(child)


@total_ordering
class Expr:
    """Base class for all microcode symbolic expressions."""

    __slots__ = ('_size',)

    def __init__(self, size: int):
        """
        @param size: expression size in bytes
        """
        self._size = size

    @property
    def size(self) -> int:
        """Size in bytes."""
        return self._size

    @property
    def bit_size(self) -> int:
        """Size in bits."""
        return self._size * 8

    @property
    def mask(self) -> int:
        """Bitmask for this expression's size."""
        return _size_mask(self._size)

    def is_int(self) -> bool:
        """Return True if this expression is a concrete integer."""
        return False

    def is_id(self) -> bool:
        """Return True if this expression is a symbolic identifier."""
        return False

    def is_op(self) -> bool:
        """Return True if this expression is an operation."""
        return False

    def is_mopid(self) -> bool:
        """Return True if this expression is an operation."""
        return False

    def is_mem(self) -> bool:
        """Return True if this expression is a memory access."""
        return False

    def is_slice(self) -> bool:
        """Return True if this expression is a bit slice."""
        return False

    def is_compose(self) -> bool:
        """Return True if this expression is a composition."""
        return False

    def is_cond(self) -> bool:
        """Return True if this expression is a conditional."""
        return False

    def as_int(self) -> Optional[int]:
        """Try to extract concrete integer value. Returns None if symbolic."""
        return None

    def __eq__(self, other):
        if not isinstance(other, Expr):
            return NotImplemented
        return self._eq(other)

    def __ne__(self, other):
        if not isinstance(other, Expr):
            return NotImplemented
        return not self._eq(other)

    def __lt__(self, other):
        if not isinstance(other, Expr):
            return NotImplemented
        return repr(self) < repr(other)

    def __hash__(self):
        return hash(repr(self))

    def _eq(self, other: Expr) -> bool:
        """Subclass equality check."""
        return False

    def copy(self) -> Expr:
        """Return a copy of this expression."""
        raise NotImplementedError

    def replace(self, mapping: dict) -> Expr:
        """
        Replace subexpressions according to the mapping.

        @param mapping: dict mapping source expressions to replacement expressions.
                       Can map Expr objects or (for convenience) strings to Expr.
        @return: new expression with replacements applied

        Example:
            x = ExprId("x29", 8)
            e = ExprOp("+", [x, ExprInt(5, 8)], 8)
            # Replace by expression
            e2 = e.replace({x: ExprInt(10, 8)})
            # Replace by variable name (convenience)
            e3 = e.replace({"x29": ExprInt(10, 8)})
        """
        raise NotImplementedError


class ExprInt(Expr):
    """Concrete integer value."""

    __slots__ = ('_value',)

    def __init__(self, value: int, size: int):
        super().__init__(size)
        self._value = value & _size_mask(size)

    @property
    def value(self) -> int:
        return self._value

    def is_int(self) -> bool:
        return True

    def as_int(self) -> int:
        return self._value

    def signed_value(self) -> int:
        """Return signed interpretation of the value."""
        if self._value >= (1 << (self._size * 8 - 1)):
            return self._value - (1 << (self._size * 8))
        return self._value

    def _eq(self, other: Expr) -> bool:
        if not isinstance(other, ExprInt):
            return False
        return self._value == other._value and self._size == other._size

    def __hash__(self):
        return hash(('ExprInt', self._value, self._size))

    def __repr__(self):
        if self._value > 0xFFFF:
            return "0x{:X}:{:d}".format(self._value, self._size)
        return "{:d}:{:d}".format(self._value, self._size)

    def copy(self) -> ExprInt:
        return ExprInt(self._value, self._size)

    def replace(self, mapping: dict) -> Expr:
        """Replace subexpressions. Check if this exact expression is in mapping."""
        # Check exact match first
        if self in mapping:
            return mapping[self]
        # ExprInt is a leaf, no further replacement needed
        return self


class ExprId(Expr):
    """Symbolic identifier (register, stack variable, global variable)."""

    __slots__ = ('_name',)

    def __init__(self, name: str, size: int):
        super().__init__(size)
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def is_id(self) -> bool:
        return True

    def _eq(self, other: Expr) -> bool:
        if not isinstance(other, ExprId):
            return False
        return self._name == other._name and self._size == other._size

    def __hash__(self):
        return hash(('ExprId', self._name, self._size))

    def __repr__(self):
        return "{}:{:d}".format(self._name, self._size)

    def copy(self) -> ExprId:
        return ExprId(self._name, self._size)

    def replace(self, mapping: dict) -> Expr:
        """Replace this identifier if it's in the mapping."""
        # Check exact match first
        if self in mapping:
            return mapping[self]
        # For convenience, also check by name (string key)
        if self._name in mapping:
            return mapping[self._name]
        return self

class ExprMem(Expr):
    """Memory access expression: @size[addr_expr]."""

    __slots__ = ('_addr',)

    def __init__(self, addr: Expr, size: int):
        """
        @param addr: address expression
        @param size: size of memory read in bytes
        """
        super().__init__(size)
        self._addr = addr

    @property
    def addr(self) -> Expr:
        return self._addr

    def is_mem(self) -> bool:
        return True

    def _eq(self, other: Expr) -> bool:
        if not isinstance(other, ExprMem):
            return False
        return self._addr == other._addr and self._size == other._size

    def __hash__(self):
        return hash(('ExprMem', self._addr, self._size))

    def __repr__(self):
        return "@{:d}[{}]".format(self._size, self._addr)

    def copy(self) -> ExprMem:
        return ExprMem(self._addr.copy(), self._size)

    def replace(self, mapping: dict) -> Expr:
        """Replace subexpressions in memory address."""
        # Check if this entire mem expression is in mapping
        if self in mapping:
            return mapping[self]
        # Recursively replace in address
        new_addr = self._addr.replace(mapping)
        if new_addr is self._addr:
            return self
        return ExprMem(new_addr, self._size)


class ExprOp(Expr):
    """Operation expression: op(arg1, arg2, ...)."""

    __slots__ = ('_op', '_args')

    def __init__(self, op: str, args: List[Expr], size: int):
        """
        @param op: operation name ('+', '-', '*', '/', '%', '|', '&', '^',
                   '<<', '>>', '>>a', '~', 'neg', 'lnot',
                   '==', '!=', '<u', '<=u', '>u', '>=u', '<s', '<=s', '>s', '>=s',
                   'cfadd', 'ofadd', 'sets', 'seto', 'parity', 'ror')
        @param args: list of argument expressions
        @param size: result size in bytes
        """
        super().__init__(size)
        self._op = op
        self._args = list(args)

    @property
    def op(self) -> str:
        return self._op

    @property
    def args(self) -> List[Expr]:
        return self._args

    def is_op(self) -> bool:
        return True

    def _eq(self, other: Expr) -> bool:
        if not isinstance(other, ExprOp):
            return False
        if self._op != other._op or self._size != other._size:
            return False
        if len(self._args) != len(other._args):
            return False
        return all(a == b for a, b in zip(self._args, other._args))

    def __hash__(self):
        return hash(('ExprOp', self._op, tuple(self._args), self._size))

    def __repr__(self):
        if len(self._args) == 1:
            return "{}({}):{:d}".format(self._op, self._args[0], self._size)
        # 如果操作符是 call_ 开头，使用函数调用格式
        if self._op.startswith("call_"):
            args_str = ", ".join(str(a) for a in self._args)
            return "{}({}):{:d}".format(self._op, args_str, self._size)
        # 其他操作符使用中缀格式
        args_str = " {} ".format(self._op).join(str(a) for a in self._args)
        return "({}):{:d}".format(args_str, self._size)

    def copy(self) -> ExprOp:
        return ExprOp(self._op, [a.copy() for a in self._args], self._size)

    def replace(self, mapping: dict) -> Expr:
        """Replace subexpressions in operation arguments."""
        # Check if this entire operation is in mapping
        if self in mapping:
            return mapping[self]
        # Recursively replace in arguments
        new_args = [arg.replace(mapping) for arg in self._args]
        if all(new is old for new, old in zip(new_args, self._args)):
            return self
        return ExprOp(self._op, new_args, self._size)


class ExprSlice(Expr):
    """Bit slice expression: expr[start:stop] (in bits)."""

    __slots__ = ('_arg', '_start', '_stop')

    def __init__(self, arg: Expr, start: int, stop: int):
        """
        @param arg: source expression
        @param start: start bit (inclusive)
        @param stop: stop bit (exclusive)
        """
        assert (stop - start) % 8 == 0, "Slice must be byte-aligned"
        super().__init__((stop - start) // 8)
        self._arg = arg
        self._start = start
        self._stop = stop

    @property
    def arg(self) -> Expr:
        return self._arg

    @property
    def start(self) -> int:
        return self._start

    @property
    def stop(self) -> int:
        return self._stop

    def is_slice(self) -> bool:
        return True

    def _eq(self, other: Expr) -> bool:
        if not isinstance(other, ExprSlice):
            return False
        return (self._arg == other._arg and self._start == other._start
                and self._stop == other._stop)

    def __hash__(self):
        return hash(('ExprSlice', self._arg, self._start, self._stop))

    def __repr__(self):
        return "{}[{:d}:{:d}]".format(self._arg, self._start, self._stop)

    def copy(self) -> ExprSlice:
        return ExprSlice(self._arg.copy(), self._start, self._stop)

    def replace(self, mapping: dict) -> Expr:
        """Replace subexpressions in slice argument."""
        # Check if this entire slice is in mapping
        if self in mapping:
            return mapping[self]
        # Recursively replace in argument
        new_arg = self._arg.replace(mapping)
        if new_arg is self._arg:
            return self
        return ExprSlice(new_arg, self._start, self._stop)


class ExprCompose(Expr):
    """
    Compose expression: concatenation of sub-expressions.
    Each element is (expr, start_bit, stop_bit).
    """

    __slots__ = ('_parts',)

    def __init__(self, parts: List[Tuple[Expr, int, int]]):
        """
        @param parts: list of (expr, start_bit, stop_bit)
        """
        if not parts:
            raise ValueError("ExprCompose requires at least one part")
        max_bit = max(stop for _, _, stop in parts)
        assert max_bit % 8 == 0, "Compose total size must be byte-aligned"
        super().__init__(max_bit // 8)
        self._parts = parts

    @property
    def parts(self) -> List[Tuple[Expr, int, int]]:
        return self._parts

    def is_compose(self) -> bool:
        return True

    def _eq(self, other: Expr) -> bool:
        if not isinstance(other, ExprCompose):
            return False
        if len(self._parts) != len(other._parts):
            return False
        for (e1, s1, t1), (e2, s2, t2) in zip(self._parts, other._parts):
            if s1 != s2 or t1 != t2 or e1 != e2:
                return False
        return True

    def __hash__(self):
        return hash(('ExprCompose', tuple((hash(e), s, t) for e, s, t in self._parts)))

    def __repr__(self):
        parts_str = ", ".join("{}[{:d}:{:d}]".format(e, s, t) for e, s, t in self._parts)
        return "{{{}}}.{:d}".format(parts_str, self._size)

    def copy(self) -> ExprCompose:
        return ExprCompose([(e.copy(), s, t) for e, s, t in self._parts])

    def replace(self, mapping: dict) -> Expr:
        """Replace subexpressions in compose parts."""
        # Check if this entire compose is in mapping
        if self in mapping:
            return mapping[self]
        # Recursively replace in each part
        new_parts = [(e.replace(mapping), s, t) for e, s, t in self._parts]
        if all(new is old for (new, _, _), (old, _, _) in zip(new_parts, self._parts)):
            return self
        return ExprCompose(new_parts)


class ExprCond(Expr):
    """Conditional expression: cond ? src_true : src_false."""

    __slots__ = ('_cond', '_src_true', '_src_false')

    def __init__(self, cond: Expr, src_true: Expr, src_false: Expr):
        """
        @param cond: condition expression
        @param src_true: value when condition is true (non-zero)
        @param src_false: value when condition is false (zero)
        """
        assert src_true.size == src_false.size, "Cond branches must have same size"
        super().__init__(src_true.size)
        self._cond = cond
        self._src_true = src_true
        self._src_false = src_false

    @property
    def cond(self) -> Expr:
        return self._cond

    @property
    def src_true(self) -> Expr:
        return self._src_true

    @property
    def src_false(self) -> Expr:
        return self._src_false

    def is_cond(self) -> bool:
        return True

    def _eq(self, other: Expr) -> bool:
        if not isinstance(other, ExprCond):
            return False
        return (self._cond == other._cond and self._src_true == other._src_true
                and self._src_false == other._src_false)

    def __hash__(self):
        return hash(('ExprCond', self._cond, self._src_true, self._src_false))

    def __repr__(self):
        return "({} ? {} : {}):{:d}".format(self._cond, self._src_true, self._src_false, self._size)

    def copy(self) -> ExprCond:
        return ExprCond(self._cond.copy(), self._src_true.copy(), self._src_false.copy())

    def replace(self, mapping: dict) -> Expr:
        """Replace subexpressions in condition and branches."""
        # Check if this entire cond is in mapping
        if self in mapping:
            return mapping[self]
        # Recursively replace in condition and branches
        new_cond = self._cond.replace(mapping)
        new_true = self._src_true.replace(mapping)
        new_false = self._src_false.replace(mapping)
        if new_cond is self._cond and new_true is self._src_true and new_false is self._src_false:
            return self
        return ExprCond(new_cond, new_true, new_false)