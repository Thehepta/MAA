from __future__ import annotations
from d810.Expr import Expr
from d810.hexrays_helpers import equal_mops_ignore_size
from d810.utils import get_mop_name


class ExprMopId(Expr):
    """Symbolic identifier (register, stack variable, global variable)."""

    __slots__ = ('_name', '_type', '_mop')

    def __init__(self, mop):
        super().__init__(mop.size)
        self._name = get_mop_name(mop)
        self._type = mop.t
        self._mop = mop

    @property
    def name(self) -> str:
        return self._name

    def get_mop(self):
        return self._mop

    def get_mop_t(self):
        return self._type

    def is_mopid(self) -> bool:
        return True

    def _eq(self, other: ExprMopId) -> bool:
        if not isinstance(other, ExprMopId):
            return False
        return equal_mops_ignore_size(self._mop, other._mop)

    def __hash__(self):
        return hash(('MopExprId', self._name, self._type))

    def __repr__(self):
        return "{}:{:d}".format(self._name, self._size)

    def copy(self) -> ExprMopId:
        return ExprMopId(self._mop)

    def replace(self, mapping: dict) -> Expr:
        """Replace this identifier if it's in the mapping."""
        # Check exact match first
        if self in mapping:
            return mapping[self]
        return self
