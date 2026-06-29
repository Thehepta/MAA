from typing import List, Optional
from d810.hexrays_helpers import get_mop_index
from d810.Expr import Expr
from ida_hexrays import mop_t



class SymMopMap:
    """Maps mop_t objects to symbolic expressions (Expr)."""

    def __init__(self):
        self.mops: List[mop_t] = []
        self.mop_values: List[Expr] = []

    def __setitem__(self, mop: mop_t, value: Expr):
        mop_index = get_mop_index(mop, self.mops)
        if mop_index != -1:
            self.mop_values[mop_index] = value
            return
        self.mops.append(mop)
        self.mop_values.append(value)

    def __getitem__(self, key : Optional[Expr|mop_t] ) -> Optional[Expr|mop_t]:

        # 分支1：key是mop，根据mop找Expr（原有逻辑）
        if not isinstance(key, Expr):
            mop_index = get_mop_index(key, self.mops)
            if mop_index != -1:
                return self.mop_values[mop_index]
            return None

        # 分支2：key是Expr，反向查找对应的mop
        expr_target = key
        for mop, expr in zip(self.mops, self.mop_values):
            if expr == expr_target:
                return mop
        return None

    def __len__(self):
        return len(self.mops)

    def __delitem__(self, mop: mop_t):
        mop_index = get_mop_index(mop, self.mops)
        if mop_index == -1:
            raise KeyError
        del self.mops[mop_index]
        del self.mop_values[mop_index]

    def __contains__(self, mop: mop_t) -> bool:
        return get_mop_index(mop, self.mops) != -1

    def clear(self):
        self.mops = []
        self.mop_values = []

    def copy(self) -> "SymMopMap":
        new_mapping = SymMopMap()
        for mop, value in zip(self.mops, self.mop_values):
            new_mapping.mops.append(mop)
            new_mapping.mop_values.append(value)
        return new_mapping

    def items(self):
        return list(zip(self.mops, self.mop_values))
