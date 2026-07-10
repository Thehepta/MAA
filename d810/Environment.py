"""
Symbolic microcode execution engine for IDA.

Replaces the concrete MicroCodeInterpreter with a symbolic execution engine that
operates over IDA microcode. When variables are undefined, they become symbolic
identifiers that propagate through operations. Expressions are simplified on the fly.
"""
from __future__ import annotations
import logging
from typing import List, Optional

from d810.hexrays_helpers import equal_mops_ignore_size
from d810.utils import get_mop_name
from ida_hexrays import (
    mblock_t, mop_t,
    mop_r, mop_S, mop_v, mop_f, mop_a,
)

from d810.Expr import (
    Expr, ExprId, ExprOp, ExprCond,
)
from d810.ExprSimplifier import simplify, append_expr_if_not_in_list
from d810.hexrays_formatters import format_mop_t, mop_type_to_string
from d810.errors import UnsupportedMopException

symb_log = logging.getLogger('D810.env')


class MopExprId(Expr):
    """Symbolic identifier (register, stack variable, global variable)."""

    __slots__ = ('_name','_type','_mop')

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

    def _eq(self, other: MopExprId) -> bool:
        if not isinstance(other, MopExprId):
            return False
        return equal_mops_ignore_size(self._mop, other._mop)

    def __hash__(self):
        return hash(('MopExprId', self._name,self._type, self._size))

    def __repr__(self):
        return "{}:{:d}".format(self._name, self._size)

    def copy(self) -> MopExprId:
        return MopExprId(self._mop)

    def replace(self, mapping: dict) -> Expr:
        """Replace this identifier if it's in the mapping."""
        # Check exact match first
        if self in mapping:
            return mapping[self]
        return self





class SymbolicMicroCodeEnvironment:
    """
    Symbolic environment mapping microcode operands to symbolic expressions.

    Unlike MicroCodeEnvironment which maps mop_t -> int and crashes on undefined,
    this environment maps mop_t -> Expr and returns a fresh symbolic variable
    when a mop is not defined.
    """

    def __init__(self):
        self.mop_define = {}
        self.mop_undefind : List[Expr] = []
        self.mop_unsupport = {}
        # 符号化跳转目标，类似 Miasm 的 IRDst（per-block：当前块的出口）
        # 具体跳转: ExprInt(serial, 4)
        # 条件跳转: ExprCond(cond, ExprInt(target), ExprInt(fallthrough))
        self.irdst: Optional[Expr|ExprCond] = None

        # 路径约束（per-path）：执行所经过的每个条件分支的约束，按所选方向取正/取反。
        # 与 irdst 不同，它跨块累积，整条路径的可行性 = 列表中所有约束的合取(AND)。
        self.his_path_cond: List[Expr] = []

    def get_path_cond_expr(self):
        if len(self.his_path_cond) == 1:
            return self.his_path_cond[0]
        res = self.his_path_cond[0]
        for e in self.his_path_cond[1:]:
            res = ExprOp("&", [res, e], 4)
        return res

    def merge_env(self,env:SymbolicMicroCodeEnvironment):
        self.mop_define.update(env.mop_define)
        self.mop_unsupport.update(env.mop_unsupport)

        for mop_expr in env.mop_undefind:
            append_expr_if_not_in_list(mop_expr, self.mop_undefind)

        for mop_expr in env.his_path_cond:
            append_expr_if_not_in_list(mop_expr, self.his_path_cond)

        if env.irdst != None:
            self.irdst = env.irdst.copy()

    def get_copy(self) -> SymbolicMicroCodeEnvironment:
        """Create a full copy of this environment (all records are copied)."""
        new_env = SymbolicMicroCodeEnvironment()
        new_env.mop_define = self.mop_define.copy()
        new_env.mop_undefind =self.mop_undefind.copy()
        if new_env.irdst is not None:
            new_env.irdst = self.irdst.copy()
        new_env.his_path_cond = list(self.his_path_cond)
        return new_env

    def add_path_condition(self, cond: Expr, taken: bool):
        """
        累积一条路径约束。

        当驱动在一个符号条件分支处选择走某条边时调用：
          taken=True  表示选择了 taken 边（条件成立），约束为 cond
          taken=False 表示选择了 fallthrough 边（条件不成立），约束为 lnot(cond)
        整条路径的可行性等于 path_conditions 中所有约束的合取(AND)。
        具体值（cond.is_int()）不产生约束（恒真/恒假已在选边时体现），直接跳过。
        """
        if cond is None or cond.is_int():
            return
        if taken:
            self.his_path_cond.append(cond)
        else:
            self.his_path_cond.append(simplify(ExprOp('lnot', [cond], 1)))

    def defineExpr(self, mopExpr: MopExprId, value: Expr):
        self.mop_define[mopExpr] = value

    def define(self, mop: mop_t, value: Expr):
        """Define a mop's symbolic value."""
        if mop.t in (mop_r, mop_S, mop_v,mop_a):
            mop_id = MopExprId(mop)
            self.mop_define[mop_id] = value
        elif mop.t == mop_f:
            mop_id = ExprId(mop.dstr(),mop.size)
            self.mop_unsupport[mop_id] = value
        else:
            raise UnsupportedMopException("Defining unsupported mop type '{0}': '{1}'".format(
                mop_type_to_string(mop.t), format_mop_t(mop)))

    def lookup(self, mop: mop_t, create_undefind_symbol: bool = True) -> Expr:
        """
        Look up a mop's symbolic value.
        If not found and create_symbol is True, returns a fresh symbolic variable.
        """
        result = None
        if mop.t in (mop_r, mop_S, mop_v, mop_a):
            mop_id = MopExprId(mop)
            result = self.mop_define.get(mop_id)
        else:
            raise UnsupportedMopException("lookup unsupported mop type '{0}': '{1}'".format(
                mop_type_to_string(mop.t), format_mop_t(mop)))

        if result is not None:
            return result

        # Not found: create a fresh symbolic variable
        if create_undefind_symbol:
            mop_id = MopExprId(mop)
            self.mop_undefind.append(mop_id)
            symb_log.debug("Created symbolic variable for undefined mop: {0}".format(mop_id.name))
            return mop_id

        return None

    def dump(self,logger=None):
        """
        将环境中所有已定义的符号值输出到 IDA 控制台。
        格式: mop_name = expr_value
        """
        log = logger if logger is not None else symb_log

        log.debug("=" * 60)
        log.debug("SymbolicMicroCodeEnvironment dump")
        log.debug("=" * 60)

        if self.irdst is not None:
            log.debug("IRDst: {0}".format(self.irdst))
        if len(self.his_path_cond) > 0:
            log.debug("Path conditions (all must hold):")
            for i, cond in enumerate(self.his_path_cond):
                log.debug("  [{0}] {1}".format(i, cond))

        if len(self.mop_define) > 0:
            log.debug("[Registers]")
            for mopExpr, value in self.mop_define.items():
                log.debug("  {0} = {1}".format(mopExpr.name, value))
        if len(self.mop_undefind) > 0:
            log.debug("[Undefine]")
            for mopExpr in self.mop_undefind:
                log.debug("  mop : {0}".format(mopExpr.name))

        total = len(self.mop_define)
        log.debug("-" * 60)
        log.debug("Total: {0} entries".format(total))
        log.debug("=" * 60)

