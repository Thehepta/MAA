"""
Symbolic microcode execution engine for IDA.

Replaces the concrete MicroCodeInterpreter with a symbolic execution engine that
operates over IDA microcode. When variables are undefined, they become symbolic
identifiers that propagate through operations. Expressions are simplified on the fly.
"""
from __future__ import annotations
import logging
from typing import List, Optional

from d810.SymMopMap import SymMopMap
from d810.utils import get_mop_name
from ida_hexrays import (
    mblock_t, mop_t,
    mop_r, mop_S, mop_v, mop_f,
)

from d810.Expr import (
    Expr, ExprId, ExprOp,
)
from d810.ExprSimplifier import simplify
from d810.hexrays_formatters import format_mop_t, mop_type_to_string
from d810.errors import UnsupportedMopException

symb_log = logging.getLogger('D810.env')




class SymbolicMicroCodeEnvironment:
    """
    Symbolic environment mapping microcode operands to symbolic expressions.

    Unlike MicroCodeEnvironment which maps mop_t -> int and crashes on undefined,
    this environment maps mop_t -> Expr and returns a fresh symbolic variable
    when a mop is not defined.
    """

    def __init__(self):
        self.mop_define = SymMopMap()
        self.mop_undefind = SymMopMap()

        # 符号化跳转目标，类似 Miasm 的 IRDst（per-block：当前块的出口）
        # 具体跳转: ExprInt(serial, 4)
        # 条件跳转: ExprCond(cond, ExprInt(target), ExprInt(fallthrough))
        self.irdst: Optional[Expr] = None

        # 路径约束（per-path）：执行所经过的每个条件分支的约束，按所选方向取正/取反。
        # 与 irdst 不同，它跨块累积，整条路径的可行性 = 列表中所有约束的合取(AND)。
        self.path_conditions: List[Expr] = []



    def get_copy(self) -> SymbolicMicroCodeEnvironment:
        """Create a full copy of this environment (all records are copied)."""
        new_env = SymbolicMicroCodeEnvironment()
        new_env.mop_define = self.mop_define.copy()
        new_env.irdst = self.irdst
        new_env.path_conditions = list(self.path_conditions)
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
            self.path_conditions.append(cond)
        else:
            self.path_conditions.append(simplify(ExprOp('lnot', [cond], 1)))

    def define(self, mop: mop_t, value: Expr):
        """Define a mop's symbolic value."""
        if mop.t in (mop_r, mop_S, mop_v,mop_f):
            self.mop_define[mop] = value
        else:
            raise UnsupportedMopException("Defining unsupported mop type '{0}': '{1}'".format(
                mop_type_to_string(mop.t), format_mop_t(mop)))

    def lookup(self, mop: mop_t, create_symbol: bool = True) -> Expr:
        """
        Look up a mop's symbolic value.
        If not found and create_symbol is True, returns a fresh symbolic variable.
        """
        result = None
        if mop.t in (mop_r, mop_S, mop_v, mop_f):
            result = self.mop_define[mop]
        else:
            raise UnsupportedMopException("lookup unsupported mop type '{0}': '{1}'".format(
                mop_type_to_string(mop.t), format_mop_t(mop)))

        if result is not None:
            return result

        # Not found: create a fresh symbolic variable
        if create_symbol:
            size = mop.size if mop.size > 0 else 8
            name = get_mop_name(mop)
            symbol = ExprId(name, size)
            self.mop_undefind[mop] = symbol
            symb_log.debug("Created symbolic variable for undefined mop: {0}".format(name))
            return symbol

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
        if len(self.path_conditions) > 0:
            log.debug("Path conditions (all must hold):")
            for i, cond in enumerate(self.path_conditions):
                log.debug("  [{0}] {1}".format(i, cond))

        if len(self.mop_define) > 0:
            log.debug("[Registers]")
            for mop, value in self.mop_define.items():
                name = get_mop_name(mop)
                log.debug("  {0} = {1}".format(name, value))
        if len(self.mop_undefind) > 0:
            log.debug("[Undefine]")
            for mop, value in self.mop_undefind.items():
                name = get_mop_name(mop)
                log.debug("  mop : {0} -> ExprId : {1}".format(name, value))

        total = len(self.mop_define)
        log.debug("-" * 60)
        log.debug("Total: {0} entries".format(total))
        log.debug("=" * 60)

