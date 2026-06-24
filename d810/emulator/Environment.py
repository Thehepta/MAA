"""
Symbolic microcode execution engine for IDA.

Replaces the concrete MicroCodeInterpreter with a symbolic execution engine that
operates over IDA microcode. When variables are undefined, they become symbolic
identifiers that propagate through operations. Expressions are simplified on the fly.
"""
from __future__ import annotations
import logging
from typing import List, Union, Optional, Dict

from d810.utils import get_mop_name
from ida_bytes import get_qword
from ida_hexrays import (
    minsn_t, mblock_t, mop_t,
    mop_z, mop_r, mop_n, mop_d, mop_S, mop_v, mop_a, mop_b, mop_h, mop_f,
    m_mov, m_neg, m_lnot, m_bnot, m_xds, m_xdu, m_low, m_high,
    m_add, m_sub, m_mul, m_udiv, m_sdiv, m_umod, m_smod,
    m_or, m_and, m_xor, m_shl, m_shr, m_sar,
    m_cfadd, m_ofadd, m_sets, m_seto, m_setp,
    m_setnz, m_setz, m_setae, m_setb, m_seta, m_setbe,
    m_setg, m_setge, m_setl, m_setle,
    m_jcnd, m_jnz, m_jz, m_jae, m_jb, m_ja, m_jbe,
    m_jg, m_jge, m_jl, m_jle, m_jtbl, m_ijmp, m_goto,
    m_call, m_icall, m_ldx, m_stx,get_mreg_name,
)

from d810.symbolic_expr import (
    Expr, ExprId, ExprOp,
)
from d810.symbolic_simplifier import simplify
from d810.hexrays_helpers import  get_mop_index
from d810.hexrays_formatters import format_minsn_t, format_mop_t, mop_type_to_string, opcode_to_string
from d810.errors import EmulationException, EmulationIndirectJumpException, UnsupportedMopException

symb_log = logging.getLogger('D810.emulator')


class SymbolicMopMapping:
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

    def __getitem__(self, mop: mop_t) -> Optional[Expr]:
        mop_index = get_mop_index(mop, self.mops)
        if mop_index == -1:
            return None
        return self.mop_values[mop_index]

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

    def copy(self) -> SymbolicMopMapping:
        new_mapping = SymbolicMopMapping()
        for mop, value in zip(self.mops, self.mop_values):
            new_mapping.mops.append(mop)
            new_mapping.mop_values.append(value)
        return new_mapping

    def items(self):
        return list(zip(self.mops, self.mop_values))


class SymbolicMicroCodeEnvironment:
    """
    Symbolic environment mapping microcode operands to symbolic expressions.

    Unlike MicroCodeEnvironment which maps mop_t -> int and crashes on undefined,
    this environment maps mop_t -> Expr and returns a fresh symbolic variable
    when a mop is not defined.
    """

    def __init__(self):
        self.mop_r_record = SymbolicMopMapping()
        self.mop_S_record = SymbolicMopMapping()
        self.mop_v_record = SymbolicMopMapping()

        self.cur_blk: Optional[mblock_t] = None
        self.cur_ins: Optional[minsn_t] = None
        self.next_blk: Optional[mblock_t] = None
        self.next_ins: Optional[minsn_t] = None

        # 符号化跳转目标，类似 Miasm 的 IRDst（per-block：当前块的出口）
        # 具体跳转: ExprInt(serial, 4)
        # 条件跳转: ExprCond(cond, ExprInt(target), ExprInt(fallthrough))
        self.irdst: Optional[Expr] = None

        # 路径约束（per-path）：执行所经过的每个条件分支的约束，按所选方向取正/取反。
        # 与 irdst 不同，它跨块累积，整条路径的可行性 = 列表中所有约束的合取(AND)。
        self.path_conditions: List[Expr] = []

        # Counter for generating unique symbol names
        self._symbol_counter = 0

    def _gen_symbol_name(self, prefix: str) -> str:
        """Generate a unique symbol name."""
        self._symbol_counter += 1
        return "{}_{}".format(prefix, self._symbol_counter)


    def get_copy(self) -> SymbolicMicroCodeEnvironment:
        """Create a full copy of this environment (all records are copied)."""
        new_env = SymbolicMicroCodeEnvironment()
        new_env.mop_r_record = self.mop_r_record.copy()
        new_env.mop_S_record = self.mop_S_record.copy()
        new_env.mop_v_record = self.mop_v_record.copy()
        new_env.cur_blk = self.cur_blk
        new_env.cur_ins = self.cur_ins
        new_env.next_blk = self.next_blk
        new_env.next_ins = self.next_ins
        new_env.irdst = self.irdst
        new_env.path_conditions = list(self.path_conditions)
        new_env._symbol_counter = self._symbol_counter
        return new_env

    def set_cur_flow(self, cur_blk: mblock_t, cur_ins: minsn_t):
        # irdst 只反映"最近求值的这条指令"的跳转目标。
        # 每条顶层指令求值前都会调用本方法，因此在此重置；
        # 块内非控制流指令会把它清回 None，只有控制流指令才会重新写入。
        # 这样一个块执行完毕后，irdst 恰好是该块的跳转目标（或 None）。
        self.irdst = None
        self.cur_blk = cur_blk
        self.cur_ins = cur_ins
        self.next_blk = cur_blk
        if self.cur_ins is None:
            self.next_blk = self.cur_blk.mba.get_mblock(self.cur_blk.serial + 1)
            self.next_ins = self.next_blk.head
        else:
            self.next_ins = self.cur_ins.next
            if self.next_ins is None:
                self.next_blk = self.cur_blk.mba.get_mblock(self.cur_blk.serial + 1)
                self.next_ins = self.next_blk.head
        symb_log.debug("Setting next block {0} and next ins {1}".format(
            self.next_blk.serial, format_minsn_t(self.next_ins)))

    def set_next_flow(self, next_blk: mblock_t, next_ins: minsn_t):
        self.next_blk = next_blk
        self.next_ins = next_ins

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
        if mop.t == mop_r:
            self.mop_r_record[mop] = value
        elif mop.t == mop_S:
            self.mop_S_record[mop] = value
        elif mop.t == mop_v:
            self.mop_v_record[mop] = value
        else:
            raise UnsupportedMopException("Defining unsupported mop type '{0}': '{1}'".format(
                mop_type_to_string(mop.t), format_mop_t(mop)))

    def lookup(self, mop: mop_t, create_symbol: bool = True) -> Expr:
        """
        Look up a mop's symbolic value.
        If not found and create_symbol is True, returns a fresh symbolic variable.
        """
        result = None
        if mop.t == mop_r:
            result = self.mop_r_record[mop]
        elif mop.t == mop_S:
            result = self.mop_S_record[mop]
        elif mop.t == mop_v:
            result = self.mop_v_record[mop]

        if result is not None:
            return result

        # Not found: create a fresh symbolic variable
        if create_symbol:
            size = mop.size if mop.size > 0 else 8
            name = get_mop_name(mop)
            symbol = ExprId(name, size)
            symb_log.debug("Created symbolic variable for undefined mop: {0}".format(name))
            return symbol

        return None


    def dump(self):
        """
        将环境中所有已定义的符号值输出到 IDA 控制台。
        格式: mop_name = expr_value
        """
        print("=" * 60)
        print("SymbolicMicroCodeEnvironment dump")
        print("=" * 60)
        if self.irdst is not None:
            print("IRDst: {0}".format(self.irdst))
        if len(self.path_conditions) > 0:
            print("Path conditions (all must hold):")
            for i, cond in enumerate(self.path_conditions):
                print("  [{0}] {1}".format(i, cond))

        if len(self.mop_r_record) > 0:
            print("[Registers]")
            for mop, value in self.mop_r_record.items():
                name = get_mop_name(mop)
                print("  {0} = {1}".format(name, value))
        if len(self.mop_S_record) > 0:
            print("[Stack Variables]")
            for mop, value in self.mop_S_record.items():
                name = get_mop_name(mop)
                print("  {0} = {1}".format(name, value))
        if len(self.mop_v_record) > 0:
            print("[Global Variables]")
            for mop, value in self.mop_v_record.items():
                name = get_mop_name(mop)
                print("  {0} = {1}".format(name, value))

        total = len(self.mop_r_record) + len(self.mop_S_record) + len(self.mop_v_record)
        print("-" * 60)
        print("Total: {0} entries".format(total))
        print("=" * 60)

