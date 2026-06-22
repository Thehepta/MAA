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
from ida_segment import getseg, SEGPERM_WRITE

from d810.symbolic_expr import (
    Expr, ExprInt, ExprId, ExprMem, ExprOp,
    ExprSlice, ExprCompose, ExprCond, _size_mask
)
from d810.symbolic_simplifier import simplify, unsigned_to_signed
from d810.hexrays_helpers import equal_mops_ignore_size, get_mop_index, AND_TABLE, CONTROL_FLOW_OPCODES, \
    CONDITIONAL_JUMP_OPCODES
from d810.hexrays_formatters import format_minsn_t, format_mop_t, mop_type_to_string, opcode_to_string
from d810.cfg_utils import get_block_serials_by_address
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

        # 符号化跳转目标，类似 Miasm 的 IRDst
        # 具体跳转: ExprInt(serial, 4)
        # 条件跳转: ExprCond(cond, ExprInt(target), ExprInt(fallthrough))
        self.irdst: Optional[Expr] = None

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
        new_env._symbol_counter = self._symbol_counter
        return new_env

    def set_cur_flow(self, cur_blk: mblock_t, cur_ins: minsn_t):
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


    def define_concrete(self, mop: mop_t, value: int):
        """Define a mop with a concrete integer value."""
        size = mop.size if mop.size > 0 else 8
        self.define(mop, ExprInt(value, size))

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

    def assign(self, mop: mop_t, value: Expr):
        """Assign a value to a mop (lookup + update or create)."""
        self.define(mop, value)


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
        next_blk = self.next_blk
        if isinstance(next_blk, mblock_t):
            print("next_blk:", next_blk.serial)
        else:
            print("next_blk is None")

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


class SymbolicMicroCodeInterpreter:
    """
    Symbolic execution engine for IDA microcode.

    Similar interface to MicroCodeInterpreter but returns Expr (symbolic expressions)
    instead of int. When variables are undefined, they become symbolic identifiers
    that propagate through operations and can potentially simplify to concrete values.
    """

    def __init__(self, global_environment: Optional[SymbolicMicroCodeEnvironment] = None):
        self.global_environment = SymbolicMicroCodeEnvironment() if global_environment is None else global_environment

    def _eval_instruction_and_update_environment(self, blk: mblock_t, ins: minsn_t,
                                                  environment: SymbolicMicroCodeEnvironment) -> Optional[Expr]:
        environment.set_cur_flow(blk, ins)
        res = self._eval_instruction(ins, environment)
        if res is not None:
            if (ins.d is not None) and ins.d.t != mop_z:
                environment.assign(ins.d, res)
        return res

    def _eval_instruction(self, ins: minsn_t, environment: SymbolicMicroCodeEnvironment) -> Optional[Expr]:
        if ins is None:
            return None

        is_flow_instruction = self._eval_control_flow_instruction(ins, environment)
        if is_flow_instruction:
            return None

        call_helper_res = self._eval_call_helper(ins, environment)
        if call_helper_res is not None:
            return call_helper_res

        if ins.opcode in (m_call, m_icall):
            return self._eval_call(ins, environment)

        res_size = ins.d.size if ins.d.size > 0 else 8

        if ins.opcode == m_ldx:
            return self._eval_load(ins, environment)
        elif ins.opcode == m_stx:
            return self._eval_store(ins, environment)

        # Unary operations
        elif ins.opcode == m_mov:
            return self._apply_size(self.eval(ins.l, environment), res_size)
        elif ins.opcode == m_neg:
            arg = self.eval(ins.l, environment)
            return simplify(ExprOp('neg', [arg], res_size))
        elif ins.opcode == m_lnot:
            arg = self.eval(ins.l, environment)
            return simplify(ExprOp('lnot', [arg], res_size))
        elif ins.opcode == m_bnot:
            arg = self.eval(ins.l, environment)
            return simplify(ExprOp('~', [arg], res_size))
        elif ins.opcode == m_xds:
            # Sign-extend
            arg = self.eval(ins.l, environment)
            if arg.is_int():
                from d810.utils import unsigned_to_signed, signed_to_unsigned
                signed_val = unsigned_to_signed(arg.as_int(), ins.l.size)
                return ExprInt(signed_to_unsigned(signed_val, res_size) & _size_mask(res_size), res_size)
            return simplify(ExprOp('xds', [arg], res_size))
        elif ins.opcode == m_xdu:
            # Zero-extend
            arg = self.eval(ins.l, environment)
            if arg.is_int():
                return ExprInt(arg.as_int() & _size_mask(res_size), res_size)
            return simplify(ExprOp('xdu', [arg], res_size))
        elif ins.opcode == m_low:
            # Truncate (low part)
            arg = self.eval(ins.l, environment)
            return self._apply_size(arg, res_size)
        elif ins.opcode == m_high:
            # High part
            arg = self.eval(ins.l, environment)
            if arg.is_int():
                shift = (ins.l.size - res_size) * 8
                return ExprInt((arg.as_int() >> shift) & _size_mask(res_size), res_size)
            return simplify(ExprSlice(arg, (ins.l.size - res_size) * 8, ins.l.size * 8))

        # Binary arithmetic/logic operations
        elif ins.opcode == m_add:
            return self._eval_binop('+', ins, environment, res_size)
        elif ins.opcode == m_sub:
            return self._eval_binop('-', ins, environment, res_size)
        elif ins.opcode == m_mul:
            return self._eval_binop('*', ins, environment, res_size)
        elif ins.opcode == m_udiv:
            return self._eval_binop('/', ins, environment, res_size)
        elif ins.opcode == m_sdiv:
            return self._eval_binop('/s', ins, environment, res_size)
        elif ins.opcode == m_umod:
            return self._eval_binop('%', ins, environment, res_size)
        elif ins.opcode == m_smod:
            return self._eval_binop('%s', ins, environment, res_size)
        elif ins.opcode == m_or:
            return self._eval_binop('|', ins, environment, res_size)
        elif ins.opcode == m_and:
            return self._eval_binop('&', ins, environment, res_size)
        elif ins.opcode == m_xor:
            return self._eval_binop('^', ins, environment, res_size)
        elif ins.opcode == m_shl:
            return self._eval_binop('<<', ins, environment, res_size)
        elif ins.opcode == m_shr:
            return self._eval_binop('>>', ins, environment, res_size)
        elif ins.opcode == m_sar:
            return self._eval_binop('>>a', ins, environment, res_size)

        # Flag/comparison operations
        elif ins.opcode == m_cfadd:
            return self._eval_binop('cfadd', ins, environment, res_size)
        elif ins.opcode == m_ofadd:
            return self._eval_binop('ofadd', ins, environment, res_size)
        elif ins.opcode == m_sets:
            left = self.eval(ins.l, environment)
            # sets only takes left operand for sign check
            return simplify(ExprOp('sets', [left, ExprInt(0, ins.l.size)], res_size))
        elif ins.opcode == m_seto:
            return self._eval_binop('seto', ins, environment, res_size)
        elif ins.opcode == m_setp:
            return self._eval_binop('parity', ins, environment, res_size)
        elif ins.opcode == m_setnz:
            return self._eval_binop('!=', ins, environment, res_size)
        elif ins.opcode == m_setz:
            return self._eval_binop('==', ins, environment, res_size)
        elif ins.opcode == m_setae:
            return self._eval_binop('>=u', ins, environment, res_size)
        elif ins.opcode == m_setb:
            return self._eval_binop('<u', ins, environment, res_size)
        elif ins.opcode == m_seta:
            return self._eval_binop('>u', ins, environment, res_size)
        elif ins.opcode == m_setbe:
            return self._eval_binop('<=u', ins, environment, res_size)
        elif ins.opcode == m_setg:
            return self._eval_binop('>s', ins, environment, res_size)
        elif ins.opcode == m_setge:
            return self._eval_binop('>=s', ins, environment, res_size)
        elif ins.opcode == m_setl:
            return self._eval_binop('<s', ins, environment, res_size)
        elif ins.opcode == m_setle:
            return self._eval_binop('<=s', ins, environment, res_size)

        raise EmulationException("Unsupported instruction opcode '{0}': '{1}'"
                                 .format(opcode_to_string(ins.opcode), format_minsn_t(ins)))

    def _eval_binop(self, op: str, ins: minsn_t, environment: SymbolicMicroCodeEnvironment, res_size: int) -> Expr:
        """Evaluate a binary operation symbolically."""
        left = self.eval(ins.l, environment)
        right = self.eval(ins.r, environment)
        return simplify(ExprOp(op, [left, right], res_size))

    def _apply_size(self, expr: Expr, size: int) -> Expr:
        """Apply size constraint (truncation or zero-extension)."""
        if expr.size == size:
            return expr
        if expr.is_int():
            return ExprInt(expr.as_int() & _size_mask(size), size)
        if expr.size > size:
            # Truncate via slice
            return simplify(ExprSlice(expr, 0, size * 8))
        # Zero extend - keep as-is for symbolic (size info is in the expr)
        return simplify(ExprOp('xdu', [expr], size))

    @staticmethod
    def _get_blk_serial(mop: mop_t) -> int:
        if mop.t == mop_b:
            return mop.b
        raise EmulationException("Get block serial with unsupported mop type '{0}': '{1}'"
                                 .format(mop_type_to_string(mop.t), format_mop_t(mop)))

    def _eval_conditional_jump_cond(self, ins: minsn_t, environment: SymbolicMicroCodeEnvironment) -> Optional[Expr]:
        """
        Evaluate conditional jump condition symbolically.
        Returns an Expr representing the condition (non-zero = jump taken).
        Returns None if not a conditional jump.
        """
        if ins.opcode not in CONDITIONAL_JUMP_OPCODES:
            return None
        if ins.opcode == m_jtbl:
            return None

        if ins.opcode == m_jcnd:
            return self.eval(ins.l, environment)

        left = self.eval(ins.l, environment)
        right = self.eval(ins.r, environment)

        if ins.opcode == m_jnz:
            return simplify(ExprOp('!=', [left, right], 1))
        elif ins.opcode == m_jz:
            return simplify(ExprOp('==', [left, right], 1))
        elif ins.opcode == m_jae:
            return simplify(ExprOp('>=u', [left, right], 1))
        elif ins.opcode == m_jb:
            return simplify(ExprOp('<u', [left, right], 1))
        elif ins.opcode == m_ja:
            return simplify(ExprOp('>u', [left, right], 1))
        elif ins.opcode == m_jbe:
            return simplify(ExprOp('<=u', [left, right], 1))
        elif ins.opcode == m_jg:
            return simplify(ExprOp('>s', [left, right], 1))
        elif ins.opcode == m_jge:
            return simplify(ExprOp('>=s', [left, right], 1))
        elif ins.opcode == m_jl:
            return simplify(ExprOp('<s', [left, right], 1))
        elif ins.opcode == m_jle:
            return simplify(ExprOp('<=s', [left, right], 1))
        else:
            raise EmulationException("Unhandled conditional jump:  '{0}'".format(format_minsn_t(ins)))

    def _eval_control_flow_instruction(self, ins: minsn_t, environment: SymbolicMicroCodeEnvironment) -> bool:
        if ins.opcode not in CONTROL_FLOW_OPCODES:
            return False
        cur_blk = environment.cur_blk
        if cur_blk is None:
            raise EmulationException("Can't evaluate control flow instruction with null block: '{0}'"
                                     .format(format_minsn_t(ins)))

        cond = self._eval_conditional_jump_cond(ins, environment)
        if cond is not None:
            target_serial = self._get_blk_serial(ins.d)
            fallthrough_serial = cur_blk.serial + 1

            if cond.is_int():
                # 条件是具体值：选择对应路径
                if cond.as_int() != 0:
                    next_blk_serial = target_serial
                else:
                    next_blk_serial = fallthrough_serial
                next_blk = cur_blk.mba.get_mblock(next_blk_serial)
                next_ins = next_blk.head
                environment.set_next_flow(next_blk, next_ins)
                environment.irdst = ExprInt(next_blk_serial, 4)
            else:
                # 条件是符号的：构建 ExprCond 跳转目标
                environment.irdst = ExprCond(
                    cond,
                    ExprInt(target_serial, 4),
                    ExprInt(fallthrough_serial, 4)
                )
            return True

        if ins.opcode == m_goto:
            next_blk_serial = self._get_blk_serial(ins.l)
            next_blk = cur_blk.mba.get_mblock(next_blk_serial)
            next_ins = next_blk.head
            environment.set_next_flow(next_blk, next_ins)
            environment.irdst = ExprInt(next_blk_serial, 4)
            return True

        if ins.opcode == m_jtbl:
            left_value = self.eval(ins.l, environment)
            if not left_value.is_int():
                symb_log.debug("jtbl index is symbolic, cannot resolve")
                return False
            int_value = left_value.as_int()
            cases = ins.r.c
            next_blk_serial = [x for x in cases.targets][-1]
            for possible_values, target_block_serial in zip(cases.values, cases.targets):
                for test_value in possible_values:
                    if int_value == test_value:
                        next_blk_serial = target_block_serial
                        break
        elif ins.opcode == m_ijmp:
            dest_expr = self.eval(ins.d, environment)
            if not dest_expr.is_int():
                symb_log.debug("ijmp destination is symbolic, cannot resolve")
                return False
            ijmp_dest_ea = dest_expr.as_int()
            dest_block_serials = get_block_serials_by_address(environment.cur_blk.mba, ijmp_dest_ea)
            if len(dest_block_serials) == 0:
                raise EmulationIndirectJumpException(
                    "No blocks found at address {0:x}".format(ijmp_dest_ea),
                    ijmp_dest_ea, dest_block_serials)
            if len(dest_block_serials) > 1:
                raise EmulationIndirectJumpException(
                    "Multiple blocks at address {0:x}: {1}".format(ijmp_dest_ea, dest_block_serials),
                    ijmp_dest_ea, dest_block_serials)
            next_blk_serial = dest_block_serials[0]
        else:
            return False

        if next_blk_serial is None:
            return False
        next_blk = cur_blk.mba.get_mblock(next_blk_serial)
        next_ins = next_blk.head
        environment.set_next_flow(next_blk, next_ins)
        environment.irdst = ExprInt(next_blk_serial, 4)
        return True

    def _eval_call_helper(self, ins: minsn_t, environment: SymbolicMicroCodeEnvironment) -> Optional[Expr]:
        """Evaluate helper function calls symbolically."""
        if ins.opcode != m_call or ins.l.t != mop_h:
            return None
        res_size = ins.d.size if ins.d.size > 0 else 8
        helper_name = ins.l.helper
        args_list = ins.d

        symb_log.debug("Call helper for {0}".format(helper_name))

        if helper_name == "__ROR4__":
            data_1 = self.eval(args_list.f.args[0], environment)
            data_2 = self.eval(args_list.f.args[1], environment)
            if data_1.is_int() and data_2.is_int():
                from d810.utils import ror
                result = ror(data_1.as_int(), data_2.as_int(), 8 * args_list.f.args[0].size)
                return ExprInt(result & _size_mask(res_size), res_size)
            return simplify(ExprOp('ror', [data_1, data_2], res_size))
        elif helper_name == "__readfsqword":
            return ExprInt(0, res_size)

        # Unknown helper: return symbolic
        return ExprId("call_{}".format(helper_name), res_size)

    def _eval_load(self, ins: minsn_t, environment: SymbolicMicroCodeEnvironment) -> Optional[Expr]:
        """Evaluate memory load symbolically."""
        res_size = ins.d.size if ins.d.size > 0 else 8
        addr_expr = self.eval(ins.r, environment)

        if ins.opcode == m_ldx:
            formatted_seg_register = format_mop_t(ins.l)
            if formatted_seg_register == "ss.2":
                # Stack access - look up as stack variable
                if addr_expr.is_int():
                    stack_mop = mop_t()
                    stack_mop.erase()
                    stack_mop._make_stkvar(environment.cur_blk.mba, addr_expr.as_int())
                    result = environment.lookup(stack_mop)
                    return self._apply_size(result, res_size)
                # Symbolic stack address
                return ExprMem(addr_expr, res_size)
            else:
                # Non-stack memory access
                if addr_expr.is_int():
                    load_address = addr_expr.as_int()
                    try:
                        mem_seg = getseg(load_address)
                        if mem_seg is not None:
                            seg_perm = mem_seg.perm
                            if (seg_perm & SEGPERM_WRITE) != 0:
                                # Writable memory: return symbolic mem read
                                return ExprMem(addr_expr, res_size)
                            else:
                                # Read-only memory: can read concrete value
                                memory_value = get_qword(load_address)
                                return ExprInt(memory_value & _size_mask(res_size), res_size)
                    except Exception:
                        pass
                # Symbolic or unresolvable address
                return ExprMem(addr_expr, res_size)

        return ExprMem(addr_expr, res_size)

    def _eval_store(self, ins: minsn_t, environment: SymbolicMicroCodeEnvironment) -> Optional[Expr]:
        """Evaluate memory store symbolically (store value in environment if possible)."""
        symb_log.debug("Symbolic store: {0}".format(format_minsn_t(ins)))
        # We don't track memory writes for now; return None (no result assigned to d)
        return None

    def _eval_call(self, ins: minsn_t, environment: SymbolicMicroCodeEnvironment) -> Optional[Expr]:
        """Evaluate call instruction symbolically."""
        res_size = ins.d.size if ins.d.size > 0 else 8
        # Return a symbolic value representing the call result
        call_target = format_mop_t(ins.l)
        symb_log.debug("Symbolic call to: {0}".format(call_target))
        return ExprId("call_{}".format(call_target), res_size)

    def eval(self, mop: mop_t, environment: SymbolicMicroCodeEnvironment) -> Expr:
        """
        Evaluate a microcode operand symbolically.
        Returns a Expr (may be concrete ExprInt or symbolic).
        Never raises on undefined variables.
        """
        size = mop.size if mop.size > 0 else 8

        if mop.t == mop_n:
            return ExprInt(mop.nnn.value & _size_mask(size), size)
        elif mop.t in (mop_r, mop_S):
            result = environment.lookup(mop)
            # Handle size mismatch: equal_mops_ignore_size may return a value
            # stored at a different size (e.g., wrote eax.4, now reading rax.8)
            return self._apply_size(result, size)
        elif mop.t == mop_d:
            result = self._eval_instruction(mop.d, environment)
            if result is None:
                return ExprId("sub_insn_{}".format(format_mop_t(mop)), size)
            return result
        elif mop.t == mop_a:
            if mop.a.t == mop_v:
                return ExprInt(mop.a.g, size)
            elif mop.a.t == mop_S:
                return ExprInt(mop.a.s.off & _size_mask(size), size)
            # Unknown address type - return symbolic
            return ExprId("addr_{}".format(format_mop_t(mop)), size)
        elif mop.t == mop_v:
            # Global variable
            try:
                mem_seg = getseg(mop.g)
                if mem_seg is not None:
                    seg_perm = mem_seg.perm
                    if (seg_perm & SEGPERM_WRITE) != 0:
                        # Writable global: look up symbolically
                        result = environment.lookup(mop)
                        return self._apply_size(result, size)
                    else:
                        # Read-only global: return address as concrete value
                        return ExprInt(mop.g, size)
            except Exception:
                pass
            result = environment.lookup(mop)
            return self._apply_size(result, size)

        # Unsupported mop type - return symbolic
        symb_log.debug("Unsupported mop type '{0}': '{1}' - creating symbol".format(
            mop_type_to_string(mop.t), format_mop_t(mop)))
        return ExprId("mop_{}".format(format_mop_t(mop)), size)

    def eval_instruction(self, blk: mblock_t, ins: minsn_t,
                         environment: Optional[SymbolicMicroCodeEnvironment] = None,
                         raise_exception: bool = False) -> bool:
        """
        Evaluate a single instruction symbolically.
        Returns True on success, False on failure.
        """
        try:
            if environment is None:
                environment = self.global_environment
            symb_log.info("Evaluating symbolically: '{0}'".format(format_minsn_t(ins)))
            if ins is None:
                return False
            self._eval_instruction_and_update_environment(blk, ins, environment)
            return True
        except EmulationException as e:
            symb_log.warning("Can't evaluate instruction: '{0}': {1}".format(format_minsn_t(ins), e))
            if raise_exception:
                raise e
        except Exception as e:
            symb_log.warning("Error during evaluation of: '{0}': {1}".format(format_minsn_t(ins), e))
            if raise_exception:
                raise e
        return False

    def eval_mop(self, mop: mop_t, environment: Optional[SymbolicMicroCodeEnvironment] = None) -> Expr:
        """
        Evaluate a mop and return symbolic expression.
        Never raises (returns symbolic on failure).
        """
        if environment is None:
            environment = self.global_environment
        return self.eval(mop, environment)

    def eval_mop_concrete(self, mop: mop_t,
                          environment: Optional[SymbolicMicroCodeEnvironment] = None) -> Optional[int]:
        """
        Evaluate a mop and return concrete value if available, None if symbolic.
        Backward compatible with MicroCodeInterpreter.eval_mop.
        """
        result = self.eval_mop(mop, environment)
        return result.as_int()
