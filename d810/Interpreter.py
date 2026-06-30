"""
Symbolic microcode execution engine for IDA.

Replaces the concrete MicroCodeInterpreter with a symbolic execution engine that
operates over IDA microcode. When variables are undefined, they become symbolic
identifiers that propagate through operations. Expressions are simplified on the fly.
"""
from __future__ import annotations
import logging
from typing import  Optional
from d810.utils import unsigned_to_signed, signed_to_unsigned,ror

from d810.Environment import SymbolicMicroCodeEnvironment
from ida_bytes import get_qword
from ida_hexrays import (
    minsn_t, mblock_t, mop_t,
    mop_z, mop_r, mop_n, mop_d, mop_S, mop_v, mop_a, mop_h, m_mov, m_neg, m_lnot, m_bnot, m_xds, m_xdu, m_low, m_high,
    m_add, m_sub, m_mul, m_udiv, m_sdiv, m_umod, m_smod,
    m_or, m_and, m_xor, m_shl, m_shr, m_sar,
    m_cfadd, m_ofadd, m_sets, m_seto, m_setp,
    m_setnz, m_setz, m_setae, m_setb, m_seta, m_setbe,
    m_setg, m_setge, m_setl, m_setle,
    m_jcnd, m_jnz, m_jz, m_jae, m_jb, m_ja, m_jbe,
    m_jg, m_jge, m_jl, m_jle, m_jtbl, m_ijmp, m_goto,
    m_call, m_icall, m_ldx, m_stx, )
from ida_segment import getseg, SEGPERM_WRITE

from d810.Expr import (
    Expr, ExprInt, ExprId, ExprMem, ExprOp,
    ExprSlice, ExprCond, _size_mask
)
from d810.ExprSimplifier import simplify, unsigned_to_signed
from d810.hexrays_helpers import CONTROL_FLOW_OPCODES,  CONDITIONAL_JUMP_OPCODES
from d810.hexrays_formatters import format_minsn_t, format_mop_t, mop_type_to_string, opcode_to_string
from d810.cfg_utils import get_block_serials_by_address
from d810.errors import EmulationException, EmulationIndirectJumpException

interpreter = logging.getLogger('D810.interpreter')


class SymbolicMicroCodeInterpreter:
    """
    Symbolic execution engine for IDA microcode.

    Similar interface to MicroCodeInterpreter but returns Expr (symbolic expressions)
    instead of int. When variables are undefined, they become symbolic identifiers
    that propagate through operations and can potentially simplify to concrete values.
    """

    def __init__(self, global_environment: Optional[SymbolicMicroCodeEnvironment] = None):
        self.global_environment = SymbolicMicroCodeEnvironment() if global_environment is None else global_environment

    def _eval_instruction_and_update_environment(self, blk: Optional[mblock_t],ins: Optional[minsn_t],
                                                  environment: SymbolicMicroCodeEnvironment) -> Optional[Expr]:
        res = self._eval_instruction(blk,ins, environment)
        if res is not None:
            if (ins.d is not None) and ins.d.t != mop_z:
                environment.define(ins.d, res)
        return res

    def _eval_instruction(self,blk: Optional[mblock_t], ins: Optional[minsn_t], environment: SymbolicMicroCodeEnvironment ) -> Optional[Expr]:
        if ins is None:
            return None

        is_flow_instruction = self._eval_control_flow_instruction(blk,ins, environment)
        if is_flow_instruction:
            return None

        call_helper_res = self._eval_call_helper(blk,ins, environment)
        if call_helper_res is not None:
            return call_helper_res

        if ins.opcode in (m_call, m_icall):
            return self._eval_call(ins, environment)

        res_size = ins.d.size if ins.d.size > 0 else 8

        if ins.opcode == m_ldx:
            return self._eval_load(ins, environment, blk)
        elif ins.opcode == m_stx:
            return self._eval_store(ins, environment)

        # Unary operations
        elif ins.opcode == m_mov:
            return self._apply_size(self.eval(ins.l, environment,blk), res_size)
        elif ins.opcode == m_neg:
            arg = self.eval(ins.l, environment,blk)
            return simplify(ExprOp('neg', [arg], res_size))
        elif ins.opcode == m_lnot:
            arg = self.eval(ins.l, environment,blk)
            return simplify(ExprOp('lnot', [arg], res_size))
        elif ins.opcode == m_bnot:
            arg = self.eval(ins.l, environment,blk)
            return simplify(ExprOp('~', [arg], res_size))
        elif ins.opcode == m_xds:
            # Sign-extend
            arg = self.eval(ins.l, environment,blk)
            if arg.is_int():
                signed_val = unsigned_to_signed(arg.as_int(), ins.l.size)
                return ExprInt(signed_to_unsigned(signed_val, res_size) & _size_mask(res_size), res_size)
            return simplify(ExprOp('xds', [arg], res_size))
        elif ins.opcode == m_xdu:
            # Zero-extend
            arg = self.eval(ins.l, environment,blk)
            if arg.is_int():
                return ExprInt(arg.as_int() & _size_mask(res_size), res_size)
            return simplify(ExprOp('xdu', [arg], res_size))
        elif ins.opcode == m_low:
            # Truncate (low part)
            arg = self.eval(ins.l, environment,blk)
            return self._apply_size(arg, res_size)
        elif ins.opcode == m_high:
            # High part
            arg = self.eval(ins.l, environment,blk)
            if arg.is_int():
                shift = (ins.l.size - res_size) * 8
                return ExprInt((arg.as_int() >> shift) & _size_mask(res_size), res_size)
            return simplify(ExprSlice(arg, (ins.l.size - res_size) * 8, ins.l.size * 8))

        # Binary arithmetic/logic operations
        elif ins.opcode == m_add:
            return self._eval_binop(blk,'+', ins, environment, res_size)
        elif ins.opcode == m_sub:
            return self._eval_binop(blk,'-', ins, environment, res_size)
        elif ins.opcode == m_mul:
            return self._eval_binop(blk,'*', ins, environment, res_size)
        elif ins.opcode == m_udiv:
            return self._eval_binop(blk,'/', ins, environment, res_size)
        elif ins.opcode == m_sdiv:
            return self._eval_binop(blk,'/s', ins, environment, res_size)
        elif ins.opcode == m_umod:
            return self._eval_binop(blk,'%', ins, environment, res_size)
        elif ins.opcode == m_smod:
            return self._eval_binop(blk,'%s', ins, environment, res_size)
        elif ins.opcode == m_or:
            return self._eval_binop(blk,'|', ins, environment, res_size)
        elif ins.opcode == m_and:
            return self._eval_binop(blk,'&', ins, environment, res_size)
        elif ins.opcode == m_xor:
            return self._eval_binop(blk,'^', ins, environment, res_size)
        elif ins.opcode == m_shl:
            return self._eval_binop(blk,'<<', ins, environment, res_size)
        elif ins.opcode == m_shr:
            return self._eval_binop(blk,'>>', ins, environment, res_size)
        elif ins.opcode == m_sar:
            return self._eval_binop(blk,'>>a', ins, environment, res_size)

        # Flag/comparison operations
        elif ins.opcode == m_cfadd:
            return self._eval_binop(blk,'cfadd', ins, environment, res_size)
        elif ins.opcode == m_ofadd:
            return self._eval_binop(blk,'ofadd', ins, environment, res_size)
        elif ins.opcode == m_sets:
            left = self.eval(ins.l, environment,blk)
            # sets only takes left operand for sign check
            return simplify(ExprOp('sets', [left, ExprInt(0, ins.l.size)], res_size))
        elif ins.opcode == m_seto:
            return self._eval_binop(blk,'seto', ins, environment, res_size)
        elif ins.opcode == m_setp:
            return self._eval_binop(blk,'parity', ins, environment, res_size)
        elif ins.opcode == m_setnz:
            return self._eval_binop(blk,'!=', ins, environment, res_size)
        elif ins.opcode == m_setz:
            return self._eval_binop(blk,'==', ins, environment, res_size)
        elif ins.opcode == m_setae:
            return self._eval_binop(blk,'>=u', ins, environment, res_size)
        elif ins.opcode == m_setb:
            return self._eval_binop(blk,'<u', ins, environment, res_size)
        elif ins.opcode == m_seta:
            return self._eval_binop(blk,'>u', ins, environment, res_size)
        elif ins.opcode == m_setbe:
            return self._eval_binop(blk,'<=u', ins, environment, res_size)
        elif ins.opcode == m_setg:
            return self._eval_binop(blk,'>s', ins, environment, res_size)
        elif ins.opcode == m_setge:
            return self._eval_binop(blk,'>=s', ins, environment, res_size)
        elif ins.opcode == m_setl:
            return self._eval_binop(blk,'<s', ins, environment, res_size)
        elif ins.opcode == m_setle:
            return self._eval_binop(blk,'<=s', ins, environment, res_size)

        raise EmulationException("Unsupported instruction opcode '{0}': '{1}'"
                                 .format(opcode_to_string(ins.opcode), format_minsn_t(ins)))

    def _eval_binop(self, blk: Optional[mblock_t],op: str, ins: minsn_t, environment: SymbolicMicroCodeEnvironment, res_size: int) -> Expr:
        """Evaluate a binary operation symbolically."""
        left = self.eval(ins.l, environment,blk)
        right = self.eval(ins.r, environment,blk)
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


    def _eval_conditional_jump_cond(self, blk: mblock_t ,ins: minsn_t, environment: SymbolicMicroCodeEnvironment) -> Optional[Expr]:
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
            return self.eval(ins.l, environment,blk)

        left = self.eval(ins.l, environment,blk)
        right = self.eval(ins.r, environment,blk)

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

    def _eval_control_flow_instruction(self,cur_blk: mblock_t, ins: minsn_t, environment: SymbolicMicroCodeEnvironment) -> bool:
        if ins.opcode not in CONTROL_FLOW_OPCODES:
            return False
        if cur_blk is None:
            raise EmulationException("Can't evaluate control flow instruction with null block: '{0}'"
                                     .format(format_minsn_t(ins)))

        cond = self._eval_conditional_jump_cond(cur_blk,ins, environment)
        if cond is not None:
            target_serial = ins.d.b
            fallthrough_serial = cur_blk.serial + 1

            if cond.is_int():
                # 条件是具体值：选择对应路径
                if cond.as_int() != 0:
                    next_blk_serial = target_serial
                else:
                    next_blk_serial = fallthrough_serial
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
            next_blk_serial = ins.l.b
            environment.irdst = ExprInt(next_blk_serial, 4)
            return True

        if ins.opcode == m_jtbl:
            left_value = self.eval(ins.l, environment,cur_blk)
            if not left_value.is_int():
                interpreter.debug("jtbl index is symbolic, cannot resolve")
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
            dest_expr = self.eval(ins.d, environment,cur_blk)
            if not dest_expr.is_int():
                interpreter.debug("ijmp destination is symbolic, cannot resolve")
                return False
            ijmp_dest_ea = dest_expr.as_int()
            dest_block_serials = get_block_serials_by_address(cur_blk.mba, ijmp_dest_ea)
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
        environment.irdst = ExprInt(next_blk_serial, 4)
        return True

    def _eval_call_helper(self , blk: mblock_t, ins: minsn_t, environment: SymbolicMicroCodeEnvironment) -> Optional[Expr]:
        """Evaluate helper function calls symbolically."""
        if ins.opcode != m_call or ins.l.t != mop_h:
            return None
        res_size = ins.d.size if ins.d.size > 0 else 8
        helper_name = ins.l.helper
        args_list = ins.d

        interpreter.debug("Call helper for {0}".format(helper_name))
        # if helper_name == "__ROR4__":
        #     data_1 = self.eval(args_list.f.args[0], environment,blk)
        #     data_2 = self.eval(args_list.f.args[1], environment,blk)
        #     if data_1.is_int() and data_2.is_int():
        #         result = ror(data_1.as_int(), data_2.as_int(), 8 * args_list.f.args[0].size)
        #         return ExprInt(result & _size_mask(res_size), res_size)
        #     return simplify(ExprOp('ror', [data_1, data_2], res_size))
        # elif helper_name == "__readfsqword":
        #     return ExprInt(0, res_size)

        # Unknown helper: return symbolic
        return ExprId("call_{}".format(helper_name), res_size)

    def _eval_load(self,ins: minsn_t, environment: SymbolicMicroCodeEnvironment,cur_blk:mblock_t) -> Optional[Expr]:
        """Evaluate memory load symbolically."""
        res_size = ins.d.size if ins.d.size > 0 else 8
        addr_expr = self.eval(ins.r, environment,cur_blk)

        if ins.opcode == m_ldx:
            formatted_seg_register = format_mop_t(ins.l)
            if formatted_seg_register == "ss.2":
                # Stack access - look up as stack variable
                if addr_expr.is_int():
                    stack_mop = mop_t()
                    stack_mop.erase()
                    stack_mop._make_stkvar(cur_blk.mba, addr_expr.as_int())
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
        interpreter.debug("Symbolic store: {0}".format(format_minsn_t(ins)))
        # We don't track memory writes for now; return None (no result assigned to d)
        return None

    def _eval_call(self, ins: minsn_t, environment: SymbolicMicroCodeEnvironment) -> Optional[Expr]:
        """Evaluate call instruction symbolically."""
        res_size = ins.d.size if ins.d.size > 0 else 8
        # Return a symbolic value representing the call result
        call_target = format_mop_t(ins.l)
        interpreter.debug("Symbolic call to: {0}".format(call_target))
        return ExprId("call_{}".format(call_target), res_size)

    def eval(self,mop: mop_t, environment: SymbolicMicroCodeEnvironment,cur_blk:Optional[mblock_t] = None) -> Expr:
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
            if cur_blk is None:
                raise EmulationException("instruction opcode '{0}': '{1}' cur_blk is None"
                                         .format(opcode_to_string(mop.d), format_minsn_t(mop.d)))
            result = self._eval_instruction(cur_blk,mop.d, environment)
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
        interpreter.debug("Unsupported mop type '{0}': '{1}' - creating symbol".format(
            mop_type_to_string(mop.t), format_mop_t(mop)))
        return ExprId("mop_{}".format(format_mop_t(mop)), size)

    def eval_mop(self, mop: mop_t, environment: Optional[SymbolicMicroCodeEnvironment] = None) -> Expr:
        """
        Evaluate a mop and return symbolic expression.
        Never raises (returns symbolic on failure).
        """
        if environment is None:
            environment = self.global_environment
        return self.eval(mop, environment)

    def eval_instruction(self, blk: mblock_t, ins: minsn_t,
                         environment: Optional[SymbolicMicroCodeEnvironment] = None,
                         raise_exception: bool = False) -> Optional[Expr|None]:
        """
        Evaluate a single instruction symbolically.
        Returns True on success, False on failure.
        """
        try:
            if environment is None:
                environment = self.global_environment
            interpreter.info("Evaluating symbolically: '{0}'".format(format_minsn_t(ins)))
            if ins is None:
                return None
            return self._eval_instruction_and_update_environment(blk,ins, environment)
        except EmulationException as e:
            interpreter.warning("Can't evaluate instruction: '{0}': {1}".format(format_minsn_t(ins), e))
            if raise_exception:
                raise e
        except Exception as e:
            interpreter.warning("Error during evaluation of: '{0}': {1}".format(format_minsn_t(ins), e))
            if raise_exception:
                raise e
        return None

    def eval_blk(self, current_block, microcode_environment: Optional[SymbolicMicroCodeEnvironment] = None):
        """
        对单个基本块做符号执行。

        顺序求值块内每一条指令，直到块尾。遇到控制流指令时，
        eval_instruction 会把（可能是符号化的）跳转目标写入
        microcode_environment.irdst，本函数不跟随跳转、也不清空 irdst，
        而是将其原样保留在环境中供调用方做后续分析。
        """
        if microcode_environment is None:
            microcode_environment = SymbolicMicroCodeEnvironment()
        cur_ins = current_block.head
        while cur_ins is not None:
            self.eval_instruction(current_block, cur_ins, microcode_environment)
            cur_ins = cur_ins.next

        if microcode_environment.irdst is None:
            microcode_environment.irdst = ExprInt(current_block.serial + 1, 4)


        return microcode_environment