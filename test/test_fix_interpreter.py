import logging
from typing import List, Tuple, Optional

import ida_bytes
import ida_funcs
import ida_ida
import ida_range
# from d810.emulator import MicroCodeInterpreter, MicroCodeEnvironment
from d810 import tracker, utils, Interpreter
from d810.Environment import SymbolicMicroCodeEnvironment
from d810.Expr import walk_expr_iter, ExprId, ExprInt, Expr, ExprOp
from d810.ExprSimplifier import get_branch_condition, simplify, append_expr_if_not_in_list
from d810.Interpreter import SymbolicMicroCodeInterpreter
from d810.generic import GenericDispatcherInfo
from d810.generic import GenericDispatcherBlockInfo
from d810.hexrays_formatters import format_mop_t, format_minsn_t
from d810.hexrays_helpers import append_mop_if_not_in_list, extract_num_mop, CONTROL_FLOW_OPCODES, \
    equal_mops_ignore_size, make_reg
from d810.tracker import duplicate_histories
from d810.utils import get_mop_name, enable_console_log, create_console_logger

from ida_hexrays import mblock_t, mop_t, optblock_t, minsn_visitor_t, mbl_array_t, get_mreg_name
import ida_hexrays as hr
import ida_kernwin as kw
import traceback
import ida_dbg

FLATTENING_JUMP_OPCODES = [hr.m_jnz, hr.m_jz, hr.m_jae, hr.m_jb, hr.m_ja, hr.m_jbe, hr.m_jg, hr.m_jge, hr.m_jl,
                           hr.m_jle]


class test(SymbolicMicroCodeInterpreter):

    def _eval_call_helper(self, blk: mblock_t, ins, environment: SymbolicMicroCodeEnvironment) -> Optional[Expr]:
        """Evaluate helper function calls symbolically."""
        if ins.opcode != hr.m_call or ins.l.t != hr.mop_h:
            return None
        res_size = ins.d.size
        helper_name = ins.l.helper
        args_list = []

        for arg in ins.d.f.args:
            data = self.eval(blk, arg, environment)
            args_list.append(data)
        print("     Call helper for {0}".format(helper_name))
        return ExprOp("call_{}".format(helper_name), args_list, res_size)

def UnFlaInfo(mba):
    # import pydevd_pycharm
    # pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)
    microcode_environment = SymbolicMicroCodeEnvironment()
    microcode_interpreter = test()
    blk = mba.get_mblock(17)
    microcode_interpreter.eval_blk(blk, microcode_environment)
    microcode_environment.dump(create_console_logger())

# 将函数转变成 ida的mba，然后进行解混淆，并显示解混淆后的cfg
def start(mmat):
    # import pydevd_pycharm
    # pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)    sel, sea, eea = kw.read_range_selection(None)
    sel, sea, eea = kw.read_range_selection(None)
    pfn = ida_funcs.get_func(kw.get_screen_ea())
    if not sel and not pfn:
        return (False, "Position cursor within a function or select range")

    if not sel and pfn:
        sea = pfn.start_ea
        eea = pfn.end_ea
    print("fun addr:", hex(sea))
    addr_fmt = "%016x" if ida_ida.inf_is_64bit() else "%08x"
    fn_name = (ida_funcs.get_func_name(pfn.start_ea)
               if pfn else "0x%s-0x%s" % (addr_fmt % sea, addr_fmt % eea))

    F = ida_bytes.get_flags(sea)
    if not ida_bytes.is_code(F):
        return (False, "The selected range must start with an instruction")
    text = "unfla"
    mmat = mmat
    if text is None and mmat is None:
        return (True, "Cancelled")

    if not sel and pfn:
        mbr = hr.mba_ranges_t(pfn)
    else:
        mbr = hr.mba_ranges_t()
        mbr.ranges.push_back(ida_range.range_t(sea, eea))

    hf = hr.hexrays_failure_t()
    ml = hr.mlist_t()
    mba = hr.gen_microcode(mbr, hf, ml, hr.DECOMP_WARNINGS, mmat)

    # 使用D810的api解FLA混淆
    UnFlaInfo(mba)

    # 将mba 的cfg显示出来
    # show_microcode_graph(mba, fn_name)


if __name__ == '__main__':  # 也可以直接在脚本里执行
    try:
        start(hr.MMAT_GLBOPT2)
    except Exception as e:
        traceback.print_exc()  # 直接打印完整堆栈到stderr
