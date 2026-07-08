import logging
from typing import List, Tuple

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_hexrays as hr
import ida_ida
import ida_idp
import ida_range
import ida_kernwin as kw
import traceback

from d810.cfg_utils import insert_nop_blk, change_1way_block_successor, change_2way_block_conditional_successor
from d810.hexrays_formatters import opcode_to_string, mop_type_to_string, get_mop_content
from d810.InsnCollector import InstructionDefUseCollector
from ida_hexrays import mblock_t
from lucid.ui.graph import show_microcode_graph



def start():
    # import pydevd_pycharm
    # pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)
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
    mmat = hr.MMAT_GLBOPT3
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
    block = mba.get_mblock(18)

    ins = block.tail
    print("op:{0}     type:{1} content:{2}:".format(opcode_to_string(ins.opcode),type(ins.opcode),ins.opcode))
    print("insn.l:{0} type:{1} content:{2}:".format(ins.l.dstr(),mop_type_to_string(ins.l.t),get_mop_content(ins.l)))
    print("insn.r:{0} type:{1} content:{2}:".format(ins.r.dstr(),mop_type_to_string(ins.r.t),get_mop_content(ins.r)))
    print("insn.d:{0} type:{1} content:{2}:".format(ins.d.dstr(),mop_type_to_string(ins.d.t),get_mop_content(ins.d)))

    print("found:", ins.dstr())
    print("found:", ins.l.dstr())
    print("found:", type(ins.l.dstr()))
    print("found:", ins.d.dstr())


    defined_mops = []
if __name__ == '__main__':  # 也可以直接在脚本里执行
    try:
        start()
    except Exception as e:
        traceback.print_exc()  # 直接打印完整堆栈到stderr
