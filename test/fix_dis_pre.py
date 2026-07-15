import logging
from typing import List, Tuple

import ida_bytes
import ida_funcs
import ida_hexrays as hr
import ida_ida
import ida_range
import ida_kernwin as kw
import traceback

from d810.cfg_utils import insert_nop_blk, change_1way_block_successor, change_2way_block_conditional_successor
from d810.hexrays_helpers import extract_num_mop
from ida_hexrays import mblock_t
from lucid.ui.graph import show_microcode_graph


def duplicate_block(block_to_duplicate: mblock_t) -> Tuple[mblock_t, mblock_t]:
    mba = block_to_duplicate.mba
    end_blk = mba.get_mblock(mba.qty - 1)
    pre_end_blk_serial = end_blk.predset[0]
    print("end_blk:",end_blk.serial)
    pre_end_blk_fix = False
    if pre_end_blk_serial+1 == end_blk.serial:
        print("pre_end_blk is need fix")
        pre_end_blk_fix = True

    duplicated_blk = mba.copy_block(block_to_duplicate, mba.qty - 1)
    print("  Duplicated {0} -> {1}".format(block_to_duplicate.serial, duplicated_blk.serial))
    duplicated_blk_default = None
    if (block_to_duplicate.tail is not None) and hr.is_mcode_jcond(block_to_duplicate.tail.opcode):
        block_to_duplicate_default_successor = mba.get_mblock(block_to_duplicate.serial + 1)
        duplicated_blk_default = insert_nop_blk(duplicated_blk)
        change_1way_block_successor(duplicated_blk_default, block_to_duplicate.serial + 1)
        print("  {0} is conditional, so created a default child {1} for {2} which goto {3}"
                            .format(block_to_duplicate.serial, duplicated_blk_default.serial, duplicated_blk.serial,
                                    block_to_duplicate_default_successor.serial))
    elif duplicated_blk.nsucc() == 1:
        print("Making {0} goto {1}".format(duplicated_blk.serial, block_to_duplicate.succset[0]))
        change_1way_block_successor(duplicated_blk, block_to_duplicate.succset[0])
    elif duplicated_blk.nsucc() == 0:
        print("  Duplicated block {0} has no successor => Nothing to do".format(duplicated_blk.serial))

        # 修复处理前驱
    # 在测试中发现ida的这个代码复制逻辑没有处理前驱，开始我并没有想到，后来调试中我发现，microcode的这个代码块cfg,结束块必须唯一最后一个位置，不能在结束块
    # 后面添加块，只能在前面添加，所以，复制了一个块，是在结束块的前面，这就导致，如果结束块的前驱是直接顺序执行到结束块的，在复制新块以后变成了执行到新的块，逻辑发生了改变
    if pre_end_blk_fix is True:
        pre_end_blk = mba.get_mblock(pre_end_blk_serial)
        print("fix pre_end_blk")
        change_1way_block_successor(pre_end_blk, end_blk.serial)

    return duplicated_blk, duplicated_blk_default

# 将函数转变成 ida的mba，然后进行解混淆，并显示解混淆后的cfg
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
    mmat = hr.MMAT_GLBOPT2
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

    # 找到前驱最多的块作为调度块
    dispatch_npred = -1
    dispatch_block = None
    for blk_idx in range(mba.qty):
        blk = mba.get_mblock(blk_idx)
        npred = blk.npred()
        if dispatch_npred < npred:
            dispatch_npred = npred
            dispatch_block = blk
    print(dispatch_block.tail.dstr())
    num_mop, mop_compared = extract_num_mop(dispatch_block.tail)
    if num_mop is None or mop_compared is None:
        print("num_mop is None or mop_compared is None")

# for dispatcher_father_serial in dispatch_block.predset:
    #     dispatcher_father_pre_blk = mba.get_mblock(dispatcher_father_serial)
    #     dispatcher_father_list_serial = [x for x in dispatcher_father_pre_blk.succset]
    #     print(dispatcher_father_serial,dispatcher_father_list_serial)

    # pred_block = mba.get_mblock(31)
    # block_to_duplicate = mba.get_mblock(4)
    # duplicated_blk_jmp, duplicated_blk_default = duplicate_block(block_to_duplicate)
    #
    # if (pred_block.tail is None) or (not hr.is_mcode_jcond(pred_block.tail.opcode)):
    #     change_1way_block_successor(pred_block, duplicated_blk_jmp.serial)
    # else:
    #     if block_to_duplicate.serial == pred_block.tail.d.b:
    #         change_2way_block_conditional_successor(pred_block, duplicated_blk_jmp.serial)
    #     else:
    #         print(" not sure this is suppose to happen")
    #         change_1way_block_successor(pred_block.mba.get_mblock(pred_block.serial + 1),
    #                                     duplicated_blk_jmp.serial)
    # 将mba 的cfg显示出来
    # show_microcode_graph(mba, fn_name)



if __name__ == '__main__':  # 也可以直接在脚本里执行
    try:
        start()
    except Exception as e:
        traceback.print_exc()  # 直接打印完整堆栈到stderr
