import logging
from typing import List, Tuple

import ida_bytes
import ida_funcs
import ida_hexrays as hr
import ida_ida
import ida_range
import ida_kernwin as kw
import traceback

from d810.cfg_utils import insert_nop_blk, change_2way_block_conditional_successor, insert_goto_instruction, \
    change_1way_call_block_successor
from ida_hexrays import mblock_t
from lucid.ui.graph import show_microcode_graph


def change_1way_block_successor(blk: mblock_t, blk_successor_serial: int) -> bool:
    if blk.nsucc() != 1:
        return False

    mba: hr.mbl_array_t = blk.mba
    previous_blk_successor_serial = blk.succset[0]
    previous_blk_successor = mba.get_mblock(previous_blk_successor_serial)

    if blk.tail is None:
        # We add a goto instruction
        insert_goto_instruction(blk, blk_successor_serial, nop_previous_instruction=False)
    elif blk.tail.opcode == hr.m_goto:
        # We change goto target directly
        blk.tail.l.make_blkref(blk_successor_serial)
    elif blk.tail.opcode == hr.m_ijmp:
        # We replace ijmp instruction with goto instruction
        insert_goto_instruction(blk, blk_successor_serial, nop_previous_instruction=True)
    elif blk.tail.opcode == hr.m_call:
        #  Before maturity MMAT_CALLS, we can't add a goto after a call instruction
        if mba.maturity < hr.MMAT_CALLS:
            return change_1way_call_block_successor(blk, blk_successor_serial)
        else:
            insert_goto_instruction(blk, blk_successor_serial, nop_previous_instruction=False)
    else:
        # We add a goto instruction
        insert_goto_instruction(blk, blk_successor_serial, nop_previous_instruction=False)

    # Update block properties
    blk.type = hr.BLT_1WAY
    blk.flags |= hr.MBL_GOTO

    # Bookkeeping
    blk.succset._del(previous_blk_successor_serial)
    blk.succset.push_back(blk_successor_serial)
    blk.mark_lists_dirty()

    previous_blk_successor.predset._del(blk.serial)
    if previous_blk_successor.serial != mba.qty - 1:
        previous_blk_successor.mark_lists_dirty()

    new_blk_successor = blk.mba.get_mblock(blk_successor_serial)
    new_blk_successor.predset.push_back(blk.serial)

    if new_blk_successor.serial != mba.qty - 1:
        new_blk_successor.mark_lists_dirty()

    mba.mark_chains_dirty()
    # try:
    #     mba.verify(True)
    #     return True
    # except RuntimeError as e:
    #     print("Error in change_1way_block_successor: {0}".format(e))
    #     raise e

def copy_block(block_to_duplicate: mblock_t) -> mblock_t:
    mba = block_to_duplicate.mba
    duplicated_blk = mba.insert_block(mba.qty-1)  # 在 next_blk_num 之前插入
    # 填充内容
    ins = block_to_duplicate.head
    while ins:
        new_ins = hr.minsn_t(ins)
        duplicated_blk.insert_into_block(new_ins, duplicated_blk.tail)
        ins = ins.next

    return duplicated_blk

def duplicate_block(block_to_duplicate: mblock_t) -> Tuple[mblock_t, mblock_t]:
    mba = block_to_duplicate.mba

    duplicated_blk = None
    duplicated_blk_default = None
    if (block_to_duplicate.tail is not None) and hr.is_mcode_jcond(block_to_duplicate.tail.opcode):
        block_to_duplicate_default_successor = mba.get_mblock(block_to_duplicate.serial + 1)
        duplicated_blk = copy_block(block_to_duplicate)
        duplicated_blk_default = insert_nop_blk(duplicated_blk)
        change_1way_block_successor(duplicated_blk_default, block_to_duplicate.serial + 1)
        print("  {0} is conditional, so created a default child {1} for {2} which goto {3}"
                            .format(block_to_duplicate.serial, duplicated_blk_default.serial, duplicated_blk.serial,
                                    block_to_duplicate_default_successor.serial))
    elif block_to_duplicate.nsucc() == 1:
        duplicated_blk = copy_block(block_to_duplicate)
        insert_goto_instruction(duplicated_blk,block_to_duplicate.succset[0])
        print("  Making {0} goto {1}".format(duplicated_blk.serial, block_to_duplicate.succset[0]))
    elif block_to_duplicate.nsucc() == 0:
        print("  Duplicated block {0} has no successor => Nothing to do".format(duplicated_blk.serial))
        duplicated_blk = copy_block(block_to_duplicate)

    print("  Duplicated {0} -> {1}".format(block_to_duplicate.serial, duplicated_blk.serial))


    # try:
    #     mba.verify(True)
    # except RuntimeError as e:
    #     print("Error in change_1way_block_successor: {0}".format(e))
    #     raise e
    return duplicated_blk, duplicated_blk_default

# 将函数转变成 ida的mba，然后进行解混淆，并显示解混淆后的cfg
def start():
    import pydevd_pycharm
    pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)
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
    pred_block = mba.get_mblock(31)
    block_to_duplicate = mba.get_mblock(4)
    print("block_to_duplicate:",block_to_duplicate.nsucc())
    duplicated_blk_jmp, duplicated_blk_default = duplicate_block(block_to_duplicate)

    if (pred_block.tail is None) or (not hr.is_mcode_jcond(pred_block.tail.opcode)):
        print("  make {0} -> to {1}".format(pred_block.serial, duplicated_blk_jmp.serial))
        change_1way_block_successor(pred_block, duplicated_blk_jmp.serial)
    # else:
    #     if block_to_duplicate.serial == pred_block.tail.d.b:
    #         change_2way_block_conditional_successor(pred_block, duplicated_blk_jmp.serial)
    #     else:
    #         print(" not sure this is suppose to happen")
    #         change_1way_block_successor(pred_block.mba.get_mblock(pred_block.serial + 1),
    #                                     duplicated_blk_jmp.serial)
    # 将mba 的cfg显示出来
    show_microcode_graph(mba, fn_name)



if __name__ == '__main__':  # 也可以直接在脚本里执行
    try:
        start()
    except Exception as e:
        traceback.print_exc()  # 直接打印完整堆栈到stderr
