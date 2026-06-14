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
from d810.hexrays_hooks import InstructionDefUseCollector
from ida_hexrays import mblock_t
from lucid.ui.graph import show_microcode_graph

import ida_hexrays
import ida_lines

import ida_hexrays
import ida_lines


def get_block_top_level_inputs(mblock) -> list:
    """
    从后向前遍历单个基本块，提取所有属于 ud 链顶层（即块外流入）的输入 mop。
    基于逻辑：如果在当前输入指令的后续指令中找不到定义，它就是顶层输入。
    """
    if not mblock:
        return []

    top_inputs = []  # 存放最终提取出的顶层 mop 实例
    seen_keys = set()  # 用于防止结果重复记录
    defined_so_far = set()  # 动态账本：记录从后向前走过的指令中，哪些物理实体被重新定义/赋值了

    def get_mop_key(op) -> str:
        """规整化 mop 的物理特征，作为唯一比对键"""
        if op.t == ida_hexrays.mop_r:
            return f"reg_{op.r}"  # 绑定寄存器编号，无视访问大小和对象实例差异
        elif op.t == ida_hexrays.mop_S:
            return f"stk_{op.s.off}_{op.dstr()}"
        return op.dstr()

    # 从基本块的最后一条顶层指令 (tail) 开始，利用 prev 指针向前倒序遍历
    insn = mblock.tail
    while insn:
        # 1. 实例化你写好的收集器，并借助原生的 for_all_ops 收集当前指令的 use 和 def
        # 你的 visitor 遇到 mop_d 返回 0 的设计，天然保证了这里绝不会因为嵌套而卡死
        collector = InstructionDefUseCollector()
        insn.for_all_ops(collector)

        # 2. 【处理输入】合并常规输入与内存输入
        current_uses = collector.unresolved_ins_mops + collector.memory_unresolved_ins_mops
        for use_mop in current_uses:
            use_key = get_mop_key(use_mop)

            # 如果这个输入在它后面的指令里【没有找到】关于它的定义，说明它目前来自块外部（顶层）
            if use_key not in defined_so_far:
                if use_key not in seen_keys:
                    seen_keys.add(use_key)
                    top_inputs.append(use_mop)

        # 3. 【更新定义账本】记录当前指令改写了什么
        # 它的作用是：让当前指令前方（更早执行）的指令在走到第 2 步时，能够有依据进行“重新处理”并将其过滤
        for def_mop in collector.target_mops:
            if def_mop.t in [ida_hexrays.mop_r, ida_hexrays.mop_S, ida_hexrays.mop_v]:
                def_key = get_mop_key(def_mop)
                defined_so_far.add(def_key)

        # 向前移动到上一条顶层指令
        insn = insn.prev
    print(f"--- Block {mblock.serial} 顶层输入名字清单 ---")
    for op in top_inputs:
        # 去掉 IDA 自带的文本颜色标签，直接打印干净的名字（如 rax, var_10 等）
        mop_name = ida_lines.tag_remove(op.dstr())
        print(mop_name)
    return top_inputs
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
    block = mba.get_mblock(1)
    get_block_top_level_inputs(block)
if __name__ == '__main__':  # 也可以直接在脚本里执行
    try:
        start()
    except Exception as e:
        traceback.print_exc()  # 直接打印完整堆栈到stderr
