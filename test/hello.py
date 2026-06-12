from typing import List, Tuple
from lucid.ui.graph import show_microcode_graph
import ida_bytes
import ida_funcs
import ida_ida
import ida_range
from d810.generic import GenericDispatcherInfo
from d810.generic import GenericDispatcherBlockInfo
from d810.hexrays_helpers import append_mop_if_not_in_list, extract_num_mop, CONTROL_FLOW_OPCODES

from ida_hexrays import mblock_t, mop_t, optblock_t, minsn_visitor_t, mbl_array_t
import ida_hexrays as hr
import ida_kernwin as kw
from d810.cfg_utils import change_1way_block_successor

from d810.tracker import  MopTracker,duplicate_histories

FLATTENING_JUMP_OPCODES = [hr.m_jnz, hr.m_jz, hr.m_jae, hr.m_jb, hr.m_ja, hr.m_jbe, hr.m_jg, hr.m_jge, hr.m_jl,
                           hr.m_jle]

#GenericDispatcherInfo 这个有两个功能，第一部分就是调用模拟执行，返回对应的真实块，第二部分提供分发器分析以及模拟执行反会真实块需要的一些接口或者属性。
class D810OllvmDispatcherInfo(GenericDispatcherInfo):


    # 分发器内部块
    # self.dispatcher_internal_blocks = []
    # 不属于分发器的块，分发器退出的块
    # self.dispatcher_exit_blocks = []

    # 寻找分发器入口块，不是入口块返回False
    def explore(self, blk: mblock_t) -> bool:
        self.reset()
        if not self._is_candidate_for_dispatcher_entry_block(blk):
            return False
        # entry_block 分发器入口块，分发器不是一个块，而是有很多块，每一个块都是一个 GenericDispatcherBlockInfo对象
        self.entry_block = GenericDispatcherBlockInfo(blk)
        self.entry_block.parse()
        for used_mop in self.entry_block.use_list:
            append_mop_if_not_in_list(used_mop, self.entry_block.assume_def_list)
        self.dispatcher_internal_blocks.append(self.entry_block)

        # 最后一条跳转指令对应的条件变量和比较的常量
        num_mop, self.mop_compared = self._get_comparison_info(self.entry_block.blk)
        self.comparison_values.append(num_mop.nnn.value)

        # 从分发器入口块开始解析所有的块
        self._explore_children(self.entry_block)

        dispatcher_blk_with_external_father = self._get_dispatcher_blocks_with_external_father()
        # TODO: I think this can be wrong because we are too permissive in detection of dispatcher blocks
        if len(dispatcher_blk_with_external_father) != 0:
            return False
        return True

    # 判断这个快是否可以成为分发器入口块的候选者
    def _is_candidate_for_dispatcher_entry_block(self, blk: mblock_t) -> bool:
        # blk must be a condition branch with one numerical operand
        num_mop, mop_compared = self._get_comparison_info(blk)
        if (num_mop is None) or (mop_compared is None):
            return False
        # Its fathers are not conditional branch with this mop
        #判断前驱块使用的mop_compared是不是和分发器使用的相同，如果相同，不是分发器入口
        for father_serial in blk.predset:
            father_blk = self.mba.get_mblock(father_serial)
            father_num_mop, father_mop_compared = self._get_comparison_info(father_blk)
            if (father_num_mop is not None) and (father_mop_compared is not None):
                #比较两个 mop是否相等
                if mop_compared.equal_mops(father_mop_compared, hr.EQ_IGNSIZE):
                    return False
        return True

    # 判断块的最后一条指令是不是 FLATTENING_JUMP_OPCODES，如果是的话，返回条件判断的变量和满足条件的常量
    def _get_comparison_info(self, blk: mblock_t) -> Tuple[mop_t, mop_t]:
        # We check if blk is a good candidate for dispatcher entry block: blk.tail must be a conditional branch
        if (blk.tail is None) or (blk.tail.opcode not in FLATTENING_JUMP_OPCODES):
            return None, None
        # One operand must be numerical
        num_mop, mop_compared = extract_num_mop(blk.tail)
        if num_mop is None or mop_compared is None:
            return None, None
        return num_mop, mop_compared

    # 判断块是不是属于分发器内部快，通过变量使用判断,他的father块使用的变量，和最后一条指令是否是 FLATTENING_JUMP_OPCODES
    def is_part_of_dispatcher(self, block_info: GenericDispatcherBlockInfo) -> bool:
        is_ok = block_info.does_only_need(block_info.father.assume_def_list)
        if not is_ok:
            return False
        if (block_info.blk.tail is not None) and (block_info.blk.tail.opcode not in FLATTENING_JUMP_OPCODES):
            return False
        return True

    # 从分发器开始，向下进行深度dfs遍历，收集 dispatcher_internal_blocks 和 dispatcher_exit_blocks
    def _explore_children(self, father_info: GenericDispatcherBlockInfo):
        for child_serial in father_info.blk.succset:
            if child_serial in [blk_info.blk.serial for blk_info in self.dispatcher_internal_blocks]:
                return
            if child_serial in [blk_info.blk.serial for blk_info in self.dispatcher_exit_blocks]:
                return
            child_blk = self.mba.get_mblock(child_serial)
            child_info = GenericDispatcherBlockInfo(child_blk, father_info)
            child_info.parse()
            if not self.is_part_of_dispatcher(child_info):
                print("add dispatcher_exit_blocks:",child_serial)
                self.dispatcher_exit_blocks.append(child_info)
            else:
                self.dispatcher_internal_blocks.append(child_info)
                print("add dispatcher_internal_blocks:", child_serial)
                if child_info.comparison_value is not None:
                    self.comparison_values.append(child_info.comparison_value)
                self._explore_children(child_info)

    # 遍历 dispatcher_internal_blocks，在除去分发器的情况下，是否有外部快直接进入分发器内部
    def _get_dispatcher_blocks_with_external_father(self) -> List[mblock_t]:
        dispatcher_blocks_with_external_father = []
        for blk_info in self.dispatcher_internal_blocks:
            if blk_info.blk.serial != self.entry_block.blk.serial:
                external_fathers = self._get_external_fathers(blk_info)
                if len(external_fathers) > 0:
                    dispatcher_blocks_with_external_father.append(blk_info)
        return dispatcher_blocks_with_external_father

    # 判断 dispatcher_internal_blocks 的前驱是否有存在外部快进入的情况，分发器的的入口块在上个函数中会被排除
    # 所以不可能存在有外部直接进入内部快的情况
    def _get_external_fathers(self, block_info: GenericDispatcherBlockInfo) -> List[mblock_t]:
        internal_serials = [blk_info.blk.serial for blk_info in self.dispatcher_internal_blocks]
        external_fathers = []
        for blk_father in block_info.blk.predset:
            if blk_father not in internal_serials:
                external_fathers.append(blk_father)
        return external_fathers


# 使用d810的api进行解混淆,一个最简陋的demo，专门针对于hello_ollvm 这个程序，分发器是写死的
def UnFla(mba, dispatch_block):

    # import pydevd_pycharm
    # pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)
    # 创建一个 DispatcherInfo 的类，他继承自GenericDispatcherInfo 这个类
    # DispatcherInfo 这个类主要实现的部分用于分发器的寻找，和判断是否是分发器
    dispatch_info = D810OllvmDispatcherInfo(mba)
        # 判断是否是分发器
    if not dispatch_info.explore(dispatch_block):
        print("set dispatch failed, dispatch_info->explore is False")
        return 0
    # 遍历分发器的前驱，判断是否有单分支多路径的情况，如果有的话，直接使用控制流修复处理
    for dispatcher_father_serial in dispatch_block.predset:
        # 生成一个 MopTracker 用于向后追踪，追踪的数据是分发器中的定义和使用的数据， ispatch_info.entry_block.use_before_def_list
        father_tracker = MopTracker(dispatch_info.entry_block.use_before_def_list, max_nb_block=100, max_path=100)
        father_tracker.reset()
        dispatcher_father_block = mba.get_mblock(dispatcher_father_serial)
        # 先后递归寻找，多个赋值没关系，出现多个分支就分裂寻找，找到最近的哪个赋值的就返回
        # 如果有多个分支，并且有不同的赋值，就会出现多个father_histories
        father_histories = father_tracker.search_backward(dispatcher_father_block, None)
        if len(father_histories) > 1:
            print("father_block:{0} is  multiple branches".format(dispatcher_father_serial))
            # 如果出现多个father_histories，使用duplicate_histories会自动把这些多的处理成多条单路径单分支
            duplicate_histories(father_histories, max_nb_pass=10)

    # 如果程序经过修复以后，分发器的前驱可能增加，所以在这里需要再次重新循环获取
    # 这次循环的目的是修复每个前驱

    dispatcher_father_serial_list = [x for x in dispatch_block.predset]

    for dispatcher_father_serial in dispatcher_father_serial_list:
        # 生成一个 MopTracker 用于向后追踪，最终的数据是分发器中的定义和使用的数据， ispatch_info.entry_block.use_before_def_list
        father_tracker = MopTracker(dispatch_info.entry_block.use_before_def_list, max_nb_block=100, max_path=100)
        father_tracker.reset()
        dispatcher_father_block = mba.get_mblock(dispatcher_father_serial)

        # 先后递归寻找，多个赋值没关系，出现多个分支就分裂寻找，找到最近的哪个赋值的就返回
        # 如果有多个分支，并且有不同的赋值，就会出现多个father_histories
        father_histories = father_tracker.search_backward(dispatcher_father_block, None)
        if len(father_histories) > 1:
            # 在前面已经修复过了，针对于hello_ollvm 这个程序来说，不会有这种特殊的情况
            print("unknow error")

        # 这个 MopHistory，里面是这个前驱的路径执行完毕以后，其中所有变量以及对应的值
        # 将 father_histories[0] 中 变量的对应的值，设置到仿真执行环境中，当从分发器开始执行的时候，其中的状态寄存器的值，已经变成了当前这个前驱执行完了以后的值。
        # 通过dispatch_info这个，从分发器开始一个块一个块的仿真执行，执行到 dispatcher_exit_blocks 会停止
        # 返回 用 father_histories 的状态变量，执行到的，真实代码的起始位置，以及指令，用于patch
        target_blk, disp_ins = dispatch_info.emulate_dispatcher_with_father_history(father_histories[0])
        if target_blk is not None:
            print("Unflattening graph: Making {0} goto {1}"
                  .format(dispatcher_father_serial, target_blk.serial))
            # 直接patch
            change_1way_block_successor(dispatcher_father_block, target_blk.serial)

    return 0

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
    dispatcher_block = mba.get_mblock(2)

    # 使用D810的api解FLA混淆
    UnFla(mba, dispatcher_block)

    # 将mba 的cfg显示出来
    show_microcode_graph(mba, fn_name)


class blkOPt(hr.optblock_t):

    def func(self, blk):
        if blk.head is None:
            # print("blk head is None", blk.serial)
            return 0
        # print(blk.mba.maturity, hex(blk.head.ea), blk.serial)
        if blk.mba.maturity != hr.MMAT_GLBOPT2:
            return 0

        if blk.serial == 2:
            return UnFla(blk.mba,blk)

        return 0

if __name__ == '__main__':  # 也可以直接在脚本里执行
    start()

    # try:
    #     optimizer = blkOPt()
    #     optimizer.install()
    # except Exception as e:
    #     print(e)