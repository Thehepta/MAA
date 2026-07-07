import logging
from typing import List, Tuple

import ida_bytes
import ida_funcs
import ida_ida
import ida_range
# from d810.emulator import MicroCodeInterpreter, MicroCodeEnvironment
from d810.emulator_Interpreter import SymbolicMicroCodeEnvironment
from d810.generic import GenericDispatcherInfo
from d810.generic import GenericDispatcherBlockInfo
from d810.hexrays_formatters import format_mop_t, format_minsn_t
from d810.hexrays_helpers import append_mop_if_not_in_list, extract_num_mop, CONTROL_FLOW_OPCODES

from ida_hexrays import mblock_t, mop_t, optblock_t, minsn_visitor_t, mbl_array_t,get_mreg_name
import ida_hexrays as hr
import ida_kernwin as kw
import traceback

from d810.tracker import  MopTracker
from d810.utils import NotResolvableFatherException, get_all_possibles_values
from lucid.util.D810Utils import eva_blk

FLATTENING_JUMP_OPCODES = [hr.m_jnz, hr.m_jz, hr.m_jae, hr.m_jb, hr.m_ja, hr.m_jbe, hr.m_jg, hr.m_jge, hr.m_jl,
                           hr.m_jle]

helper_logger = logging.getLogger('D810.helper')
helper_logger.setLevel(logging.NOTSET)
# logger = logging.getLogger('D810.tracker')


def find_all_paths_dfs(start_block, end_blocks):
    if not start_block or not end_blocks:
        return []

    end_block_nums = set(blk.serial for blk in end_blocks)
    print(f"终点块编号: {end_block_nums}")  # 调试输出

    all_paths = []
    visited = set()

    def dfs(current_block, path):
        current_num = current_block.serial

        if current_num in visited:
            return

        if current_num in end_block_nums:
            print(f"到达终点 {current_num}, 路径: {path}")  # 调试输出
            all_paths.append(path.copy())
            return

        path.append(current_num)
        visited.add(current_num)

        for succ_block in current_block.succs():
            dfs(succ_block, path)

        path.pop()
        visited.remove(current_num)

    dfs(start_block, [])
    unique_paths = []
    seen = set()
    for path in all_paths:
        path_tuple = tuple(path)
        if path_tuple not in seen:
            seen.add(path_tuple)
            unique_paths.append(path)
    return unique_paths

class D810OllvmDispatcherInfo(GenericDispatcherInfo):

    def explore(self, blk: mblock_t) -> bool:
        self.reset()
        if not self._is_candidate_for_dispatcher_entry_block(blk):
            return False
        self.entry_block = GenericDispatcherBlockInfo(blk)
        self.entry_block.parse()
        for used_mop in self.entry_block.use_list:
            append_mop_if_not_in_list(used_mop, self.entry_block.assume_def_list)
        self.dispatcher_internal_blocks.append(self.entry_block)
        num_mop, self.mop_compared = self._get_comparison_info(self.entry_block.blk)
        self.comparison_values.append(num_mop.nnn.value)
        self._explore_children(self.entry_block)
        dispatcher_blk_with_external_father = self._get_dispatcher_blocks_with_external_father()
        # TODO: I think this can be wrong because we are too permissive in detection of dispatcher blocks
        if len(dispatcher_blk_with_external_father) != 0:
            return False

        dispatcher_internal_blocks = [x.serial for x in self.dispatcher_internal_blocks]
        print("dispatcher_internal_blocks:", dispatcher_internal_blocks)
        end_block_nums = set(Gdbi.blk for Gdbi in self.dispatcher_exit_blocks)
        all_paths = find_all_paths_dfs(self.entry_block.blk,end_block_nums)
        print(len(all_paths))

        for paths in all_paths:
            microcode_environment = SymbolicMicroCodeEnvironment()
            for p in paths:
                current_block = self.mba.get_mblock(p)
                eva_blk(current_block,microcode_environment)
            microcode_environment.dump()
        return True

    def _is_candidate_for_dispatcher_entry_block(self, blk: mblock_t) -> bool:
        # blk must be a condition branch with one numerical operand
        num_mop, mop_compared = self._get_comparison_info(blk)
        if (num_mop is None) or (mop_compared is None):
            return False
            # Its fathers are not conditional branch with this mop
        for father_serial in blk.predset:
            father_blk = self.mba.get_mblock(father_serial)
            father_num_mop, father_mop_compared = self._get_comparison_info(father_blk)
            if (father_num_mop is not None) and (father_mop_compared is not None):
                if mop_compared.equal_mops(father_mop_compared, hr.EQ_IGNSIZE):
                    return False
        return True

    def _get_comparison_info(self, blk: mblock_t) -> Tuple[mop_t, mop_t]:
        # We check if blk is a good candidate for dispatcher entry block: blk.tail must be a conditional branch
        if (blk.tail is None) or (blk.tail.opcode not in FLATTENING_JUMP_OPCODES):
            return None, None
            # One operand must be numerical
        num_mop, mop_compared = extract_num_mop(blk.tail)
        if num_mop is None or mop_compared is None:
            return None, None
        return num_mop, mop_compared

    def is_part_of_dispatcher(self, block_info: GenericDispatcherBlockInfo) -> bool:
        is_ok = block_info.does_only_need(block_info.father.assume_def_list)
        if not is_ok:
            return False
        if (block_info.blk.tail is not None) and (block_info.blk.tail.opcode not in FLATTENING_JUMP_OPCODES):
            return False
        return True

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
                self.dispatcher_exit_blocks.append(child_info)
                # print("self.dispatcher_exit_blocks: {0}".format(child_serial))
            else:
                self.dispatcher_internal_blocks.append(child_info)
                if child_info.comparison_value is not None:
                    self.comparison_values.append(child_info.comparison_value)
                self._explore_children(child_info)
                print("self.dispatcher_internal_blocks: {0}".format(child_serial))

    def _get_external_fathers(self, block_info: GenericDispatcherBlockInfo) -> List[mblock_t]:
        internal_serials = [blk_info.blk.serial for blk_info in self.dispatcher_internal_blocks]
        external_fathers = []
        for blk_father in block_info.blk.predset:
            if blk_father not in internal_serials:
                external_fathers.append(blk_father)
        return external_fathers

    def _get_dispatcher_blocks_with_external_father(self) -> List[mblock_t]:
        dispatcher_blocks_with_external_father = []
        for blk_info in self.dispatcher_internal_blocks:
            if blk_info.blk.serial != self.entry_block.blk.serial:
                external_fathers = self._get_external_fathers(blk_info)
                if len(external_fathers) > 0:
                    dispatcher_blocks_with_external_father.append(blk_info)
        return dispatcher_blocks_with_external_father



def get_block_external_deps_by_ud(mba, target_serial):
    """
    使用 UD 链找出 target_serial 块的所有外部依赖变量。

    返回：list of (voff_t, def_block_serials)
    """
    graph = mba.get_graph()
    ud = graph.get_ud(hr.GC_REGS_AND_STKVARS)

    bc = ud.at(target_serial)  # block_chains_t

    external_deps = []

    # 遍历该块所有 chain
    # chain_t 继承自 intvec_t，可以直接 for 循环
    for chain in bc:
        if not chain.is_inited():
            continue

        # chain 里是定义了这个变量的所有块号
        def_blocks = set(int(bn) for bn in chain)

        # 如果当前块自己不定义它，就是外部依赖
        if target_serial not in def_blocks:
            voff = chain.key()
            external_deps.append((voff, def_blocks))

    return external_deps

def UnFlaInfo(mba):
    # import pydevd_pycharm
    # pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)
    # print("dispatch_block serial:", hex(dispatch_block.serial))
    # blk_preset_list = [x for x in dispatch_block.predset]
    # print("dispatch_block father list:", blk_preset_list)


    blk = mba.get_mblock(21)
    entry_block = GenericDispatcherBlockInfo(blk)
    entry_block.parse()
    for m in entry_block.use_before_def_list:
        print("use_before_def_list:",m.dstr())

    for m in entry_block.use_list:
        print("use_list:",m.dstr())

    # for m in entry_block.def_list:
    #     print("def_list:",m.dstr())

# 将函数转变成 ida的mba，然后进行解混淆，并显示解混淆后的cfg
def start():
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

    # 使用D810的api解FLA混淆
    UnFlaInfo(mba)

    # 将mba 的cfg显示出来
    # show_microcode_graph(mba, fn_name)



if __name__ == '__main__':  # 也可以直接在脚本里执行
    try:
        start()
    except Exception as e:
        traceback.print_exc()  # 直接打印完整堆栈到stderr
