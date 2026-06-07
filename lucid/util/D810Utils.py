from typing import List, Tuple

from d810.generic import GenericDispatcherInfo
from d810.generic import GenericDispatcherBlockInfo
from d810.hexrays_helpers import append_mop_if_not_in_list, extract_num_mop, CONTROL_FLOW_OPCODES

from ida_hexrays import mblock_t, mop_t, optblock_t, minsn_visitor_t, mbl_array_t
import ida_hexrays as hr
import ida_kernwin as kw


from d810.tracker import MopHistory, MopTracker
from d810.utils import NotResolvableFatherException, get_all_possibles_values

FLATTENING_JUMP_OPCODES = [hr.m_jnz, hr.m_jz, hr.m_jae, hr.m_jb, hr.m_ja, hr.m_jbe, hr.m_jg, hr.m_jge, hr.m_jl,
                           hr.m_jle]

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
            else:
                self.dispatcher_internal_blocks.append(child_info)
                if child_info.comparison_value is not None:
                    self.comparison_values.append(child_info.comparison_value)
                self._explore_children(child_info)

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


def UnFlaInfo(mba,dispatch_block):

    # import pydevd_pycharm
    # pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)

    print("dispatch_block serial:",hex(dispatch_block.serial))
    blk_preset_list = [x for x in dispatch_block.predset]
    print("dispatch_block father list:",blk_preset_list)

    def dfs( current_node, target_node, path, paths, visited):
        path.append(current_node.serial)
        visited.add(current_node.serial)

        for neighbor in current_node.succs():
            if neighbor.serial == target_node.serial and len(path) > 1:
                paths.append(list(path))
            elif neighbor.serial not in visited:
                dfs(neighbor, target_node, path, paths, visited)

        path.pop()
        visited.remove(current_node.serial)
    paths = []

    dfs(dispatch_block,dispatch_block,[],paths,set())

    dispatch_info = D810OllvmDispatcherInfo(mba)
    if not dispatch_info.explore(dispatch_block):
        print("set dispatch failed, dispatch_info->explore is False")
        return


    for dispatcher_father_serial in dispatch_block.predset:
        father_tracker = MopTracker(dispatch_info.entry_block.use_before_def_list, max_nb_block=100, max_path=100)
        father_tracker.reset()
        dispatcher_father_block = mba.get_mblock(dispatcher_father_serial)
        father_histories = father_tracker.search_backward(dispatcher_father_block, None)
        if len(father_histories) > 1:
            print("father_block:{0} is  multiple branches".format(dispatcher_father_serial))
        try:
            # 还原,分发器到分发器的前驱这条代码路径的混淆
            target_blk, disp_ins = dispatch_info.emulate_dispatcher_with_father_history(father_histories[0])
            if target_blk is not None:
                print("Unflattening graph: Making {0} goto {1}".format(dispatcher_father_serial, target_blk.serial))
        except NotResolvableFatherException as e:
            print("NotResolvableFatherException")

        father_histories_cst = get_all_possibles_values(father_histories, dispatch_info.entry_block.use_before_def_list,verbose=False)
        Const_Hex_str=""
        for list1 in father_histories_cst:
            for print_const in list1:
                Const_Hex_str =  Const_Hex_str+hex(print_const)+":"
        print("father_block:{0}:{1}".format(dispatcher_father_serial,Const_Hex_str))


    for path in paths:
        print("path:",path)