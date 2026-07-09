import logging
from typing import List, Tuple

from d810.hexrays_formatters import format_minsn_t, format_mop_list, format_mop_t
from d810.hexrays_helpers import append_mop_if_not_in_list, get_mop_index, CONDITIONAL_JUMP_OPCODES, extract_num_mop
from d810.InsnCollector import InstructionDefUseCollector, remove_segment_registers
from ida_hexrays import mop_t, minsn_t, mblock_t, mbl_array_t

unflat_logger = logging.getLogger('D810.unflat')


class GenericDispatcherBlockInfo(object):

    def __init__(self, blk, father=None):
        self.blk = blk
        self.ins = []
        # 这个块中所有使用的变量
        self.use_list = []
        # 这个块中所有使用了,但是没有赋值的变量,一般是外部传入的变量
        self.use_before_def_list = []
        # 这个块中所有赋值的变量
        self.def_list = []
        # 假设定义,父块的assume_def_list 和 由当前块的def_list 组成 以及分发器的 use_list
        self.assume_def_list = []
        self.comparison_value = None
        self.compared_mop = None

        self.father = None
        if father is not None:
            self.register_father(father)

    @property
    def serial(self) -> int:
        return self.blk.serial

    def register_father(self, father: 'GenericDispatcherBlockInfo'):
        self.father = father
        self.assume_def_list = [x for x in father.assume_def_list]

    def update_use_def_lists(self, ins_mops_used: List[mop_t], ins_mops_def: List[mop_t]):
        for mop_used in ins_mops_used:
            # 如果mop 不在列表中则添加
            append_mop_if_not_in_list(mop_used, self.use_list)
            mop_used_index = get_mop_index(mop_used, self.def_list)
            if mop_used_index == -1:
                append_mop_if_not_in_list(mop_used, self.use_before_def_list)
        for mop_def in ins_mops_def:
            append_mop_if_not_in_list(mop_def, self.def_list)

    def update_with_ins(self, ins: minsn_t):
        # 定义指定收集器，遍历一个指令中所有的mop
        ins_mop_info = InstructionDefUseCollector()
        ins.for_all_ops(ins_mop_info)
        # 删除段寄存器 x86架构段寄存器
        cleaned_unresolved_ins_mops = remove_segment_registers(ins_mop_info.unresolved_ins_mops)
        # 更新use 和def 链
        self.update_use_def_lists(cleaned_unresolved_ins_mops + ins_mop_info.memory_unresolved_ins_mops,
                                  ins_mop_info.target_mops)
        self.ins.append(ins)
        # 当前块 的当前指令是不是 CONDITIONAL_JUMP_OPCODES ，如果是就把跳转的 comparison_value 和 compared_mop 保留
        if ins.opcode in CONDITIONAL_JUMP_OPCODES:
            num_mop, other_mop = extract_num_mop(ins)
            if num_mop is not None:
                self.comparison_value = num_mop.nnn.value
                self.compared_mop = other_mop

    def parse(self):
        curins = self.blk.head
        while curins is not None:
            self.update_with_ins(curins)
            curins = curins.next
        for mop_def in self.def_list:
            append_mop_if_not_in_list(mop_def, self.assume_def_list)

    def does_only_need(self, prerequisite_mop_list: List[mop_t]) -> bool:
        for used_before_def_mop in self.use_before_def_list:
            mop_index = get_mop_index(used_before_def_mop, prerequisite_mop_list)
            if mop_index == -1:
                return False
        return True

    def recursive_get_father(self) -> List['GenericDispatcherBlockInfo']:
        if self.father is None:
            return [self]
        else:
            return self.father.recursive_get_father() + [self]

    def show_history(self):
        full_father_list = self.recursive_get_father()
        unflat_logger.info("    Show history of Block {0}".format(self.blk.serial))
        for father in full_father_list[:-1]:
            for ins in father.ins:
                unflat_logger.info("      {0}.{1}".format(father.blk.serial, format_minsn_t(ins)))

    def print_info(self):
        unflat_logger.info("Block {0} information:".format(self.blk.serial))
        unflat_logger.info("  USE list: {0}".format(format_mop_list(self.use_list)))
        unflat_logger.info("  DEF list: {0}".format(format_mop_list(self.def_list)))
        unflat_logger.info("  USE BEFORE DEF list: {0}".format(format_mop_list(self.use_before_def_list)))
        unflat_logger.info("  ASSUME DEF list: {0}".format(format_mop_list(self.assume_def_list)))



class GenericDispatcherInfo(object):
    def __init__(self, mba: mbl_array_t):
        self.mba = mba
        self.mop_compared = None
        self.entry_block = None
        self.comparison_values = []
        self.dispatcher_internal_blocks = []
        self.dispatcher_exit_blocks = []

    def reset(self):
        self.mop_compared = None
        self.entry_block = None
        self.comparison_values = []
        self.dispatcher_internal_blocks = []
        self.dispatcher_exit_blocks = []

    def explore(self, blk: mblock_t) -> bool:
        return False

    def get_shared_internal_blocks(self, other_dispatcher: "GenericDispatcherInfo") -> List[mblock_t]:
        my_dispatcher_block_serial = [blk_info.blk.serial for blk_info in self.dispatcher_internal_blocks]
        other_dispatcher_block_serial = [blk_info.blk.serial
                                         for blk_info in other_dispatcher.dispatcher_internal_blocks]
        return [self.mba.get_mblock(blk_serial) for blk_serial in my_dispatcher_block_serial
                if blk_serial in other_dispatcher_block_serial]

    def is_sub_dispatcher(self, other_dispatcher: "GenericDispatcherInfo") -> bool:
        shared_blocks = self.get_shared_internal_blocks(other_dispatcher)
        if (len(shared_blocks) > 0) and (self.entry_block.blk.npred() < other_dispatcher.entry_block.blk.npred()):
            return True
        return False

    def should_emulation_continue(self, cur_blk: mblock_t) -> bool:
        exit_block_serial_list = [exit_block.serial for exit_block in self.dispatcher_exit_blocks]
        if (cur_blk is not None) and (cur_blk.serial not in exit_block_serial_list):
            return True
        return False

    def print_info(self, verbose=False):
        unflat_logger.info("Dispatcher information: ")
        unflat_logger.info("  Entry block: {0}.{1}: ".format(self.entry_block.blk.serial,
                                                             format_minsn_t(self.entry_block.blk.tail)))
        unflat_logger.info("  Entry block predecessors: {0}: "
                           .format([blk_serial for blk_serial in self.entry_block.blk.predset]))
        unflat_logger.info("    Compared mop: {0} ".format(format_mop_t(self.mop_compared)))
        unflat_logger.info("    Comparison values: {0} ".format(", ".join([hex(x) for x in self.comparison_values])))
        self.entry_block.print_info()
        unflat_logger.info("  Number of internal blocks: {0} ({1})"
                           .format(len(self.dispatcher_internal_blocks),
                                   [blk_info.blk.serial for blk_info in self.dispatcher_internal_blocks]))
        if verbose:
            for disp_blk in self.dispatcher_internal_blocks:
                unflat_logger.info("    Internal block: {0}.{1} ".format(disp_blk.blk.serial,
                                                                         format_minsn_t(disp_blk.blk.tail)))
                disp_blk.show_history()
        unflat_logger.info("  Number of Exit blocks: {0} ({1})"
                           .format(len(self.dispatcher_exit_blocks),
                                   [blk_info.blk.serial for blk_info in self.dispatcher_exit_blocks]))
        if verbose:
            for exit_blk in self.dispatcher_exit_blocks:
                unflat_logger.info("    Exit block: {0}.{1} ".format(exit_blk.blk.serial,
                                                                     format_minsn_t(exit_blk.blk.head)))
                exit_blk.show_history()



import ida_hexrays as hr

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
        mba_count = self.mba.qty -1
        if mba_count < block_info.serial:
            raise RuntimeError("self.mba.qty > block_info.serial")
        if mba_count == block_info.serial:
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