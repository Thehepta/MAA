import logging
from typing import List, Tuple

from d810.emulator import MicroCodeInterpreter, MicroCodeEnvironment
from d810.hexrays_formatters import format_minsn_t, format_mop_list, format_mop_t
from d810.hexrays_helpers import append_mop_if_not_in_list, get_mop_index, CONDITIONAL_JUMP_OPCODES, extract_num_mop
from d810.hexrays_hooks import InstructionDefUseCollector
from d810.tracker import remove_segment_registers, MopHistory
from ida_hexrays import mop_t, minsn_t, mblock_t, mbl_array_t

from d810.utils import NotResolvableFatherException

unflat_logger = logging.getLogger('D810.unflat')


class GenericDispatcherBlockInfo(object):

    def __init__(self, blk, father=None):
        self.blk = blk
        self.ins = []
        self.use_list = []
        self.use_before_def_list = []
        self.def_list = []
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

    def emulate_dispatcher_with_father_history(self, father_history: MopHistory) -> Tuple[mblock_t, List[minsn_t]]:
        microcode_interpreter = MicroCodeInterpreter()
        microcode_environment = MicroCodeEnvironment()
        dispatcher_input_info = []
        # First, we setup the MicroCodeEnvironment with the state variables (self.entry_block.use_before_def_list)
        # used by the dispatcher
        for initialization_mop in self.entry_block.use_before_def_list:
            # We recover the value of each state variable from the dispatcher father
            initialization_mop_value = father_history.get_mop_constant_value(initialization_mop)
            if initialization_mop_value is None:
                raise NotResolvableFatherException("Can't emulate dispatcher {0} with history {1}"
                                                   .format(self.entry_block.serial, father_history.block_serial_path))
            # We store this value in the MicroCodeEnvironment
            microcode_environment.define(initialization_mop, initialization_mop_value)
            dispatcher_input_info.append("{0} = {1:x}".format(format_mop_t(initialization_mop),
                                                              initialization_mop_value))

        unflat_logger.info("Executing dispatcher {0} with: {1}"
                           .format(self.entry_block.blk.serial, ", ".join(dispatcher_input_info)))

        # Now, we start the emulation of the code at the dispatcher entry block
        instructions_executed = []
        cur_blk = self.entry_block.blk
        cur_ins = cur_blk.head
        # We will continue emulation while we are in one of the dispatcher blocks
        while self.should_emulation_continue(cur_blk):
            unflat_logger.debug("  Executing: {0}.{1}".format(cur_blk.serial, format_minsn_t(cur_ins)))
            # We evaluate the current instruction of the dispatcher to determine
            # which block and instruction should be executed next
            is_ok = microcode_interpreter.eval_instruction(cur_blk, cur_ins, microcode_environment)
            if not is_ok:
                return cur_blk, instructions_executed
            instructions_executed.append(cur_ins)
            cur_blk = microcode_environment.next_blk
            cur_ins = microcode_environment.next_ins
        # We return the first block executed which is not part of the dispatcher
        # and all instructions which have been executed by the dispatcher
        return cur_blk, instructions_executed

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

