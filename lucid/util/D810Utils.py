import logging
from typing import List, Tuple

import ida_hexrays
import ida_idp
from d810.generic import GenericDispatcherInfo
from d810.generic import GenericDispatcherBlockInfo
from d810.hexrays_helpers import append_mop_if_not_in_list, extract_num_mop, CONTROL_FLOW_OPCODES
from d810.hexrays_hooks import InstructionDefUseCollector
from d810.symbolic_expr import ExprInt

from ida_hexrays import mblock_t, mop_t, optblock_t, minsn_visitor_t, mbl_array_t
import ida_hexrays as hr
import ida_kernwin as kw

from d810.emulator import symb_log, SymbolicMicroCodeInterpreter, SymbolicMicroCodeEnvironment
from ida_idp import reg_info_t, parse_reg_name

symb_log.setLevel(logging.DEBUG)

from d810.tracker import MopTracker
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


def UnFlaInfo(mba, dispatch_block):
    # import pydevd_pycharm
    # pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)

    print("dispatch_block serial:", hex(dispatch_block.serial))
    blk_preset_list = [x for x in dispatch_block.predset]
    print("dispatch_block father list:", blk_preset_list)

    def dfs(current_node, target_node, path, paths, visited):
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

    dfs(dispatch_block, dispatch_block, [], paths, set())

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

        target_blk, disp_ins = dispatch_info.emulate_dispatcher_with_father_history(father_histories[0])
        if target_blk is not None:
            print("Unflattening graph: Making {0} goto {1}"
                  .format(dispatcher_father_serial, target_blk.serial))

        # father_histories_cst = get_all_possibles_values(father_histories, dispatch_info.entry_block.use_before_def_list,verbose=False)
        # Const_Hex_str=""
        # for list1 in father_histories_cst:
        #     for print_const in list1:
        #         Const_Hex_str =  Const_Hex_str+hex(print_const)+":"
        # print("father_block:{0}:{1}".format(dispatcher_father_serial,Const_Hex_str))

    for path in paths:
        print("path:", path)


def get_mop_key(op) -> str:
    """规整化 mop 的物理特征，作为唯一比对键"""
    if op.t == ida_hexrays.mop_r:
        return f"reg_{op.r}"  # 绑定寄存器编号，无视访问大小和对象实例差异
    elif op.t == ida_hexrays.mop_S:
        return f"stk_{op.s.off}_{op.dstr()}"
    return op.dstr()


def get_block_top_level_inputs_for_mop(mblock) -> list:
    """
    判断块最后一条指令是否是条件跳转。
    如果不是，直接返回空列表。
    如果是，向上追踪影响条件跳转变量的顶层输入。
    """
    if not mblock:
        return []

    # 检查最后一条指令是否是条件跳转
    last_insn = mblock.tail

    # 判断是否是条件跳转指令
    if (last_insn is None) or (not ida_hexrays.is_mcode_jcond(last_insn.opcode)):
        # 不是条件跳转，直接返回
        print(f"--- Block {mblock.serial} 最后一条指令不是条件跳转，跳过 ---")
        return []

    # 收集条件跳转使用的变量
    collector = InstructionDefUseCollector()
    last_insn.for_all_ops(collector)

    condition_uses = collector.unresolved_ins_mops + collector.memory_unresolved_ins_mops

    if not condition_uses:
        print(f"--- Block {mblock.serial} 条件跳转没有使用变量 ---")
        return []

    print(f"--- 条件跳转使用的变量: {[op.dstr() for op in condition_uses]} ---")

    # 追踪列表：{key: mop对象}
    tracking_vars = {}

    for use_mop in condition_uses:
        key = get_mop_key(use_mop)
        tracking_vars[key] = use_mop

    # 从倒数第二条指令开始向前遍历
    insn = last_insn.prev
    while insn:
        collector = InstructionDefUseCollector()
        insn.for_all_ops(collector)

        current_defs = collector.target_mops
        current_uses = collector.unresolved_ins_mops + collector.memory_unresolved_ins_mops

        # 检查当前指令是否定义了追踪变量
        for def_mop in current_defs:
            if def_mop.t in [ida_hexrays.mop_r, ida_hexrays.mop_S, ida_hexrays.mop_v]:
                def_key = get_mop_key(def_mop)

                # 如果定义了追踪变量，移除它，并加入当前指令的输入
                if def_key in tracking_vars:
                    del tracking_vars[def_key]

                    # 将当前指令的输入加入追踪
                    for use_mop in current_uses:
                        use_key = get_mop_key(use_mop)
                        if use_key not in tracking_vars:
                            tracking_vars[use_key] = use_mop

        insn = insn.prev

    top_inputs = list(tracking_vars.values())
    print(f"--- Block {mblock.serial} 影响条件跳转的顶层输入数量: {len(top_inputs)} ---")
    return top_inputs



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
    return top_inputs


def eval_blk( current_block, environment_values):
    print("eval_blk serial:", hex(current_block.serial))
    microcode_interpreter = SymbolicMicroCodeInterpreter()
    microcode_environment = SymbolicMicroCodeEnvironment()
    for mop_obj, val in environment_values.items():
        print(f" -> [原始微码 MOP] 对象名字: {mop_obj.dstr()} 对应的修补值: {val}")
        if val != "None":
            microcode_environment.define(mop_obj, ExprInt(val, mop_obj.size))
    cur_blk = current_block
    cur_ins = current_block.head
    while cur_ins is not None:
        print(cur_ins.dstr())
        microcode_interpreter.eval_instruction(cur_blk, cur_ins, microcode_environment)
        cur_ins = cur_ins.next
    microcode_environment.dump()
    next_blk = microcode_environment.next_blk
    if isinstance(next_blk, hr.mblock_t):
        print("next_blk", next_blk.serial)
    else:
        print("next_blk", next_blk)
