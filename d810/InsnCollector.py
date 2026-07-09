import logging
from ida_hexrays import *
from d810.hexrays_helpers import append_mop_if_not_in_list
from d810.hexrays_formatters import format_mop_t, mop_type_to_string

helper_logger = logging.getLogger('D810.helper')


class InstructionDefUseCollector(mop_visitor_t):
    def __init__(self):
        super().__init__()
        self.unresolved_ins_mops = []
        self.memory_unresolved_ins_mops = []
        self.target_mops = []

    def visit_mop(self, op: mop_t, op_type: int, is_target: bool):
        if is_target:
            append_mop_if_not_in_list(op, self.target_mops)
        else:
            # TODO whatever the case, in the end we will always return 0. May be this code can be better optimized.
            # TODO handle other special case (e.g. ldx ins, ...)
            if op.t == mop_S:
                append_mop_if_not_in_list(op, self.unresolved_ins_mops)
            elif op.t == mop_r:
                append_mop_if_not_in_list(op, self.unresolved_ins_mops)
            elif op.t == mop_v:
                append_mop_if_not_in_list(op, self.memory_unresolved_ins_mops)
            elif op.t == mop_a:
                if op.a.t == mop_v:
                    return 0
                elif op.a.t == mop_S:
                    return 0
                helper_logger.warning("Calling visit_mop with unsupported mop type {0} - {1}: '{2}'"
                                      .format(mop_type_to_string(op.t), mop_type_to_string(op.a.t), format_mop_t(op)))
                return 0
            elif op.t == mop_n:
                return 0
            elif op.t == mop_d:
                return 0
            elif op.t == mop_h:
                return 0
            elif op.t == mop_b:
                return 0
            else:
                helper_logger.warning("Calling visit_mop with unsupported mop type {0}: '{1}'"
                                      .format(mop_type_to_string(op.t), format_mop_t(op)))
        return 0


def get_mop_key(op) -> str:
    """规整化 mop 的物理特征，作为唯一比对键"""
    if op.t == mop_r:
        return f"reg_{op.r}"  # 绑定寄存器编号，无视访问大小和对象实例差异
    elif op.t == mop_S:
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
    if (last_insn is None) or (not is_mcode_jcond(last_insn.opcode)):
        # 不是条件跳转，直接返回
        print(f"--- Block {mblock.serial} 最后一条指令不是条件跳转，跳过 ---")
        return []

    # 收集条件跳转使用的变量
    collector = InstructionDefUseCollector()
    last_insn.for_all_ops(collector)

    ins_mop_info = collector.unresolved_ins_mops + collector.memory_unresolved_ins_mops
    condition_uses = remove_segment_registers(ins_mop_info.unresolved_ins_mops)

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
            if def_mop.t in [mop_r, mop_S, mop_v]:
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


def get_segment_register_indexes(mop_list: List[mop_t]) -> List[int]:
    # This is a very dirty and probably buggy
    segment_register_indexes = []
    for i, mop in enumerate(mop_list):
        if mop.t == mop_r:
            formatted_mop = format_mop_t(mop)
            if formatted_mop in ["ds.2", "cs.2", "es.2", "ss.2"]:
                segment_register_indexes.append(i)
    return segment_register_indexes


def remove_segment_registers(mop_list: List[mop_t]) -> List[mop_t]:
    # TODO: instead of doing that, we should add the segment registers to the (global?) emulation environment
    segment_register_indexes = get_segment_register_indexes(mop_list)
    if len(segment_register_indexes) == 0:
        return mop_list
    new_mop_list = []
    for i, mop in enumerate(mop_list):
        if i in segment_register_indexes:
            pass
        else:
            new_mop_list.append(mop)
    return new_mop_list
