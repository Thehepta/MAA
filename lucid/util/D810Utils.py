from typing import List, Tuple

import ida_hexrays
from d810.Environment import SymbolicMicroCodeEnvironment
from d810.Interpreter import SymbolicMicroCodeInterpreter
from d810.generic import D810OllvmDispatcherInfo
from d810.hexrays_formatters import opcode_to_string, mop_type_to_string, get_mop_content
from d810.InsnCollector import InstructionDefUseCollector
from d810.Expr import ExprInt

from d810.tracker import MopTracker
from lucid.util import log


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


def get_block_top_level_inputs(current_block) -> list:
    microcode_interpreter = SymbolicMicroCodeInterpreter()
    microcode_environment = SymbolicMicroCodeEnvironment()
    microcode_interpreter.eval_blk(current_block,microcode_environment)
    # microcode_environment.dump(log.console_logger)
    return microcode_environment.mop_undefinde
# def get_block_top_level_inputs(mblock) -> list:
#     entry_block = GenericDispatcherBlockInfo(mblock)
#     entry_block.parse()
#     return entry_block.use_before_def_list


def eval_current_blk(current_block, environment_values: dict):
    """
    @param environment_values: {mop_t: int_value} 字典
    """
    microcode_interpreter = SymbolicMicroCodeInterpreter()
    microcode_environment = SymbolicMicroCodeEnvironment()
    for mopExpr, value_int in environment_values.items():
        microcode_environment.define(mopExpr.get_mop(), ExprInt(value_int, mopExpr.size))
    microcode_interpreter.eval_blk(current_block, microcode_environment)
    microcode_environment.dump(log.console_logger)


def eva_blks(mba, start_blk_serial, end_blk_serial, max_blocks: int = 1000):
    """
    跨多个基本块做符号执行，并累积路径约束。

    先使用 BFS 计算从 start_blk_serial 到 end_blk_serial 的路径，
    然后沿着这条路径顺序执行符号解释器。

    执行结束后 microcode_environment.path_conditions 即整条路径必须同时
    满足的约束集合（合取）。
    """
    from collections import deque

    # 使用 BFS 找到从 start_blk_serial 到 end_blk_serial 的路径
    def find_path(start_serial, end_serial):
        if start_serial == end_serial:
            return [start_serial]

        queue = deque([(start_serial, [start_serial])])
        visited = {start_serial}

        while queue:
            current_serial, path = queue.popleft()
            current_blk = mba.get_mblock(current_serial)

            # 遍历所有后继块
            for succ_serial in current_blk.succset:
                if succ_serial == end_serial:
                    return path + [succ_serial]

                if succ_serial not in visited:
                    visited.add(succ_serial)
                    queue.append((succ_serial, path + [succ_serial]))

        return None  # 未找到路径

    # 计算路径
    path = find_path(start_blk_serial, end_blk_serial)
    if path is None:
        print("No path found from block {0} to block {1}".format(start_blk_serial, end_blk_serial))
        return None

    print("Found path: {0}".format(path))

    # 沿着路径执行符号解释
    microcode_environment = SymbolicMicroCodeEnvironment()
    microcode_interpreter = SymbolicMicroCodeInterpreter()

    for blk_serial in path:
        if blk_serial >= mba.qty:
            print("Block {0} out of range".format(blk_serial))
            break

        cur_blk = mba.get_mblock(blk_serial)
        microcode_interpreter.eval_blk(cur_blk, microcode_environment)

    microcode_environment.dump(log.console_logger)

def show_insn_info(ins,blk):

    print("op:{0}     type:{1} content:{2}".format(opcode_to_string(ins.opcode), type(ins.opcode), ins.opcode))
    print("insn.l:{0} type:{1} content:{2} valnum:{3}".format(ins.l.dstr(), mop_type_to_string(ins.l.t),
                                                    get_mop_content(ins.l),ins.l.valnum))
    print("insn.r:{0} type:{1} content:{2} valnum:{3}".format(ins.r.dstr(), mop_type_to_string(ins.r.t),
                                                    get_mop_content(ins.r),ins.r.valnum))
    print("insn.d:{0} type:{1} content:{2} valnum:{3}".format(ins.d.dstr(), mop_type_to_string(ins.d.t),
                                                    get_mop_content(ins.d),ins.d.valnum))