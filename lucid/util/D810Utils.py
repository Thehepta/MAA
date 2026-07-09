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
    return microcode_environment.mop_undefind
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
        microcode_environment.defineExpr(mopExpr, ExprInt(value_int, mopExpr.size))
    microcode_interpreter.eval_blk(current_block, microcode_environment)
    microcode_environment.dump(log.console_logger)


def eva_blks(start_block, microcode_environment: SymbolicMicroCodeEnvironment,
             max_blocks: int = 1000):
    """
    跨多个基本块做符号执行，并累积路径约束。

    以单块执行 eva_blk 为基本步，按块尾的 irdst 决定下一块：
      - 具体跳转 ExprInt：直接跟随到该块；
      - 符号条件跳转 ExprCond：选择 fallthrough(src_false) 边继续，
        同时调用 add_path_condition 记录"该条件不成立"的约束；
      - 其它（间接/符号目标）或无 irdst：停止。

    用 visited 检测回边(back-edge)，避免在含循环的混淆 CFG 上死循环。
    执行结束后 microcode_environment.path_conditions 即整条路径必须同时
    满足的约束集合（合取）。
    """
    if microcode_environment is None:
        microcode_environment = SymbolicMicroCodeEnvironment()
    microcode_interpreter = SymbolicMicroCodeInterpreter()

    cur_blk = start_block
    visited = set()
    count = 0

    while cur_blk is not None and count < max_blocks:
        count += 1
        if cur_blk.serial in visited:
            print("Back-edge to block {0}, stopping".format(cur_blk.serial))
            break
        visited.add(cur_blk.serial)

        microcode_interpreter.eval_blk(cur_blk, microcode_environment)
        irdst = microcode_environment.irdst

        if irdst is None:
            # 块尾不是控制流指令：自然 fallthrough 到 serial+1
            cur_blk = cur_blk.mba.get_mblock(cur_blk.serial + 1)
            continue

        if irdst.is_int():
            cur_blk = cur_blk.mba.get_mblock(irdst.as_int())
            continue

        if irdst.is_cond():
            # 符号条件分支：选择 fallthrough 边，并累积"条件不成立"的约束
            microcode_environment.add_path_condition(irdst.cond, taken=False)
            fallthrough_false = irdst.src_false
            if not fallthrough_false.is_int():
                print("Symbolic fallthrough target {0}, stopping".format(fallthrough_false))
                break
            cur_blk = cur_blk.mba.get_mblock(fallthrough_false.as_int())

            microcode_environment.add_path_condition(irdst.cond, taken=True)
            fallthrough_true = irdst.src_true
            if not fallthrough_true.is_int():
                print("Symbolic fallthrough target {0}, stopping".format(fallthrough_true))
                break
            cur_blk = cur_blk.mba.get_mblock(fallthrough_true.as_int())

            continue

        # 间接/符号跳转目标：无法解析，停止
        print("Unresolvable jump target {0}, stopping".format(irdst))
        break

    return microcode_environment

def show_insn_info(ins):

    print("op:{0}     type:{1} content:{2}".format(opcode_to_string(ins.opcode), type(ins.opcode), ins.opcode))
    print("insn.l:{0} type:{1} content:{2}".format(ins.l.dstr(), mop_type_to_string(ins.l.t),
                                                    get_mop_content(ins.l)))
    print("insn.r:{0} type:{1} content:{2}".format(ins.r.dstr(), mop_type_to_string(ins.r.t),
                                                    get_mop_content(ins.r)))
    print("insn.d:{0} type:{1} content:{2}".format(ins.d.dstr(), mop_type_to_string(ins.d.t),
                                                    get_mop_content(ins.d)))