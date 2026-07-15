import logging
from typing import List, Tuple

import ida_bytes
import ida_funcs
import ida_ida
import ida_range
# from d810.emulator import MicroCodeInterpreter, MicroCodeEnvironment
from d810 import tracker, utils
from d810.Environment import SymbolicMicroCodeEnvironment
from d810.Expr import walk_expr_iter, ExprId, ExprInt, Expr
from d810.ExprSimplifier import get_branch_condition,simplify
from d810.Interpreter import SymbolicMicroCodeInterpreter
from d810.generic import D810OllvmDispatcherInfo
from d810.hexrays_formatters import format_mop_t, format_minsn_t, mop_type_to_string
from d810.hexrays_helpers import append_mop_if_not_in_list, extract_num_mop, CONTROL_FLOW_OPCODES, get_mop_index
from d810.tracker import duplicate_histories
from d810.utils import get_mop_name

import ida_hexrays as hr
import ida_kernwin as kw
import traceback

utils.enable_console_log(tracker.logger)


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
            tmp_path = path.copy()
            tmp_path.append(current_num)
            print(f"到达终点 {current_num}, 路径: {tmp_path}")  # 调试输出
            all_paths.append(tmp_path)
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


def find_all_paths_dfs2(start_block, end_blocks):
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

class ollvmflaCase(object):

    def __init__(self,paths,mba):
        self.path_conds = []
        self.dst_blk =None
        self.depends = []
        self.paths = paths
        self.mba = mba

    def parse(self):
        microcode_environment = SymbolicMicroCodeEnvironment()
        microcode_interpreter = SymbolicMicroCodeInterpreter()
        for idx, item in enumerate(self.paths):

            has_next = idx != len(self.paths) - 1
            if has_next is False:
                break
            blk = self.mba.get_mblock(item)
            microcode_interpreter.eval_blk(blk, microcode_environment)
            next_blk = self.paths[idx + 1]
            target_expr = ExprInt(next_blk, 4)
            jump_cond = get_branch_condition(microcode_environment.irdst, target_expr)
            self.path_conds.append(jump_cond)
            self.dst_blk = next_blk
            exprs = list(walk_expr_iter(microcode_environment.irdst))
            for expr in exprs:
                if expr.is_mopid():
                    self.depends.append(expr)


    def is_satisfy(self, mop_def_list):

        replacement_map = {}
        for dep_mop in self.depends:
            value_expr = mop_def_list[dep_mop]
            replacement_map[dep_mop] = value_expr

        for cond in self.path_conds:
            # 替换
            replaced = cond.replace(replacement_map)
            # 化简
            simplified = simplify(replaced)
            # 检查是否为 True (值为 1)
            if not simplified.is_int() or simplified.as_int() != 1:
                return False  # 有约束不满足

        return True  # 所有约束都满足


class ollvmflaSwitch(object):

    def __init__(self):
        self.switch_status = []
        self.cases = []

    def add_case(self,case:ollvmflaCase):
        self.cases.append(case)
        for mop_expr in case.depends:
            append_mop_if_not_in_list(mop_expr.get_mop(), self.switch_status)

    def get_real_blk(self,mop_def_list):
        for case in self.cases:
            if case.is_satisfy(mop_def_list) is True:
                return case.dst_blk
        return -1

    def dump(self):
        print("ollvmflaSwitch dump")
        for mop_used in self.switch_status:
            name = get_mop_name(mop_used)
            print("switch status:  {0}".format(name))

        for case in self.cases:
            print(case.dst_blk)
            for path_cond in case.path_conds:
                print(path_cond)


def UnFlaInfo(mba):
    # import pydevd_pycharm
    # pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)
    # print("dispatch_block serial:", hex(dispatch_block.serial))
    # blk_preset_list = [x for x in dispatch_block.predset]
    # print("dispatch_block father list:", blk_preset_list)

    dispatch_npred = -1
    dispatch_block = None
    for blk_idx in range(mba.qty):
        blk = mba.get_mblock(blk_idx)
        npred = blk.npred()
        if dispatch_npred < npred:
            dispatch_npred = npred
            dispatch_block = blk
    print("dispatch_block:",dispatch_block.serial)

    dispatch_info = D810OllvmDispatcherInfo(mba)
    if not dispatch_info.explore(dispatch_block):
        print("set dispatch failed, dispatch_info->explore is False")
        return

    dispatcher_internal_blocks = [x.serial for x in dispatch_info.dispatcher_internal_blocks]
    print("dispatcher_internal_blocks:", dispatcher_internal_blocks)
    end_block_nums = set(Gdbi.blk for Gdbi in dispatch_info.dispatcher_exit_blocks)
    all_paths = find_all_paths_dfs(dispatch_info.entry_block.blk, end_block_nums)
    print("all_paths len",len(all_paths))

    unflaSwitch = ollvmflaSwitch()
    for paths in all_paths:
        unflacase = ollvmflaCase(paths, blk.mba)
        unflacase.parse()
        unflaSwitch.add_case(unflacase)
    unflaSwitch.dump()
    #
    # for dispatcher_father_serial in dispatch_block.predset:
    #     father_tracker = tracker.MopTracker(unflaSwitch.switch_status, max_nb_block=100, max_path=100)
    #     father_tracker.reset()
    #     dispatcher_father_block = mba.get_mblock(dispatcher_father_serial)
    #     print("MopTracker block:{0}".format(dispatcher_father_serial))
    #     father_histories = father_tracker.search_backward(dispatcher_father_block, None,[dispatch_block.serial])
    #     if len(father_histories) > 1:
    #         nb_duplication, nb_change = duplicate_histories(father_histories)
    #         print("father_block:{0} is  multiple branches".format(dispatcher_father_serial))
    #         # for history in father_histories:
    #         #     if history.is_resolved() is True:
    #         #         history.print_info()
    #                 # target_blk = unflaSwitch.get_real_blk(history._current_environment.mop_define)
    #                 # print("target_blk:",target_blk)
    #     else:
    #         if len(father_histories) == 1:
    #             if father_histories[0].is_resolved() is True:
    #                 father_histories[0].print_info()
    #                 target_blk = unflaSwitch.get_real_blk(father_histories[0]._current_environment.mop_define)
    #                 print("target_blk:",target_blk)
    #         else:
    #             print("father_block:{0} is  len = 0".format(dispatcher_father_serial))
    #     try:
    #         # 还原,分发器到分发器的前驱这条代码路径的混淆
    #         for cur_history in father_histories:
    #             print("emulate_dispatcher:{0}".format( cur_history))
    #             target_blk, disp_ins = dispatch_info.emulate_dispatcher_with_father_history(cur_history)
    #             if target_blk is not None:
    #                 print("Unflattening graph: Making {0} goto {1}".format(dispatcher_father_serial, target_blk.serial))
    #     except NotResolvableFatherException as e:
    #         print("NotResolvableFatherException")
    #
    #     father_histories_cst = get_all_possibles_values(father_histories, dispatch_info.entry_block.use_before_def_list,
    #                                                     verbose=False)
    #     # Const_Hex_str = ""
    #     # for list1 in father_histories_cst:
    #     #     for print_const in list1:
    #     #         Const_Hex_str = Const_Hex_str + hex(print_const) + ":"
    #     print("father_block:{0}:{1}".format(dispatcher_father_serial, father_histories_cst))
    #
    # for path in paths:
    #     print("path:", path)


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
