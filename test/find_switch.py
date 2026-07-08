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
from d810.generic import GenericDispatcherInfo
from d810.generic import GenericDispatcherBlockInfo
from d810.hexrays_formatters import format_mop_t, format_minsn_t
from d810.hexrays_helpers import append_mop_if_not_in_list, extract_num_mop, CONTROL_FLOW_OPCODES, \
    equal_mops_ignore_size
from d810.tracker import duplicate_histories
from d810.utils import get_mop_name

from ida_hexrays import mblock_t, mop_t, optblock_t, minsn_visitor_t, mbl_array_t,get_mreg_name
import ida_hexrays as hr
import ida_kernwin as kw
import traceback
import ida_dbg

FLATTENING_JUMP_OPCODES = [hr.m_jnz, hr.m_jz, hr.m_jae, hr.m_jb, hr.m_ja, hr.m_jbe, hr.m_jg, hr.m_jge, hr.m_jl,
                           hr.m_jle]

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
        self.mba = None
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


class SymbolExecHistory:

    def __init__(self):
        self.history_blk = []

        self._initial_environment = SymbolicMicroCodeEnvironment()

    def get_copy(self) -> "SymbolExecHistory":
        new_history = SymbolExecHistory()
        new_history.history = [x for x in self.history_blk]
        new_history._initial_environment = self._initial_environment.get_copy()

        return new_history

    @property
    def initial_environment(self):
        return self._initial_environment


class SwitchFind(object):


    def __init__(self):
        self.history = SymbolExecHistory()

    def is_resolved(self):
        pass

    def exec_branch(self,current_block):

        cur_blk = current_block
        microcode_interpreter = SymbolicMicroCodeInterpreter()
        while not self.is_resolved():
            microcode_interpreter.eval_blk(cur_blk, self.history.initial_environment)
            if cur_blk.npred() > 1:
                return cur_blk
            elif cur_blk.npred() == 0:
                return None
            else:
                cur_blk = cur_blk.mba.get_mblock(cur_blk.predset[0])


    def SwitchParse(self,dispatch_blk):

        blk_with_multiple_pred = self.exec_branch(dispatch_blk)
        if self.is_resolved():
            return [self.history]

        possible_histories = []
        for blk_pred_serial in blk_with_multiple_pred.predset:
            possible_histories += self.SwitchParse(self.mba.get_mblock(blk_pred_serial))
        return possible_histories






def find_all_paths_from_dispatch(dispatch_block):
    """
    从调度块开始，先序遍历所有路径，边遍历边符号执行。
    终止条件：当前块执行后新产生的未定义变量，能在执行前的环境中找到。
    错误检测：如果路径交叉（一个块被多条路径访问），报错退出。

    @param dispatch_block: 调度块
    @return: [(path, environment), ...] 路径和对应的符号执行环境
    """

    if not dispatch_block:
        return []

    # 记录所有已访问的块（用于检测交叉）
    visited_blocks = set()

    res = []
    interpreter = SymbolicMicroCodeInterpreter()

    # 初始环境，先执行调度块
    initial_env = SymbolicMicroCodeEnvironment()
    interpreter.eval_blk(dispatch_block, initial_env)
    visited_blocks.add(dispatch_block.serial)

    # 栈元素: (当前块, 路径, 累积的符号执行环境)
    stack = [(dispatch_block, [dispatch_block.serial], initial_env)]

    while stack:
        node, path, env = stack.pop()

        # 检查后继块
        has_valid_successor = False
        for succ_serial in node.succset:
            # 避免环路（同一条路径内）
            if succ_serial in path:
                continue

            # 检测交叉：如果这个块已经被其他路径访问过
            if succ_serial in visited_blocks:
                raise RuntimeError(
                    f"路径交叉错误：块 {succ_serial} 被多条路径访问！\n"
                    f"当前路径: {' -> '.join(map(str, path))}\n"
                    f"从调度块向下的节点不应该交叉。"
                )

            # 保存之前累积的环境
            prev_env = env

            # 用干净的环境执行当前块（不累积）
            block_env = SymbolicMicroCodeEnvironment()
            succ_block = node.mba.get_mblock(succ_serial)
            interpreter.eval_blk(succ_block, block_env)
            print("current:", succ_block.serial)
            # 检查终止条件：当前块的未定义变量是否能在之前累积的环境中找到
            # if block_env.irdst.is_cond() is False:
            #     continue
            can_terminate = False
            if block_env.mop_undefind:  # 当前块的未定义变量
                for mop_expr in block_env.mop_undefind:
                    print("mop_expr current:",succ_block.serial)
                    mop = mop_expr.get_mop()
                    # 在之前累积的环境中查找
                    found_in_define = prev_env.lookup(mop, create_symbol=False) is not None
                    found_in_undefind = any( equal_mops_ignore_size(h_mop_expr.get_mop(),mop) for h_mop_expr in prev_env.mop_undefind)

                    # 如果这个未定义变量在之前环境中找不到，终止这条路径
                    if not (found_in_define or found_in_undefind):
                        can_terminate = True
                        break

            if block_env.irdst.is_cond() is False:
                can_terminate = True
            # 如果终止了，不再继续向下
            if can_terminate:
                new_env = prev_env.get_copy()
                interpreter.eval_blk(succ_block, new_env)
                res.append((path + [succ_serial], new_env))
                # print(f"  路径 {' -> '.join(map(str, path + [succ_serial]))} "
                #       f"终止：发现未定义变量 {mop_expr.name} 在之前的环境中找不到")
                continue


            # 继续向下执行：合并环境
            new_env = prev_env.get_copy()
            interpreter.eval_blk(succ_block, new_env)
            visited_blocks.add(succ_serial)
            stack.append((succ_block, path + [succ_serial], new_env))
            has_valid_successor = True

        # 如果没有有效后继（死路），也记录
        if not has_valid_successor and len(node.succset) == 0:
            res.append((path, env))

    return res




def UnFlaInfo(mba):
    # import pydevd_pycharm
    # pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)

    # 找到前驱最多的块作为调度块
    dispatch_npred = -1
    dispatch_block = None
    for blk_idx in range(mba.qty):
        blk = mba.get_mblock(blk_idx)
        npred = blk.npred()
        if dispatch_npred < npred:
            dispatch_npred = npred
            dispatch_block = blk

    print("=" * 60)
    print(f"调度块: {dispatch_block.serial}")
    print(f"调度块前驱: {list(dispatch_block.predset)}")

    # 从调度块开始遍历所有路径并符号执行
    path_environments = find_all_paths_from_dispatch(dispatch_block)
    print(f"\n找到 {len(path_environments)} 条路径")

    # 打印每条路径的符号执行结果
    for i, (path, env) in enumerate(path_environments):
        print(f"\n--- 路径 {i}: {' -> '.join(map(str, path))} ---")

        # 打印最终跳转目标
        if env.irdst:
            print(f"  irdst: {env.irdst}")

        # # 打印未定义的变量
        # if env.mop_undefind:
        #     print(f"  未定义变量: {len(env.mop_undefind)} 个")
        #     for mop_expr in env.mop_undefind[:3]:
        #         print(f"    - {mop_expr.name}")
        #     if len(env.mop_undefind) > 3:
        #         print(f"    ... 还有 {len(env.mop_undefind) - 3} 个")

    print("=" * 60)
    return path_environments  # 返回 [(path, environment), ...]


    # SwitchParse(mba)

    # dispatch_info = D810OllvmDispatcherInfo(mba)
    # if not dispatch_info.explore(dispatch_block):
    #     print("set dispatch failed, dispatch_info->explore is False")
    #     return
    #
    # dispatcher_internal_blocks = [x.serial for x in dispatch_info.dispatcher_internal_blocks]
    # print("dispatcher_internal_blocks:", dispatcher_internal_blocks)
    # end_block_nums = set(Gdbi.blk for Gdbi in dispatch_info.dispatcher_exit_blocks)
    # all_paths = find_all_paths_dfs(dispatch_info.entry_block.blk, end_block_nums)
    # print(len(all_paths))
    #
    # unflaSwitch = ollvmflaSwitch()
    # for paths in all_paths:
    #     unflacase = ollvmflaCase(paths, blk.mba)
    #     unflacase.parse()
    #     unflaSwitch.add_case(unflacase)
    # unflaSwitch.dump()
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
