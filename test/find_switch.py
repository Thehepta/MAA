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
from d810.ExprSimplifier import get_branch_condition, simplify, append_expr_if_not_in_list
from d810.Interpreter import SymbolicMicroCodeInterpreter
from d810.generic import GenericDispatcherInfo
from d810.generic import GenericDispatcherBlockInfo
from d810.hexrays_formatters import format_mop_t, format_minsn_t
from d810.hexrays_helpers import append_mop_if_not_in_list, extract_num_mop, CONTROL_FLOW_OPCODES, \
    equal_mops_ignore_size, make_reg
from d810.tracker import duplicate_histories
from d810.utils import get_mop_name, enable_console_log

from ida_hexrays import mblock_t, mop_t, optblock_t, minsn_visitor_t, mbl_array_t,get_mreg_name
import ida_hexrays as hr
import ida_kernwin as kw
import traceback
import ida_dbg

FLATTENING_JUMP_OPCODES = [hr.m_jnz, hr.m_jz, hr.m_jae, hr.m_jb, hr.m_ja, hr.m_jbe, hr.m_jg, hr.m_jge, hr.m_jl,
                           hr.m_jle]

utils.enable_console_log(tracker.logger)


class ollvmflaCase(object):

    def __init__(self,paths,dst_blk,path_conds):
        self.path_conds = path_conds
        self.dst_blk = dst_blk
        self.paths = paths

    def is_satisfy(self, mop_def_list):

        for cond in self.path_conds:
            # 替换
            replaced = cond.replace(mop_def_list)
            # 化简
            simplified = simplify(replaced)
            # 检查是否为 True (值为 1)
            if not simplified.is_int() or simplified.as_int() != 1:
                return False  # 有约束不满足

        return True  # 所有约束都满足


class ollvmflaSwitch(object):

    def __init__(self,mba):
        self.switch_status = []
        self.cases = []
        self.mba = mba
        self.dis_patch_blk = None
        self.dispatcher_internal_blocks = []
        self.dispatcher_exit_blocks = []
        
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

    def explore(self):
        dispatch_blk = self.get_dispath_blk()
        path_environments = self.find_all_paths_from_dispatch(dispatch_blk)
        print(f"\n找到 {len(path_environments)} 条路径")

        # 打印每条路径的符号执行结果
        for i, (path, env) in enumerate (path_environments):
            ofc = ollvmflaCase(path,path[-1],env.his_path_cond)
            self.cases.append(ofc)
            for his_cond in env.his_path_cond:
                his_exprs = list(walk_expr_iter(his_cond))
                for expr in his_exprs:
                    if expr.is_mopid():
                        append_mop_if_not_in_list(expr.get_mop(),self.switch_status)

        for mop in self.switch_status:
            print(mop.dstr())

    def get_dispath_blk(self):
        if self.dis_patch_blk is None:
            dispatch_npred = -1
            dispatch_block = None
            for blk_idx in range(self.mba.qty):
                blk = self.mba.get_mblock(blk_idx)
                npred = blk.npred()
                if dispatch_npred < npred:
                    dispatch_npred = npred
                    dispatch_block = blk
            self.dis_patch_blk = dispatch_block
        return self.dis_patch_blk

    def getSymbolicMicroCodeEnvironment(self):
        initial_env = SymbolicMicroCodeEnvironment()
        # mop_x25 = make_reg(208,8)
        # initial_env.define(mop_x25, ExprInt(0xC710C75845A867BC, 8))
        # mop_x26 = make_reg(216,8)
        # initial_env.define(mop_x26, ExprInt(0x544A90BCC9ECFDA0, 8))
        # mop_x21 = make_reg(176,8)
        # initial_env.define(mop_x21, ExprInt(0x57DB78112D3789A3, 8))
        # mop_x24 = make_reg(200,8)
        # initial_env.define(mop_x24, ExprInt(0x930DC4B5EFE424D4, 8))
        # mop_x23 = make_reg(192,8)
        # initial_env.define(mop_x23, ExprInt(0xA012A46ED5CF616, 8))
        # mop_x28 = make_reg(232,8)
        # initial_env.define(mop_x28, ExprInt(0x89ACAA6D5B4F5508, 8))

        return initial_env

    def find_all_paths_from_dispatch(self,dispatch_block):
        """
        从调度块开始，先序遍历所有路径，边遍历边符号执行。
        终止条件：当前块执行后新产生的未定义变量，能在执行前的环境中找到。
        错误检测：如果路径交叉（一个块被多条路径访问），报错退出。

        @param dispatch_block: 调度块
        @return: [(path, environment), ...] 路径和对应的符号执行环境
        """
        try:
            if not dispatch_block:
                return []

            # 记录所有已访问的块（用于检测交叉）
            visited_blocks = set()

            res = []
            interpreter = SymbolicMicroCodeInterpreter()

            # 初始环境，先执行调度块
            initial_env = self.getSymbolicMicroCodeEnvironment()
            interpreter.eval_blk(dispatch_block, initial_env)
            visited_blocks.add(dispatch_block.serial)

            # 栈元素: (当前块, 路径, 累积的符号执行环境)
            stack = [(dispatch_block, [dispatch_block.serial], initial_env)]

            while stack:
                node, path, env = stack.pop()

                for succ_serial in node.succset:
                    # 避免环路（同一条路径内）
                    if succ_serial in path:
                        continue

                    # 检测交叉：如果这个块已经被其他路径访问过
                    if succ_serial in visited_blocks:
                        raise RuntimeError("analyzia dispatch failed")
                        continue

                    # 保存之前累积的环境
                    prev_env = env

                    # 用干净的环境执行当前块（不累积）
                    block_env = self.getSymbolicMicroCodeEnvironment()
                    succ_block = node.mba.get_mblock(succ_serial)
                    interpreter.eval_blk(succ_block, block_env)

                    # 检查终止条件：当前块的未定义变量是否能在之前累积的环境中找到
                    can_terminate = False
                    if block_env.mop_undefind:  # 当前块的未定义变量
                        for mop_expr in block_env.mop_undefind:
                            mop = mop_expr.get_mop()
                            # 在之前累积的环境中查找
                            found_in_define = prev_env.lookup(mop, create_undefind_symbol=False) is not None
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
                        self.dispatcher_exit_blocks.append(succ_serial)
                        # print(f"  路径 {' -> '.join(map(str, path + [succ_serial]))} "
                        #       f"终止：发现未定义变量 {mop_expr.name} 在之前的环境中找不到")
                        continue


                    # 继续向下执行：合并环境
                    new_env = prev_env.get_copy()
                    interpreter.eval_blk(succ_block, new_env)
                    visited_blocks.add(succ_serial)
                    stack.append((succ_block, path + [succ_serial], new_env))

                # 如果没有有效后继（死路），也记录
                if len(node.succset) == 0:
                    res.append((path, env))
            print("dispatcher_internal_blocks:",visited_blocks)
            print("dispatcher_exit_blocks:",self.dispatcher_exit_blocks)
            return res

        except RuntimeError as e:
            return None




def UnFlaInfo(mba):
    import pydevd_pycharm
    pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)

    ofs = ollvmflaSwitch(mba)
    ofs.explore()
    for dispatcher_father_serial in ofs.get_dispath_blk().predset:
        father_tracker = tracker.MopTracker(ofs.switch_status, max_nb_block=100, max_path=100)
        father_tracker.reset()
        dispatcher_father_block = mba.get_mblock(dispatcher_father_serial)
        father_histories = father_tracker.search_backward(dispatcher_father_block, None, [ofs.get_dispath_blk().serial])
        if len(father_histories) > 1:
            nb_duplication, nb_change = duplicate_histories(father_histories)
            print("fix father_block:{0} is  multiple branches".format(dispatcher_father_serial))
    for dispatcher_father_serial in ofs.get_dispath_blk().predset:
        father_tracker = tracker.MopTracker(ofs.switch_status, max_nb_block=100, max_path=100)
        father_tracker.reset()
        dispatcher_father_block = mba.get_mblock(dispatcher_father_serial)
        print("MopTracker block:{0}".format(dispatcher_father_serial))

        father_histories = father_tracker.search_backward(dispatcher_father_block, None, [ofs.get_dispath_blk().serial])
        if len(father_histories) == 1:
            if father_histories[0].is_resolved() is True:

                father_histories[0]._execute_microcode()
                target_blk = ofs.get_real_blk(father_histories[0]._current_environment.mop_define)
                print("target_blk:",target_blk)
            else:
                print("can not is_resolved")
        else:
            print("father_block:{0} is  len = 0".format(dispatcher_father_serial))



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
