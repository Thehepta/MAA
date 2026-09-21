from __future__ import annotations
import logging
from typing import Dict, Optional

from d810.Environment import SymbolicMicroCodeEnvironment
from d810.ExprSimplifier import simplify
from d810.Interpreter import SymbolicMicroCodeInterpreter
from ida_hexrays import *

from d810.Expr import Expr, ExprInt, ExprId
from d810.cfg_utils import change_1way_block_successor, change_2way_block_conditional_successor, duplicate_block
from d810.hexrays_helpers import equal_mops_ignore_size, get_mop_index, get_blk_index
from d810.hexrays_formatters import format_minsn_t, format_mop_t

# This module can be use to find the instruction that define the value of a mop. Basically, you:
# 1 - Create a MopTracker object with the list of mops to search
# 2 - Call search_backward while specifying the instruction where the search should start
# It will return a list if MopHistory, each MopHistory object of this list:
# * Represents one possible path to compute the searched mops
# * Stores all instructions used to compute the searched mops
#
# You can get the value of one of the searched mop by calling the get_mop_constant_value API of a MopHistory object.
# Behind the scene, it will emulate all microcode instructions on the MopHistory path.
#
# Finally the duplicate_histories API can be used to duplicate microcode blocks so that for each microcode block,
# the searched mops have only one possible values. For instance, this is a preliminary step used in code unflattening.


logger = logging.getLogger('D810.symtracker')

class BlockInfo(object):
    def __init__(self, blk: mblock_t):
        self.blk = blk

    def get_copy(self) -> BlockInfo:
        new_block_info = BlockInfo(self.blk)
        return new_block_info

interpreter = SymbolicMicroCodeInterpreter()


class SymbolicMopHistory:
    """
    Symbolic version of MopHistory.

    Uses SymbolicMicroCodeInterpreter to evaluate microcode paths.
    Variables that cannot be resolved remain symbolic instead of causing errors.
    """

    def __init__(self, searched_mop_list: List[mop_t]):
        self.searched_mop_list = [mop_t(x) for x in searched_mop_list]
        self.block_path_list: List[BlockInfo] = []

        self._interpreter = SymbolicMicroCodeInterpreter()
        self.initial_environment = SymbolicMicroCodeEnvironment()

    def add_mop_initial_value(self, mop: mop_t, value: Union[int, Expr]):
        """Define an initial value for a mop (concrete or symbolic)."""
        if isinstance(value, int):
            size = mop.size if mop.size > 0 else 8
            expr_value = ExprInt(value, size)
        else:
            expr_value = value
        self.initial_environment.define(mop, expr_value)

    def add_mop_initial_symbol(self, mop: mop_t, name: Optional[str] = None):
        """
        Define an initial symbolic variable for a mop.
        If name is None, uses the formatted mop name.
        """
        size = mop.size if mop.size > 0 else 8
        if name is None:
            name = format_mop_t(mop)
        self.initial_environment.define(mop, ExprId(name, size))

    def get_copy(self) -> SymbolicMopHistory:
        new_history = SymbolicMopHistory(self.searched_mop_list)
        new_history.block_path_list = [x.get_copy() for x in self.block_path_list]
        new_history.initial_environment = self.initial_environment.get_copy()
        return new_history

    def is_resolved(self) -> bool:
        """Check if all searched mops can be evaluated (even symbolically)."""
        for searched_mop in self.searched_mop_list:
            result = self.initial_environment.lookup(searched_mop, create_undefind_symbol=False)
            if result is not None:
                return result.is_int()
        return False

    def track_block(self,blk):
        initial_env = SymbolicMicroCodeEnvironment()
        interpreter.eval_blk(blk, initial_env)
        self.initial_environment.track_backward(initial_env)

    @property
    def block_path(self) -> List[mblock_t]:
        return [blk_info.blk for blk_info in self.block_path_list]

    @property
    def block_serial_path(self) -> List[int]:
        return [blk.serial for blk in self.block_path]

    def replace_block_in_path(self, old_blk: mblock_t, new_blk: mblock_t) -> bool:
        blk_index = get_blk_index(old_blk, self.block_path)
        if blk_index > 0:
            self.block_path_list[blk_index].blk = new_blk
            return True
        return False

    def insert_block_in_path(self, blk: mblock_t, where_index: int):
        self.block_path_list = self.block_path_list[:where_index] + [BlockInfo(blk)] + self.block_path_list[where_index:]

    def insert_ins_in_block(self, blk: mblock_t, ins: minsn_t, before=True):
        blk_index = get_blk_index(blk, self.block_path)
        if blk_index < 0:
            return False
        blk_info = self.block_path_list[blk_index]
        if before:
            blk_info.ins_list = [ins] + blk_info.ins_list
        else:
            blk_info.ins_list = blk_info.ins_list + [ins]

    def get_defind_expr(self):
        return self.initial_environment.mop_define

    def get_mop_symbolic_value(self, searched_mop: mop_t) -> Expr:
        """
        Get the symbolic value of a mop after executing the path.
        Always returns a Expr (concrete or symbolic).
        """
        return self.initial_environment.lookup(searched_mop,create_undefind_symbol=False)

    def get_mop_constant_value(self, searched_mop: mop_t) -> Optional[int]:
        """
        Get the concrete value of a mop after executing the path.
        Returns int if the value resolved to concrete, None if still symbolic.
        Backward compatible with MopHistory.get_mop_constant_value.
        """
        expr = self.get_mop_symbolic_value(searched_mop)
        if expr is None:
            return None
        return simplify(expr).as_int()

    def print_info(self, detailed_info=False):
        formatted_mop_searched_list = [format_mop_t(x) for x in self.searched_mop_list]
        tmp_parts = []
        for formatted_mop, mop in zip(formatted_mop_searched_list, self.searched_mop_list):
            sym_val = self.get_mop_symbolic_value(mop)
            tmp_parts.append("{0}={1}".format(formatted_mop, sym_val))
        tmp = ", ".join(tmp_parts)
        logger.info("SymbolicMopHistory: resolved={0}, path={1}, mops={2}"
                    .format(self.is_resolved(), self.block_serial_path, tmp))
        if detailed_info:
            str_mop_list = "['" + "', '".join(formatted_mop_searched_list) + "']"
            if len(self.block_path) == 0:
                logger.info("SymbolicMopHistory for {0} => nothing".format(str_mop_list))
                return
            logger.info("  path {0}".format(self.block_serial_path))


# A MopTracker will create new MopTracker to recursively track variable when multiple paths are possible,
# The cur_mop_tracker_nb_path global variable is used to limit the number of MopTracker created
cur_mop_tracker_nb_path = 0


class MopTracker(object):
    def __init__(self, searched_mop_list: List[mop_t], max_nb_block=-1, max_path=-1):
        self.mba = None
        self.searched_mop_list = searched_mop_list
        self.history = SymbolicMopHistory(searched_mop_list)
        self.max_nb_block = max_nb_block
        self.max_path = max_path
        self.avoid_list = []
        self.call_detected = False

    @staticmethod
    def reset():
        global cur_mop_tracker_nb_path
        cur_mop_tracker_nb_path = 0

    def get_copy(self) -> MopTracker:
        global cur_mop_tracker_nb_path
        new_mop_tracker = MopTracker(self.searched_mop_list, self.max_nb_block, self.max_path)
        new_mop_tracker.history = self.history.get_copy()
        cur_mop_tracker_nb_path += 1
        return new_mop_tracker

    def search_backward(self, blk: mblock_t, ins: Optional[minsn_t|None], avoid_list=None, must_use_pred=None,
                        stop_at_first_duplication=False) -> List[SymbolicMopHistory]:
        logger.debug("Searching backward for: {0}".format([format_mop_t(x) for x in self.searched_mop_list]))
        self.mba = blk.mba
        self.avoid_list = avoid_list if avoid_list else []
        blk_with_multiple_pred = self.search_until_multiple_predecessor(blk, ins)
        
        if self.is_resolved():
            logger.debug("MopTracker is resolved:  {0}".format(self.history.block_serial_path))
            return [self.history]
        elif blk_with_multiple_pred is None:
            logger.debug("MopTracker unresolved: (blk_with_multiple_pred): {0}".format(self.history.block_serial_path))
            return [self.history]
        elif self.max_nb_block != -1 and len(self.history.block_serial_path) > self.max_nb_block:
            logger.debug("MopTracker unresolved: (max_nb_block): {0}".format(self.history.block_serial_path))
            return [self.history]
        elif self.max_path != -1 and cur_mop_tracker_nb_path > self.max_path:
            logger.debug("MopTracker unresolved: (max_path: {0}".format(cur_mop_tracker_nb_path))
            return [self.history]
        elif self.call_detected:
            logger.debug("MopTracker unresolved: (call): {0}".format(self.history.block_serial_path))
            return [self.history]
        if stop_at_first_duplication:
            return [self.history]
        logger.debug("MopTracker creating child because multiple pred: {0}".format(self.history.block_serial_path))
        possible_histories = []
        if must_use_pred is not None and must_use_pred.serial in blk_with_multiple_pred.predset:
            new_tracker = self.get_copy()
            possible_histories += new_tracker.search_backward(must_use_pred, None, self.avoid_list, must_use_pred)
        else:
            for blk_pred_serial in blk_with_multiple_pred.predset:
                new_tracker = self.get_copy()
                possible_histories += new_tracker.search_backward(self.mba.get_mblock(blk_pred_serial), None,
                                                                  self.avoid_list, must_use_pred)
        return possible_histories

    def is_resolved(self) -> bool:
        return self.history.is_resolved();

    def search_until_multiple_predecessor(self, blk: mblock_t, ins: Union[None, minsn_t] = None) -> Union[None, mblock_t]:

        cur_blk = blk
        while not self.is_resolved():
            # 检查循环和避免列表
            if cur_blk.serial in self.history.block_serial_path:
                self.history.insert_block_in_path(cur_blk, 0)
                return None
            if cur_blk.serial in self.avoid_list:
                self.history.insert_block_in_path(cur_blk, 0)
                return None
            self.history.insert_block_in_path(cur_blk, 0)

            self.history.track_block(cur_blk)

            # 检查前驱
            if cur_blk.npred() > 1:
                return cur_blk
            elif cur_blk.npred() == 0:
                return None
            else:
                cur_blk = self.mba.get_mblock(cur_blk.predset[0])

        # 处理 self.is_resolved() 在开始时就为 True 的情况
        if len(self.history.block_serial_path) == 0:
            self.history.insert_block_in_path(cur_blk, 0)
        return None


def get_block_with_multiple_predecessors(var_histories: List[SymbolicMopHistory]) -> Tuple[Union[None, mblock_t],
                                                                                   Union[None, Dict[int, List[SymbolicMopHistory]]]]:
    for i, var_history in enumerate(var_histories):
        pred_blk = var_history.block_path[0]
        for block in var_history.block_path[1:]:
            tmp_dict = {pred_blk.serial: [var_history]}
            for j in range(i + 1, len(var_histories)):
                blk_index = get_blk_index(block, var_histories[j].block_path)
                if (blk_index - 1) >= 0:
                    other_pred = var_histories[j].block_path[blk_index - 1]
                    if other_pred.serial not in tmp_dict.keys():
                        tmp_dict[other_pred.serial] = []
                    tmp_dict[other_pred.serial].append(var_histories[j])
            if len(tmp_dict) > 1:
                return block, tmp_dict
            pred_blk = block
    return None, None


def try_to_duplicate_one_block(var_histories: List[SymbolicMopHistory]) -> Tuple[int, int]:
    nb_duplication = 0
    nb_change = 0
    if (len(var_histories) == 0) or (len(var_histories[0].block_path) == 0):
        return nb_duplication, nb_change
    mba = var_histories[0].block_path[0].mba
    block_to_duplicate, pred_dict = get_block_with_multiple_predecessors(var_histories)
    if block_to_duplicate is None:
        return nb_duplication, nb_change
    logger.debug("Block to duplicate found: {0} with {1} successors"
                 .format(block_to_duplicate.serial, block_to_duplicate.nsucc()))
    i = 0
    for pred_serial, pred_history_group in pred_dict.items():
        # We do not duplicate first group
        if i >= 1:
            logger.debug("  Before {0}: {1}"
                         .format(pred_serial, [var_history.block_serial_path for var_history in pred_history_group]))
            pred_block = mba.get_mblock(pred_serial)
            duplicated_blk_jmp, duplicated_blk_default = duplicate_block(block_to_duplicate)
            nb_duplication += 1 if duplicated_blk_jmp is not None else 0
            nb_duplication += 1 if duplicated_blk_default is not None else 0
            logger.debug("  Making {0} goto {1}".format(pred_block.serial, duplicated_blk_jmp.serial))
            if (pred_block.tail is None) or (not is_mcode_jcond(pred_block.tail.opcode)):
                change_1way_block_successor(pred_block, duplicated_blk_jmp.serial)
                nb_change += 1
            else:
                if block_to_duplicate.serial == pred_block.tail.d.b:
                    change_2way_block_conditional_successor(pred_block, duplicated_blk_jmp.serial)
                    nb_change += 1
                else:
                    logger.warning(" not sure this is suppose to happen")
                    change_1way_block_successor(pred_block.mba.get_mblock(pred_block.serial + 1),
                                                duplicated_blk_jmp.serial)
                    nb_change += 1

            block_to_duplicate_default_successor = mba.get_mblock(block_to_duplicate.serial + 1)
            logger.debug("  Now, we fix var histories...")
            for var_history in pred_history_group:
                var_history.replace_block_in_path(block_to_duplicate, duplicated_blk_jmp)
                if block_to_duplicate.tail is not None and is_mcode_jcond(block_to_duplicate.tail.opcode):
                    index_jump_block = get_blk_index(duplicated_blk_jmp, var_history.block_path)
                    if index_jump_block + 1 < len(var_history.block_path):
                        original_jump_block_successor = var_history.block_path[index_jump_block + 1]
                        if original_jump_block_successor.serial == block_to_duplicate_default_successor.serial:
                            var_history.insert_block_in_path(duplicated_blk_default, index_jump_block + 1)
        i += 1
        logger.debug("  After {0}: {1}"
                     .format(pred_serial, [var_history.block_serial_path for var_history in pred_history_group]))
    for i, var_history in enumerate(var_histories):
        logger.debug(" internal_pass_end.{0}: {1}".format(i, var_history.block_serial_path))
    return nb_duplication, nb_change


def duplicate_histories(var_histories: List[SymbolicMopHistory], max_nb_pass: int = 10) -> Tuple[int, int]:
    cur_pass = 0
    total_nb_duplication = 0
    total_nb_change = 0
    logger.info("Trying to fix new var_history...")
    for i, var_history in enumerate(var_histories):
        logger.info(" start.{0}: {1}".format(i, var_history.block_serial_path))
    while cur_pass < max_nb_pass:
        logger.debug("Current path {0}".format(cur_pass))
        nb_duplication, nb_change = try_to_duplicate_one_block(var_histories)
        if nb_change == 0 and nb_duplication == 0:
            break
        total_nb_duplication += nb_duplication
        total_nb_change += nb_change
        cur_pass += 1
    for i, var_history in enumerate(var_histories):
        logger.info(" end.{0}: {1}".format(i, var_history.block_serial_path))
    return total_nb_duplication, total_nb_change

def deduplicate_histories(mop_histories, searched_mop_list):
    result = []

    for i, hist_i in enumerate(mop_histories):
        # 先假设它不是重复的
        is_duplicate = False

        # 拿它和前面已经保留的每一条比
        for hist_j in result:
            # 两条历史在所有 searched_mop 上的值都一样，就算重复
            same = True
            for mop in searched_mop_list:
                if hist_i.get_mop_constant_value(mop) != hist_j.get_mop_constant_value(mop):
                    same = False
                    break

            if same:
                is_duplicate = True
                break

        if not is_duplicate:
            result.append(hist_i)
    return result