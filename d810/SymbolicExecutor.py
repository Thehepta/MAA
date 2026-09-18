from typing import Optional, Dict, List

from d810 import Expr
from d810.Environment import SymbolicMicroCodeEnvironment
from d810.Interpreter import SymbolicMicroCodeInterpreter


class SymbolicExecutor:
    """
    封装 SymbolicMicroCodeInterpreter 和 SymbolicMicroCodeEnvironment 的统一接口。
    提供符号执行的完整功能，包括执行指令、块、查询变量状态等。
    """

    def __init__(self, initial_environment: SymbolicMicroCodeEnvironment = None):
        self._interpreter = SymbolicMicroCodeInterpreter()
        self._environment = initial_environment or SymbolicMicroCodeEnvironment()

    # ==================== 执行相关 ====================

    def eval_instruction(self, blk, ins) -> Optional[Expr]:
        """执行单条指令"""
        return self._interpreter.eval_instruction(blk, ins, self._environment)

    def eval_blk(self, blk) -> SymbolicMicroCodeEnvironment:
        """执行整个块，返回更新后的 environment"""
        return self._interpreter.eval_blk(blk, self._environment)

    def lookup(self, mop, create_undefind_symbol: bool = True) -> Expr:
        """查询变量的符号值"""
        return self._environment.lookup(mop, create_undefind_symbol)

    def define(self, mop, value: Expr):
        """定义变量的符号值"""
        self._environment.define(mop, value)

    def get_defined_vars(self) -> Dict:
        """获取所有已定义的变量"""
        return self._environment.mop_define

    def get_undefined_vars(self) -> List:
        """获取所有未定义的变量"""
        return self._environment.mop_undefind

    # ==================== 状态管理 ====================

    def get_environment(self) -> SymbolicMicroCodeEnvironment:
        """获取内部 environment（用于高级操作）"""
        return self._environment

    def get_copy(self) -> 'SymbolicExecutor':
        """创建副本"""
        new_executor = SymbolicExecutor(self._environment.get_copy())
        return new_executor

    # ==================== 路径约束 ====================

    def add_path_condition(self, cond: Expr, taken: bool):
        """添加路径约束"""
        self._environment.add_path_condition(cond, taken)

    def get_path_cond_expr(self) -> Expr:
        """获取路径约束表达式"""
        return self._environment.get_path_cond_expr()