from typing import Optional, Dict, List

from d810 import Expr
from d810.Environment import SymbolicMicroCodeEnvironment, ExprMopId
from d810.Expr import ExprInt, ExprId, ExprMem, ExprSlice, ExprCond, ExprOp, ExprCompose
from d810.ExprSimplifier import simplify
from d810.Interpreter import SymbolicMicroCodeInterpreter


class SymbolicExecutor:
    """
    封装 SymbolicMicroCodeInterpreter 和 SymbolicMicroCodeEnvironment 的统一接口。
    提供符号执行的完整功能，包括执行指令、块、查询变量状态等。
    """

    def __init__(self, initial_environment: SymbolicMicroCodeEnvironment = None):

        self.expr_to_visitor = {
            ExprInt: self.eval_exprint,
            ExprMopId: self.eval_expr_mopid,
            ExprMem: self.eval_exprmem,
            ExprSlice: self.eval_exprslice,
            ExprCond: self.eval_exprcond,
            ExprOp: self.eval_exprop,
            ExprCompose: self.eval_exprcompose,
        }

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
        return self._environment.mop_undefinde

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

    # ==================== expr求解 ====================

    def eval_expr(self, expr, eval_cache=None):
        """
        Evaluate @expr
        @expr: Expression instance to evaluate
        @cache: None or dictionary linking variables to their values
        """
        if eval_cache is None:
            eval_cache = {}
        ret = self.eval_expr_visitor(expr, cache=eval_cache)
        assert ret is not None
        return ret

    def eval_expr_visitor(self, expr, cache=None):
        """
        [DEV]: Override to change the behavior of an Expr evaluation.
        This function recursively applies 'eval_expr*' to @expr.
        This function uses @cache to speedup re-evaluation of expression.
        """
        if cache is None:
            cache = {}

        ret = cache.get(expr, None)
        if ret is not None:
            return ret

        new_expr = simplify(expr)
        ret = cache.get(expr, None)
        if ret is not None:
            return ret

        func = self.expr_to_visitor.get(new_expr.__class__, None)
        if func is None:
            raise TypeError("Unknown expr type")

        ret = func(new_expr, cache=cache)
        ret = simplify(ret)
        assert ret is not None

        cache[expr] = ret
        cache[new_expr] = ret
        return ret

    def eval_expr_mopid(self, expr, **kwargs):
        """[DEV]: Evaluate an ExprId using the current state"""
        ret = self._environment.lookup(expr)
        return ret

    def eval_exprint(self, expr, **kwargs):
        """[DEV]: Evaluate an ExprInt using the current state"""
        return expr

    def eval_exprmem(self, expr, **kwargs):
        """[DEV]: Evaluate an ExprMem using the current state
        This function first evaluate the memory pointer value.
        Override 'mem_read' to modify the effective memory accesses
        """
        ptr = self.eval_expr_visitor(expr.ptr, **kwargs)
        mem = ExprMem(ptr, expr.size)
        ret = self.mem_read(mem)
        return ret

    def eval_exprslice(self, expr, **kwargs):
        """[DEV]: Evaluate an ExprSlice using the current state"""
        arg = self.eval_expr_visitor(expr.arg, **kwargs)
        ret = ExprSlice(arg, expr.start, expr.stop)
        return ret

    def eval_exprop(self, expr, **kwargs):
        """[DEV]: Evaluate an ExprOp using the current state"""
        args = []
        for oarg in expr.args:
            arg = self.eval_expr_visitor(oarg, **kwargs)
            args.append(arg)

        ret = ExprOp(expr.op, *args,4)
        return ret

    def eval_exprcompose(self, expr, **kwargs):
        """[DEV]: Evaluate an ExprCompose using the current state"""
        args = []
        for arg in expr.args:
            args.append(self.eval_expr_visitor(arg, **kwargs))
        ret = ExprCompose(*args)
        return ret

    def eval_exprcond(self, expr, **kwargs):
        """[DEV]: Evaluate an ExprCond using the current state"""
        cond = self.eval_expr_visitor(expr.cond, **kwargs)
        src1 = self.eval_expr_visitor(expr.src1, **kwargs)
        src2 = self.eval_expr_visitor(expr.src2, **kwargs)
        ret = ExprCond(cond, src1, src2)
        return ret