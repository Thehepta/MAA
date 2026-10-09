from d810 import ExprMopId
from d810.Expr import Expr, ExprOp, ExprCond, ExprInt, ExprMem, ExprSlice, ExprCompose
from d810.ExprSimplifier import simplify


class ExprEvaluator:
    """
    封装 SymbolicMicroCodeInterpreter 和 SymbolicMicroCodeEnvironment 的统一接口。
    提供符号执行的完整功能，包括执行指令、块、查询变量状态等。
    """

    def __init__(self):

        self.expr_to_visitor = {
            ExprInt: self.eval_exprint,
            ExprMopId: self.eval_expr_mopid,
            ExprMem: self.eval_exprmem,
            ExprSlice: self.eval_exprslice,
            ExprCond: self.eval_exprcond,
            ExprOp: self.eval_exprop,
            ExprCompose: self.eval_exprcompose,
        }

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

        ret = ExprOp(expr.op, *args,expr.size)
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

    def eval_expr_mopid(self, expr, **kwargs):
        pass

    def mem_read(self,mem) -> Expr:
        pass