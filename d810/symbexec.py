from ida_hexrays import mop_z





class SymbolicExecutionEngine(object):

    def __init__(self):
        self.environment = SymbolMngr()

    def eval_updt_blk(self, microcode_block):
        cur_ins = microcode_block.head
        while cur_ins is not None:
            self.eval_instruction(microcode_block, cur_ins)
            cur_ins = cur_ins.next

    def eval_instruction(self, blk, ins):
        res = self._eval_instruction(ins)
        if res is not None:
            if (ins.d is not None) and ins.d.t != mop_z:
                self.symbols.define(ins.d, res)
        return res

    def _eval_instruction(self, ins):
        pass


class SymbolMngr(object):

    def __init__(self):
        self.symbols_id = {}

    def __setitem__(self, expr, value):
        self.write(expr, value)

    def __getitem__(self, expr):
        return self.read(expr)

    def read(self, src):
        """
        Return the value corresponding to Expr @src
        @src: ExprId or ExprMem instance
        """
        if src.is_id():
            return self.symbols_id.get(src, src)
        else:
            raise TypeError("Bad source expr")

    def write(self, dst, src):
        """
        Update @dst with @src expression
        @dst: ExprId or ExprMem instance
        @src: Expression instance
        """
        assert dst.size == src.size
        if dst.is_id():
            if dst == src:
                if dst in self.symbols_id:
                    del self.symbols_id[dst]
            else:
                self.symbols_id[dst] = src
        elif dst.is_mem():
            # Only byte aligned accesses are supported for now
            assert dst.size % 8 == 0
            # self.symbols_mem.write(dst.ptr, src)
        else:
            raise TypeError("Bad destination expr")
