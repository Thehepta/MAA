import ida_graph
import ida_hexrays as hr
import ida_kernwin as kw
from ida_hexrays import mblock_t, mop_t, optblock_t, minsn_visitor_t, mbl_array_t, mop_n

import ida_lines
import re

from PySide6 import QtWidgets
from lucid.ui.TraceBlkManagerChooser import TraceBlksDialog
from lucid.ui.VariableManagerChooser import PureModalPatchChooser
from lucid.util.D810Utils import UnFlaInfo, get_block_top_level_inputs
from d810.Environment import SymbolicMicroCodeEnvironment
from d810.hexrays_formatters import format_mop_t
from lucid.util import log, D810Utils


def graphviz(mba, output_path):
    from graphviz import Digraph
    dot = Digraph()
    dot.attr(splines='ortho')
    for blk_idx in range(mba.qty):
        blk = mba.get_mblock(blk_idx)
        if blk.head is None:
            lines = ["{0}:None".format(blk_idx)]
        else:
            lines = ["{0}:{1}".format(blk_idx, hex(blk.head.ea))]
        insn = blk.head
        while insn:
            lines.append(insn.dstr())
            if insn == blk.tail:
                break
            insn = insn.next
        label = "\n".join(lines)
        dot.node(str(blk_idx), label=label, shape="rect", style="filled", fillcolor="lightblue")

    for blk_idx in range(mba.qty):
        blk = mba.get_mblock(blk_idx)
        succset = [x for x in blk.succset]
        for succ in succset:
            dot.edge(str(blk_idx), str(succ))

    # dot.render("/home/chic/graph_with_contentgraph_with_content", format="png")
    with open(output_path, "w") as f:
        f.write(dot.source)
    # dot.render("/home/chic/graph_with_content", format="png")
    print("dot已保存到 :", output_path)


class microcode_graphviewer_t(ida_graph.GraphViewer):
    """Displays the graph view of Hex-Rays microcode."""

    def __init__(self, mba, title, lines):
        title = "Microcode graph: %s" % title
        ida_graph.GraphViewer.__init__(self, title, True)
        self._mba = mba
        self._mba.set_mba_flags(hr.MBA_SHORT)
        self._process_lines(lines)
        if mba.maturity == hr.MMAT_GENERATED or mba.maturity == hr.MMAT_PREOPTIMIZED:
            mba.build_graph()

    def _process_lines(self, lines):
        self._blockcmts = {}
        curblk = "-1"
        self._blockcmts[curblk] = []
        for i, line in enumerate(lines):
            plain_line = ida_lines.tag_remove(line).lstrip()
            if plain_line.startswith(';'):
                # msg("%s" % plain_line)
                re_ret = re.findall("BLOCK ([0-9]+) ", plain_line)
                if len(re_ret) > 0:
                    curblk = re_ret[0]
                    self._blockcmts[curblk] = [line]
                else:
                    self._blockcmts[curblk].append(line)
        if "0" in self._blockcmts:
            self._blockcmts["0"] = self._blockcmts["-1"] + self._blockcmts["0"]
        del self._blockcmts["-1"]

    def OnRefresh(self):
        self.Clear()
        qty = self._mba.qty
        for src in range(qty):
            self.AddNode(src)
        for src in range(qty):
            mblock = self._mba.get_mblock(src)
            for dest in mblock.succset:
                self.AddEdge(src, dest)
        return True

    def OnGetText(self, node):
        mblock = self._mba.get_mblock(node)
        vp = hr.qstring_printer_t(None, True)
        mblock._print(vp)

        node_key = "%d" % node
        if node_key in self._blockcmts:
            return ''.join(self._blockcmts[node_key]) + vp.s
        else:
            return vp.s





class dominance_graphviewer_t(microcode_graphviewer_t):

    def __init__(self, *args):
        microcode_graphviewer_t.__init__(self, *args)
        self.dom_command_id = self.AddCommand("Show Dominance Graph", "")
        self.full_command_id = self.AddCommand("Show Full Graph", "")
        self.back_command_id = self.AddCommand("Show Previous Graph", "")
        self.save_graphviz_id = self.AddCommand("save Graph to graphviz ", "")
        self.jump_blk_id = self.AddCommand("jump to target blk", "")
        self.show_UnFlatten_log_id = self.AddCommand("show UnFlatten Info log ", "")
        self.eval_current_blk_id = self.AddCommand("eval current blk ", "")
        self.execute_blks_id = self.AddCommand("execute blks", "")
        self.trace_blks_id = self.AddCommand("trace blks", "")
        self.state = "cfg"
        self.back_stack = []
        self.select_block = None
        self.select_node = -1
        self.dom = {}

        self.compute_dominates()

    def OnCommand(self, cmd_id):
        if self.select_node != -1:
            node = self[self.select_node]
            if isinstance(node, hr.mblock_t):
                self.select_block = node
            elif isinstance(node, int):
                self.select_block = self._mba.get_mblock(node)
        if cmd_id == self.dom_command_id and self.select_node != -1:
            self.state = "dom"
            self.Refresh()
            self.Select(self.select_node)
            self.back_stack.append(self.select_block.serial)
        elif cmd_id == self.full_command_id:
            self.state = "cfg"
            last_select = self.select_block.serial if self.select_block else -1
            self.select_node = -1
            self.select_block = None
            self.Refresh()
            if last_select >= 0:
                self.Select(last_select)
        elif cmd_id == self.back_command_id and len(self.back_stack) > 0:
            self.back_stack.pop()
            if not self.back_stack:
                return self.OnCommand(self.full_command_id)
            else:
                serial = self.back_stack[-1]
                self.select_block = self._mba.get_mblock(serial)
                self.state = "dom"
                self.Refresh()
                self.Select(self.select_node)
        elif cmd_id == self.show_UnFlatten_log_id:
            UnFlaInfo(self._mba, self.select_block)
        elif cmd_id == self.eval_current_blk_id:
            title_msg = "eval设置变量 (双击改值 / 确定即可开始执行)"
            mop_undefind = get_block_top_level_inputs(self.select_block)
            dialog = PureModalPatchChooser(title_msg, mop_undefind)
            if QtWidgets.QDialog.DialogCode.Accepted == dialog.exec():
                environment_values = dialog.get_results()  # 现在直接返回 {mop_t: int}
                D810Utils.eval_current_blk(self.select_block, environment_values)
            else:
                print("dialog cancelled")
        elif cmd_id == self.execute_blks_id:
            start_blk, end_blk = self.eval_blks_dialog("execute blks")
            if start_blk is not None and end_blk is not None:
                D810Utils.eval_blks(self._mba, start_blk, end_blk)
                print("exe blks ", start_blk, end_blk)
        elif cmd_id == self.trace_blks_id:
            if self.select_block is None:
                print("请先选择一个块")
                return

            # 获取未定义变量
            undefined_vars = get_block_top_level_inputs(self.select_block)
            if not undefined_vars:
                print("当前块没有未定义变量")
                return

            # 获取前驱块
            pred_blocks = []
            for pred_serial in self.select_block.predset:
                pred_blocks.append(self._mba.get_mblock(pred_serial))

            if not pred_blocks:
                print("当前块没有前驱块")
                return

            # 显示对话框
            dialog = TraceBlksDialog("Trace Blocks", undefined_vars, pred_blocks)
            if QtWidgets.QDialog.DialogCode.Accepted == dialog.exec():
                selected_undef_mops, selected_pred = dialog.get_results()
                if not selected_undef_mops:
                    print("请至少选择一个未定义变量")
                    return
                if selected_pred is None:
                    print("请选择一个前驱块")
                    return

                print("选中的变量: {0}".format([format_mop_t(v) for v in selected_undef_mops]))
                print("选中的前驱块: {0}".format(selected_pred.serial))

                # 执行向后追踪
                D810Utils.trace_blks(self._mba, selected_pred.serial, selected_undef_mops)
            else:
                print("对话框已取消")
        elif cmd_id == self.save_graphviz_id:
            file_path = kw.ask_file(True, "*.dot", "Please select a file")
            if file_path:
                kw.msg("Selected file: {}\n".format(file_path))
                graphviz(self._mba, file_path)
            else:
                kw.msg("No file selected\n")
            print("save_graphviz_id")
        elif cmd_id == self.jump_blk_id:
            block_num = kw.ask_long(0, "请输入要跳转的块号:")
            if block_num is not None and block_num >= 0:
                if self._mba.qty - 1 < block_num:
                    # print("not found block:", block_num)
                    return
                node = self._mba.get_mblock(block_num)
                if isinstance(node, hr.mblock_t):
                    self.Select(block_num)

    def OnClick(self, node_id):
        self.select_node = node_id

    def OnKeydown(self, vkey, shift):
        """
        User pressed a key
        :param vkey: Virtual key code
        :param shift: Shift flag
        :returns: Boolean. True if you handled the event
        """
        print("OnKeydown, vk=%d shift=%d" % (vkey, shift))

    def eval_blks_dialog(self, title="Execute Blocks"):

        class ExecuteBlksForm(kw.Form):
            def __init__(self, form_title):
                F = kw.Form
                F.__init__(
                    self,
                    r"""STARTITEM 0
{title}

<##Start Block :{{start_blk}}>
<##End Block   :{{end_blk}}>
""".format(title=form_title),
                    {
                        'start_blk': F.StringInput(swidth=20),
                        'end_blk': F.StringInput(swidth=20),
                    }
                )

        form = ExecuteBlksForm(title)
        form, args = form.Compile()
        ok = form.Execute()
        if ok != 1:
            form.Free()
            return None,None

        try:
            start_blk = int(form.start_blk.value)
            end_blk = int(form.end_blk.value)
        except ValueError:
            print("Block numbers must be integers")
            form.Free()
            return None,None
        form.Free()

        # mba 的第一个块(serial=0)和最后一个块(serial=qty-1)是空块，有效范围是 1 ~ qty-2
        max_valid = self._mba.qty - 2
        if start_blk < 1 or end_blk > max_valid:
            print("Block range must be within 1 ~ %d (first and last blocks are empty)" % max_valid)
            return None,None

        return start_blk, end_blk

    def compute_dominates(self):
        nodes = set(list(range(self._mba.qty)))
        self.dom = {}
        for node in nodes:
            self.dom[node] = set(nodes)

        self.dom[0] = set([0])
        todo = set(nodes)

        while todo:
            node = todo.pop()

            if node == 0:
                continue

            new_dom = None
            mblock = self._mba.get_mblock(node)
            for pred in mblock.predset:
                if not pred in nodes:
                    continue

                if new_dom is None:
                    new_dom = set(self.dom[pred])
                new_dom &= self.dom[pred]
            if new_dom is None:
                new_dom = set([node])
            else:
                new_dom |= set([node])

            if new_dom == self.dom[node]:
                continue

            self.dom[node] = new_dom
            for succ in mblock.succset:
                todo.add(succ)

    def _get_dominates(self, blk):
        result = []
        for dom in self.dom:
            if blk.serial in self.dom[dom]:
                result.append(self._mba.get_mblock(dom))
        return result

    def OnRefresh(self):
        if self.state == "dom" and self.select_block:
            self.Clear()
            node_ids = {}
            dominates = self._get_dominates(self.select_block)
            for block in dominates:
                node_id = self.AddNode(block)
                if block.serial == self.select_block.serial:
                    self.select_node = node_id
                node_ids[block.serial] = node_id
            for block in dominates:
                for dest in block.succset:
                    if dest in node_ids:
                        self.AddEdge(node_ids[block.serial], node_ids[dest])
            return True
        return microcode_graphviewer_t.OnRefresh(self)

    def OnGetText(self, node_id):
        if isinstance(self[node_id], hr.mblock_t):
            node_id = self[node_id].serial
        return microcode_graphviewer_t.OnGetText(self, node_id)


class printer_t(hr.vd_printer_t):
    """Converts microcode output to an array of strings."""

    def __init__(self, *args):
        hr.vd_printer_t.__init__(self)
        self.mc = []

    def get_mc(self):
        return self.mc

    def _print(self, indent, line):  # 被动调用，一行行的传入microcode反编译结果
        self.mc.append(line)
        return 1


def show_microcode_graph(mba, fn_name, lines=None):
    if lines == None:
        vp = printer_t()
        mba.set_mba_flags(mba.get_mba_flags())
        mba._print(vp)
        g = dominance_graphviewer_t(mba, fn_name, vp.get_mc())
        if g:
            g.Show()
        return g
    else:
        g = dominance_graphviewer_t(mba, fn_name, lines)
        if g:
            g.Show()
        return g
