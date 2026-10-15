
from PySide6 import QtWidgets, QtCore, QtGui
from d810.hexrays_formatters import format_mop_t


class TraceBlksDialog(QtWidgets.QDialog):
    """
    向后追踪对话框：
    - 未定义变量列表（可多选）
    - 前驱块列表（单选）
    """

    def __init__(self, title, undefined_vars, pred_blocks, parent=None):
        """
        @param undefined_vars: list[ExprMopId] - 未定义变量列表
        @param pred_blocks: list[mblock_t] - 前驱块列表
        """
        super().__init__(parent)
        self.setWindowTitle(title)
        self.undefined_vars = undefined_vars
        self.pred_blocks = pred_blocks

        layout = QtWidgets.QVBoxLayout(self)

        # 未定义变量列表（可多选）
        layout.addWidget(QtWidgets.QLabel("未定义变量（可多选）:"))
        self.var_list = QtWidgets.QListWidget()
        self.var_list.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.MultiSelection)
        for var in undefined_vars:
            self.var_list.addItem(format_mop_t(var))
        layout.addWidget(self.var_list)

        # 前驱块列表（单选）
        layout.addWidget(QtWidgets.QLabel("前驱块（单选）:"))
        self.pred_list = QtWidgets.QListWidget()
        self.pred_list.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        for blk in pred_blocks:
            self.pred_list.addItem("Block {0}".format(blk.serial))
        layout.addWidget(self.pred_list)

        # 按钮
        btn_box = QtWidgets.QDialogButtonBox()
        btn_ok = QtWidgets.QPushButton("确定")
        btn_cancel = QtWidgets.QPushButton("取消")
        btn_box.addButton(btn_ok, QtWidgets.QDialogButtonBox.ButtonRole.AcceptRole)
        btn_box.addButton(btn_cancel, QtWidgets.QDialogButtonBox.ButtonRole.RejectRole)
        btn_box.accepted.connect(self.accept)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

        self.setMinimumWidth(400)
        self.setMinimumHeight(300)

    def get_results(self):
        """
        返回 (selected_vars, selected_pred)
        - selected_vars: list[ExprMopId] - 选中的未定义变量
        - selected_pred: mblock_t or None - 选中的前驱块
        """
        selected_vars = []
        for idx in self.var_list.selectedIndexes():
            selected_vars.append(self.undefined_vars[idx.row()])

        selected_pred = None
        pred_indexes = self.pred_list.selectedIndexes()
        if pred_indexes:
            selected_pred = self.pred_blocks[pred_indexes[0].row()]

        return selected_vars, selected_pred