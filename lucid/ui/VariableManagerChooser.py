import ida_kernwin
from PySide6 import QtWidgets, QtCore, QtGui
from d810.utils import get_mop_name


def str_to_num(s: str, default=None):
    try:
        s = s.strip()
        sign = 1
        if s.startswith("-"):
            sign = -1
            s = s[1:]
        elif s.startswith("+"):
            s = s[1:]

        if s.startswith(("0x", "0X")):
            val = int(s, 16)
        elif s.startswith(("0b", "0B")):
            val = int(s, 2)
        elif s.startswith(("0o", "0O")):
            val = int(s, 8)
        else:
            val = int(s)
        return sign * val
    except (ValueError, TypeError, AttributeError):
        return default


class PureModalPatchChooser(QtWidgets.QDialog):
    """
    基于 PySide6 QDialog 的变量编辑器，替代 IDA Choose。
    解决问题：
      - CH_MODAL Choose 双击一行后窗口直接关闭
      - Esc 键无法拦截，直接退出
    现在完全掌控窗口生命周期：
      - 双击编辑值后窗口保持打开，可连续修改
      - Esc 键仅清除选中/关闭输入框，不会关闭整个窗口
      - 点击「确定」关闭并返回结果，点击「取消」放弃修改
    """

    COL_NAME = 0
    COL_VALUE = 1
    COL_BASE = 2
    COL_SIZE = 3

    def __init__(self, title, top_inputs_list, parent=None):
        """
        @param top_inputs_list: list[MopExprId] - 从 get_block_top_level_inputs 返回的表达式列表
        """
        super().__init__(parent)
        self.setWindowTitle(title)

        # 变量名 -> MopExprId 的映射（去重）
        self.name_to_expr = {}

        # 去重：同名变量只保留第一个
        for mop_expr in top_inputs_list:
            clean_name = mop_expr.name
            if clean_name in self.name_to_expr:
                continue  # 跳过重复
            self.name_to_expr[clean_name] = mop_expr

        # ---- 表格 ----
        self.table = QtWidgets.QTableWidget(len(self.name_to_expr), 4, self)
        self.table.setHorizontalHeaderLabels(["变量名称", "当前值/修补值", "进制", "宽度"])
        self.table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeMode.ResizeToContents
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.cellDoubleClicked.connect(self._on_cell_double_clicked)
        self.table.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        # 填充数据
        for row, (name, mop_expr) in enumerate(self.name_to_expr.items()):
            # 名称
            name_item = QtWidgets.QTableWidgetItem(name)
            name_item.setTextAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, self.COL_NAME, name_item)

            # 值
            val_item = QtWidgets.QTableWidgetItem("None")
            val_item.setTextAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, self.COL_VALUE, val_item)

            # 进制
            base_item = QtWidgets.QTableWidgetItem("16")
            base_item.setTextAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, self.COL_BASE, base_item)

            # 宽度
            size_item = QtWidgets.QTableWidgetItem(str(mop_expr.size))
            size_item.setTextAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, self.COL_SIZE, size_item)

        # ---- 按钮 ----
        btn_exec = QtWidgets.QPushButton("执行")
        btn_cancel = QtWidgets.QPushButton("取消")
        btn_box = QtWidgets.QDialogButtonBox()
        btn_box.addButton(btn_exec, QtWidgets.QDialogButtonBox.ButtonRole.AcceptRole)
        btn_box.addButton(btn_cancel, QtWidgets.QDialogButtonBox.ButtonRole.RejectRole)
        btn_box.accepted.connect(self.accept)
        btn_box.rejected.connect(self.reject)

        # ---- 布局 ----
        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.table)
        layout.addWidget(btn_box)

        self._adjust_size()

    def _adjust_size(self):
        """根据表格行数自适应窗口高度，消除垂直滚动条"""
        self.table.resizeColumnsToContents()
        self.table.resizeRowsToContents()

        header_h = self.table.horizontalHeader().height()
        rows_h = sum(self.table.rowHeight(r) for r in range(self.table.rowCount()))
        table_h = header_h + rows_h + 4

        btn_h = 40
        margins = self.layout().contentsMargins()
        spacing = self.layout().spacing()
        extra = margins.top() + margins.bottom() + spacing + btn_h + 8

        ideal_h = table_h + extra
        screen_h = QtWidgets.QApplication.primaryScreen().availableGeometry().height()
        max_h = int(screen_h * 0.8)

        self.setFixedHeight(min(ideal_h, max_h))
        self.setMinimumWidth(480)
        self.setMaximumHeight(max_h)

    def keyPressEvent(self, event):
        """拦截 Esc：不关闭窗口，仅清除表格选中"""
        if event.key() == QtCore.Qt.Key.Key_Escape:
            self.table.clearSelection()
            return
        super().keyPressEvent(event)

    def _on_cell_double_clicked(self, row, col):
        """双击编辑值"""
        if col != self.COL_VALUE:
            return

        name_item = self.table.item(row, self.COL_NAME)
        value_item = self.table.item(row, self.COL_VALUE)
        base_item = self.table.item(row, self.COL_BASE)
        if not (name_item and value_item and base_item):
            return

        var_name = name_item.text()
        current_val = value_item.text()
        current_base = int(base_item.text())

        new_val, ok = QtWidgets.QInputDialog.getText(
            self,
            f"修改 [{var_name}]",
            f"请输入 MOP [{var_name}] 的新修补值 (自动转为16进制):",
            text=str(current_val),
        )
        if not ok:
            return

        new_val = new_val.strip()
        if new_val.upper() == "NONE":
            value_item.setText("None")
            return

        num = str_to_num(new_val)
        if num is None:
            QtWidgets.QMessageBox.warning(
                self,
                "输入错误",
                f"值 '{new_val}' 无法按 {current_base} 进制解析！",
            )
            return

        value_item.setText(hex(num))

    def get_results(self) -> dict:
        """
        返回 {mop_t: int_value} 字典。
        只包含用户设置了值的变量（不是 "None"）。
        """
        result = {}
        for row in range(self.table.rowCount()):
            name = self.table.item(row, self.COL_NAME).text()
            value_str = self.table.item(row, self.COL_VALUE).text()

            if value_str == "None":
                continue

            mop_expr = self.name_to_expr.get(name)
            if mop_expr is None:
                continue

            num = str_to_num(value_str)
            if num is not None:
                result[mop_expr] = num  # 直接用 mop_expr.mop

        return result

