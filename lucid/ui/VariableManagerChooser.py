import ida_kernwin
from PySide6 import QtWidgets, QtCore, QtGui
from d810.utils import get_mop_name


class MopResultWrapper:
    """
    专门解决 mop_t 不可哈希问题的返回结果包装类。
    """
    def __init__(self, variables_list, mop_mapping):
        self.data = {}
        for name, value, numeral, size in variables_list:
            mop_obj = mop_mapping.get(name)
            self.data[name] = {
                "mop": mop_obj,    # 这里存的是货真价实的 mop_t 对象（或者是 None）
                "value": value     # 用户输入的值
            }

    def items(self):
        """
        下游神器：像字典一样遍历，直接返回 (mop_t_对象, 字符串值)
        如果该变量是用户手动新增的（没有原始mop），则第一个元素是它的名字字符串
        """
        for name, info in self.data.items():
            if info["mop"] is not None:
                yield info["mop"], info["value"]
            else:
                yield name, info["value"]

    def get_value_by_name(self, name):
        """支持通过名字快捷查询用户输入的值"""
        if name in self.data:
            return self.data[name]["value"]
        return None


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
        super().__init__(parent)
        self.setWindowTitle(title)

        self.mop_mapping = {}
        self._raw_rows = []  # [[name, value, base, size], ...]

        # ---- 构建 mop_mapping ----
        for op in top_inputs_list:
            clean_name = get_mop_name(op)
            base_name = clean_name
            counter = 1
            while clean_name in self.mop_mapping:
                clean_name = f"{base_name}_{counter}"
                counter += 1
            self.mop_mapping[clean_name] = op
            self._raw_rows.append([clean_name, "None", "16", str(op.size)])

        # ---- 表格 ----
        self.table = QtWidgets.QTableWidget(len(self._raw_rows), 4, self)
        self.table.setHorizontalHeaderLabels(["变量名称", "当前值/修补值", "进制", "宽度"])
        # 所有列按内容自适应宽度，消除水平滚动条
        self.table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeMode.ResizeToContents
        )
        # 最后一列 Stretch 填满剩余宽度
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.cellDoubleClicked.connect(self._on_cell_double_clicked)

        # 禁用滚动条 —— 窗口高度会自适应行数
        self.table.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        # 填充数据
        for row, data in enumerate(self._raw_rows):
            for col, val in enumerate(data):
                item = QtWidgets.QTableWidgetItem(str(val))
                item.setTextAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
                self.table.setItem(row, col, item)

        # ---- 进制下拉代理（双击进制列可切 10/16） ----
        self._base_delegate = _BaseComboDelegate(self)
        self.table.setItemDelegateForColumn(self.COL_BASE, self._base_delegate)

        # ---- 按钮：执行 / 取消 ----
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
        self.setLayout(layout)

        # ---- 自适应窗口大小：根据行数计算高度 ----
        self._adjust_size()

    def _adjust_size(self):
        """根据表格行数自适应窗口高度，消除垂直滚动条"""
        self.table.resizeColumnsToContents()
        self.table.resizeRowsToContents()

        # 计算表格理想高度
        header_h = self.table.horizontalHeader().height()
        rows_h = sum(self.table.rowHeight(r) for r in range(self.table.rowCount()))
        table_ideal_h = header_h + rows_h + 4  # 4px 容差

        # 按钮 + 布局边距
        btn_h = 40
        margins = self.layout().contentsMargins()
        spacing = self.layout().spacing()
        extra = margins.top() + margins.bottom() + spacing + btn_h + 8

        ideal_h = table_ideal_h + extra
        # 限高：不超过屏幕 80%
        screen_h = QtWidgets.QApplication.primaryScreen().availableGeometry().height()
        max_h = int(screen_h * 0.8)
        final_h = min(ideal_h, max_h)

        self.setFixedHeight(final_h)
        self.setMinimumWidth(480)
        self.setMaximumHeight(max_h)

    # ------------------------------------------------------------------
    # 拦截 Esc：不关闭窗口，仅清除表格选中
    # ------------------------------------------------------------------
    def keyPressEvent(self, event):
        if event.key() == QtCore.Qt.Key.Key_Escape:
            self.table.clearSelection()
            return
        super().keyPressEvent(event)

    # ------------------------------------------------------------------
    # 双击编辑值
    # ------------------------------------------------------------------
    def _on_cell_double_clicked(self, row, col):
        if col != self.COL_VALUE:
            return
        var_name_item = self.table.item(row, self.COL_NAME)
        value_item = self.table.item(row, self.COL_VALUE)
        base_item = self.table.item(row, self.COL_BASE)
        if not (var_name_item and value_item and base_item):
            return

        var_name = var_name_item.text()
        current_val = value_item.text()
        current_base = int(base_item.text())

        new_val, ok = QtWidgets.QInputDialog.getText(
            self,
            f"修改 [{var_name}]",
            f"请输入 MOP [{var_name}] 的新修补值 (当前进制={current_base}):",
            text=str(current_val),
        )
        if not ok:
            # 用户按了取消 / Esc，仅关闭输入框，主窗口不动
            return
        new_val_stripped = new_val.strip()
        if new_val_stripped == "None":
            value_item.setText("None")
            return
        try:
            actual_int = int(new_val_stripped, current_base)
            value_item.setText(str(actual_int))
        except ValueError:
            QtWidgets.QMessageBox.warning(
                self,
                "输入错误",
                f"值 '{new_val_stripped}' 无法按 {current_base} 进制解析！",
            )

    # ------------------------------------------------------------------
    # 返回结果，API 与旧版保持一致
    # ------------------------------------------------------------------
    def get_results(self):
        variables_list = []
        for row in range(self.table.rowCount()):
            name = self.table.item(row, self.COL_NAME).text()
            value = self.table.item(row, self.COL_VALUE).text()
            numeral = self.table.item(row, self.COL_BASE).text()
            size = self.table.item(row, self.COL_SIZE).text()
            variables_list.append([name, value, numeral, size])
        return MopResultWrapper(variables_list, self.mop_mapping)


class _BaseComboDelegate(QtWidgets.QStyledItemDelegate):
    """进制列的下拉代理，双击可在 10 / 16 之间切换"""
    BASES = ["10", "16"]

    def createEditor(self, parent, option, index):
        combo = QtWidgets.QComboBox(parent)
        combo.addItems(self.BASES)
        current = index.data(QtCore.Qt.ItemDataRole.DisplayRole)
        idx = self.BASES.index(current) if current in self.BASES else 0
        combo.setCurrentIndex(idx)
        return combo

    def setModelData(self, editor, model, index):
        model.setData(index, editor.currentText(), QtCore.Qt.ItemDataRole.EditRole)

    def updateEditorGeometry(self, editor, option, index):
        editor.setGeometry(option.rect)
