
from PySide6 import QtWidgets, QtCore
from d810.hexrays_formatters import format_mop_t


class TraceBlksDialog(QtWidgets.QDialog):
    """
    向后追踪对话框：
    - 未定义变量列表（可多选，checkbox 在右侧）
    - 前驱块列表（单选，带 radio button）
    """

    def __init__(self, title, undefined_vars, pred_blocks, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.undefined_vars = undefined_vars
        self.pred_blocks = pred_blocks

        layout = QtWidgets.QVBoxLayout(self)

        # 未定义变量列表（可多选，checkbox 在右侧）
        layout.addWidget(QtWidgets.QLabel("未定义变量（可多选）:"))
        self.var_list = QtWidgets.QListWidget()
        self.var_list.setResizeMode(QtWidgets.QListWidget.ResizeMode.Adjust)
        self.var_checkboxes = []
        for var in undefined_vars:
            item = QtWidgets.QListWidgetItem()
            item.setSizeHint(QtCore.QSize(0, 30))  # 设置合适的行高
            widget = QtWidgets.QWidget()
            h_layout = QtWidgets.QHBoxLayout(widget)
            h_layout.setContentsMargins(4, 2, 4, 2)
            label = QtWidgets.QLabel(format_mop_t(var))
            checkbox = QtWidgets.QCheckBox()
            h_layout.addWidget(label)
            h_layout.addStretch()
            h_layout.addWidget(checkbox)
            self.var_list.addItem(item)
            self.var_list.setItemWidget(item, widget)
            self.var_checkboxes.append(checkbox)
        layout.addWidget(self.var_list)

        # 前驱块列表（单选，使用真正的 radio button）
        layout.addWidget(QtWidgets.QLabel("前驱块（单选）:"))

        scroll_area = QtWidgets.QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setMaximumHeight(150)

        container = QtWidgets.QWidget()
        self.pred_layout = QtWidgets.QVBoxLayout(container)
        self.pred_layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)

        self.pred_radio_group = QtWidgets.QButtonGroup(self)
        self.pred_radios = []

        for i, blk in enumerate(pred_blocks):
            radio = QtWidgets.QRadioButton("Block {0}".format(blk.serial))
            self.pred_radio_group.addButton(radio, i)
            self.pred_radios.append(radio)
            self.pred_layout.addWidget(radio)

        if self.pred_radios:
            self.pred_radios[0].setChecked(True)

        self.pred_layout.addStretch()
        scroll_area.setWidget(container)
        layout.addWidget(scroll_area)

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
        selected_vars = []
        for i, checkbox in enumerate(self.var_checkboxes):
            if checkbox.isChecked():
                selected_vars.append(self.undefined_vars[i])

        selected_pred = None
        checked_id = self.pred_radio_group.checkedId()
        if checked_id >= 0:
            selected_pred = self.pred_blocks[checked_id]

        return selected_vars, selected_pred
