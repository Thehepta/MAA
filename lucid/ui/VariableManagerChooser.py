import ida_kernwin


class MopResultWrapper:
    """
    专门解决 mop_t 不可哈希问题的返回结果包装类。
    """
    def __init__(self, variables_list, mop_mapping):
        self.data = {}
        for name, value,numeral ,size in variables_list:
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

class PureModalPatchChooser(ida_kernwin.Choose):
    def __init__(self, title, top_inputs_list):


        columns = [
            ["变量名称", 40],
            ["当前值/修补值", 40],
            ["进制", 10],
            ["宽度", 10]
        ]
        # 🌟 传入 CH_MODAL 标志
        ida_kernwin.Choose.__init__(
            self,
            title,
            columns,
            flags=ida_kernwin.Choose.CH_MODAL | ida_kernwin.CH_KEEP |     ida_kernwin.Choose.CH_QFLT
        )
        self.mop_mapping = {}
        self.variables_list = []

        for op in top_inputs_list:
            # 提取干净的名称作为展示和 Key
            clean_name = op.dstr()

            # 处理重名情况（比如不同指令里的同名实体，防止字典覆盖）
            base_name = clean_name
            counter = 1
            while clean_name in self.mop_mapping:
                clean_name = f"{base_name}_{counter}"
                counter += 1

            self.mop_mapping[clean_name] = op
            # 默认初始值给 "0"，你可以根据需求改为其他的默认占位符
            self.variables_list.append([clean_name, "None","16",str(op.size)])



    def OnCommand(self, n, cmd_id):
        """
        当用户执行自定义命令（包括按下绑定的快捷键）时回调
        """
        print("[*] 检测到您按下了 Esc 键！已被成功拦截，大窗口绝不闪退。")

        # if cmd_id == self.cmd_esc_id:
        #     # 成功拦截！弹一个警告提示，并且什么都不做（不调用 self.Close()）
        #     print("[*] 检测到您按下了 Esc 键！已被成功拦截，大窗口绝不闪退。")
        #     ida_kernwin.msg(
        #         "请注意：为了防止修补数据丢失，已禁用 Esc 键退出！\n如果确认修补完成，请点右上角的 [X] 按钮关闭并保存。\n")
        #     return
        #
        #     # 其它命令交给底层
        # ida_kernwin.Choose.OnCommand(self, n, cmd_id)

    def OnGetSize(self):
        return len(self.variables_list)

    def OnGetLine(self, n):
        return self.variables_list[n]

    # ----------------------------------------------------
    # 动作 1：连续双击修改。返回 [1, n] 原地强刷，大窗口绝对不退！
    # ----------------------------------------------------
    def OnSelectLine(self, n):
        """双击处理：允许用户修改‘值’，修改完后直接根据当前行的进制生成 int"""
        if 0 <= n < len(self.variables_list):
            var_name = self.variables_list[n][0]
            current_val = self.variables_list[n][1]
            current_base = self.variables_list[n][2]  # 🌟 这一列本身就存了 "10" 或 "16"

            # 1. 弹出输入框让用户改值
            new_val = ida_kernwin.ask_str(current_val, 0, f"请输入 MOP [{var_name}] 的新修补值:")
            if new_val is not None:
                new_val_striped = new_val.strip()
                if new_val_striped == "None":
                    return [ida_kernwin.Choose.SELECTION_CHANGED, n]
                try:
                    # current_base 是字符串 "16" 或 "10"，int() 接收 int 类型，所以转一下
                    actual_int = int(new_val_striped, int(current_base))
                    self.variables_list[n][1] = actual_int
                    # 🌟 核心：返回已经改变，行号给 n。配合 CH_KEEP 就会稳定重绘而不闪退
                    return [ida_kernwin.Choose.ALL_CHANGED, n]
                except ValueError:
                    # 保底机制：如果用户作死在 10 进制下列输入了字母，或者输入错误
                    ida_kernwin.warning(
                        f"输入数据异常！\n\n"
                        f"您输入的值 '{new_val_striped}' 无法被识别为有效的16进制数字。\n"
                    )
                return [ida_kernwin.Choose.NOTHING_CHANGED, n]

        return [ida_kernwin.Choose.SELECTION_CHANGED, n]

    def OnDeleteLine(self, n):
        return [ida_kernwin.Choose.NOTHING_CHANGED, n]
    # ----------------------------------------------------
    # 动作 2：按键盘【Insert】键（或右键 Insert）-> 手动添加新变量
    # ----------------------------------------------------
    # def OnInsertLine(self, n):
    #     name = ida_kernwin.ask_str("", 0, "请输入要额外添加的变量名称:")
    #     if name and name.strip():
    #         if any(item[0] == name.strip() for item in self.variables_list):
    #             print(f"[-] 错误：变量 {name} 已存在！")
    #             return [0, n]
    #
    #         val = ida_kernwin.ask_str("0", 0, f"请为新变量 [{name}] 设置初始值:")
    #         val = val if val is not None else "0"
    #
    #         self.variables_list.append([name.strip(), val])
    #         print(f"[+] 手动成功添加新变量: {name} = {val}")
    #         return [1, len(self.variables_list) - 1]
    #     return [0, n]

    # ----------------------------------------------------
    # 动作 3：按键盘【Delete】键（或右键 Delete）-> 删除变量
    # ----------------------------------------------------
    def get_results(self):
        # 🌟 实例化包装类返回，彻底告别 TypeError 报错
        return MopResultWrapper(self.variables_list, self.mop_mapping)
