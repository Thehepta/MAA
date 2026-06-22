import ida_funcs
import ida_hexrays as hr
import ida_kernwin


def collect_mops(mop, out):
    if mop is None:
        return
    if mop.t == hr.mop_r:
        out.append(mop)
    if mop.t == hr.mop_d:
        collect_mops(mop.d.l, out)
        collect_mops(mop.d.r, out)
        collect_mops(mop.d.d, out)
    elif mop.t == hr.mop_a:
        collect_mops(mop.a, out)
    elif mop.t == hr.mop_p:
        collect_mops(mop.pair.lop, out)
        collect_mops(mop.pair.hop, out)


def build_ud_chain_for_block(blk):
    ud = []
    ins = blk.head
    while ins:
        # 收集这条指令所有寄存器 mop
        all_mops = []
        collect_mops(ins.l, all_mops)
        collect_mops(ins.r, all_mops)
        collect_mops(ins.d, all_mops)

        use_list = blk.build_use_list(ins, hr.MUST_ACCESS)

        for mop in all_mops:
            if mop.t != hr.mop_r:
                continue

            # 直接用 bitset.has_any 检查，不走 mlist_t.has_common
            if not use_list.reg.has_any(mop.r, mop.size):
                continue

            name = hr.get_mreg_name(mop.r, mop.size)

            # 往前找定义
            p = ins.prev
            found = False
            while p:
                prior_def = blk.build_def_list(p, hr.MUST_ACCESS)
                if prior_def.reg.has_any(mop.r, mop.size):
                    ud.append((name, ins, p))
                    found = True
                    break
                p = p.prev

            if not found:
                ud.append((name, ins, None))

        ins = ins.next

    return ud


def run(mba, block_serial):
    mba.build_graph()
    blk = mba.get_mblock(block_serial)

    # 调试：先看每条指令的 use/def 是否非空
    print("--- 调试 ---")
    ins = blk.head
    while ins:
        use_list = blk.build_use_list(ins, hr.MUST_ACCESS)
        def_list = blk.build_def_list(ins, hr.MUST_ACCESS)
        print(f"  {ins.ea:X}: {ins.dstr()}")
        print(f"    use_empty={use_list.reg.empty()} def_empty={def_list.reg.empty()}")
        if not use_list.reg.empty():
            print(f"    use_reg={use_list.reg.dstr()}")
        if not def_list.reg.empty():
            print(f"    def_reg={def_list.reg.dstr()}")
        ins = ins.next

    # 正式跑 UD 链
    ud = build_ud_chain_for_block(blk)
    print(f"\n块 {block_serial}, UD 链数量: {len(ud)}")
    for name, use_insn, def_insn in ud:
        if def_insn:
            print(f"  {name}: {use_insn.dstr()}")
            print(f"    <- {def_insn.dstr()}")
        else:
            print(f"  {name}: {use_insn.dstr()}")
            print(f"    <- 外部输入")
# ========== 使用 ==========
def main():
    ea = ida_kernwin.get_screen_ea()
    pfn = ida_funcs.get_func(ea)
    if not pfn:
        print("请在函数内使用")
        return

    mbr = hr.mba_ranges_t(pfn)
    hf = hr.hexrays_failure_t()
    mba = hr.gen_microcode(
        mbr, hf, None,
        hr.DECOMP_WARNINGS | hr.DECOMP_NO_CACHE,
        hr.MMAT_GLBOPT2
    )
    if not mba:
        print("微码生成失败")
        return


    run(mba,5)


if __name__ == '__main__':
    main()