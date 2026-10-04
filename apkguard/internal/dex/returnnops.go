package dex

// 本文件实现 A20 的第二种花指令形态：「return 前单发 nop」。
//
// 参考样本（classes.dex 2862 条 / classes2.dex 3539 条单发 nop，占指令字
// 3.7~4.0%）的形态是**每条 return* 之前垫 1 条 nop（0x0000）**，全部单发、
// 无连续段、不改变控制流图；而既有的入口形态（nop×N + 两条不可达 goto/16）
// 只是同族的另一种布局。两者并存，由 ControlFlow.ReturnNops 开关。
//
// 正确性依赖 InsnList 的既有机制，不另写重定位：
//   - InsertBefore 让插入的 nop 与 return 共享旧偏移，Encode 的 old2new
//     以「最后出现的项」为准，因此原本指向该 return 的分支在重定位后仍指向
//     return 本身（跳过 nop），fallthrough 则自然执行 nop 再 return；
//   - 分支偏移、try/handler 目标、handler_off 全部由 Encode/CodeItemFull.Encode
//     统一重算（与入口形态同一条路径）；
//   - 不插入 invoke、不写寄存器，registers_size/outs_size 不变。
//
// 含 try 或 switch/fill-array-data payload 的方法在 controlFlowCodeItem 里
// 已被整体跳过（与入口形态同一判据），因此这里不会遇到需要特殊处理的 try
// 端点或 payload 对齐。

// returnNopBudget 返回单个方法允许插入的 return 前 nop 数量上限。
//
// 上限对齐「总指令字增幅 ≤ 8%」：按方法原指令字数取 8%，至少 1 条——
// 至少 1 条保证小方法也有该形态（样本形态本就是「每个 return 前一条」），
// 8% 封顶则避免「大量 return 的小方法」被撑大（例如 if 链分解的 switch）。
func returnNopBudget(words int) int {
	b := words * 8 / 100
	if b < 1 {
		b = 1
	}
	return b
}

// insertReturnNops 在每个 return* 指令之前插入 1 条 nop，最多 budget 条。
//
// 从后往前插入：InsertBefore 会平移其后项的项下标，倒序处理保证尚未处理的
// return 下标仍然有效。返回实际插入的 nop 条数。
func insertReturnNops(l *InsnList, budget int) int {
	if budget <= 0 || l == nil {
		return 0
	}
	var idxs []int
	for i := 0; i < l.ItemCount(); i++ {
		if !l.ItemIsInsn(i) {
			continue
		}
		op := byte(l.ItemWords(i)[0] & 0xff)
		if op >= 0x0e && op <= 0x11 { // return-void / return / return-wide / return-object
			idxs = append(idxs, i)
		}
	}
	added := 0
	for k := len(idxs) - 1; k >= 0 && added < budget; k-- {
		l.InsertBefore(idxs[k], []uint16{0x0000})
		added++
	}
	return added
}
