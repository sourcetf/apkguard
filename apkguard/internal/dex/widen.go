package dex

// 本文件实现「自动把越界的 const-string 加宽为 const-string/jumbo」。
//
// 背景（真实缺陷）：
//
//	DEX 的 const-string（操作码 0x1a，格式 21c）字符串索引只有 **16 位**，
//	只有 const-string/jumbo（0x1b，格式 31c）能引用 65535 以上的下标。
//	重建会按 UTF-16 序**重排**字符串池（DEX 要求 string_ids 有序，ART 会校验），
//	于是新下标与旧下标无关：只要池长度超过 65535，某个原本合法的 const-string
//	就可能被映射到 >65535 的新下标，remapCode 直接失败：
//
//	  dex: 指令 0x1a @word 23 引用索引 65592 超出 16 位，需要指令加宽
//
//	实测触发：Termux 的 classes.dex 有 65866 个字符串（本身就超过 16 位，
//	原 DEX 用 jumbo 表达高位串），我们一追加字符串（A1 成员改名、A19 垃圾串等）
//	就可能越界。此前 internal/passes/rename.go 只能**降级**：池接近上限就整体
//	放弃追加字符串的改名通道。本文件把降级变成正解。
//
// 绝不能再走的老路（已回退）：
//
//	「把被 const-string 引用的字符串排到池前部」——那破坏了 string_ids 的
//	有序性，ART 报 "Out-of-order string_ids: 'V' then ''" 并丢弃整个 DEX。
//	因此这里只改指令**宽度**，绝不改索引本身；索引仍由 remapCode 统一重映射。

// WidenStats 汇总一次重建中「const-string 加宽为 const-string/jumbo」的结果。
type WidenStats struct {
	// Widened 是被自动加宽为 const-string/jumbo 的指令数。
	Widened int
	// Skipped 是因无法加宽（寄存器号放不下等）而保持原样的指令数。
	// 这类指令随后会让 remapCode 照旧报错——宁可失败也不产出坏 DEX。
	Skipped int
}

// maxStringIdx16 是 const-string（21c）能表达的字符串下标上限。
const maxStringIdx16 = 0xffff

// widenConstStrings 扫描一个 code_item，把「重映射后会越界」的 const-string
// 就地加宽为 const-string/jumbo。
//
// 必须在 remapCode **之前**调用：remapCode 按 insnWidth 的固定宽度线性遍历，
// 加宽会改变字位置，若在其之后做，后面的字全部错位。
//
// 输入 src 是「当前形态」的 code_item 字节流（A2/A3 之后），skip 是各改写
// 步骤登记的「已是最终索引、不可再映射」的绝对字位置。返回的 blob 尚未做索引
// 重映射，newSkip 是按插入位移平移后的 skip（若返回 changed=false，调用方
// 应沿用原 blob 与 skip）。
//
// 加宽时写入的是**旧索引**：索引值仍由 remapCode 重映射，因此新指令的两个
// 索引字不能进入 skip（否则 remapCode 会跳过它们，留下未重映射的旧索引）。
func (b *builder) widenConstStrings(pl *plan, src []byte, skip map[int]bool) (blob []byte, newSkip map[int]bool, changed bool, err error) {
	if b.R == nil || len(b.R.String) == 0 {
		return nil, nil, false, nil
	}
	// 池长度不足以产生 >0xffff 的下标时，加宽必然无事可做：直接返回，
	// 连解析都省掉（也保证小池重建是严格的 no-op）。
	if len(pl.pool) <= maxStringIdx16+1 {
		return nil, nil, false, nil
	}
	ci, err := ParseCodeItemBytes(src)
	if err != nil {
		return nil, nil, false, err
	}
	l, err := ParseInsns(ci.Insns)
	if err != nil {
		return nil, nil, false, err
	}

	// 先记下每项「改写前的字长」。Encode 只给出项起点的新偏移，而 skip 与
	// try 端点可能落在指令**内部**的字上（A2/A3 的 fresh 就是项内偏移），
	// 必须靠「项内相对偏移」把它们精确换算到新坐标，否则会漏跳或错跳。
	oldLens := make([]int, len(l.items))
	for i := range l.items {
		oldLens[i] = len(l.items[i].words)
	}

	// 找出需要加宽的 const-string。
	//
	// 判据用的是 b.R.String（旧索引 -> 新索引），与 remapCode 的 mapRef 完全一致；
	// 这样「加宽与否」和「remapCode 是否报错」永远同源，不会出现加了宽却仍越界、
	// 或没加宽却被跳过的情况。
	type pending struct {
		item   int
		reg    int
		oldIdx uint32
	}
	var todo []pending
	for i := 0; i < l.ItemCount(); i++ {
		if !l.ItemIsInsn(i) {
			continue
		}
		w := l.ItemWords(i)
		if byte(w[0]&0xff) != 0x1a { // 只处理非 jumbo 的 const-string
			continue
		}
		oldIdx := uint32(w[1])
		if int(oldIdx) >= len(b.R.String) {
			// 旧索引本身越界：留给 remapCode 报它原有的错误，这里不记账
			// （它不是「因加宽能力不足而失败」）。
			continue
		}
		if b.R.String[oldIdx] <= maxStringIdx16 {
			continue // 新下标放得下，保持 2 字
		}
		reg := int(w[0] >> 8)
		if reg > 0xff {
			// 21c / 31c 的寄存器字段都只有 8 位，>255 无法用 jumbo 表达。
			// 实际上 0x1a 的 AA 就是 8 位，这里不可能触发；保留判据是为了
			// 将来格式变化时也能保守失败，并把失败原因记账。
			pl.widen.Skipped++
			continue
		}
		todo = append(todo, pending{item: i, reg: reg, oldIdx: oldIdx})
	}
	if len(todo) == 0 {
		return nil, nil, false, nil
	}

	// 替换为 jumbo：0x1b | AA<<8，随后 lo16、hi16（共 3 字）。
	// 不传 fresh——这两个索引字必须交给 remapCode 重映射。
	for _, p := range todo {
		l.Replace(p.item, []uint16{
			0x1b | uint16(p.reg)<<8,
			uint16(p.oldIdx & 0xffff),
			uint16(p.oldIdx >> 16),
		})
	}

	insns, m, _, err := l.EncodeChecked()
	if err != nil {
		return nil, nil, false, err
	}
	pl.widen.Widened += len(todo)

	ci.Insns = insns

	// try 区间端点与异常处理器目标地址必须随长度变化修正。
	//
	// 端点通常是指令起点，由 m（old2new）覆盖；但为稳妥，落在指令**内部**
	// 的字位置也按项内相对偏移换算（见 oldLens 的说明）。
	fixAddr := func(old uint32) uint32 {
		if v, ok := m[int(old)]; ok {
			return uint32(v)
		}
		for i, it := range l.items {
			ol := oldLens[i]
			if int(old) > it.old && int(old) < it.old+ol {
				return uint32(it.new + (int(old) - it.old))
			}
		}
		return old
	}

	// skip 平移：这是本步最容易错的地方。
	//
	// skip 里是「已是最终索引、不可再映射」的**绝对字位置**（A2 写的密文索引与
	// 解密方法索引、A3 写的类型/方法索引）。加宽插入了一个字，所有位于插入点
	// 之后的字位置都要后移；平移错了 remapCode 就会漏跳（把新索引当旧索引再映射
	// 一次，产物静默损坏）或错跳（跳过不该跳的字，留下未映射的旧索引）。
	//
	// 这里不简单地「+1」：Encode 可能因 payload 对齐插入 nop、或把 goto 加宽，
	// 使位移不止 1。因此按「项内相对偏移」精确换算：找到包含该字位置的项，
	// 用它的最终起点 it.new 还原。skip 恒为 A2/A3 替换项的**内部字**，
	// 项长在本步不变，换算可靠。
	newSkip = make(map[int]bool, len(skip))
	for p := range skip {
		np := p
		for i, it := range l.items {
			ol := oldLens[i]
			if p >= it.old && p < it.old+ol {
				np = it.new + (p - it.old)
				break
			}
		}
		newSkip[np] = true
	}

	code, err := ci.EncodeChecked(fixAddr)
	if err != nil {
		return nil, nil, false, err
	}
	return code, newSkip, true, nil
}
