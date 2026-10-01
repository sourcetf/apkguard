package dex

import "fmt"

// ValidateDescriptors 校验 DEX 类型表中的每一个描述符都合法。
//
// 为什么需要单独做这件事：改名/重建会**生成新的类描述符**（A1 给类分配短名，
// 注入类也用构造出来的名字）。若生成逻辑出错（例如把默认包类的包前缀算成空串，
// 得到 "auo;" 这种缺 'L' 的名字，数组形式更是 "[[auo;"），产物在 ART 眼里就是
// 非法 DEX，被直接丢弃——表现是 ClassNotFoundException，而本地极易漏掉：
//
//   - dex.Verify 只校验校验和/签名，不看描述符；
//   - 校验和自洽的产物 dex2oat --compiler-filter=verify 也不报错；
//   - 只有在设备上、或先用 dexdump 之类的官方工具才能看出来。
//
// 所以把这条检查前移到本地：任何一次重建之后都能立刻失败。
func ValidateDescriptors(data []byte) error {
	f, err := Parse(data)
	if err != nil {
		return err
	}
	for i := uint32(0); i < f.NType; i++ {
		s, err := f.Type(i)
		if err != nil {
			return fmt.Errorf("读取类型 %d 失败: %w", i, err)
		}
		if !ValidDescriptor(s) {
			return fmt.Errorf("类型表中存在非法描述符 %q（ART 会判 Invalid type descriptor 并丢弃整个 DEX）", s)
		}
	}
	return nil
}

// ValidDescriptor 判断一个类型描述符是否符合 DEX 规范。
//
// 允许的形式：基本类型（VZBSCIJFD）、对象类型（L...;）、以及二者的数组（[ 前缀）。
func ValidDescriptor(s string) bool {
	if s == "" {
		return false
	}
	// 剥掉数组维度
	body := s
	for len(body) > 0 && body[0] == '[' {
		body = body[1:]
	}
	if body == "" {
		return false
	}
	if len(body) == 1 {
		// 基本类型（含 V，虽然 V 不应作为字段/数组元素类型，这里不做更严的判定）
		return body[0] == 'V' || body[0] == 'Z' || body[0] == 'B' || body[0] == 'S' ||
			body[0] == 'C' || body[0] == 'I' || body[0] == 'J' || body[0] == 'F' || body[0] == 'D'
	}
	// 对象类型：L...; 且名字里不能出现 '.'、'['、';'
	if body[0] != 'L' || body[len(body)-1] != ';' {
		return false
	}
	name := body[1 : len(body)-1]
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		switch name[i] {
		case '.', '[', ';':
			return false
		}
	}
	return true
}
