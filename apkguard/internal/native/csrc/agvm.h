/*
 * B6：VMP 私有字节码解释器（核心 + 注册表 + 宿主自测）。
 *
 * 契约（与 Go 侧 internal/vmp 严格一致，改动必须两侧同步）：
 *   - 操作码数值必须与 internal/vmp/isa.go 完全一致。Go 测试
 *     TestOpcodeContractWithC 解析本文件的 ag_op 枚举逐值比对，
 *     任何一侧悄悄改号都会在 CI 被拦下。
 *   - 私有指令是**定长 32 位**：op[7:0] vA[15:8] vB[23:16] vC[31:24]。
 *     Goto/If 的目标是**绝对私有 PC**（单位：32 位字）。
 *   - 宽值（long）占两个连续寄存器槽，低 32 位在低编号槽（与 Dalvik 一致）。
 *   - 数值语义对齐 Dalvik：整除向零截断、除零是错误（宿主抛
 *     ArithmeticException）、INT_MIN/-1 回绕；移位按 31/63 取模。
 *   - 程序结构在解析期做完整校验（ag_vm_verify）：未知操作码、寄存器/
 *     池索引越界、跳转目标不在指令边界一律拒绝，绝不让坏字节码进解释器。
 *
 * 本段在 NDK（AG_JNI）、宿主自测（AG_HOST_TEST）与 Linux 自测下都编译；
 * 对象/字段/调用通过 ag_vm_rt 回调与宿主交互，核心不依赖 JNI。
 *
 * 「真 VMP」的判别点：解释器有**独立的 dispatch 循环**（ag_vm_execute 的
 * for(;;) switch），消费的是私有指令流——不是把解密后的原始 Dalvik 交回 ART。
 */

#ifndef APKGUARD_AGVM_H
#define APKGUARD_AGVM_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(AG_JNI)
#include <pthread.h>
#endif

/* ------------------------------------------------------------------ */
/* 私有指令集（与 internal/vmp/isa.go 是同一份二进制契约）             */
/* ------------------------------------------------------------------ */

enum ag_op {
	AG_OP_NOP = 0x00,

	AG_OP_MOVE = 0x01,
	AG_OP_MOVEWIDE = 0x02,
	AG_OP_MOVEOBJECT = 0x03,
	AG_OP_CONST = 0x04,
	AG_OP_CONSTWIDE = 0x05,
	AG_OP_CONSTSTRING = 0x06,
	AG_OP_MOVERESULT = 0x07,
	AG_OP_MOVERESULTWIDE = 0x08,
	AG_OP_MOVERESULTOBJECT = 0x09,

	AG_OP_NEGINT = 0x10,
	AG_OP_NOTINT = 0x11,
	AG_OP_NEGLONG = 0x12,
	AG_OP_NOTLONG = 0x13,
	AG_OP_I2B = 0x14,
	AG_OP_I2C = 0x15,
	AG_OP_I2S = 0x16,
	AG_OP_I2L = 0x17,
	AG_OP_L2I = 0x18,

	AG_OP_ADDINT = 0x20,
	AG_OP_SUBINT = 0x21,
	AG_OP_MULINT = 0x22,
	AG_OP_DIVINT = 0x23,
	AG_OP_REMINT = 0x24,
	AG_OP_ANDINT = 0x25,
	AG_OP_ORINT = 0x26,
	AG_OP_XORINT = 0x27,
	AG_OP_SHLINT = 0x28,
	AG_OP_SHRINT = 0x29,
	AG_OP_USHRINT = 0x2a,
	AG_OP_ADDLONG = 0x2b,
	AG_OP_SUBLONG = 0x2c,
	AG_OP_MULLONG = 0x2d,
	AG_OP_DIVLONG = 0x2e,
	AG_OP_REMLONG = 0x2f,
	AG_OP_ANDLONG = 0x30,
	AG_OP_ORLONG = 0x31,
	AG_OP_XORLONG = 0x32,
	AG_OP_SHLLONG = 0x33,
	AG_OP_SHRLONG = 0x34,
	AG_OP_USHRLONG = 0x35,
	AG_OP_CMPLONG = 0x36,

	AG_OP_ADDINTIMM = 0x40,
	AG_OP_MULINTIMM = 0x42,
	AG_OP_DIVINTIMM = 0x43,
	AG_OP_REMINTIMM = 0x44,
	AG_OP_ANDINTIMM = 0x45,
	AG_OP_ORINTIMM = 0x46,
	AG_OP_XORINTIMM = 0x47,
	AG_OP_SHLINTIMM = 0x48,
	AG_OP_SHRINTIMM = 0x49,
	AG_OP_USHRINTIMM = 0x4a,

	AG_OP_GOTO = 0x50,
	AG_OP_IFEQ = 0x51,
	AG_OP_IFNE = 0x52,
	AG_OP_IFLT = 0x53,
	AG_OP_IFGE = 0x54,
	AG_OP_IFGT = 0x55,
	AG_OP_IFLE = 0x56,
	AG_OP_IFEQZ = 0x57,
	AG_OP_IFNEZ = 0x58,
	AG_OP_IFLTZ = 0x59,
	AG_OP_IFGEZ = 0x5a,
	AG_OP_IFGTZ = 0x5b,
	AG_OP_IFLEZ = 0x5c,

	AG_OP_IGET = 0x60,
	AG_OP_IPUT = 0x61,
	AG_OP_SGET = 0x62,
	AG_OP_SPUT = 0x63,
	AG_OP_IGETWIDE = 0x64,
	AG_OP_IPUTWIDE = 0x65,
	AG_OP_SGETWIDE = 0x66,
	AG_OP_SPUTWIDE = 0x67,
	AG_OP_IGETOBJECT = 0x68,
	AG_OP_IPUTOBJECT = 0x69,
	AG_OP_SGETOBJECT = 0x6a,
	AG_OP_SPUTOBJECT = 0x6b,

	AG_OP_INVOKESTATIC = 0x70,
	AG_OP_INVOKEVIRTUAL = 0x71,
	AG_OP_INVOKEDIRECT = 0x72,
	AG_OP_INVOKESUPER = 0x73,
	AG_OP_INVOKEINTERFACE = 0x74,

	AG_OP_RETURNVOID = 0x75,
	AG_OP_RETURN = 0x76,
	AG_OP_RETURNWIDE = 0x77,
	AG_OP_RETURNOBJECT = 0x78
};

/* 与 Go 侧 MaxRegisters / MaxInsns 对应。 */
#define AG_VM_MAX_REGS 64
#define AG_VM_MAX_INVOKE_ARGS 5
#define AG_VM_MAX_CODE 0xFFFFFFu
#define AG_VM_MAX_POOL 65536u
#define AG_VM_MAX_STRUNITS (1u << 20)
#define AG_VM_MAX_STEPS 10000000u
#define AG_VM_BLOB_VERSION 1u
#define AG_VM_REG_MAX 256

/* ------------------------------------------------------------------ */
/* 值与错误码                                                          */
/* ------------------------------------------------------------------ */

typedef enum {
	AG_VV_VOID = 0,
	AG_VV_INT = 1,
	AG_VV_WIDE = 2,
	AG_VV_REF = 3
} ag_vv_kind;

typedef struct {
	uint8_t kind;
	uint64_t i;    /* 32/64 位原始位（int 已符号扩展） */
	void *ref;     /* 后端不透明引用 */
} ag_vv;

typedef enum {
	AG_VM_OK = 0,
	AG_VM_ERR_ARG = -1,
	AG_VM_ERR_FORMAT = -2,
	AG_VM_ERR_VERIFY = -3,
	AG_VM_ERR_DIV0 = -4,
	AG_VM_ERR_STEP = -5,
	AG_VM_ERR_PC = -6,
	AG_VM_ERR_OP = -7,
	AG_VM_ERR_REG = -8,
	AG_VM_ERR_POOL = -9,
	AG_VM_ERR_MOVERESULT = -10,
	AG_VM_ERR_RT = -11,
	AG_VM_ERR_NOMEM = -12
} ag_vm_err;

static const char *ag_vm_strerror(int code) {
	switch (code) {
	case AG_VM_OK: return "ok";
	case AG_VM_ERR_ARG: return "参数非法";
	case AG_VM_ERR_FORMAT: return "字节码格式损坏";
	case AG_VM_ERR_VERIFY: return "字节码结构校验失败";
	case AG_VM_ERR_DIV0: return "整数除数为零";
	case AG_VM_ERR_STEP: return "执行步数超限（疑似死循环）";
	case AG_VM_ERR_PC: return "pc 越界";
	case AG_VM_ERR_OP: return "未知操作码";
	case AG_VM_ERR_REG: return "寄存器越界";
	case AG_VM_ERR_POOL: return "池索引越界";
	case AG_VM_ERR_MOVERESULT: return "move-result 与最近一次调用返回类型不符";
	case AG_VM_ERR_RT: return "宿主运行时错误";
	case AG_VM_ERR_NOMEM: return "内存不足";
	default: return "未知错误";
	}
}

/* ------------------------------------------------------------------ */
/* 程序与池结构                                                        */
/* ------------------------------------------------------------------ */

typedef struct {
	uint16_t *u;
	uint32_t n;
} ag_vm_str;

typedef struct {
	char *cls;
	char *name;
	char *proto;
	uint8_t kind; /* 0 static / 1 virtual / 2 direct / 3 super / 4 interface */
} ag_vm_mref;

typedef struct {
	char *cls;
	char *name;
	char *type;
	uint8_t is_static;
} ag_vm_fref;

typedef struct ag_vm_prog {
	uint32_t vmid;
	uint32_t access;
	char *cls;
	char *name;
	char *proto;
	char *sig; /* cls + "->" + name + proto（与 Go Program.Sig 同格式） */
	uint16_t regs;
	uint16_t ins;
	uint32_t ncode;
	uint32_t *code;
	uint32_t nstr;
	ag_vm_str *strs;
	uint32_t nmth;
	ag_vm_mref *mths;
	uint32_t nfld;
	ag_vm_fref *flds;
} ag_vm_prog;

typedef struct {
	ag_vm_prog **progs;
	uint32_t n;
} ag_vm_blob;

/* 运行时回调：宿主（JNI 后端 / 宿主自测 mock）实现。 */
typedef struct ag_vm_rt {
	void *ctx;
	/* 由 UTF-16 码元构造字符串对象。 */
	int (*str_new)(void *ctx, const uint16_t *u, uint32_t n, void **out);
	int (*field_get)(void *ctx, const ag_vm_fref *f, void *obj, ag_vv *out);
	int (*field_put)(void *ctx, const ag_vm_fref *f, void *obj, const ag_vv *v);
	int (*invoke)(void *ctx, const ag_vm_mref *m, const ag_vv *args, uint32_t argc, ag_vv *out);
} ag_vm_rt;

/* ------------------------------------------------------------------ */
/* 小端读取器（带边界检查）                                            */
/* ------------------------------------------------------------------ */

typedef struct {
	const uint8_t *b;
	size_t n;
	size_t p;
	int err;
} agvm_rd;

static uint8_t agvm_rd8(agvm_rd *r) {
	if (r->err || r->p + 1 > r->n) {
		r->err = 1;
		return 0;
	}
	return r->b[r->p++];
}

static uint16_t agvm_rd16(agvm_rd *r) {
	uint16_t v;
	if (r->err || r->p + 2 > r->n) {
		r->err = 1;
		return 0;
	}
	v = (uint16_t)((uint16_t)r->b[r->p] | ((uint16_t)r->b[r->p + 1] << 8));
	r->p += 2;
	return v;
}

static uint32_t agvm_rd32(agvm_rd *r) {
	uint32_t v;
	if (r->err || r->p + 4 > r->n) {
		r->err = 1;
		return 0;
	}
	v = (uint32_t)r->b[r->p] | ((uint32_t)r->b[r->p + 1] << 8) |
	    ((uint32_t)r->b[r->p + 2] << 16) | ((uint32_t)r->b[r->p + 3] << 24);
	r->p += 4;
	return v;
}

/* agvm_rdstr 读 u16 长度 + 原始字节，返回 NUL 结尾的副本（调用方 free）。 */
static char *agvm_rdstr(agvm_rd *r) {
	uint16_t n = agvm_rd16(r);
	char *s;
	if (r->err) {
		return 0;
	}
	if (n > 4096) {
		r->err = 1;
		return 0;
	}
	if (r->p + n > r->n) {
		r->err = 1;
		return 0;
	}
	s = (char *)malloc((size_t)n + 1);
	if (!s) {
		r->err = 1;
		return 0;
	}
	memcpy(s, r->b + r->p, n);
	s[n] = 0;
	r->p += n;
	return s;
}

static void ag_vm_free_prog(ag_vm_prog *p) {
	uint32_t i;
	if (!p) {
		return;
	}
	free(p->cls);
	free(p->name);
	free(p->proto);
	free(p->sig);
	free(p->code);
	for (i = 0; i < p->nstr; i++) {
		free(p->strs[i].u);
	}
	free(p->strs);
	for (i = 0; i < p->nmth; i++) {
		free(p->mths[i].cls);
		free(p->mths[i].name);
		free(p->mths[i].proto);
	}
	free(p->mths);
	for (i = 0; i < p->nfld; i++) {
		free(p->flds[i].cls);
		free(p->flds[i].name);
		free(p->flds[i].type);
	}
	free(p->flds);
	free(p);
}

/* ------------------------------------------------------------------ */
/* 结构校验                                                            */
/* ------------------------------------------------------------------ */

/*
 * ag_vm_width 返回 pc 处私有指令的字数；未知操作码返回 -1。
 * 宽度只取决于操作码与 invoke 实参个数，与目标地址无关。
 */
static int ag_vm_width(const uint32_t *code, uint32_t n, uint32_t pc) {
	uint8_t op;
	if (pc >= n) {
		return -1;
	}
	op = (uint8_t)(code[pc] & 0xff);
	if (op == AG_OP_NOP || op == AG_OP_MOVE || op == AG_OP_MOVEWIDE ||
	    op == AG_OP_MOVEOBJECT || op == AG_OP_MOVERESULT || op == AG_OP_MOVERESULTWIDE ||
	    op == AG_OP_MOVERESULTOBJECT || (op >= AG_OP_NEGINT && op <= AG_OP_L2I) ||
	    (op >= AG_OP_ADDINT && op <= AG_OP_CMPLONG) ||
	    (op >= AG_OP_RETURNVOID && op <= AG_OP_RETURNOBJECT)) {
		return 1;
	}
	if (op == AG_OP_CONST || op == AG_OP_CONSTSTRING ||
	    (op >= AG_OP_ADDINTIMM && op <= AG_OP_USHRINTIMM) ||
	    (op >= AG_OP_GOTO && op <= AG_OP_IFLEZ) ||
	    (op >= AG_OP_IGET && op <= AG_OP_SPUTOBJECT)) {
		return 2;
	}
	if (op == AG_OP_CONSTWIDE) {
		return 3;
	}
	if (op >= AG_OP_INVOKESTATIC && op <= AG_OP_INVOKEINTERFACE) {
		return 2 + (int)(((code[pc] >> 8) & 0xff) + 3) / 4;
	}
	return -1;
}

static int ag_vm_invoke_argc(const uint32_t *code, uint32_t pc) {
	return (int)((code[pc] >> 8) & 0xff);
}

static int ag_vm_invoke_arg(const uint32_t *code, uint32_t pc, int i) {
	uint32_t w = code[pc + 2 + (uint32_t)i / 4];
	return (int)((w >> (8u * (uint32_t)(i % 4))) & 0xff);
}

/* 字段操作码按 4 个一组排列：iget/iput/sget/sput。 */
static int ag_vm_field_static(uint8_t op) { return (int)((op - AG_OP_IGET) % 4) >= 2; }

static int ag_vm_field_wide(uint8_t op) {
	return op == AG_OP_IGETWIDE || op == AG_OP_IPUTWIDE || op == AG_OP_SGETWIDE ||
	       op == AG_OP_SPUTWIDE;
}

static int ag_vm_field_object(uint8_t op) {
	return op == AG_OP_IGETOBJECT || op == AG_OP_IPUTOBJECT || op == AG_OP_SGETOBJECT ||
	       op == AG_OP_SPUTOBJECT;
}

/* ag_vm_field_type_ok 校验字段读写指令的宽窄与字段类型一致。 */
static int ag_vm_field_type_ok(uint8_t op, const char *typ) {
	char c;
	if (!typ || !typ[0]) {
		return 0;
	}
	c = typ[0];
	if (ag_vm_field_wide(op)) {
		return c == 'J';
	}
	if (ag_vm_field_object(op)) {
		return c == 'L' || c == '[';
	}
	return c == 'Z' || c == 'B' || c == 'S' || c == 'C' || c == 'I';
}

/* ------------------------------------------------------------------ */
/* 方法原型扫描（第一版只支持整型/长整型/引用）                        */
/* ------------------------------------------------------------------ */

enum { AG_PK_INT = 0, AG_PK_WIDE = 1, AG_PK_REF = 2, AG_PK_FLOAT = 3 };

/*
 * ag_vm_proto_next 解析 q 处的一个参数类型；*kind 填分类，返回新位置。
 * 解析到 ')' 或字符串末尾返回 0。
 */
static const char *ag_vm_proto_next(const char *q, int *kind) {
	const char *s = q;
	if (*s == '[') {
		while (*s == '[') {
			s++;
		}
		if (*s == 'L') {
			while (*s && *s != ';') {
				s++;
			}
			if (*s == ';') {
				s++;
			}
		} else if (*s) {
			s++;
		}
		*kind = AG_PK_REF;
		return s;
	}
	switch (*s) {
	case 'J':
		*kind = AG_PK_WIDE;
		return s + 1;
	case 'D':
	case 'F':
		*kind = AG_PK_FLOAT;
		return s + 1;
	case 'L':
		while (*s && *s != ';') {
			s++;
		}
		if (*s == ';') {
			s++;
		}
		*kind = AG_PK_REF;
		return s;
	case 'Z':
	case 'B':
	case 'S':
	case 'C':
	case 'I':
		*kind = AG_PK_INT;
		return s + 1;
	default:
		return 0;
	}
}

/*
 * ag_vm_proto_slots 返回实例方法（含接收者）或静态方法的寄存器槽总数，
 * 同时拒绝浮点参数与语法非法。*ok 为 0 表示原型非法。
 */
static int ag_vm_proto_slots(const char *proto, int is_static, int *ok) {
	const char *q = proto;
	int slots = 0;
	*ok = 0;
	if (!q || *q != '(') {
		return 0;
	}
	q++;
	while (*q && *q != ')') {
		int kind;
		const char *nq = ag_vm_proto_next(q, &kind);
		if (!nq || nq == q) {
			return 0;
		}
		if (kind == AG_PK_FLOAT) {
			return 0;
		}
		slots += (kind == AG_PK_WIDE) ? 2 : 1;
		q = nq;
	}
	if (*q != ')') {
		return 0;
	}
	*ok = 1;
	return slots + (is_static ? 0 : 1);
}

static int ag_vm_verify(const ag_vm_prog *p) {
	uint8_t *starts = 0;
	uint32_t pc;
	int ok;

	/* registers=0 合法：无参 void 方法可以一个寄存器都不用（RustDesk 实测）。 */
	if (!p || p->regs > AG_VM_MAX_REGS) {
		return AG_VM_ERR_VERIFY;
	}
	if (p->ins > p->regs) {
		return AG_VM_ERR_VERIFY;
	}
	if (p->ncode == 0 || p->ncode > AG_VM_MAX_CODE) {
		return AG_VM_ERR_VERIFY;
	}
	starts = (uint8_t *)calloc(p->ncode, 1);
	if (!starts) {
		return AG_VM_ERR_NOMEM;
	}
	pc = 0;
	while (pc < p->ncode) {
		int w = ag_vm_width(p->code, p->ncode, pc);
		if (w <= 0 || pc + (uint32_t)w > p->ncode) {
			free(starts);
			return AG_VM_ERR_VERIFY;
		}
		starts[pc] = 1;
		pc += (uint32_t)w;
	}
	if (pc != p->ncode) {
		free(starts);
		return AG_VM_ERR_VERIFY;
	}

#define AG_REG(NAME, R) \
	do { if ((int)(R) < 0 || (int)(R) >= (int)p->regs) { free(starts); return AG_VM_ERR_VERIFY; } } while (0)
#define AG_REGW(NAME, R) \
	do { if ((int)(R) < 0 || (int)(R) + 1 >= (int)p->regs) { free(starts); return AG_VM_ERR_VERIFY; } } while (0)
	pc = 0;
	while (pc < p->ncode) {
		int w = ag_vm_width(p->code, p->ncode, pc);
		uint8_t op = (uint8_t)(p->code[pc] & 0xff);
		int a = (int)((p->code[pc] >> 8) & 0xff);
		int b = (int)((p->code[pc] >> 16) & 0xff);
		int c = (int)((p->code[pc] >> 24) & 0xff);
		if (op == AG_OP_NOP) {
			/* nothing */
		} else if (op == AG_OP_MOVE || op == AG_OP_MOVEOBJECT) {
			AG_REG("move", a);
			AG_REG("move", b);
		} else if (op == AG_OP_MOVEWIDE) {
			AG_REGW("move-wide", a);
			AG_REGW("move-wide", b);
		} else if (op == AG_OP_CONST) {
			AG_REG("const", a);
		} else if (op == AG_OP_CONSTWIDE) {
			AG_REGW("const-wide", a);
		} else if (op == AG_OP_CONSTSTRING) {
			AG_REG("const-string", a);
			if ((int)p->code[pc + 1] < 0 || (uint32_t)p->code[pc + 1] >= p->nstr) {
				free(starts);
				return AG_VM_ERR_VERIFY;
			}
		} else if (op == AG_OP_MOVERESULT) {
			AG_REG("move-result", a);
		} else if (op == AG_OP_MOVERESULTWIDE) {
			AG_REGW("move-result-wide", a);
		} else if (op == AG_OP_MOVERESULTOBJECT) {
			AG_REG("move-result-object", a);
		} else if (op >= AG_OP_NEGINT && op <= AG_OP_L2I) {
			if (op == AG_OP_NEGLONG || op == AG_OP_NOTLONG) {
				AG_REGW("unary-wide", a);
				AG_REGW("unary-wide", b);
			} else if (op == AG_OP_I2L) {
				AG_REGW("int-to-long", a);
				AG_REG("int-to-long", b);
			} else if (op == AG_OP_L2I) {
				AG_REG("long-to-int", a);
				AG_REGW("long-to-int", b);
			} else {
				AG_REG("unary", a);
				AG_REG("unary", b);
			}
		} else if (op >= AG_OP_ADDINT && op <= AG_OP_CMPLONG) {
			if (op == AG_OP_CMPLONG) {
				/* cmp-long 的目标是 32 位 int，只有两个源是宽值。 */
				AG_REG("cmp-long", a);
				AG_REGW("cmp-long", b);
				AG_REGW("cmp-long", c);
			} else if (op >= AG_OP_ADDLONG) {
				AG_REGW("binary-wide", a);
				AG_REGW("binary-wide", b);
				AG_REGW("binary-wide", c);
			} else {
				AG_REG("binary", a);
				AG_REG("binary", b);
				AG_REG("binary", c);
			}
		} else if (op >= AG_OP_ADDINTIMM && op <= AG_OP_USHRINTIMM) {
			AG_REG("imm", a);
			AG_REG("imm", b);
		} else if (op == AG_OP_GOTO) {
			uint32_t t = p->code[pc + 1];
			if (t >= p->ncode || !starts[t]) {
				free(starts);
				return AG_VM_ERR_VERIFY;
			}
		} else if (op >= AG_OP_IFEQ && op <= AG_OP_IFLE) {
			AG_REG("if", a);
			AG_REG("if", b);
			if (p->code[pc + 1] >= p->ncode || !starts[p->code[pc + 1]]) {
				free(starts);
				return AG_VM_ERR_VERIFY;
			}
		} else if (op >= AG_OP_IFEQZ && op <= AG_OP_IFLEZ) {
			AG_REG("ifz", a);
			if (p->code[pc + 1] >= p->ncode || !starts[p->code[pc + 1]]) {
				free(starts);
				return AG_VM_ERR_VERIFY;
			}
		} else if (op >= AG_OP_IGET && op <= AG_OP_SPUTOBJECT) {
			if (ag_vm_field_wide(op)) {
				AG_REGW("field-wide", a);
			} else {
				AG_REG("field-a", a);
			}
			if (!ag_vm_field_static(op)) {
				AG_REG("field-b", b);
			}
			if ((uint32_t)p->code[pc + 1] >= p->nfld) {
				free(starts);
				return AG_VM_ERR_VERIFY;
			}
			if (!ag_vm_field_type_ok(op, p->flds[p->code[pc + 1]].type)) {
				free(starts);
				return AG_VM_ERR_VERIFY;
			}
		} else if (op >= AG_OP_INVOKESTATIC && op <= AG_OP_INVOKEINTERFACE) {
			int argc = ag_vm_invoke_argc(p->code, pc);
			int slots, is_static, li;
			uint32_t mi;
			const char *q;
			if (argc > AG_VM_MAX_INVOKE_ARGS) {
				free(starts);
				return AG_VM_ERR_VERIFY;
			}
			mi = p->code[pc + 1];
			if (mi >= p->nmth) {
				free(starts);
				return AG_VM_ERR_VERIFY;
			}
			is_static = p->mths[mi].kind == 0;
			slots = ag_vm_proto_slots(p->mths[mi].proto, is_static, &ok);
			if (!ok || slots != argc) {
				free(starts);
				return AG_VM_ERR_VERIFY;
			}
			q = p->mths[mi].proto + 1;
			li = 0;
			if (!is_static) {
				AG_REG("invoke-recv", ag_vm_invoke_arg(p->code, pc, li));
				li++;
			}
			while (*q && *q != ')') {
				int kind;
				const char *nq = ag_vm_proto_next(q, &kind);
				if (!nq || nq == q) {
					free(starts);
					return AG_VM_ERR_VERIFY;
				}
				if (kind == AG_PK_WIDE) {
					if (li + 1 >= argc) {
						free(starts);
						return AG_VM_ERR_VERIFY;
					}
					AG_REGW("invoke", ag_vm_invoke_arg(p->code, pc, li));
					li += 2;
				} else {
					AG_REG("invoke", ag_vm_invoke_arg(p->code, pc, li));
					li++;
				}
				q = nq;
			}
			if (li != argc) {
				free(starts);
				return AG_VM_ERR_VERIFY;
			}
		} else if (op >= AG_OP_RETURNVOID && op <= AG_OP_RETURNOBJECT) {
			if (op == AG_OP_RETURNWIDE) {
				AG_REGW("return-wide", a);
			} else if (op != AG_OP_RETURNVOID) {
				AG_REG("return", a);
			}
		} else {
			free(starts);
			return AG_VM_ERR_OP;
		}
		pc += (uint32_t)w;
	}
#undef AG_REG
#undef AG_REGW
	free(starts);
	return AG_VM_OK;
}

/* ------------------------------------------------------------------ */
/* 记录 / blob 解析                                                    */
/* ------------------------------------------------------------------ */

/*
 * ag_vm_parse_record_n 解析单方法记录（Go 侧 EncodeMethodRecord 的格式），
 * 解析成功后立即做结构校验；*consumed 返回消费的字节数（blob 解析用）。
 * 失败返回 NULL。
 */
static ag_vm_prog *ag_vm_parse_record_n(const uint8_t *b, size_t n, size_t *consumed, int *err) {
	agvm_rd r;
	ag_vm_prog *p;
	uint32_t i;

	if (!b || n == 0) {
		if (err) {
			*err = AG_VM_ERR_ARG;
		}
		return 0;
	}
	p = (ag_vm_prog *)calloc(1, sizeof(*p));
	if (!p) {
		if (err) {
			*err = AG_VM_ERR_NOMEM;
		}
		return 0;
	}
	r.b = b;
	r.n = n;
	r.p = 0;
	r.err = 0;

	p->vmid = agvm_rd32(&r);
	p->access = agvm_rd32(&r);
	p->cls = agvm_rdstr(&r);
	p->name = agvm_rdstr(&r);
	p->proto = agvm_rdstr(&r);
	p->regs = agvm_rd16(&r);
	p->ins = agvm_rd16(&r);
	p->ncode = agvm_rd32(&r);
	if (r.err || p->ncode > AG_VM_MAX_CODE || p->ncode == 0) {
		goto fail;
	}
	p->code = (uint32_t *)malloc((size_t)p->ncode * 4);
	if (!p->code) {
		goto fail;
	}
	for (i = 0; i < p->ncode; i++) {
		p->code[i] = agvm_rd32(&r);
	}
	p->nstr = agvm_rd32(&r);
	if (r.err || p->nstr > AG_VM_MAX_POOL) {
		goto fail;
	}
	if (p->nstr) {
		p->strs = (ag_vm_str *)calloc(p->nstr, sizeof(ag_vm_str));
		if (!p->strs) {
			goto fail;
		}
	}
	for (i = 0; i < p->nstr; i++) {
		uint32_t k, len = agvm_rd32(&r);
		if (r.err || len > AG_VM_MAX_STRUNITS) {
			goto fail;
		}
		p->strs[i].u = (uint16_t *)malloc(((size_t)len + 1) * 2);
		if (!p->strs[i].u) {
			goto fail;
		}
		p->strs[i].n = len;
		for (k = 0; k < len; k++) {
			p->strs[i].u[k] = agvm_rd16(&r);
		}
	}
	p->nmth = agvm_rd32(&r);
	if (r.err || p->nmth > AG_VM_MAX_POOL) {
		goto fail;
	}
	if (p->nmth) {
		p->mths = (ag_vm_mref *)calloc(p->nmth, sizeof(ag_vm_mref));
		if (!p->mths) {
			goto fail;
		}
	}
	for (i = 0; i < p->nmth; i++) {
		p->mths[i].kind = agvm_rd8(&r);
		p->mths[i].cls = agvm_rdstr(&r);
		p->mths[i].name = agvm_rdstr(&r);
		p->mths[i].proto = agvm_rdstr(&r);
		if (r.err || p->mths[i].kind > 4) {
			goto fail;
		}
	}
	p->nfld = agvm_rd32(&r);
	if (r.err || p->nfld > AG_VM_MAX_POOL) {
		goto fail;
	}
	if (p->nfld) {
		p->flds = (ag_vm_fref *)calloc(p->nfld, sizeof(ag_vm_fref));
		if (!p->flds) {
			goto fail;
		}
	}
	for (i = 0; i < p->nfld; i++) {
		uint8_t flags = agvm_rd8(&r);
		p->flds[i].cls = agvm_rdstr(&r);
		p->flds[i].name = agvm_rdstr(&r);
		p->flds[i].type = agvm_rdstr(&r);
		p->flds[i].is_static = (flags & 1) ? 1 : 0;
		if (r.err) {
			goto fail;
		}
	}
	if (r.err) {
		goto fail;
	}
	/* sig = cls + "->" + name + proto（与 Go Program.Sig 一致）。 */
	{
		size_t lc = strlen(p->cls), ln = strlen(p->name), lp = strlen(p->proto);
		p->sig = (char *)malloc(lc + ln + lp + 3);
		if (!p->sig) {
			goto fail;
		}
		memcpy(p->sig, p->cls, lc);
		memcpy(p->sig + lc, "->", 2);
		memcpy(p->sig + lc + 2, p->name, ln);
		memcpy(p->sig + lc + 2 + ln, p->proto, lp + 1);
	}
	if (ag_vm_verify(p) != AG_VM_OK) {
		if (err) {
			*err = AG_VM_ERR_VERIFY;
		}
		ag_vm_free_prog(p);
		return 0;
	}
	if (err) {
		*err = AG_VM_OK;
	}
	if (consumed) {
		*consumed = r.p;
	}
	return p;

fail:
	ag_vm_free_prog(p);
	if (err) {
		*err = AG_VM_ERR_FORMAT;
	}
	return 0;
}

static ag_vm_prog *ag_vm_parse_record(const uint8_t *b, size_t n, int *err) {
	size_t used = 0;
	ag_vm_prog *p = ag_vm_parse_record_n(b, n, &used, err);
	if (p && used != n) {
		ag_vm_free_prog(p);
		if (err) {
			*err = AG_VM_ERR_FORMAT;
		}
		return 0;
	}
	return p;
}

static ag_vm_blob *ag_vm_parse_blob(const uint8_t *b, size_t n, int *err) {
	agvm_rd r;
	ag_vm_blob *blob;
	uint32_t i, count, ver, magic;

	if (!b || n < 12) {
		if (err) {
			*err = AG_VM_ERR_FORMAT;
		}
		return 0;
	}
	magic = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
	if (magic != 0x4d564741u) { /* "AGVM" 小端 */
		if (err) {
			*err = AG_VM_ERR_FORMAT;
		}
		return 0;
	}
	r.b = b + 4;
	r.n = n - 4;
	r.p = 0;
	r.err = 0;
	ver = agvm_rd32(&r);
	count = agvm_rd32(&r);
	if (r.err || ver != AG_VM_BLOB_VERSION || count > AG_VM_MAX_POOL) {
		if (err) {
			*err = AG_VM_ERR_FORMAT;
		}
		return 0;
	}
	blob = (ag_vm_blob *)calloc(1, sizeof(*blob));
	if (!blob) {
		if (err) {
			*err = AG_VM_ERR_NOMEM;
		}
		return 0;
	}
	if (count) {
		blob->progs = (ag_vm_prog **)calloc(count, sizeof(ag_vm_prog *));
		if (!blob->progs) {
			free(blob);
			if (err) {
				*err = AG_VM_ERR_NOMEM;
			}
			return 0;
		}
	}
	for (i = 0; i < count; i++) {
		size_t used = 0;
		ag_vm_prog *p = ag_vm_parse_record_n(b + 4 + r.p, n - 4 - r.p, &used, err);
		if (!p || used == 0) {
			r.err = 1;
			break;
		}
		r.p += used;
		blob->progs[i] = p;
		blob->n++;
	}
	if (r.err || blob->n != count) {
		ag_vm_blob *tmp = blob;
		uint32_t k;
		for (k = 0; k < tmp->n; k++) {
			ag_vm_free_prog(tmp->progs[k]);
		}
		free(tmp->progs);
		free(tmp);
		if (err) {
			*err = AG_VM_ERR_FORMAT;
		}
		return 0;
	}
	if (err) {
		*err = AG_VM_OK;
	}
	return blob;
}

static void ag_vm_free_blob(ag_vm_blob *b) {
	uint32_t i;
	if (!b) {
		return;
	}
	for (i = 0; i < b->n; i++) {
		ag_vm_free_prog(b->progs[i]);
	}
	free(b->progs);
	free(b);
}

/* ------------------------------------------------------------------ */
/* 解释器                                                              */
/* ------------------------------------------------------------------ */

typedef struct {
	uint64_t vals[AG_VM_MAX_REGS];
	void *refs[AG_VM_MAX_REGS];
} ag_vm_regs;

/* 避免实现定义的「无符号 -> 有符号」转换：按位重解释。 */
static int32_t ag_wrap32(uint32_t u) {
	int32_t v;
	memcpy(&v, &u, 4);
	return v;
}

static int64_t ag_wrap64(uint64_t u) {
	int64_t v;
	memcpy(&v, &u, 8);
	return v;
}

static int32_t ag_idiv(int32_t x, int32_t y, int *err) {
	if (y == 0) {
		*err = AG_VM_ERR_DIV0;
		return 0;
	}
	if (y == -1 && x == INT32_MIN) {
		return INT32_MIN; /* Java/Dalvik 语义：回绕，不触发 SIGFPE */
	}
	return x / y;
}

static int32_t ag_irem(int32_t x, int32_t y, int *err) {
	if (y == 0) {
		*err = AG_VM_ERR_DIV0;
		return 0;
	}
	if (y == -1) {
		return 0; /* 避免 INT32_MIN % -1 的 UB */
	}
	return x % y;
}

static int64_t ag_ldiv(int64_t x, int64_t y, int *err) {
	if (y == 0) {
		*err = AG_VM_ERR_DIV0;
		return 0;
	}
	if (y == -1 && x == INT64_MIN) {
		return INT64_MIN;
	}
	return x / y;
}

static int64_t ag_lrem(int64_t x, int64_t y, int *err) {
	if (y == 0) {
		*err = AG_VM_ERR_DIV0;
		return 0;
	}
	if (y == -1) {
		return 0;
	}
	return x % y;
}

/* ag_vm_field_store 把字段值写入寄存器（按字段类型规格化）。 */
static int ag_vm_field_store(ag_vm_regs *r, const ag_vm_fref *f, int idx, const ag_vv *v) {
	switch (f->type[0]) {
	case 'J':
		if (v->kind != AG_VV_WIDE) {
			return AG_VM_ERR_RT;
		}
		r->vals[idx] = v->i;
		r->vals[idx + 1] = v->i >> 32;
		r->refs[idx] = r->refs[idx + 1] = 0;
		return AG_VM_OK;
	case 'L':
	case '[':
		if (v->kind != AG_VV_REF) {
			return AG_VM_ERR_RT;
		}
		r->refs[idx] = v->ref;
		return AG_VM_OK;
	default: {
		uint32_t x;
		if (v->kind != AG_VV_INT) {
			return AG_VM_ERR_RT;
		}
		x = (uint32_t)v->i;
		switch (f->type[0]) {
		case 'Z':
			x &= 1u;
			break;
		case 'B':
			x = (uint32_t)(int32_t)(int8_t)x;
			break;
		case 'C':
			x = (uint32_t)(uint16_t)x;
			break;
		case 'S':
			x = (uint32_t)(int32_t)(int16_t)x;
			break;
		default:
			break;
		}
		r->vals[idx] = (uint64_t)(int64_t)ag_wrap32(x);
		r->refs[idx] = 0;
		return AG_VM_OK;
	}
	}
}

/* ag_vm_field_load 把寄存器值按字段类型打包为字段写入值。 */
static int ag_vm_field_load(ag_vm_regs *r, const ag_vm_fref *f, int idx, ag_vv *out) {
	switch (f->type[0]) {
	case 'J':
		out->kind = AG_VV_WIDE;
		out->i = r->vals[idx] | (r->vals[idx + 1] << 32);
		out->ref = 0;
		return AG_VM_OK;
	case 'L':
	case '[':
		out->kind = AG_VV_REF;
		out->i = 0;
		out->ref = r->refs[idx];
		return AG_VM_OK;
	case 'Z': {
		int32_t x = ag_wrap32((uint32_t)r->vals[idx]);
		out->kind = AG_VV_INT;
		out->i = (uint64_t)(int64_t)(x & 1);
		out->ref = 0;
		return AG_VM_OK;
	}
	case 'B': {
		int32_t x = (int32_t)(int8_t)ag_wrap32((uint32_t)r->vals[idx]);
		out->kind = AG_VV_INT;
		out->i = (uint64_t)(int64_t)x;
		out->ref = 0;
		return AG_VM_OK;
	}
	case 'C': {
		int32_t x = (int32_t)(uint16_t)ag_wrap32((uint32_t)r->vals[idx]);
		out->kind = AG_VV_INT;
		out->i = (uint64_t)(int64_t)x;
		out->ref = 0;
		return AG_VM_OK;
	}
	case 'S': {
		int32_t x = (int32_t)(int16_t)ag_wrap32((uint32_t)r->vals[idx]);
		out->kind = AG_VV_INT;
		out->i = (uint64_t)(int64_t)x;
		out->ref = 0;
		return AG_VM_OK;
	}
	default: {
		int32_t x = ag_wrap32((uint32_t)r->vals[idx]);
		out->kind = AG_VV_INT;
		out->i = (uint64_t)(int64_t)x;
		out->ref = 0;
		return AG_VM_OK;
	}
	}
}

static int ag_vm_store_int(ag_vm_regs *r, int idx, int32_t v) {
	r->vals[idx] = (uint64_t)(int64_t)v;
	r->refs[idx] = 0;
	return AG_VM_OK;
}

static int ag_vm_store_wide(ag_vm_regs *r, int idx, int64_t v) {
	r->vals[idx] = (uint64_t)v;
	r->vals[idx + 1] = (uint64_t)v >> 32;
	r->refs[idx] = r->refs[idx + 1] = 0;
	return AG_VM_OK;
}

/*
 * ag_vm_execute 执行一个已校验的私有程序。
 *
 * args 每个形参一个值（实例方法第 0 个是接收者），与 Go 侧 Program.Run 一致。
 * 返回值放入 *ret（可为 NULL 表示不关心）。
 */
static int ag_vm_execute(const ag_vm_prog *p, const ag_vm_rt *rt, const ag_vv *args, uint32_t argc,
                         ag_vv *ret) {
	ag_vm_regs r;
	const char *q;
	int reg, ai, is_static, err = AG_VM_OK;
	uint32_t pc, steps;
	ag_vv last;

	if (!p || !rt) {
		return AG_VM_ERR_ARG;
	}
	if (ag_vm_verify(p) != AG_VM_OK) {
		return AG_VM_ERR_VERIFY;
	}
	memset(&r, 0, sizeof(r));
	last.kind = AG_VV_VOID;
	last.i = 0;
	last.ref = 0;

	is_static = (p->access & 0x8) != 0;
	reg = (int)p->regs - (int)p->ins;
	ai = 0;
	if (!is_static) {
		if (argc < 1 || args[0].kind != AG_VV_REF) {
			return AG_VM_ERR_ARG;
		}
		if (reg >= (int)p->regs) {
			return AG_VM_ERR_REG;
		}
		r.refs[reg++] = args[0].ref;
		ai = 1;
	}
	q = p->proto;
	if (!q || *q != '(') {
		return AG_VM_ERR_ARG;
	}
	q++;
	while (*q && *q != ')') {
		int kind;
		const char *nq = ag_vm_proto_next(q, &kind);
		if (!nq || nq == q) {
			return AG_VM_ERR_ARG;
		}
		if (ai >= (int)argc) {
			return AG_VM_ERR_ARG;
		}
		if (kind == AG_PK_FLOAT) {
			return AG_VM_ERR_ARG;
		}
		if (kind == AG_PK_WIDE) {
			if (args[ai].kind != AG_VV_WIDE || reg + 1 >= (int)p->regs) {
				return AG_VM_ERR_ARG;
			}
			r.vals[reg] = args[ai].i;
			r.vals[reg + 1] = args[ai].i >> 32;
			reg += 2;
		} else if (kind == AG_PK_REF) {
			if (args[ai].kind != AG_VV_REF || reg >= (int)p->regs) {
				return AG_VM_ERR_ARG;
			}
			r.refs[reg] = args[ai].ref;
			reg++;
		} else {
			if (args[ai].kind != AG_VV_INT || reg >= (int)p->regs) {
				return AG_VM_ERR_ARG;
			}
			r.vals[reg] = args[ai].i;
			reg++;
		}
		ai++;
		q = nq;
	}
	if (*q != ')' || ai != (int)argc || reg != (int)(p->regs - p->ins) + p->ins) {
		return AG_VM_ERR_ARG;
	}

	pc = 0;
	steps = 0;
	for (;;) {
		int w, a, b, c;
		uint8_t op;
		uint32_t next;
		steps++;
		if (steps > AG_VM_MAX_STEPS) {
			return AG_VM_ERR_STEP;
		}
		if (pc >= p->ncode || (w = ag_vm_width(p->code, p->ncode, pc)) <= 0) {
			return AG_VM_ERR_PC;
		}
		op = (uint8_t)(p->code[pc] & 0xff);
		a = (int)((p->code[pc] >> 8) & 0xff);
		b = (int)((p->code[pc] >> 16) & 0xff);
		c = (int)((p->code[pc] >> 24) & 0xff);
		next = pc + (uint32_t)w;
		switch (op) {
		case AG_OP_NOP:
			break;
		case AG_OP_MOVE:
			r.vals[a] = r.vals[b];
			r.refs[a] = r.refs[b];
			break;
		case AG_OP_MOVEWIDE:
			r.vals[a] = r.vals[b];
			r.vals[a + 1] = r.vals[b + 1];
			r.refs[a] = r.refs[a + 1] = 0;
			break;
		case AG_OP_MOVEOBJECT:
			r.refs[a] = r.refs[b];
			break;
		case AG_OP_CONST:
			r.vals[a] = (uint64_t)(int64_t)(int32_t)p->code[pc + 1];
			r.refs[a] = 0;
			break;
		case AG_OP_CONSTWIDE:
			r.vals[a] = (uint64_t)p->code[pc + 1] | ((uint64_t)p->code[pc + 2] << 32);
			r.vals[a + 1] = r.vals[a] >> 32;
			r.refs[a] = r.refs[a + 1] = 0;
			break;
		case AG_OP_CONSTSTRING: {
			void *obj = 0;
			if (rt->str_new) {
				if (rt->str_new(rt->ctx, p->strs[p->code[pc + 1]].u,
				                p->strs[p->code[pc + 1]].n, &obj) != 0) {
					err = AG_VM_ERR_RT;
					goto done;
				}
			}
			r.refs[a] = obj;
			break;
		}
		case AG_OP_MOVERESULT:
			if (last.kind != AG_VV_INT) {
				err = AG_VM_ERR_MOVERESULT;
				goto done;
			}
			r.vals[a] = last.i;
			last.kind = AG_VV_VOID;
			break;
		case AG_OP_MOVERESULTWIDE:
			if (last.kind != AG_VV_WIDE) {
				err = AG_VM_ERR_MOVERESULT;
				goto done;
			}
			r.vals[a] = last.i;
			r.vals[a + 1] = last.i >> 32;
			last.kind = AG_VV_VOID;
			break;
		case AG_OP_MOVERESULTOBJECT:
			if (last.kind != AG_VV_REF) {
				err = AG_VM_ERR_MOVERESULT;
				goto done;
			}
			r.refs[a] = last.ref;
			last.kind = AG_VV_VOID;
			break;
		case AG_OP_NEGINT:
			ag_vm_store_int(&r, a, ag_wrap32(0u - (uint32_t)r.vals[b]));
			break;
		case AG_OP_NOTINT:
			ag_vm_store_int(&r, a, ag_wrap32(~(uint32_t)r.vals[b]));
			break;
		case AG_OP_NEGLONG:
			ag_vm_store_wide(&r, a, ag_wrap64(0ULL - r.vals[b]));
			break;
		case AG_OP_NOTLONG:
			ag_vm_store_wide(&r, a, ag_wrap64(~r.vals[b]));
			break;
		case AG_OP_I2B:
			ag_vm_store_int(&r, a, (int32_t)(int8_t)ag_wrap32((uint32_t)r.vals[b]));
			break;
		case AG_OP_I2C:
			ag_vm_store_int(&r, a, (int32_t)(uint16_t)ag_wrap32((uint32_t)r.vals[b]));
			break;
		case AG_OP_I2S:
			ag_vm_store_int(&r, a, (int32_t)(int16_t)ag_wrap32((uint32_t)r.vals[b]));
			break;
		case AG_OP_I2L:
			ag_vm_store_wide(&r, a, (int64_t)ag_wrap32((uint32_t)r.vals[b]));
			break;
		case AG_OP_L2I:
			ag_vm_store_int(&r, a, ag_wrap32((uint32_t)(r.vals[b] | (r.vals[b + 1] << 32))));
			break;
		case AG_OP_ADDINT:
			ag_vm_store_int(&r, a, ag_wrap32((uint32_t)r.vals[b] + (uint32_t)r.vals[c]));
			break;
		case AG_OP_SUBINT:
			ag_vm_store_int(&r, a, ag_wrap32((uint32_t)r.vals[b] - (uint32_t)r.vals[c]));
			break;
		case AG_OP_MULINT:
			ag_vm_store_int(&r, a, ag_wrap32((uint32_t)r.vals[b] * (uint32_t)r.vals[c]));
			break;
		case AG_OP_DIVINT:
			ag_vm_store_int(&r, a, ag_idiv(ag_wrap32((uint32_t)r.vals[b]), ag_wrap32((uint32_t)r.vals[c]), &err));
			if (err) {
				goto done;
			}
			break;
		case AG_OP_REMINT:
			ag_vm_store_int(&r, a, ag_irem(ag_wrap32((uint32_t)r.vals[b]), ag_wrap32((uint32_t)r.vals[c]), &err));
			if (err) {
				goto done;
			}
			break;
		case AG_OP_ANDINT:
			ag_vm_store_int(&r, a, ag_wrap32((uint32_t)r.vals[b] & (uint32_t)r.vals[c]));
			break;
		case AG_OP_ORINT:
			ag_vm_store_int(&r, a, ag_wrap32((uint32_t)r.vals[b] | (uint32_t)r.vals[c]));
			break;
		case AG_OP_XORINT:
			ag_vm_store_int(&r, a, ag_wrap32((uint32_t)r.vals[b] ^ (uint32_t)r.vals[c]));
			break;
		case AG_OP_SHLINT:
			ag_vm_store_int(&r, a, ag_wrap32((uint32_t)r.vals[b] << ((uint32_t)r.vals[c] & 31u)));
			break;
		case AG_OP_SHRINT:
			ag_vm_store_int(&r, a, ag_wrap32((uint32_t)r.vals[b]) >> ((uint32_t)r.vals[c] & 31u));
			break;
		case AG_OP_USHRINT:
			ag_vm_store_int(&r, a, ag_wrap32((uint32_t)r.vals[b] >> ((uint32_t)r.vals[c] & 31u)));
			break;
		case AG_OP_ADDLONG:
			ag_vm_store_wide(&r, a, ag_wrap64((r.vals[b] | (r.vals[b + 1] << 32)) + (r.vals[c] | (r.vals[c + 1] << 32))));
			break;
		case AG_OP_SUBLONG:
			ag_vm_store_wide(&r, a, ag_wrap64((r.vals[b] | (r.vals[b + 1] << 32)) - (r.vals[c] | (r.vals[c + 1] << 32))));
			break;
		case AG_OP_MULLONG:
			ag_vm_store_wide(&r, a, ag_wrap64((r.vals[b] | (r.vals[b + 1] << 32)) * (r.vals[c] | (r.vals[c + 1] << 32))));
			break;
		case AG_OP_DIVLONG:
			ag_vm_store_wide(&r, a, ag_ldiv(ag_wrap64(r.vals[b] | (r.vals[b + 1] << 32)),
			                                ag_wrap64(r.vals[c] | (r.vals[c + 1] << 32)), &err));
			if (err) {
				goto done;
			}
			break;
		case AG_OP_REMLONG:
			ag_vm_store_wide(&r, a, ag_lrem(ag_wrap64(r.vals[b] | (r.vals[b + 1] << 32)),
			                                ag_wrap64(r.vals[c] | (r.vals[c + 1] << 32)), &err));
			if (err) {
				goto done;
			}
			break;
		case AG_OP_ANDLONG:
			ag_vm_store_wide(&r, a, ag_wrap64((r.vals[b] | (r.vals[b + 1] << 32)) & (r.vals[c] | (r.vals[c + 1] << 32))));
			break;
		case AG_OP_ORLONG:
			ag_vm_store_wide(&r, a, ag_wrap64((r.vals[b] | (r.vals[b + 1] << 32)) | (r.vals[c] | (r.vals[c + 1] << 32))));
			break;
		case AG_OP_XORLONG:
			ag_vm_store_wide(&r, a, ag_wrap64((r.vals[b] | (r.vals[b + 1] << 32)) ^ (r.vals[c] | (r.vals[c + 1] << 32))));
			break;
		case AG_OP_SHLLONG:
			ag_vm_store_wide(&r, a, ag_wrap64((r.vals[b] | (r.vals[b + 1] << 32)) << ((uint32_t)ag_wrap32((uint32_t)r.vals[c]) & 63u)));
			break;
		case AG_OP_SHRLONG:
			ag_vm_store_wide(&r, a, ag_wrap64(r.vals[b] | (r.vals[b + 1] << 32)) >> ((uint32_t)ag_wrap32((uint32_t)r.vals[c]) & 63u));
			break;
		case AG_OP_USHRLONG:
			ag_vm_store_wide(&r, a, ag_wrap64((r.vals[b] | (r.vals[b + 1] << 32)) >> ((uint32_t)ag_wrap32((uint32_t)r.vals[c]) & 63u)));
			break;
		case AG_OP_CMPLONG: {
			int64_t x = ag_wrap64(r.vals[b] | (r.vals[b + 1] << 32));
			int64_t y = ag_wrap64(r.vals[c] | (r.vals[c + 1] << 32));
			ag_vm_store_int(&r, a, x < y ? -1 : (x > y ? 1 : 0));
			break;
		}
		case AG_OP_ADDINTIMM:
			ag_vm_store_int(&r, a, ag_wrap32((uint32_t)r.vals[b] + p->code[pc + 1]));
			break;
		case AG_OP_MULINTIMM:
			ag_vm_store_int(&r, a, ag_wrap32((uint32_t)r.vals[b] * p->code[pc + 1]));
			break;
		case AG_OP_DIVINTIMM: {
			int32_t dv = (int32_t)p->code[pc + 1];
			ag_vm_store_int(&r, a, ag_idiv(ag_wrap32((uint32_t)r.vals[b]), dv, &err));
			if (err) {
				goto done;
			}
			break;
		}
		case AG_OP_REMINTIMM: {
			int32_t dv = (int32_t)p->code[pc + 1];
			ag_vm_store_int(&r, a, ag_irem(ag_wrap32((uint32_t)r.vals[b]), dv, &err));
			if (err) {
				goto done;
			}
			break;
		}
		case AG_OP_ANDINTIMM:
			ag_vm_store_int(&r, a, ag_wrap32((uint32_t)r.vals[b] & p->code[pc + 1]));
			break;
		case AG_OP_ORINTIMM:
			ag_vm_store_int(&r, a, ag_wrap32((uint32_t)r.vals[b] | p->code[pc + 1]));
			break;
		case AG_OP_XORINTIMM:
			ag_vm_store_int(&r, a, ag_wrap32((uint32_t)r.vals[b] ^ p->code[pc + 1]));
			break;
		case AG_OP_SHLINTIMM:
			ag_vm_store_int(&r, a, ag_wrap32((uint32_t)r.vals[b] << (p->code[pc + 1] & 31u)));
			break;
		case AG_OP_SHRINTIMM:
			ag_vm_store_int(&r, a, ag_wrap32((uint32_t)r.vals[b]) >> (p->code[pc + 1] & 31u));
			break;
		case AG_OP_USHRINTIMM:
			ag_vm_store_int(&r, a, ag_wrap32((uint32_t)r.vals[b] >> (p->code[pc + 1] & 31u)));
			break;
		case AG_OP_GOTO:
			next = p->code[pc + 1];
			break;
		case AG_OP_IFEQ:
			if (ag_wrap32((uint32_t)r.vals[a]) == ag_wrap32((uint32_t)r.vals[b])) {
				next = p->code[pc + 1];
			}
			break;
		case AG_OP_IFNE:
			if (ag_wrap32((uint32_t)r.vals[a]) != ag_wrap32((uint32_t)r.vals[b])) {
				next = p->code[pc + 1];
			}
			break;
		case AG_OP_IFLT:
			if (ag_wrap32((uint32_t)r.vals[a]) < ag_wrap32((uint32_t)r.vals[b])) {
				next = p->code[pc + 1];
			}
			break;
		case AG_OP_IFGE:
			if (ag_wrap32((uint32_t)r.vals[a]) >= ag_wrap32((uint32_t)r.vals[b])) {
				next = p->code[pc + 1];
			}
			break;
		case AG_OP_IFGT:
			if (ag_wrap32((uint32_t)r.vals[a]) > ag_wrap32((uint32_t)r.vals[b])) {
				next = p->code[pc + 1];
			}
			break;
		case AG_OP_IFLE:
			if (ag_wrap32((uint32_t)r.vals[a]) <= ag_wrap32((uint32_t)r.vals[b])) {
				next = p->code[pc + 1];
			}
			break;
		case AG_OP_IFEQZ:
			if (ag_wrap32((uint32_t)r.vals[a]) == 0) {
				next = p->code[pc + 1];
			}
			break;
		case AG_OP_IFNEZ:
			if (ag_wrap32((uint32_t)r.vals[a]) != 0) {
				next = p->code[pc + 1];
			}
			break;
		case AG_OP_IFLTZ:
			if (ag_wrap32((uint32_t)r.vals[a]) < 0) {
				next = p->code[pc + 1];
			}
			break;
		case AG_OP_IFGEZ:
			if (ag_wrap32((uint32_t)r.vals[a]) >= 0) {
				next = p->code[pc + 1];
			}
			break;
		case AG_OP_IFGTZ:
			if (ag_wrap32((uint32_t)r.vals[a]) > 0) {
				next = p->code[pc + 1];
			}
			break;
		case AG_OP_IFLEZ:
			if (ag_wrap32((uint32_t)r.vals[a]) <= 0) {
				next = p->code[pc + 1];
			}
			break;
		case AG_OP_IGET:
		case AG_OP_IPUT:
		case AG_OP_SGET:
		case AG_OP_SPUT:
		case AG_OP_IGETWIDE:
		case AG_OP_IPUTWIDE:
		case AG_OP_SGETWIDE:
		case AG_OP_SPUTWIDE:
		case AG_OP_IGETOBJECT:
		case AG_OP_IPUTOBJECT:
		case AG_OP_SGETOBJECT:
		case AG_OP_SPUTOBJECT: {
			const ag_vm_fref *f = &p->flds[p->code[pc + 1]];
			void *obj = 0;
			if (!ag_vm_field_static(op)) {
				obj = r.refs[b];
			}
			if (op == AG_OP_IGET || op == AG_OP_SGET || op == AG_OP_IGETWIDE ||
			    op == AG_OP_SGETWIDE || op == AG_OP_IGETOBJECT || op == AG_OP_SGETOBJECT) {
				ag_vv v;
				if (!rt->field_get) {
					err = AG_VM_ERR_RT;
					goto done;
				}
				v.kind = AG_VV_VOID;
				v.i = 0;
				v.ref = 0;
				if (rt->field_get(rt->ctx, f, obj, &v) != 0) {
					err = AG_VM_ERR_RT;
					goto done;
				}
				ag_vm_field_store(&r, f, a, &v);
			} else {
				ag_vv v;
				ag_vm_field_load(&r, f, a, &v);
				if (!rt->field_put) {
					err = AG_VM_ERR_RT;
					goto done;
				}
				if (rt->field_put(rt->ctx, f, obj, &v) != 0) {
					err = AG_VM_ERR_RT;
					goto done;
				}
			}
			break;
		}
		case AG_OP_INVOKESTATIC:
		case AG_OP_INVOKEVIRTUAL:
		case AG_OP_INVOKEDIRECT:
		case AG_OP_INVOKESUPER:
		case AG_OP_INVOKEINTERFACE: {
			const ag_vm_mref *m = &p->mths[p->code[pc + 1]];
			ag_vv argv[8];
			uint32_t nargs = 0;
			int argc2 = ag_vm_invoke_argc(p->code, pc);
			int li = 0;
			const char *pq = m->proto + 1;
			if (!rt->invoke) {
				err = AG_VM_ERR_RT;
				goto done;
			}
			if (m->kind != 0) {
				argv[nargs].kind = AG_VV_REF;
				argv[nargs].i = 0;
				argv[nargs].ref = r.refs[ag_vm_invoke_arg(p->code, pc, li)];
				nargs++;
				li++;
			}
			while (*pq && *pq != ')') {
				int kind;
				const char *nq = ag_vm_proto_next(pq, &kind);
				if (!nq || nq == pq) {
					err = AG_VM_ERR_VERIFY;
					goto done;
				}
				if (kind == AG_PK_WIDE) {
					int lo = ag_vm_invoke_arg(p->code, pc, li);
					int hi = ag_vm_invoke_arg(p->code, pc, li + 1);
					argv[nargs].kind = AG_VV_WIDE;
					argv[nargs].ref = 0;
					argv[nargs].i = (uint64_t)(uint32_t)r.vals[lo] |
					                ((uint64_t)(uint32_t)r.vals[hi] << 32);
					li += 2;
				} else if (kind == AG_PK_REF) {
					argv[nargs].kind = AG_VV_REF;
					argv[nargs].i = 0;
					argv[nargs].ref = r.refs[ag_vm_invoke_arg(p->code, pc, li)];
					li++;
				} else {
					argv[nargs].kind = AG_VV_INT;
					argv[nargs].ref = 0;
					argv[nargs].i = (uint64_t)(int64_t)ag_wrap32((uint32_t)r.vals[ag_vm_invoke_arg(p->code, pc, li)]);
					li++;
				}
				nargs++;
				pq = nq;
			}
			if (li != argc2) {
				err = AG_VM_ERR_VERIFY;
				goto done;
			}
			last.kind = AG_VV_VOID;
			last.i = 0;
			last.ref = 0;
			if (rt->invoke(rt->ctx, m, argv, nargs, &last) != 0) {
				err = AG_VM_ERR_RT;
				goto done;
			}
			break;
		}
		case AG_OP_RETURNVOID:
			if (ret) {
				ret->kind = AG_VV_VOID;
				ret->i = 0;
				ret->ref = 0;
			}
			goto done;
		case AG_OP_RETURN:
			if (ret) {
				ret->kind = AG_VV_INT;
				ret->i = (uint64_t)(int64_t)ag_wrap32((uint32_t)r.vals[a]);
				ret->ref = 0;
			}
			goto done;
		case AG_OP_RETURNWIDE:
			if (ret) {
				ret->kind = AG_VV_WIDE;
				ret->i = r.vals[a] | (r.vals[a + 1] << 32);
				ret->ref = 0;
			}
			goto done;
		case AG_OP_RETURNOBJECT:
			if (ret) {
				ret->kind = AG_VV_REF;
				ret->i = 0;
				ret->ref = r.refs[a];
			}
			goto done;
		default:
			err = AG_VM_ERR_OP;
			goto done;
		}
		pc = next;
	}
done:
	return err;
}

/* ------------------------------------------------------------------ */
/* 注册表（签名 -> 程序；线程安全）                                    */
/* ------------------------------------------------------------------ */

typedef struct {
	char *sig;
	ag_vm_prog *prog;
} ag_vm_slot;

static ag_vm_slot ag_vm_slots[AG_VM_REG_MAX];
static uint32_t ag_vm_nslots = 0;

#if defined(AG_JNI)
static pthread_mutex_t ag_vm_mu = PTHREAD_MUTEX_INITIALIZER;
#define AG_VM_LOCK() pthread_mutex_lock(&ag_vm_mu)
#define AG_VM_UNLOCK() pthread_mutex_unlock(&ag_vm_mu)
#else
#define AG_VM_LOCK() do { } while (0)
#define AG_VM_UNLOCK() do { } while (0)
#endif

/* ag_vm_register 接管 prog 的所有权；失败时调用方负责释放。 */
static int ag_vm_register(const char *sig, ag_vm_prog *prog) {
	uint32_t i;
	int rc = 0;
	if (!prog) {
		return AG_VM_ERR_ARG;
	}
	if (sig && prog->sig && strcmp(sig, prog->sig) != 0) {
		return AG_VM_ERR_ARG; /* 注册签名与记录内身份不符：拒绝，绝不张冠李戴 */
	}
	AG_VM_LOCK();
	for (i = 0; i < ag_vm_nslots; i++) {
		if (ag_vm_slots[i].prog->vmid == prog->vmid ||
		    strcmp(ag_vm_slots[i].sig, prog->sig) == 0) {
			rc = AG_VM_ERR_ARG; /* 同 id 或同签名重复注册 */
			break;
		}
	}
	if (rc == 0) {
		if (ag_vm_nslots >= AG_VM_REG_MAX) {
			rc = AG_VM_ERR_NOMEM;
		} else {
			ag_vm_slots[ag_vm_nslots].sig = prog->sig;
			ag_vm_slots[ag_vm_nslots].prog = prog;
			ag_vm_nslots++;
		}
	}
	AG_VM_UNLOCK();
	return rc;
}

static ag_vm_prog *ag_vm_find(uint32_t vmid) {
	uint32_t i;
	ag_vm_prog *p = 0;
	AG_VM_LOCK();
	for (i = 0; i < ag_vm_nslots; i++) {
		if (ag_vm_slots[i].prog->vmid == vmid) {
			p = ag_vm_slots[i].prog;
			break;
		}
	}
	AG_VM_UNLOCK();
	return p;
}

static uint32_t ag_vm_count(void) {
	uint32_t n;
	AG_VM_LOCK();
	n = ag_vm_nslots;
	AG_VM_UNLOCK();
	return n;
}

static void ag_vm_reset(void) {
	uint32_t i;
	AG_VM_LOCK();
	for (i = 0; i < ag_vm_nslots; i++) {
		ag_vm_free_prog(ag_vm_slots[i].prog);
		ag_vm_slots[i].prog = 0;
		ag_vm_slots[i].sig = 0;
	}
	ag_vm_nslots = 0;
	AG_VM_UNLOCK();
}

/* ------------------------------------------------------------------ */
/* 宿主自测（AG_HOST_TEST）：用最小 C 程序断言字节码语义              */
/* ------------------------------------------------------------------ */

#ifdef AG_HOST_TEST
#include <stdio.h>

/* ---- 记录构造器（测试专用；与 Go EncodeMethodRecord 同格式） ---- */

typedef struct {
	uint8_t b[65536];
	size_t n;
	int err;
} ag_rb;

static void rb8(ag_rb *r, uint8_t v) {
	if (r->n + 1 > sizeof(r->b)) {
		r->err = 1;
		return;
	}
	r->b[r->n++] = v;
}

static void rb16(ag_rb *r, uint16_t v) {
	rb8(r, (uint8_t)(v & 0xff));
	rb8(r, (uint8_t)(v >> 8));
}

static void rb32(ag_rb *r, uint32_t v) {
	rb8(r, (uint8_t)(v & 0xff));
	rb8(r, (uint8_t)((v >> 8) & 0xff));
	rb8(r, (uint8_t)((v >> 16) & 0xff));
	rb8(r, (uint8_t)((v >> 24) & 0xff));
}

static void rbstr(ag_rb *r, const char *s) {
	size_t n = strlen(s);
	if (n > 4096) {
		r->err = 1;
		return;
	}
	rb16(r, (uint16_t)n);
	if (r->err || r->n + n > sizeof(r->b)) {
		r->err = 1;
		return;
	}
	memcpy(r->b + r->n, s, n);
	r->n += n;
}

/* POP 必须是宏：测试用它在静态初始化器里构造指令字（函数调用不是常量表达式）。 */
#define POP(op, a, b, c) ((uint32_t)(op) | ((uint32_t)((a) & 0xff) << 8) | \
                          ((uint32_t)((b) & 0xff) << 16) | ((uint32_t)((c) & 0xff) << 24))

/* ag_psec 描述一个待编码的测试方法（至多一个字符串/方法/字段池项）。 */
typedef struct {
	uint32_t vmid;
	uint32_t access;
	const char *cls;
	const char *name;
	const char *proto;
	uint16_t regs;
	uint16_t ins;
	const uint32_t *code;
	uint32_t ncode;
	const uint16_t *s0;
	uint32_t s0n;
	const char *mcls;
	const char *mname;
	const char *mproto;
	uint8_t mkind;
	const char *fcls;
	const char *fname;
	const char *ftype;
	uint8_t fstatic;
} ag_psec;

static void rb_method(ag_rb *r, const ag_psec *s, const char *as_sig) {
	uint32_t i;
	rb32(r, s->vmid);
	rb32(r, s->access);
	rbstr(r, s->cls);
	rbstr(r, s->name);
	rbstr(r, s->proto);
	rb16(r, s->regs);
	rb16(r, s->ins);
	rb32(r, s->ncode);
	for (i = 0; i < s->ncode; i++) {
		rb32(r, s->code[i]);
	}
	rb32(r, s->s0 ? 1u : 0u);
	if (s->s0) {
		rb32(r, s->s0n);
		for (i = 0; i < s->s0n; i++) {
			rb16(r, s->s0[i]);
		}
	}
	rb32(r, s->mcls ? 1u : 0u);
	if (s->mcls) {
		rb8(r, s->mkind);
		rbstr(r, s->mcls);
		rbstr(r, s->mname);
		rbstr(r, s->mproto);
	}
	rb32(r, s->fcls ? 1u : 0u);
	if (s->fcls) {
		rb8(r, s->fstatic ? 1u : 0u);
		rbstr(r, s->fcls);
		rbstr(r, s->fname);
		rbstr(r, s->ftype);
	}
	(void)as_sig;
}

static ag_vm_prog *mkprog(const ag_psec *s, int *err) {
	ag_rb r;
	memset(&r, 0, sizeof(r));
	rb_method(&r, s, 0);
	if (r.err) {
		if (err) {
			*err = AG_VM_ERR_FORMAT;
		}
		return 0;
	}
	return ag_vm_parse_record(r.b, r.n, err);
}

/* ---- mock 运行时 ---- */

typedef struct {
	int64_t static_i;
	int32_t obj_i;
	uint16_t str[32];
	uint32_t str_n;
	int calls;
} ag_mock;

typedef struct {
	int32_t i;
} ag_mobj;

static int mock_strnew(void *ctx, const uint16_t *u, uint32_t n, void **out) {
	ag_mock *m = (ag_mock *)ctx;
	if (n > 32) {
		n = 32;
	}
	memcpy(m->str, u, (size_t)n * 2);
	m->str_n = n;
	*out = (void *)m;
	return 0;
}

static int mock_fget(void *ctx, const ag_vm_fref *f, void *obj, ag_vv *out) {
	ag_mock *m = (ag_mock *)ctx;
	out->ref = 0;
	if (f->is_static) {
		out->kind = AG_VV_INT;
		out->i = (uint64_t)m->static_i;
		return 0;
	}
	if (!obj) {
		return -1;
	}
	out->kind = AG_VV_INT;
	out->i = (uint64_t)(int64_t)((ag_mobj *)obj)->i;
	return 0;
}

static int mock_fput(void *ctx, const ag_vm_fref *f, void *obj, const ag_vv *v) {
	ag_mock *m = (ag_mock *)ctx;
	if (f->is_static) {
		m->static_i = (int64_t)v->i;
		return 0;
	}
	if (!obj) {
		return -1;
	}
	((ag_mobj *)obj)->i = (int32_t)(int64_t)v->i;
	return 0;
}

static int mock_invoke(void *ctx, const ag_vm_mref *m, const ag_vv *args, uint32_t argc, ag_vv *out) {
	ag_mock *mk = (ag_mock *)ctx;
	mk->calls++;
	out->ref = 0;
	if (strcmp(m->name, "twice") == 0 && argc == 1) {
		out->kind = AG_VV_INT;
		out->i = (uint64_t)(int64_t)(2 * (int32_t)(int64_t)args[0].i);
		return 0;
	}
	if (strcmp(m->name, "lwide") == 0 && argc == 1) {
		out->kind = AG_VV_WIDE;
		out->i = (uint64_t)(3 * (int64_t)args[0].i);
		return 0;
	}
	return -1;
}

/* ---- 断言辅助 ---- */

static int vm_expect_int(const char *name, const ag_vm_prog *p, const ag_vm_rt *rt,
                         const ag_vv *args, uint32_t argc, int64_t want) {
	ag_vv ret;
	int rc;
	memset(&ret, 0, sizeof(ret));
	rc = ag_vm_execute(p, rt, args, argc, &ret);
	if (rc != AG_VM_OK || ret.kind != AG_VV_INT || (int64_t)ret.i != want) {
		printf("FAIL vm %s: rc=%d (%s) kind=%d got=%lld want=%lld\n", name, rc,
		       ag_vm_strerror(rc), ret.kind, (long long)(int64_t)ret.i, (long long)want);
		return 1;
	}
	printf("PASS vm %s\n", name);
	return 0;
}

static int vm_expect_wide(const char *name, const ag_vm_prog *p, const ag_vm_rt *rt,
                          const ag_vv *args, uint32_t argc, int64_t want) {
	ag_vv ret;
	int rc;
	memset(&ret, 0, sizeof(ret));
	rc = ag_vm_execute(p, rt, args, argc, &ret);
	if (rc != AG_VM_OK || ret.kind != AG_VV_WIDE || (int64_t)ret.i != want) {
		printf("FAIL vm %s: rc=%d (%s) kind=%d got=%lld want=%lld\n", name, rc,
		       ag_vm_strerror(rc), ret.kind, (long long)(int64_t)ret.i, (long long)want);
		return 1;
	}
	printf("PASS vm %s\n", name);
	return 0;
}

static int vm_expect_err(const char *name, const ag_vm_prog *p, const ag_vm_rt *rt,
                         const ag_vv *args, uint32_t argc, int want) {
	ag_vv ret;
	int rc;
	memset(&ret, 0, sizeof(ret));
	rc = ag_vm_execute(p, rt, args, argc, &ret);
	if (rc != want) {
		printf("FAIL vm %s: rc=%d (%s) want=%d (%s)\n", name, rc, ag_vm_strerror(rc), want,
		       ag_vm_strerror(want));
		return 1;
	}
	printf("PASS vm %s\n", name);
	return 0;
}

static ag_vv mv_int(int32_t v) {
	ag_vv a;
	a.kind = AG_VV_INT;
	a.i = (uint64_t)(int64_t)v;
	a.ref = 0;
	return a;
}

static ag_vv mv_wide(int64_t v) {
	ag_vv a;
	a.kind = AG_VV_WIDE;
	a.i = (uint64_t)v;
	a.ref = 0;
	return a;
}

static ag_vv mv_ref(void *p) {
	ag_vv a;
	a.kind = AG_VV_REF;
	a.i = 0;
	a.ref = p;
	return a;
}

/* ag_vm_selftest 运行全部字节码断言，返回失败数（0 = 全部通过）。 */
static int ag_vm_selftest(void) {
	int bad = 0;
	int err = 0;
	ag_mock mock;
	ag_vm_rt rt;
	ag_vm_prog *p;

	memset(&mock, 0, sizeof(mock));
	memset(&rt, 0, sizeof(rt));
	rt.ctx = &mock;
	rt.str_new = mock_strnew;
	rt.field_get = mock_fget;
	rt.field_put = mock_fput;
	rt.invoke = mock_invoke;

	/* 1) 算术 + 常量 + 条件分支 + 绝对 PC 跳转。 */
	{
		/* regs=5/ins=2：形参在 v3、v4（Dalvik 约定：参数占最高编号寄存器）。
		 * v4<=0 跳到 pc=7 返回 -1，否则落空 pc=6 返回 v4。 */
		static const uint32_t code[] = {
			POP(AG_OP_CONST, 2, 0, 0), 7u,
			POP(AG_OP_ADDINT, 3, 3, 2),
			POP(AG_OP_MULINT, 4, 3, 4),
			POP(AG_OP_IFLEZ, 4, 0, 0), 7u,
			POP(AG_OP_RETURN, 4, 0, 0),
			POP(AG_OP_CONST, 3, 0, 0), (uint32_t)-1,
			POP(AG_OP_RETURN, 3, 0, 0),
		};
		ag_psec s;
		ag_vv args[2];
		memset(&s, 0, sizeof(s));
		s.vmid = 1;
		s.access = 0x9;
		s.cls = "Ltest/A;";
		s.name = "arith";
		s.proto = "(II)I";
		s.regs = 5;
		s.ins = 2;
		s.code = code;
		s.ncode = sizeof(code) / 4;
		p = mkprog(&s, &err);
		if (!p) {
			printf("FAIL vm arith 解析: %s\n", ag_vm_strerror(err));
			bad++;
		} else {
			args[0] = mv_int(7);
			args[1] = mv_int(3);
			bad += vm_expect_int("arith(7,3)=42", p, &rt, args, 2, 42);
			args[0] = mv_int(-10);
			args[1] = mv_int(3);
			bad += vm_expect_int("arith(-10,3)=-1", p, &rt, args, 2, -1);
			ag_vm_free_prog(p);
		}
	}

	/* 2) 循环 + 回边（跳转目标必须回填正确，否则死循环或结果错）。 */
	{
		/* regs=3/ins=1：形参在 v2。 */
		static const uint32_t code[] = {
			POP(AG_OP_CONST, 0, 0, 0), 0u,
			POP(AG_OP_CONST, 1, 0, 0), 1u,
			POP(AG_OP_IFGT, 1, 2, 0), 11u,
			POP(AG_OP_ADDINT, 0, 0, 1),
			POP(AG_OP_ADDINTIMM, 1, 1, 0), 1u,
			POP(AG_OP_GOTO, 0, 0, 0), 4u,
			POP(AG_OP_RETURN, 0, 0, 0),
		};
		ag_psec s;
		ag_vv args[1];
		memset(&s, 0, sizeof(s));
		s.vmid = 2;
		s.access = 0x9;
		s.cls = "Ltest/A;";
		s.name = "sum";
		s.proto = "(I)I";
		s.regs = 3;
		s.ins = 1;
		s.code = code;
		s.ncode = sizeof(code) / 4;
		p = mkprog(&s, &err);
		if (!p) {
			printf("FAIL vm loop 解析: %s\n", ag_vm_strerror(err));
			bad++;
		} else {
			args[0] = mv_int(5);
			bad += vm_expect_int("sum(5)=15", p, &rt, args, 1, 15);
			args[0] = mv_int(0);
			bad += vm_expect_int("sum(0)=0", p, &rt, args, 1, 0);
			args[0] = mv_int(1);
			bad += vm_expect_int("sum(1)=1", p, &rt, args, 1, 1);
			ag_vm_free_prog(p);
		}
	}

	/* 3) long：64 位常量、加减（含负值/回绕）。 */
	{
		/* regs=6/ins=4：形参占最高 4 格（v2..v5），scratch v0/v1（宽常量 -1）。 */
		static const uint32_t code[] = {
			POP(AG_OP_CONSTWIDE, 0, 0, 0), 0xffffffffu, 0xffffffffu,
			POP(AG_OP_ADDLONG, 2, 2, 0),
			POP(AG_OP_RETURNWIDE, 2, 0, 0),
		};
		ag_psec s;
		ag_vv args[2];
		memset(&s, 0, sizeof(s));
		s.vmid = 3;
		s.access = 0x9;
		s.cls = "Ltest/A;";
		s.name = "lw";
		s.proto = "(JJ)J";
		s.regs = 6;
		s.ins = 4;
		s.code = code;
		s.ncode = sizeof(code) / 4;
		p = mkprog(&s, &err);
		if (!p) {
			printf("FAIL vm wide 解析: %s\n", ag_vm_strerror(err));
			bad++;
		} else {
			args[0] = mv_wide(0);
			args[1] = mv_wide(0);
			bad += vm_expect_wide("wide(0)+(-1)=-1", p, &rt, args, 2, -1);
			args[0] = mv_wide(1);
			args[1] = mv_wide(0);
			bad += vm_expect_wide("wide(1)+(-1)=0", p, &rt, args, 2, 0);
			ag_vm_free_prog(p);
		}
	}

	/* 4) invoke + move-result（3 字 invoke，实参打包）。 */
	{
		static const uint32_t code[] = {
			POP(AG_OP_CONST, 0, 0, 0), 5u,
			POP(AG_OP_INVOKESTATIC, 1, 0, 0), 0u, 0u,
			POP(AG_OP_MOVERESULT, 1, 0, 0),
			POP(AG_OP_RETURN, 1, 0, 0),
		};
		ag_psec s;
		memset(&s, 0, sizeof(s));
		s.vmid = 4;
		s.access = 0x9;
		s.cls = "Ltest/A;";
		s.name = "calltwice";
		s.proto = "()I";
		s.regs = 2;
		s.ins = 0;
		s.code = code;
		s.ncode = sizeof(code) / 4;
		s.mcls = "Ltest/B;";
		s.mname = "twice";
		s.mproto = "(I)I";
		s.mkind = 0;
		p = mkprog(&s, &err);
		if (!p) {
			printf("FAIL vm invoke 解析: %s\n", ag_vm_strerror(err));
			bad++;
		} else {
			bad += vm_expect_int("calltwice()=10", p, &rt, 0, 0, 10);
			if (mock.calls != 1) {
				printf("FAIL vm invoke 次数 %d != 1\n", mock.calls);
				bad++;
			}
			ag_vm_free_prog(p);
		}
	}

	/* 5) iget/iput：对象寄存器与字段读写。 */
	{
		static const uint32_t code[] = {
			POP(AG_OP_IGET, 0, 1, 0), 0u,
			POP(AG_OP_ADDINTIMM, 0, 0, 0), 1u,
			POP(AG_OP_IPUT, 0, 1, 0), 0u,
			POP(AG_OP_RETURN, 0, 0, 0),
		};
		ag_psec s;
		ag_vv args[1];
		ag_mobj obj;
		memset(&s, 0, sizeof(s));
		s.vmid = 5;
		s.access = 0x9;
		s.cls = "Ltest/A;";
		s.name = "bump";
		s.proto = "(Ltest/O;)I";
		s.regs = 2;
		s.ins = 1;
		s.code = code;
		s.ncode = sizeof(code) / 4;
		s.fcls = "Ltest/O;";
		s.fname = "i";
		s.ftype = "I";
		s.fstatic = 0;
		obj.i = 41;
		p = mkprog(&s, &err);
		if (!p) {
			printf("FAIL vm field 解析: %s\n", ag_vm_strerror(err));
			bad++;
		} else {
			args[0] = mv_ref(&obj);
			bad += vm_expect_int("bump(41)=42", p, &rt, args, 1, 42);
			if (obj.i != 42) {
				printf("FAIL vm field 写回 %d != 42\n", obj.i);
				bad++;
			}
			ag_vm_free_prog(p);
		}
	}

	/* 6) const-string：UTF-16 码元原样交给后端（非 ASCII 不能走 UTF-8）。 */
	{
		static const uint32_t code[] = {
			POP(AG_OP_CONSTSTRING, 0, 0, 0), 0u,
			POP(AG_OP_RETURNOBJECT, 0, 0, 0),
		};
		static const uint16_t units[] = {'h', 'i', 0x4e2d};
		ag_psec s;
		ag_vv ret;
		int rc;
		memset(&s, 0, sizeof(s));
		s.vmid = 6;
		s.access = 0x9;
		s.cls = "Ltest/A;";
		s.name = "str";
		s.proto = "()Ljava/lang/String;";
		s.regs = 1;
		s.ins = 0;
		s.code = code;
		s.ncode = sizeof(code) / 4;
		s.s0 = units;
		s.s0n = 3;
		p = mkprog(&s, &err);
		if (!p) {
			printf("FAIL vm string 解析: %s\n", ag_vm_strerror(err));
			bad++;
		} else {
			memset(&ret, 0, sizeof(ret));
			rc = ag_vm_execute(p, &rt, 0, 0, &ret);
			if (rc != AG_VM_OK || ret.kind != AG_VV_REF || ret.ref == 0 || mock.str_n != 3 ||
			    mock.str[0] != 'h' || mock.str[1] != 'i' || mock.str[2] != 0x4e2d) {
				printf("FAIL vm string: rc=%d kind=%d n=%u\n", rc, ret.kind, mock.str_n);
				bad++;
			} else {
				printf("PASS vm string\n");
			}
			ag_vm_free_prog(p);
		}
	}

	/* 7) 错误路径：除零、INT_MIN/-1 回绕、死循环、坏结构。 */
	{
		static const uint32_t c_div0[] = {
			POP(AG_OP_CONST, 1, 0, 0), 0u,
			POP(AG_OP_DIVINT, 0, 0, 1),
			POP(AG_OP_RETURN, 0, 0, 0),
		};
		static const uint32_t c_min[] = {
			POP(AG_OP_CONST, 0, 0, 0), (uint32_t)-1,
			POP(AG_OP_DIVINT, 1, 2, 0),
			POP(AG_OP_RETURN, 1, 0, 0),
		};
		static const uint32_t c_loop[] = {
			POP(AG_OP_GOTO, 0, 0, 0), 0u,
		};
		static const uint32_t c_badop[] = {0x7fu};
		static const uint32_t c_badbr[] = {
			POP(AG_OP_GOTO, 0, 0, 0), 99u,
		};
		static const uint32_t c_badpool[] = {
			POP(AG_OP_CONSTSTRING, 0, 0, 0), 5u,
			POP(AG_OP_RETURNOBJECT, 0, 0, 0),
		};
		static const uint32_t c_retvoid[] = {POP(AG_OP_RETURNVOID, 0, 0, 0)};
		ag_psec s;
		ag_vv args[1];
		memset(&s, 0, sizeof(s));
		s.access = 0x9;
		s.cls = "Ltest/A;";
		s.name = "e";
		s.proto = "(I)I";
		s.regs = 2;
		s.ins = 1;

		s.vmid = 10;
		s.code = c_div0;
		s.ncode = sizeof(c_div0) / 4;
		p = mkprog(&s, &err);
		args[0] = mv_int(5);
		if (!p) {
			printf("FAIL vm div0 解析\n");
			bad++;
		} else {
			/* const v1,#0 后除零：无法走参数，直接程序内构造。 */
			bad += vm_expect_err("div0", p, &rt, args, 1, AG_VM_ERR_DIV0);
			ag_vm_free_prog(p);
		}

		s.vmid = 11;
		s.code = c_min;
		s.ncode = sizeof(c_min) / 4;
		s.regs = 3;
		s.ins = 1;
		p = mkprog(&s, &err);
		args[0] = mv_int(INT32_MIN);
		if (!p) {
			printf("FAIL vm minwrap 解析\n");
			bad++;
		} else {
			bad += vm_expect_int("INT_MIN/-1 回绕", p, &rt, args, 1, INT32_MIN);
			ag_vm_free_prog(p);
		}

		s.vmid = 12;
		s.code = c_loop;
		s.ncode = sizeof(c_loop) / 4;
		s.regs = 1;
		s.ins = 0;
		s.proto = "()V";
		p = mkprog(&s, &err);
		if (!p) {
			printf("FAIL vm loopforever 解析\n");
			bad++;
		} else {
			bad += vm_expect_err("死循环步数上限", p, &rt, 0, 0, AG_VM_ERR_STEP);
			ag_vm_free_prog(p);
		}

		s.proto = "()I";
		s.regs = 2;
		s.ins = 0;
		s.vmid = 13;
		s.code = c_badop;
		s.ncode = sizeof(c_badop) / 4;
		if (mkprog(&s, &err) != 0) {
			printf("FAIL vm 未知操作码应被拒绝\n");
			bad++;
		} else {
			printf("PASS vm 未知操作码被拒绝\n");
		}
		s.vmid = 14;
		s.code = c_badbr;
		s.ncode = sizeof(c_badbr) / 4;
		if (mkprog(&s, &err) != 0) {
			printf("FAIL vm 非法跳转目标应被拒绝\n");
			bad++;
		} else {
			printf("PASS vm 非法跳转目标被拒绝\n");
		}
		s.vmid = 15;
		s.code = c_badpool;
		s.ncode = sizeof(c_badpool) / 4;
		s.proto = "()Ljava/lang/String;";
		s.regs = 1;
		if (mkprog(&s, &err) != 0) {
			printf("FAIL vm 池索引越界应被拒绝\n");
			bad++;
		} else {
			printf("PASS vm 池索引越界被拒绝\n");
		}
		s.vmid = 16;
		s.code = c_retvoid;
		s.ncode = sizeof(c_retvoid) / 4;
		s.proto = "()V";
		s.regs = 1;
		s.ins = 2; /* ins > regs，必须拒绝 */
		if (mkprog(&s, &err) != 0) {
			printf("FAIL vm ins>regs 应被拒绝\n");
			bad++;
		} else {
			printf("PASS vm ins>regs 被拒绝\n");
		}
	}

	/* 8) blob：两条记录解析 + 截断/坏 magic 拒绝。 */
	{
		ag_rb blob;
		ag_rb r1, r2;
		ag_vm_blob *pb;
		static const uint32_t c_ret[] = {POP(AG_OP_RETURNVOID, 0, 0, 0)};
		ag_psec s;
		memset(&s, 0, sizeof(s));
		s.access = 0x9;
		s.cls = "Ltest/A;";
		s.name = "m";
		s.proto = "()V";
		s.regs = 1;
		s.code = c_ret;
		s.ncode = 1;
		s.vmid = 20;
		memset(&r1, 0, sizeof(r1));
		rb_method(&r1, &s, 0);
		s.vmid = 21;
		s.name = "n";
		memset(&r2, 0, sizeof(r2));
		rb_method(&r2, &s, 0);

		memset(&blob, 0, sizeof(blob));
		rb8(&blob, 'A');
		rb8(&blob, 'G');
		rb8(&blob, 'V');
		rb8(&blob, 'M');
		rb32(&blob, AG_VM_BLOB_VERSION);
		rb32(&blob, 2);
		if (!blob.err && blob.n + r1.n + r2.n <= sizeof(blob.b)) {
			memcpy(blob.b + blob.n, r1.b, r1.n);
			blob.n += r1.n;
			memcpy(blob.b + blob.n, r2.b, r2.n);
			blob.n += r2.n;
		} else {
			blob.err = 1;
		}
		pb = blob.err ? 0 : ag_vm_parse_blob(blob.b, blob.n, &err);
		if (!pb || pb->n != 2 || pb->progs[1]->vmid != 21) {
			printf("FAIL vm blob 解析（rc=%d）\n", err);
			bad++;
		} else {
			printf("PASS vm blob 解析（2 条）\n");
			ag_vm_free_blob(pb);
		}
		if (ag_vm_parse_blob(blob.b, blob.n - 3, &err) != 0) {
			printf("FAIL vm 截断 blob 应被拒绝\n");
			bad++;
		} else {
			printf("PASS vm 截断 blob 被拒绝\n");
		}
		{
			uint8_t badmagic[16];
			memcpy(badmagic, blob.b, sizeof(badmagic));
			badmagic[0] = 'X';
			if (ag_vm_parse_blob(badmagic, sizeof(badmagic), &err) != 0) {
				printf("FAIL vm 坏 magic 应被拒绝\n");
				bad++;
			} else {
				printf("PASS vm 坏 magic 被拒绝\n");
			}
		}
	}

	/* 9) 注册表：签名一致性、id 查找、重复注册拒绝。 */
	{
		static const uint32_t c_ret[] = {POP(AG_OP_RETURNVOID, 0, 0, 0)};
		ag_psec s;
		memset(&s, 0, sizeof(s));
		s.vmid = 30;
		s.access = 0x9;
		s.cls = "Ltest/A;";
		s.name = "reg";
		s.proto = "()V";
		s.regs = 1;
		s.code = c_ret;
		s.ncode = 1;
		p = mkprog(&s, &err);
		if (!p) {
			printf("FAIL vm registry 解析\n");
			bad++;
		} else if (strcmp(p->sig, "Ltest/A;->reg()V") != 0) {
			printf("FAIL vm sig 格式: %s\n", p->sig);
			bad++;
			ag_vm_free_prog(p);
		} else if (ag_vm_register("Ltest/A;->other()V", p) == AG_VM_OK) {
			printf("FAIL vm 签名不符应拒绝注册\n");
			bad++;
			ag_vm_free_prog(p);
		} else if (ag_vm_register("Ltest/A;->reg()V", p) != AG_VM_OK) {
			printf("FAIL vm 注册失败\n");
			bad++;
			ag_vm_free_prog(p);
		} else if (ag_vm_count() != 1) {
			printf("FAIL vm 注册计数 %u != 1\n", ag_vm_count());
			bad++;
		} else if (ag_vm_find(30) != p) {
			printf("FAIL vm 按 id 查找失败\n");
			bad++;
		} else if (ag_vm_find(31) != 0) {
			printf("FAIL vm 未注册 id 不应命中\n");
			bad++;
		} else {
			printf("PASS vm 注册表\n");
		}
		ag_vm_reset();
	}

	return bad;
}

#endif /* AG_HOST_TEST */

#endif /* APKGUARD_AGVM_H */

