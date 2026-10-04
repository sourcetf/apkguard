package dex

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"apkguard/internal/pack"
)

// 本文件验证 B3（ClassLoader 接管）注入的 Loader 类。
//
// 验证方式与 A2/A13 一致：把真实字节码送进测试解释器执行，断言其**行为**，
// 而不是只看 DEX 结构是否自洽——结构合法但寄存器分配错误的壳代码同样能通过
// Verify，却会在真机崩溃。这里为 Loader 用到的框架 API 建立一套模拟实现，
// 其中 Native.sivDecrypt 直接用 internal/pack 的 AES-256-SIV 参照实现做
// **真实**解密，因此「载荷被正确还原」这一点是被真正证明的，而不是被假定。

// ---- 模拟运行时对象 ----

// fakeAssetMgr 模拟 android.content.res.AssetManager。
type fakeAssetMgr struct{ assets map[string][]byte }

// fakeStream 模拟 java.io.InputStream。
type fakeStream struct {
	data []byte
	pos  int
}

// fakeField 模拟 java.lang.reflect.Field。
type fakeField struct {
	name string
	val  any
}

// fakeDigest 模拟 java.security.MessageDigest，内部用真实 SHA-256。
type fakeDigest struct{ data []byte }

// fakeMac 模拟 javax.crypto.Mac，内部用真实 HMAC-SHA256。
type fakeMac struct {
	key  []byte
	data []byte
}

// testNativeLibDir 是测试里模拟的应用原生库目录。
const testNativeLibDir = "/data/app/lib/x86_64"

// loaderEnv 汇总模拟运行期间共享的状态。
type loaderEnv struct {
	// readOnly 记录被标记只读的文件路径（Android 14+ 要求动态加载的
	// DEX 必须先 setReadOnly，否则系统拒绝加载）。
	readOnly []string
	// deleted 记录被 File.delete() 删除的路径（用于断言「先删后写」）。
	deleted []string
	assets  map[string][]byte
	// fs 是模拟文件系统：绝对路径 -> 文件内容。
	fs map[string][]byte
	// dexPath 是 DexClassLoader 构造时收到的 dexPath。
	dexPath string
	// clObj 是 Shell 构造出的 DexClassLoader 实例。
	clObj any
	// libPath 记录 DexClassLoader 收到的 librarySearchPath。
	libPath string
	// exited 记录壳是否调用了 System.exit（MAC 校验失败的硬终止路径）。
	exited bool
	// exitCodes 记录 System.exit 的实参，便于断言与 D1 失败路径一致。
	exitCodes []int
	// loadedLibs 记录 System.loadLibrary 的实参（壳必须加载守卫库）。
	loadedLibs []string
}

// loaderFields 是各模拟类的字段表：Java 类名 -> 字段。
var loaderFields = map[string][]*fakeField{}

// key32 把 fakeBytes 里的密钥转成 pack.Decrypt 需要的定长数组。
func key32(b []byte) ([32]byte, error) {
	var k [32]byte
	if len(b) != 32 {
		return k, fmt.Errorf("密钥长度不是 32: %d", len(b))
	}
	copy(k[:], b)
	return k, nil
}

// installLoaderMocks 注册 Loader 所需的全部框架 API 模拟。
//
// 返回恢复函数，测试结束时调用。
func installLoaderMocks(env *loaderEnv) func() {
	prev := map[string]func(in *interp, regs []int) (int32, any, error){}
	for k, v := range fakeCalls {
		prev[k] = v
	}
	h := map[string]func(in *interp, regs []int) (int32, any, error){}
	noop := func(in *interp, regs []int) (int32, any, error) { return 0, nil, nil }

	// ---- Context ----
	h["Landroid/content/Context;->getDir(Ljava/lang/String;I)Ljava/io/File;"] =
		func(in *interp, regs []int) (int32, any, error) {
			name, ok := in.objs[regs[1]].(*fakeStr)
			if !ok {
				return 0, nil, errf("getDir 的实参不是字符串")
			}
			return 0, &fakeObj{desc: descFile, aux: "/data/user/0/app/" + name.s}, nil
		}
	h["Landroid/content/Context;->getAssets()Landroid/content/res/AssetManager;"] =
		func(in *interp, regs []int) (int32, any, error) {
			return 0, &fakeAssetMgr{assets: env.assets}, nil
		}
	h["Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;"] =
		func(in *interp, regs []int) (int32, any, error) {
			return 0, &fakeObj{desc: descClassLoader}, nil
		}

	// ---- AssetManager / InputStream ----
	h["Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;"] =
		func(in *interp, regs []int) (int32, any, error) {
			name, ok := in.objs[regs[1]].(*fakeStr)
			if !ok {
				return 0, nil, errf("open 的实参不是字符串")
			}
			data, ok := env.assets[name.s]
			if !ok {
				return 0, nil, errf("assets 中不存在 %q", name.s)
			}
			return 0, &fakeStream{data: data}, nil
		}
	h["Ljava/io/InputStream;->read([BII)I"] = func(in *interp, regs []int) (int32, any, error) {
		st, ok := in.objs[regs[0]].(*fakeStream)
		if !ok {
			return 0, nil, errf("read 的接收者不是 InputStream")
		}
		buf, ok := in.objs[regs[1]].(*fakeBytes)
		if !ok {
			return 0, nil, errf("read 的缓冲区不是 byte[]")
		}
		off, n := int(in.regs[regs[2]]), int(in.regs[regs[3]])
		if st.pos >= len(st.data) {
			return -1, nil, nil
		}
		if off < 0 || n < 0 || off > len(buf.b) {
			return 0, nil, errf("read 的区间非法 off=%d n=%d", off, n)
		}
		end := st.pos + n
		if end > len(st.data) {
			end = len(st.data)
		}
		if off+(end-st.pos) > len(buf.b) {
			end = st.pos + (len(buf.b) - off)
		}
		got := copy(buf.b[off:], st.data[st.pos:end])
		st.pos += got
		return int32(got), nil, nil
	}
	h["Ljava/io/InputStream;->close()V"] = noop

	// ---- 载荷解密（真实 AES-256-SIV，与 .so 的 C 实现同规范）----
	//
	// 壳不再调用 javax.crypto 的 CBC，而是统一走 Native.sivDecrypt。这里用
	// internal/pack 的 SIV 参照实现做真解密：端到端测试（打包加密 → 解释器
	// 跑壳 → 得到明文）因此仍然是被真正证明的。
	h[NativeBridgeClass+"->sivDecrypt([B[B[B)[B"] =
		func(in *interp, regs []int) (int32, any, error) {
			keyB, ok := in.objs[regs[0]].(*fakeBytes)
			if !ok {
				return 0, nil, errf("sivDecrypt 的密钥不是 byte[]")
			}
			adB, ok := in.objs[regs[1]].(*fakeBytes)
			if !ok {
				return 0, nil, errf("sivDecrypt 的 ad 不是 byte[]")
			}
			blob, ok := in.objs[regs[2]].(*fakeBytes)
			if !ok {
				return 0, nil, errf("sivDecrypt 的密文不是 byte[]")
			}
			k, err := key32(keyB.b)
			if err != nil {
				return 0, nil, err
			}
			plain, err := pack.DecryptNamed(blob.b, k, string(adB.b))
			if err != nil {
				// 与真 native 一致：SIV 校验失败返回 null，由壳走硬终止路径。
				return 0, nil, nil
			}
			return 0, &fakeBytes{b: plain}, nil
		}
	// ad 必须是负载名的 UTF-8 字节：壳用 getBytes("UTF-8") 显式指定字符集。
	h["Ljava/lang/String;->getBytes(Ljava/lang/String;)[B"] =
		func(in *interp, regs []int) (int32, any, error) {
			s, ok := in.objs[regs[0]].(*fakeStr)
			if !ok {
				return 0, nil, errf("String.getBytes 的接收者不是字符串")
			}
			cs, ok := in.objs[regs[1]].(*fakeStr)
			if !ok {
				return 0, nil, errf("String.getBytes 的字符集不是字符串")
			}
			if cs.s != utf8Charset {
				return 0, nil, errf("String.getBytes 的字符集应为 %s，实际 %s", utf8Charset, cs.s)
			}
			return 0, &fakeBytes{b: []byte(s.s)}, nil
		}
	// 守卫库必须在首次解密之前加载：库名会被 C7 改名并同步改写，
	// 这里只记录实参，具体值由 C7 的测试断言。
	h["Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V"] =
		func(in *interp, regs []int) (int32, any, error) {
			s, ok := in.objs[regs[0]].(*fakeStr)
			if !ok || s.s == "" {
				return 0, nil, errf("System.loadLibrary 的库名不是非空字符串")
			}
			env.loadedLibs = append(env.loadedLibs, s.s)
			return 0, nil, nil
		}
	h["Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V"] =
		func(in *interp, regs []int) (int32, any, error) {
			o, ok := in.objs[regs[0]].(*fakeObj)
			if !ok {
				return 0, nil, errf("SecretKeySpec 构造的接收者类型不对")
			}
			b, ok := in.objs[regs[1]].(*fakeBytes)
			if !ok {
				return 0, nil, errf("SecretKeySpec 的密钥不是 byte[]")
			}
			o.aux = append([]byte(nil), b.b...)
			return 0, nil, nil
		}

	// ---- 载荷 MAC（真实 SHA-256 + HMAC-SHA256）----
	//
	// 这几个模拟必须用**真实**密码学实现，否则「MAC 校验通过」只是被假定。
	// MessageDigest 用于域分离派生 macKey，Mac 用于计算/比对 HMAC。
	h["Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;"] =
		func(in *interp, regs []int) (int32, any, error) {
			alg, ok := in.objs[regs[0]].(*fakeStr)
			if !ok {
				return 0, nil, errf("MessageDigest.getInstance 的实参不是字符串")
			}
			if alg.s != digestAlg {
				return 0, nil, errf("MessageDigest 算法不符: %s", alg.s)
			}
			return 0, &fakeDigest{}, nil
		}
	h["Ljava/security/MessageDigest;->update([B)V"] = func(in *interp, regs []int) (int32, any, error) {
		md, ok := in.objs[regs[0]].(*fakeDigest)
		if !ok {
			return 0, nil, errf("MessageDigest.update 的接收者不是 MessageDigest")
		}
		b, ok := in.objs[regs[1]].(*fakeBytes)
		if !ok {
			return 0, nil, errf("MessageDigest.update 的实参不是 byte[]")
		}
		md.data = append(md.data, b.b...)
		return 0, nil, nil
	}
	h["Ljava/security/MessageDigest;->digest()[B"] = func(in *interp, regs []int) (int32, any, error) {
		md, ok := in.objs[regs[0]].(*fakeDigest)
		if !ok {
			return 0, nil, errf("MessageDigest.digest 的接收者不是 MessageDigest")
		}
		sum := sha256.Sum256(md.data)
		return 0, &fakeBytes{b: append([]byte(nil), sum[:]...)}, nil
	}
	h["Ljavax/crypto/Mac;->getInstance(Ljava/lang/String;)Ljavax/crypto/Mac;"] =
		func(in *interp, regs []int) (int32, any, error) {
			alg, ok := in.objs[regs[0]].(*fakeStr)
			if !ok {
				return 0, nil, errf("Mac.getInstance 的实参不是字符串")
			}
			if alg.s != macAlg {
				return 0, nil, errf("Mac 算法不符: %s", alg.s)
			}
			return 0, &fakeMac{}, nil
		}
	h["Ljavax/crypto/Mac;->init(Ljava/security/Key;)V"] = func(in *interp, regs []int) (int32, any, error) {
		m, ok := in.objs[regs[0]].(*fakeMac)
		if !ok {
			return 0, nil, errf("Mac.init 的接收者不是 Mac")
		}
		sks, ok := in.objs[regs[1]].(*fakeObj)
		if !ok {
			return 0, nil, errf("Mac.init 的实参不是 SecretKeySpec")
		}
		k, _ := sks.aux.([]byte)
		m.key = append([]byte(nil), k...)
		return 0, nil, nil
	}
	h["Ljavax/crypto/Mac;->update([B)V"] = func(in *interp, regs []int) (int32, any, error) {
		m, ok := in.objs[regs[0]].(*fakeMac)
		if !ok {
			return 0, nil, errf("Mac.update 的接收者不是 Mac")
		}
		b, ok := in.objs[regs[1]].(*fakeBytes)
		if !ok {
			return 0, nil, errf("Mac.update 的实参不是 byte[]")
		}
		m.data = append(m.data, b.b...)
		return 0, nil, nil
	}
	h["Ljavax/crypto/Mac;->update([BII)V"] = func(in *interp, regs []int) (int32, any, error) {
		m, ok := in.objs[regs[0]].(*fakeMac)
		if !ok {
			return 0, nil, errf("Mac.update 的接收者不是 Mac")
		}
		b, ok := in.objs[regs[1]].(*fakeBytes)
		if !ok {
			return 0, nil, errf("Mac.update 的实参不是 byte[]")
		}
		off, n := int(in.regs[regs[2]]), int(in.regs[regs[3]])
		if off < 0 || n < 0 || off+n > len(b.b) {
			return 0, nil, errf("Mac.update 的区间非法 off=%d n=%d len=%d", off, n, len(b.b))
		}
		m.data = append(m.data, b.b[off:off+n]...)
		return 0, nil, nil
	}
	h["Ljavax/crypto/Mac;->doFinal()[B"] = func(in *interp, regs []int) (int32, any, error) {
		m, ok := in.objs[regs[0]].(*fakeMac)
		if !ok {
			return 0, nil, errf("Mac.doFinal 的接收者不是 Mac")
		}
		if len(m.key) != 32 {
			return 0, nil, errf("Mac 的密钥长度不是 32: %d", len(m.key))
		}
		mac := hmac.New(sha256.New, m.key)
		mac.Write(m.data)
		return 0, &fakeBytes{b: mac.Sum(nil)}, nil
	}
	h["Ljava/lang/String;->getBytes()[B"] = func(in *interp, regs []int) (int32, any, error) {
		s, ok := in.objs[regs[0]].(*fakeStr)
		if !ok {
			return 0, nil, errf("String.getBytes 的接收者不是字符串")
		}
		return 0, &fakeBytes{b: []byte(s.s)}, nil
	}
	h["Ljava/lang/System;->exit(I)V"] = func(in *interp, regs []int) (int32, any, error) {
		env.exited = true
		env.exitCodes = append(env.exitCodes, int(in.regs[regs[0]]))
		return 0, nil, nil
	}

	h["Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V"] =
		func(in *interp, regs []int) (int32, any, error) {
			src, ok := in.objs[regs[0]].(*fakeBytes)
			dst, ok2 := in.objs[regs[2]].(*fakeBytes)
			if !ok || !ok2 {
				return 0, nil, errf("arraycopy 的操作数不是 byte[]: src=%T dst=%T 实参寄存器=%v",
					in.objs[regs[0]], in.objs[regs[2]], regs)
			}
			srcPos, dstPos, n := int(in.regs[regs[1]]), int(in.regs[regs[3]]), int(in.regs[regs[4]])
			if srcPos < 0 || dstPos < 0 || n < 0 || srcPos+n > len(src.b) || dstPos+n > len(dst.b) {
				return 0, nil, errf("arraycopy 的区间非法 srcPos=%d dstPos=%d n=%d len(src)=%d len(dst)=%d 实参寄存器=%v",
					srcPos, dstPos, n, len(src.b), len(dst.b), regs)
			}
			copy(dst.b[dstPos:dstPos+n], src.b[srcPos:srcPos+n])
			return 0, nil, nil
		}

	// ---- 字符串拼接 ----
	//
	// new-instance 一律产出 *fakeObj，因此这里用 aux 挂一个 Go 的
	// strings.Builder 来承载拼接结果，而不是另建一种模拟类型。
	h["Ljava/lang/StringBuilder;-><init>()V"] = func(in *interp, regs []int) (int32, any, error) {
		o, ok := in.objs[regs[0]].(*fakeObj)
		if !ok {
			return 0, nil, errf("StringBuilder 构造的接收者类型不对")
		}
		o.aux = &strings.Builder{}
		return 0, nil, nil
	}
	h["Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;"] =
		func(in *interp, regs []int) (int32, any, error) {
			o, ok := in.objs[regs[0]].(*fakeObj)
			if !ok {
				return 0, nil, errf("append 的接收者不是 StringBuilder")
			}
			s, ok := in.objs[regs[1]].(*fakeStr)
			if !ok {
				return 0, nil, errf("append 的实参不是字符串")
			}
			sb, ok := o.aux.(*strings.Builder)
			if !ok {
				return 0, nil, errf("append 前未调用 StringBuilder 构造器")
			}
			sb.WriteString(s.s)
			return 0, o, nil
		}
	h["Ljava/lang/StringBuilder;->toString()Ljava/lang/String;"] =
		func(in *interp, regs []int) (int32, any, error) {
			o, ok := in.objs[regs[0]].(*fakeObj)
			if !ok {
				return 0, nil, errf("toString 的接收者不是 StringBuilder")
			}
			sb, ok := o.aux.(*strings.Builder)
			if !ok {
				return 0, nil, errf("toString 前未调用 StringBuilder 构造器")
			}
			return 0, &fakeStr{s: sb.String()}, nil
		}

	// ---- 文件系统 ----
	h["Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V"] =
		func(in *interp, regs []int) (int32, any, error) {
			o, ok := in.objs[regs[0]].(*fakeObj)
			if !ok {
				return 0, nil, errf("File 构造的接收者类型不对")
			}
			parent, ok := in.objs[regs[1]].(*fakeObj)
			if !ok {
				return 0, nil, errf("File 的父路径不是 File")
			}
			name, ok := in.objs[regs[2]].(*fakeStr)
			if !ok {
				return 0, nil, errf("File 的名字不是字符串")
			}
			dir, _ := parent.aux.(string)
			o.aux = dir + "/" + name.s
			return 0, nil, nil
		}
	h["Ljava/io/File;->getAbsolutePath()Ljava/lang/String;"] =
		func(in *interp, regs []int) (int32, any, error) {
			o, ok := in.objs[regs[0]].(*fakeObj)
			if !ok {
				return 0, nil, errf("getAbsolutePath 的接收者不是 File")
			}
			p, _ := o.aux.(string)
			return 0, &fakeStr{s: p}, nil
		}
	h["Landroid/content/Context;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;"] =
		func(in *interp, regs []int) (int32, any, error) {
			// nativeLibraryDir 必须真的挂在实例上：壳代码用 iget-object 读它
			// （它是实例字段而非静态字段），而这里此前返回的是一个空对象，
			// 于是传给 ClassLoader 的 librarySearchPath 一直是 null —— 旧的
			// DexClassLoader 模拟又没校验该参数，缺陷就被测试放过去了。
			// 真机上的表现是应用加载自己的 .so 时 UnsatisfiedLinkError
			// （RustDesk 的 librustdesk.so）。
			return 0, &fakeObj{
				desc: "Landroid/content/pm/ApplicationInfo;",
				// 键必须是「类描述符->字段名」：解释器的 iget-object 按这个
				// 全名取字段（见 interp_test.go 的 fieldName 与 sigcheck_test.go）。
				objFields: map[string]any{
					"Landroid/content/pm/ApplicationInfo;->nativeLibraryDir": &fakeStr{s: testNativeLibDir},
				},
			}, nil
		}
	h["Ljava/io/File;->setReadOnly()Z"] =
		func(in *interp, regs []int) (int32, any, error) {
			o, ok := in.objs[regs[0]].(*fakeObj)
			if !ok {
				return 0, nil, errf("setReadOnly 的接收者不是 File")
			}
			p, _ := o.aux.(string)
			env.readOnly = append(env.readOnly, p)
			return 1, nil, nil
		}
	// 落盘前必须先删旧文件：MarkReadOnly 打开时上次启动留下的 d0.dex 是只读的，
	// FileOutputStream 覆盖它没有写权限，真机会抛
	//   FileNotFoundException: .../app_ag/d0.dex: open failed: EACCES
	// （实测 RustDesk：第一次能开、第二次就崩）。这里把「删了哪些路径」记下来，
	// 供测试断言「写之前确实先删」。
	h["Ljava/io/File;->delete()Z"] =
		func(in *interp, regs []int) (int32, any, error) {
			o, ok := in.objs[regs[0]].(*fakeObj)
			if !ok {
				return 0, nil, errf("delete 的接收者不是 File")
			}
			p, _ := o.aux.(string)
			env.deleted = append(env.deleted, p)
			// 删掉之后模拟文件系统里确实没有了，便于断言「先删后写」的顺序。
			delete(env.fs, p)
			return 1, nil, nil
		}
	h["Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V"] =
		func(in *interp, regs []int) (int32, any, error) {
			o, ok := in.objs[regs[0]].(*fakeObj)
			if !ok {
				return 0, nil, errf("FileOutputStream 构造的接收者类型不对")
			}
			f, ok := in.objs[regs[1]].(*fakeObj)
			if !ok {
				return 0, nil, errf("FileOutputStream 的实参不是 File")
			}
			o.aux = f.aux
			return 0, nil, nil
		}
	h["Ljava/io/FileOutputStream;->write([B)V"] = func(in *interp, regs []int) (int32, any, error) {
		o, ok := in.objs[regs[0]].(*fakeObj)
		if !ok {
			return 0, nil, errf("write 的接收者不是 FileOutputStream")
		}
		b, ok := in.objs[regs[1]].(*fakeBytes)
		if !ok {
			return 0, nil, errf("write 的实参不是 byte[]")
		}
		p, _ := o.aux.(string)
		env.fs[p] = append([]byte(nil), b.b...)
		return 0, nil, nil
	}
	h["Ljava/io/FileOutputStream;->close()V"] = noop

	// ---- ClassLoader ----
	h["Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V"] =
		func(in *interp, regs []int) (int32, any, error) {
			p, ok := in.objs[regs[1]].(*fakeStr)
			if !ok {
				return 0, nil, errf("DexClassLoader 的 dexPath 不是字符串")
			}
			// 第 3 个参数是 librarySearchPath：它必须非空。少了它应用自己的
			// System.loadLibrary 会找不到 .so 而 UnsatisfiedLinkError
			// （实测 RustDesk 的 librustdesk.so）。此前这里只校验 dexPath，
			// 于是「库搜索路径悄悄变成 null」这类缺陷测试完全看不见。
			lib, ok := in.objs[regs[3]].(*fakeStr)
			if !ok || lib.s == "" {
				return 0, nil, errf("DexClassLoader 的 librarySearchPath 为空，应用自己的 .so 会加载失败")
			}
			env.libPath = lib.s
			env.dexPath = p.s
			env.clObj = in.objs[regs[0]]
			return 0, nil, nil
		}

	// ---- 反射 ----
	h["Ljava/lang/Object;->getClass()Ljava/lang/Class;"] = func(in *interp, regs []int) (int32, any, error) {
		var d string
		switch o := in.objs[regs[0]].(type) {
		case *fakeObj:
			d = o.desc
		case *fakeArr:
			d = o.desc
		case *fakeStr:
			d = descString
		default:
			return 0, nil, errf("getClass 的接收者类型未知 %T", in.objs[regs[0]])
		}
		name := ShellJavaName(d)
		c, ok := fakeClasses[name]
		if !ok {
			c = &fakeCls{name: name}
			fakeClasses[name] = c
		}
		return 0, c, nil
	}
	h["Ljava/lang/Class;->forName(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;"] =
		func(in *interp, regs []int) (int32, any, error) {
			name, ok := in.objs[regs[0]].(*fakeStr)
			if !ok {
				return 0, nil, errf("forName 的实参不是字符串")
			}
			c, ok := fakeClasses[name.s]
			if !ok {
				return 0, nil, errf("forName 未注册类 %q", name.s)
			}
			return 0, c, nil
		}
	h["Ljava/lang/Class;->getDeclaredFields()[Ljava/lang/reflect/Field;"] =
		func(in *interp, regs []int) (int32, any, error) {
			c, ok := in.objs[regs[0]].(*fakeCls)
			if !ok {
				return 0, nil, errf("getDeclaredFields 的接收者不是 Class")
			}
			fs := loaderFields[c.name]
			items := make([]any, len(fs))
			for i, f := range fs {
				items[i] = f
			}
			return 0, &fakeArr{desc: descFieldArray, items: items}, nil
		}
	h["Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;"] =
		func(in *interp, regs []int) (int32, any, error) {
			c, ok := in.objs[regs[0]].(*fakeCls)
			if !ok {
				return 0, nil, errf("getDeclaredMethod 的接收者不是 Class")
			}
			name, ok := in.objs[regs[1]].(*fakeStr)
			if !ok {
				return 0, nil, errf("getDeclaredMethod 的实参不是字符串")
			}
			for _, m := range c.mths {
				if m.name == name.s {
					return 0, m, nil
				}
			}
			return 0, nil, errf("类 %s 上找不到方法 %s", c.name, name.s)
		}
	h["Ljava/lang/reflect/Field;->getName()Ljava/lang/String;"] =
		func(in *interp, regs []int) (int32, any, error) {
			f, ok := in.objs[regs[0]].(*fakeField)
			if !ok {
				return 0, nil, errf("Field.getName 的接收者不是 Field")
			}
			return 0, &fakeStr{s: f.name}, nil
		}
	h["Ljava/lang/reflect/Field;->setAccessible(Z)V"] = noop
	h["Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;"] =
		func(in *interp, regs []int) (int32, any, error) {
			f, ok := in.objs[regs[0]].(*fakeField)
			if !ok {
				return 0, nil, errf("Field.get 的接收者不是 Field")
			}
			return 0, f.val, nil
		}
	h["Ljava/lang/reflect/Field;->set(Ljava/lang/Object;Ljava/lang/Object;)V"] =
		func(in *interp, regs []int) (int32, any, error) {
			f, ok := in.objs[regs[0]].(*fakeField)
			if !ok {
				return 0, nil, errf("Field.set 的接收者不是 Field")
			}
			f.val = in.objs[regs[2]]
			return 0, nil, nil
		}

	for k, v := range h {
		fakeCalls[k] = v
	}
	// 壳用 StringBuilder 拼接 dexPath 时会读取 File.pathSeparator，
	// 这是它用到的唯一静态字段。
	prevStatics := objStatics
	objStatics = map[string]any{
		"Ljava/io/File;->pathSeparator": &fakeStr{s: ":"},
		// 应用的 native 库目录：ClassLoader 必须拿到它，否则应用加载自己的
		// .so 会 UnsatisfiedLinkError（真实案例：RustDesk 的 librustdesk.so）。
		// 该值同时由 testNativeLibDir 用于 ApplicationInfo 的实例字段模拟。
		"Landroid/content/pm/ApplicationInfo;->nativeLibraryDir": &fakeStr{s: testNativeLibDir},
	}
	return func() {
		fakeCalls = prev
		objStatics = prevStatics
	}
}

// TestLoaderDecryptRoundTrip 验证 Loader 能解出与原始 DEX 逐字节一致的明文。
//
// 这是 B1 的核心正确性证据：载荷被 AES 加密后，只有壳侧代码真的按同样的
// 参数解密，才能还原出原 DEX。任何寄存器分配错误都会让结果对不上。
func TestLoaderDecryptRoundTrip(t *testing.T) {
	restore := installLoaderMocks(&loaderEnv{})
	defer restore()

	key, iv := testPackKey, testPackIV
	plain := Empty()
	blob := mustEncrypt(t, plain, key, iv)

	ls := &LoaderSpec{
		Class:   "Lcom/apkguard/shell/Loader;",
		Key:     key,
		TempDir: "ag",
		Items:   []LoaderItem{{Asset: "assets/pay_ab12.bin", DexName: "d0.dex", Size: len(blob)}},
	}
	add, err := LoaderAddition(ls)
	if err != nil {
		t.Fatalf("构造 Loader 失败: %v", err)
	}
	out, err := Build(add)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	env := &loaderEnv{assets: map[string][]byte{"pay_ab12.bin": blob}, fs: map[string][]byte{}}
	restore2 := installLoaderMocks(env)
	defer restore2()

	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, ls.Class)
	installActivityThreadMock()
	defer clearActivityThreadMock()

	idx, off := findMethod(t, g, ls.Class, "->"+LoaderEntry+"(")
	if _, err := runPadMethod(g, idx, off, &fakeObj{desc: descContext}); err != nil {
		t.Fatalf("Loader.a 执行失败: %v", err)
	}

	got, ok := env.fs["/data/user/0/app/ag/d0.dex"]
	if !ok {
		t.Fatalf("未落地解密后的 DEX，已有文件: %v", keysOfBytes(env.fs))
	}
	if len(got) != len(plain) {
		t.Fatalf("解密结果长度不符: %d vs %d", len(got), len(plain))
	}
	for i := range plain {
		if got[i] != plain[i] {
			t.Fatalf("解密结果第 %d 字节不符", i)
		}
	}
	if !strings.Contains(env.dexPath, "/ag/d0.dex") {
		t.Fatalf("DexClassLoader 的 dexPath 不含落地文件: %q", env.dexPath)
	}
	t.Logf("B3：载荷 AES-256-SIV 解密还原成功（%d 字节），dexPath=%s", len(got), env.dexPath)
}

// TestLoaderMarksDexReadOnly 验证落地的 DEX 被标记为只读。
//
// Android 14（API 34）起，targetSdk ≥ 34 的应用用 DexClassLoader 加载
// 「可写」文件会被系统拒绝（Safer dynamic code loading 行为变更）。
// 因此在写盘之后调用 File.setReadOnly() 不是可选优化，而是现代系统上的
// 必要条件——少了它，真机上就是在加载那一步直接崩，且不留痕迹。
func TestLoaderMarksDexReadOnly(t *testing.T) {
	blob := mustEncrypt(t, Empty(), testPackKey, testPackIV)
	ls := &LoaderSpec{Class: "Lx/L;", Key: testPackKey, TempDir: "ag",
		MarkReadOnly: true, // 模拟 targetSdk ≥ 34
		Items:        []LoaderItem{{Asset: "assets/pay.bin", DexName: "d0.dex", Size: len(blob)}}}
	add, err := LoaderAddition(ls)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	out, err := Build(add)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	env := &loaderEnv{assets: map[string][]byte{"pay.bin": blob}, fs: map[string][]byte{}}
	restore := installLoaderMocks(env)
	defer restore()
	installActivityThreadMock()
	defer clearActivityThreadMock()
	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, ls.Class)

	idx, off := findMethod(t, g, ls.Class, "->"+LoaderEntry+"(")
	if _, err := runPadMethod(g, idx, off, &fakeObj{desc: descContext}); err != nil {
		t.Fatalf("Loader.a 执行失败: %v", err)
	}
	if len(env.readOnly) == 0 {
		t.Fatal("落地后未调用 setReadOnly：Android 14+ 会拒绝加载可写的 DEX")
	}
	if env.readOnly[0] != "/data/user/0/app/ag/d0.dex" {
		t.Fatalf("只读标记落在了错误的文件上: %v", env.readOnly)
	}
	t.Logf("已标记只读: %v", env.readOnly)
}

// TestLoaderDeletesStaleDexBeforeWrite 钉住「落盘前先删旧文件」。
//
// 真实缺陷（实测 RustDesk）：MarkReadOnly 打开时（targetSdk ≥ 34），上一次启动
// 已把 d0.dex 标记为只读；第二次启动再写同一个路径时，FileOutputStream 对只读
// 文件没有写权限，抛
//
//	java.lang.RuntimeException: Unable to instantiate application
//	  java.io.FileNotFoundException: .../app_ag/d0.dex: open failed:
//	  EACCES (Permission denied)
//
// 表现为「装上第一次能开、第二次就崩」——只有反复启动才会暴露。
// 修法是写之前先 File.delete()：删只读文件在应用自己的目录里是允许的
// （目录可写即可）。
func TestLoaderDeletesStaleDexBeforeWrite(t *testing.T) {
	key, iv := testPackKey, testPackIV
	blob := mustEncrypt(t, Empty(), key, iv)

	ls := &LoaderSpec{
		Class:   "Lcom/apkguard/shell/Loader;",
		Key:     key,
		TempDir: "ag",
		Items:   []LoaderItem{{Asset: "assets/pay_ab12.bin", DexName: "d0.dex", Size: len(blob)}},
	}
	add, err := LoaderAddition(ls)
	if err != nil {
		t.Fatalf("构造 Loader 失败: %v", err)
	}
	out, err := Build(add)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	const stale = "/data/user/0/app/ag/d0.dex"
	env := &loaderEnv{
		assets: map[string][]byte{"pay_ab12.bin": blob},
		// 模拟上一次启动留下的文件（内容无关紧要，关键是它「已存在」）。
		fs: map[string][]byte{stale: []byte("stale")},
	}
	restore := installLoaderMocks(env)
	defer restore()

	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, ls.Class)
	installActivityThreadMock()
	defer clearActivityThreadMock()

	idx, off := findMethod(t, g, ls.Class, "->"+LoaderEntry+"(")
	if _, err := runPadMethod(g, idx, off, &fakeObj{desc: descContext}); err != nil {
		t.Fatalf("Loader.a 执行失败: %v", err)
	}
	deleted := false
	for _, p := range env.deleted {
		if p == stale {
			deleted = true
		}
	}
	if !deleted {
		t.Fatalf("落盘前没有删除已存在的旧文件 %s，真机上会因只读而 EACCES", stale)
	}
	got, ok := env.fs[stale]
	if !ok {
		t.Fatal("删除旧文件后没有重新写入")
	}
	if string(got) == "stale" {
		t.Fatal("写回的仍是旧内容：说明没有真正重写")
	}
	t.Logf("先删后写已生效：deleted=%v，重写后 %d 字节", env.deleted, len(got))
}

// TestLoaderInstallsClassLoader 验证接管链路确实把新 ClassLoader 写进了
// ActivityThread.mBoundApplication.info.mClassLoader。
//
// 该字段是系统加载 Application 与四大组件所用的加载器，写不进去的话
// Manifest 里的 Activity 依然会由旧加载器加载而找不到类。
func TestLoaderInstallsClassLoader(t *testing.T) {
	key, iv := testPackKey, testPackIV
	blob := mustEncrypt(t, Empty(), key, iv)

	ls := &LoaderSpec{
		Class:   "Lcom/apkguard/shell/Loader;",
		Key:     key,
		TempDir: "ag",
		Items:   []LoaderItem{{Asset: "assets/pay_ab12.bin", DexName: "d0.dex", Size: len(blob)}},
	}
	add, err := LoaderAddition(ls)
	if err != nil {
		t.Fatalf("构造 Loader 失败: %v", err)
	}
	out, err := Build(add)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, ls.Class)
	installActivityThreadMock()
	defer clearActivityThreadMock()

	// currentActivityThread 通过反射调用返回上面的 ActivityThread 实例。
	mth := fakeClasses["android.app.ActivityThread"].mths[0]
	clField := loaderFields["android.app.LoadedApk"][0]

	env := &loaderEnv{assets: map[string][]byte{"pay_ab12.bin": blob}, fs: map[string][]byte{}}
	restore := installLoaderMocks(env)
	defer restore()

	idx, off := findMethod(t, g, ls.Class, "->"+LoaderEntry+"(")
	if _, err := runPadMethod(g, idx, off, &fakeObj{desc: descContext}); err != nil {
		t.Fatalf("Loader.a 执行失败: %v", err)
	}

	if env.clObj == nil {
		t.Fatal("未构造 DexClassLoader")
	}
	if clField.val != env.clObj {
		t.Fatalf("mClassLoader 未被替换为新建的 DexClassLoader：%v", clField.val)
	}
	if !mth.accessed {
		t.Fatal("反射调用 Method.invoke 前未 setAccessible(true)")
	}
	t.Log("B3：ClassLoader 已写入 ActivityThread.mBoundApplication.info.mClassLoader")
}

// TestShellWithLoaderDelegates 验证启用 B3 的壳 Application 能走完整链路：
// attachBaseContext → 解密载荷 → 接管 ClassLoader → 委托原 Application。
func TestShellWithLoaderDelegates(t *testing.T) {
	const origName = "com.orig.MyApp"
	key, iv := testPackKey, testPackIV
	blob := mustEncrypt(t, Empty(), key, iv)

	sh := &ShellApp{
		Class: "Lapkguard/App;",
		Orig:  origName,
		Loader: &LoaderSpec{
			Class:   "Lapkguard/Loader;",
			Key:     key,
			TempDir: "ag",
			Items:   []LoaderItem{{Asset: "assets/pay_ab12.bin", DexName: "d0.dex", Size: len(blob)}},
		},
	}
	add, err := ShellAppAddition(sh)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	out, err := Build(add)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	// 模拟环境：原 Application 类未覆写 attachBaseContext，其父类才有——
	// 这正是壳必须沿父类链扫描的原因。
	paramCtx := &fakeCls{name: "android.content.Context"}
	baseApp := &fakeCls{
		name: "android.app.Application",
		mths: []*fakeMth{{name: "attachBaseContext", params: []*fakeCls{paramCtx}}},
	}
	fakeClasses[origName] = &fakeCls{name: origName, supers: []*fakeCls{baseApp}}
	defer delete(fakeClasses, origName)

	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()

	// 把两个类的全部方法登记给解释器，使其能进入方法体执行。
	registerFakeCode(t, g, sh.Class, sh.Loader.Class)

	// 搭好 ActivityThread 字段链，使接管步骤能真正执行。
	installActivityThreadMock()
	defer clearActivityThreadMock()
	clField := loaderFields["android.app.LoadedApk"][0]

	env := &loaderEnv{assets: map[string][]byte{"pay_ab12.bin": blob}, fs: map[string][]byte{}}
	restore := installLoaderMocks(env)
	defer restore()

	attachIdx, attachOff := findMethod(t, g, sh.Class, "->attachBaseContext(")
	app := &fakeObj{desc: sh.Class}
	ctx := &fakeObj{desc: descContext}

	debugCalls = []string{}
	_, err = runPadMethod(g, attachIdx, attachOff, app, ctx)
	t.Logf("attachBaseContext 调用轨迹: %v", debugCalls)
	debugCalls = nil
	if err != nil {
		t.Fatalf("attachBaseContext 执行失败: %v", err)
	}

	cached, ok := objStatics[sh.Class+"->"+shellFieldOrig].(*fakeObj)
	if !ok {
		t.Fatal("未把原 Application 实例写入静态字段")
	}
	if cached.getField("$attach") != 1 {
		t.Fatalf("原 Application 的 attachBaseContext 应被调用 1 次，实际 %d", cached.getField("$attach"))
	}
	if clField.val != env.clObj || env.clObj == nil {
		t.Fatal("ClassLoader 未被接管到 ActivityThread")
	}
	if _, ok := env.fs["/data/user/0/app/ag/d0.dex"]; !ok {
		t.Fatal("载荷未落地为 DEX 文件")
	}
	t.Log("B2+B3：壳在解密载荷、接管 ClassLoader 之后成功委托原 Application")
}

// TestShellLoaderRunsWithoutOrigApp 验证原 APK 未声明 android:name 时，
// 壳**仍然**要完成解密与 ClassLoader 接管。
//
// 这是最容易漏掉的一条路径：没有原 Application 需要委托，看上去「无事可做」，
// 但载荷里装着整个业务 DEX，不接管加载器的话 Manifest 里声明的 Activity
// 依旧会由旧加载器加载而找不到类——表现为应用能安装、一打开就崩。
func TestShellLoaderRunsWithoutOrigApp(t *testing.T) {
	key, iv := testPackKey, testPackIV
	blob := mustEncrypt(t, Empty(), key, iv)

	sh := &ShellApp{
		Class: "Lapkguard/App;",
		// Orig 故意留空：原 APK 的 Manifest 没有 android:name。
		Loader: &LoaderSpec{
			Class:   "Lapkguard/Loader;",
			Key:     key,
			TempDir: "ag",
			Items:   []LoaderItem{{Asset: "assets/pay_ab12.bin", DexName: "d0.dex", Size: len(blob)}},
		},
	}
	add, err := ShellAppAddition(sh)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	out, err := Build(add)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, sh.Class, sh.Loader.Class)
	installActivityThreadMock()
	defer clearActivityThreadMock()
	clField := loaderFields["android.app.LoadedApk"][0]

	env := &loaderEnv{assets: map[string][]byte{"pay_ab12.bin": blob}, fs: map[string][]byte{}}
	restore := installLoaderMocks(env)
	defer restore()

	attachIdx, attachOff := findMethod(t, g, sh.Class, "->attachBaseContext(")
	debugCalls = []string{}
	if _, err := runPadMethod(g, attachIdx, attachOff, &fakeObj{desc: sh.Class}, &fakeObj{desc: descContext}); err != nil {
		t.Fatalf("attachBaseContext 执行失败: %v", err)
	}
	calls := append([]string(nil), debugCalls...)
	debugCalls = nil

	// 载荷必须被解密落地，ClassLoader 必须被接管。
	if _, ok := env.fs["/data/user/0/app/ag/d0.dex"]; !ok {
		t.Fatalf("载荷未落地（调用轨迹 %v）", calls)
	}
	if env.clObj == nil || clField.val != env.clObj {
		t.Fatalf("ClassLoader 未被接管（调用轨迹 %v）", calls)
	}
	// 没有原 Application 时不应去解析原类：委托走的是带显式 ClassLoader 的
	// 三参 forName，而 Loader 接管 ActivityThread 用的是单参 forName，
	// 因此只有前者能证明「委托被误执行」。
	for _, c := range calls {
		if strings.Contains(c, "forName(Ljava/lang/String;ZLjava/lang/ClassLoader;)") {
			t.Fatalf("未声明原 Application 时不应执行委托: %v", calls)
		}
	}
	t.Log("B2+B3：未声明 Application 的 APK 依然完成了载荷解密与 ClassLoader 接管")
}

// TestLoaderMultiplePayloads 验证多份载荷（Multidex）都能被解密，
// 且 dexPath 由 File.pathSeparator 正确拼接。
//
// 真实应用几乎都是多 DEX，这条路径与单载荷完全不同：载荷名成对出现、
// 每份有各自的 IV、路径要靠 StringBuilder 拼成一份 path list。
// 只测单载荷的话，拼接逻辑出错也发现不了。
func TestLoaderMultiplePayloads(t *testing.T) {
	key := testPackKey
	// 两份明文长度不同，且各用不同 IV，能暴露「IV/载荷错位」这类错误。
	plain0 := append(append([]byte(nil), Empty()...), make([]byte, 7)...)
	plain1 := bytes.Repeat([]byte{0x5a}, 4096)
	iv0 := testPackIV
	iv1 := [16]byte{0xff, 0xfe, 0xfd, 0xfc, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	blob0 := mustEncrypt(t, plain0, key, iv0)
	blob1 := mustEncrypt(t, plain1, key, iv1)

	ls := &LoaderSpec{
		Class:   "Lcom/apkguard/shell/Loader;",
		Key:     key,
		TempDir: "ag",
		Items: []LoaderItem{
			{Asset: "assets/a.bin", DexName: "d0.dex", Size: len(blob0)},
			{Asset: "assets/b.bin", DexName: "d1.dex", Size: len(blob1)},
		},
	}
	add, err := LoaderAddition(ls)
	if err != nil {
		t.Fatalf("构造 Loader 失败: %v", err)
	}
	out, err := Build(add)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, ls.Class)
	installActivityThreadMock()
	defer clearActivityThreadMock()

	env := &loaderEnv{
		assets: map[string][]byte{"a.bin": blob0, "b.bin": blob1},
		fs:     map[string][]byte{},
	}
	restore := installLoaderMocks(env)
	defer restore()

	idx, off := findMethod(t, g, ls.Class, "->"+LoaderEntry+"(")
	if _, err := runPadMethod(g, idx, off, &fakeObj{desc: descContext}); err != nil {
		t.Fatalf("Loader.a 执行失败: %v", err)
	}

	for i, want := range [][]byte{plain0, plain1} {
		path := fmt.Sprintf("/data/user/0/app/ag/d%d.dex", i)
		got, ok := env.fs[path]
		if !ok {
			t.Fatalf("第 %d 份载荷未落地到 %s（已有 %v）", i, path, keysOfBytes(env.fs))
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("第 %d 份载荷解密结果不符（%d vs %d 字节）", i, len(got), len(want))
		}
		if !strings.Contains(env.dexPath, path) {
			t.Fatalf("dexPath 缺少 %s：%q", path, env.dexPath)
		}
	}
	// 两份路径必须用 pathSeparator 连接，否则 DexClassLoader 只会加载第一份。
	if n := strings.Count(env.dexPath, ":"); n != 1 {
		t.Fatalf("dexPath 应以一个分隔符连接两份载荷，实际 %d 个：%q", n, env.dexPath)
	}
	t.Logf("B3：多载荷解密与 dexPath 拼接正确：%s", env.dexPath)
}

// ---- 测试辅助 ----

// testPackKey / testPackIV 是测试用的固定密钥与 IV。
var (
	testPackKey = [32]byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
		0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x7f,
	}
	testPackIV = [16]byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	}
)

// mustEncrypt 用 internal/pack 的 AES-256-SIV 参照实现加密载荷（ad 为空串）。
//
// SIV 不需要 IV，输出由 (key, ad, 明文) 唯一确定；iv 形参仅保留以兼容
// 既有调用点（多数测试的 LoaderItem 不带 Name，ad 即空串）。
// 需要非空 ad 的测试用 mustEncryptAd，且 LoaderItem/LoaderLibItem.Name
// 必须与之逐字节一致，否则壳侧 SIV 校验会失败。
func mustEncrypt(t *testing.T, plain []byte, key [32]byte, iv [16]byte) []byte {
	t.Helper()
	_ = iv // SIV 无 IV
	return mustEncryptAd(t, plain, key, "")
}

// mustEncryptAd 指定 ad（载荷逻辑名）做 AES-256-SIV 加密。
func mustEncryptAd(t *testing.T, plain []byte, key [32]byte, ad string) []byte {
	t.Helper()
	blob, err := pack.EncryptNamed(plain, key, ad)
	if err != nil {
		t.Fatalf("SIV 加密失败: %v", err)
	}
	return blob
}

// mustEncryptMAC 产出「SIV 标签‖密文‖HMAC-SHA256」载荷。
//
// MAC 部分仍用独立实现（域分离串与 loader.go 的 macDomain 必须一致），
// 而密文本体交给 pack 的 SIV 实现，保证「打包 → 壳」两侧对的是同一规范。
func mustEncryptMAC(t *testing.T, plain []byte, key [32]byte, iv [16]byte, name string) []byte {
	t.Helper()
	_ = iv // SIV 无 IV
	body := mustEncryptAd(t, plain, key, name)
	mkSum := sha256.Sum256(append(append([]byte(nil), key[:]...), []byte("apkguard/payload-mac")...))
	mac := hmac.New(sha256.New, mkSum[:])
	mac.Write([]byte(name))
	mac.Write(body)
	return append(body, mac.Sum(nil)...)
}

// installActivityThreadMock 搭出 ActivityThread 的字段链与反射入口，
// 使 Loader 的接管步骤在模拟环境中可执行。
//
// 字段链取自真实框架：ActivityThread.mBoundApplication → AppBindData.info
// → LoadedApk.mClassLoader。返回被写入的那个字段，供断言检查。
func installActivityThreadMock() *fakeField {
	clField := &fakeField{name: "mClassLoader"}
	loadedApk := &fakeObj{desc: "Landroid/app/LoadedApk;"}
	bindData := &fakeObj{desc: "Landroid/app/AppBindData;"}
	thread := &fakeObj{desc: "Landroid/app/ActivityThread;"}
	loaderFields = map[string][]*fakeField{
		"android.app.ActivityThread": {{name: "mBoundApplication", val: bindData}},
		"android.app.AppBindData":    {{name: "info", val: loadedApk}},
		"android.app.LoadedApk":      {clField},
	}
	fakeClasses["android.app.ActivityThread"] = &fakeCls{
		name: "android.app.ActivityThread",
		mths: []*fakeMth{{name: "currentActivityThread", ret: thread, retSet: true}},
	}
	return clField
}

// clearActivityThreadMock 拆除 installActivityThreadMock 搭出的环境。
func clearActivityThreadMock() {
	loaderFields = map[string][]*fakeField{}
	delete(fakeClasses, "android.app.ActivityThread")
}

// registerFakeCode 把指定类的全部方法登记给解释器。
//
// 注入类的内部会相互调用（Loader.a 调用 r/c/w/i），解释器必须知道这些方法
// 在 DEX 中的 code_item 偏移才能进入其方法体执行。
func registerFakeCode(t *testing.T, g *File, classes ...string) {
	t.Helper()
	want := map[string]bool{}
	for _, c := range classes {
		want[c] = true
	}
	if err := g.Classes(func(_ uint32, cd ClassDef, name string) error {
		if !want[name] {
			return nil
		}
		pcd, err := g.ParseClassData(cd.ClassDataOff)
		if err != nil {
			return err
		}
		for _, ms := range [][]EncodedMethod{pcd.DirectMethods, pcd.VirtualMethods} {
			for _, m := range ms {
				d, _ := g.MethodDesc(m.Idx)
				fakeCode[d] = m.CodeOff
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("遍历类失败: %v", err)
	}
}

// findMethod 在被测 DEX 中定位指定类的某个方法。
func findMethod(t *testing.T, g *File, class, descPart string) (uint32, uint32) {
	t.Helper()
	var idx, off uint32
	found := false
	if err := g.Classes(func(_ uint32, cd ClassDef, name string) error {
		if name != class {
			return nil
		}
		pcd, err := g.ParseClassData(cd.ClassDataOff)
		if err != nil {
			return err
		}
		for _, ms := range [][]EncodedMethod{pcd.DirectMethods, pcd.VirtualMethods} {
			for _, m := range ms {
				d, _ := g.MethodDesc(m.Idx)
				if strings.Contains(d, descPart) {
					idx, off, found = m.Idx, m.CodeOff, true
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("遍历类失败: %v", err)
	}
	if !found {
		t.Fatalf("未找到方法 %s %s", class, descPart)
	}
	return idx, off
}

func keysOfBytes(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestLoaderSkipsReadOnlyWhenNotRequired 验证 targetSdk < 34 时**不**标记只读。
//
// 回归防线：只读标记是 Android 14+ 对 targetSdk ≥ 34 应用的要求，
// 对更低 targetSdk 的应用率先标记会造成 DexPathList 打开文件时
// EACCES(Permission denied)，表现为启动即 FileNotFoundException 闪退
// ——真实案例：RustDesk（targetSdk 33）加固后启动崩溃。
func TestLoaderSkipsReadOnlyWhenNotRequired(t *testing.T) {
	blob := mustEncrypt(t, Empty(), testPackKey, testPackIV)
	ls := &LoaderSpec{Class: "Lx/L;", Key: testPackKey, TempDir: "ag",
		MarkReadOnly: false, // 模拟 targetSdk < 34
		Items:        []LoaderItem{{Asset: "assets/pay.bin", DexName: "d0.dex", Size: len(blob)}}}
	add, err := LoaderAddition(ls)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	out, err := Build(add)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	env := &loaderEnv{assets: map[string][]byte{"pay.bin": blob}, fs: map[string][]byte{}}
	restore := installLoaderMocks(env)
	defer restore()
	installActivityThreadMock()
	defer clearActivityThreadMock()
	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, ls.Class)

	idx, off := findMethod(t, g, ls.Class, "->"+LoaderEntry+"(")
	if _, err := runPadMethod(g, idx, off, &fakeObj{desc: descContext}); err != nil {
		t.Fatalf("Loader.a 执行失败: %v", err)
	}
	if len(env.readOnly) != 0 {
		t.Fatalf("targetSdk < 34 时不应标记只读，实际标记了 %v", env.readOnly)
	}
}

// runLoaderEntry 构造并执行 Loader.a，返回填充后的 env。
//
// 新测试共用它，避免每个用例重复 Build/Parse/注册/反射搭台。
func runLoaderEntry(t *testing.T, ls *LoaderSpec, env *loaderEnv) {
	t.Helper()
	add, err := LoaderAddition(ls)
	if err != nil {
		t.Fatalf("构造 Loader 失败: %v", err)
	}
	out, err := Build(add)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	restore := installLoaderMocks(env)
	defer restore()
	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, ls.Class)
	installActivityThreadMock()
	defer clearActivityThreadMock()
	idx, off := findMethod(t, g, ls.Class, "->"+LoaderEntry+"(")
	if _, err := runPadMethod(g, idx, off, &fakeObj{desc: descContext}); err != nil {
		t.Fatalf("Loader.a 执行失败: %v", err)
	}
}

// TestLoaderMACRoundTrip 验证启用载荷 MAC 时：合法载荷通过校验并解出
// 与原始 DEX 逐字节一致的明文。
//
// 这是 MAC 的正向证据：若壳侧的域分离派生、HMAC 输入顺序（name 后 body）
// 或长度计算与 pack 不一致，这里就会失败。
func TestLoaderMACRoundTrip(t *testing.T) {
	key := testPackKey
	plain := bytes.Repeat([]byte{0x42}, 300)
	const name = "classes.dex"
	blob := mustEncryptMAC(t, plain, key, testPackIV, name)

	ls := &LoaderSpec{
		Class: "Lcom/apkguard/shell/Loader;", Key: key, TempDir: "ag", MAC: true,
		Items: []LoaderItem{{Asset: "assets/pay.bin", Name: name, DexName: "d0.dex", Size: len(blob)}},
	}
	env := &loaderEnv{assets: map[string][]byte{"pay.bin": blob}, fs: map[string][]byte{}}
	runLoaderEntry(t, ls, env)

	if env.exited {
		t.Fatalf("合法载荷不应触发 MAC 失败终止（exit=%v）", env.exitCodes)
	}
	got, ok := env.fs["/data/user/0/app/ag/d0.dex"]
	if !ok {
		t.Fatalf("未落地解密后的 DEX，已有文件: %v", keysOfBytes(env.fs))
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("MAC 校验通过后解密结果不一致（%d vs %d 字节）", len(got), len(plain))
	}
	t.Logf("载荷 MAC 正向：%d 字节载荷通过 HMAC 校验并还原", len(blob))
}

// TestLoaderMACTamperFails 验证篡改载荷任意关键字节都会让壳在解密前硬终止。
//
// 这是 MAC 存在的全部意义所在：它要求壳在解密**之前**就检出篡改。三个子用例
// 分别覆盖密文区、tag 区与 SIV 标签区，外加「换一个 name」（证明 MAC 绑定了
// 载荷身份，而不是只绑定字节）。
func TestLoaderMACTamperFails(t *testing.T) {
	key := testPackKey
	plain := bytes.Repeat([]byte{0x33}, 200)
	const name = "classes2.dex"
	base := mustEncryptMAC(t, plain, key, testPackIV, name)

	tampers := []struct {
		label  string
		mutate func([]byte)
	}{
		{"密文字节", func(b []byte) { b[20] ^= 0x01 }},         // SIV 标签(16) 之后的密文区
		{"tag 字节", func(b []byte) { b[len(b)-1] ^= 0x01 }}, // 尾部 HMAC
		{"SIV 标签字节", func(b []byte) { b[0] ^= 0x01 }},      // SIV 标签必须被 MAC 覆盖
	}
	for _, tc := range tampers {
		t.Run(tc.label, func(t *testing.T) {
			blob := append([]byte(nil), base...)
			tc.mutate(blob)
			ls := &LoaderSpec{
				Class: "Lx/L;", Key: key, TempDir: "ag", MAC: true,
				Items: []LoaderItem{{Asset: "assets/p.bin", Name: name, DexName: "d0.dex", Size: len(blob)}},
			}
			env := &loaderEnv{assets: map[string][]byte{"p.bin": blob}, fs: map[string][]byte{}}
			runLoaderEntry(t, ls, env)
			if !env.exited {
				t.Fatal("篡改后壳未调用 System.exit：MAC 未被真正校验")
			}
			if _, ok := env.fs["/data/user/0/app/ag/d0.dex"]; ok {
				t.Fatal("MAC 校验失败后仍写出了 DEX（先解密后校验？）")
			}
			if env.clObj != nil {
				t.Fatal("MAC 校验失败后仍构造了 ClassLoader")
			}
		})
	}

	// 换一个 name：字节没变但身份不符，MAC 必须失败。
	ls := &LoaderSpec{
		Class: "Lx/L;", Key: key, TempDir: "ag", MAC: true,
		Items: []LoaderItem{{Asset: "assets/p.bin", Name: "classes9.dex", DexName: "d0.dex", Size: len(base)}},
	}
	env := &loaderEnv{assets: map[string][]byte{"p.bin": base}, fs: map[string][]byte{}}
	runLoaderEntry(t, ls, env)
	if !env.exited {
		t.Fatal("载荷身份（原始 DEX 名）不符时 MAC 应失败，否则载荷可被互换")
	}
}

// TestLoaderMACDisabledNoMACInstructions 验证未启用 MAC 时壳产物里
// 不含任何 MAC 相关引用——这是「向后兼容、格式逐字节不变」的静态证据。
func TestLoaderMACDisabledNoMACInstructions(t *testing.T) {
	blob := mustEncrypt(t, Empty(), testPackKey, testPackIV)
	ls := &LoaderSpec{
		Class: "Lx/L;", Key: testPackKey, TempDir: "ag",
		Items: []LoaderItem{{Asset: "assets/p.bin", DexName: "d0.dex", Size: len(blob)}},
	}
	add, err := LoaderAddition(ls)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	out, err := Build(add)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	if bytes.Contains(out, []byte(macAlg)) {
		t.Fatalf("未启用 MAC 的壳不应含算法名 %q", macAlg)
	}
	if bytes.Contains(out, []byte(macDomain)) {
		t.Fatalf("未启用 MAC 的壳不应含域串 %q", macDomain)
	}

	// 对照：启用 MAC 时必须出现（否则上面的断言可能因字符串被压缩而假阴性）。
	macBlob := mustEncryptMAC(t, Empty(), testPackKey, testPackIV, "classes.dex")
	ls2 := &LoaderSpec{
		Class: "Lx/L;", Key: testPackKey, TempDir: "ag", MAC: true,
		Items: []LoaderItem{{Asset: "assets/p.bin", Name: "classes.dex", DexName: "d0.dex", Size: len(macBlob)}},
	}
	add2, err := LoaderAddition(ls2)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	out2, err := Build(add2)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	if err := Verify(out2); err != nil {
		t.Fatalf("启用 MAC 的壳 DEX 校验失败: %v", err)
	}
	if !bytes.Contains(out2, []byte(macAlg)) || !bytes.Contains(out2, []byte(macDomain)) {
		t.Fatal("启用 MAC 的壳应含 HmacSHA256 与域串")
	}
}

// TestLoaderLibDecryptAndSearchPath 验证 C2 正向：Loader 把原生库载荷解密
// 落地到私有目录，并把该目录（在前）与原 nativeLibraryDir（兜底）拼成
// DexClassLoader 的 librarySearchPath。
func TestLoaderLibDecryptAndSearchPath(t *testing.T) {
	key := testPackKey
	dexPlain := Empty()
	// 载荷名同时是 SIV 的 ad（绑定输入），加密与壳侧必须用同一个名字。
	dexBlob := mustEncryptAd(t, dexPlain, key, "classes.dex")
	libPlain := []byte("\x7fELF\x02\x01\x01\x00libfoo-for-c2-test")
	libBlob := mustEncryptAd(t, libPlain, key, "libfoo.so")

	ls := &LoaderSpec{
		Class: "Lcom/apkguard/shell/Loader;", Key: key, TempDir: "ag",
		LibDir: "ag/lib", LibReadOnly: true,
		Items:    []LoaderItem{{Asset: "assets/d.bin", Name: "classes.dex", DexName: "d0.dex", Size: len(dexBlob)}},
		LibItems: []LoaderLibItem{{Asset: "assets/l.bin", Name: "libfoo.so", Abi: "x86_64", Size: len(libBlob)}},
	}
	env := &loaderEnv{
		assets: map[string][]byte{"d.bin": dexBlob, "l.bin": libBlob},
		fs:     map[string][]byte{},
	}
	runLoaderEntry(t, ls, env)

	libPath := "/data/user/0/app/ag/lib/libfoo.so"
	got, ok := env.fs[libPath]
	if !ok {
		t.Fatalf("原生库未解密落地到私有目录，已有文件: %v", keysOfBytes(env.fs))
	}
	if !bytes.Equal(got, libPlain) {
		t.Fatalf("原生库解密结果不符（%d vs %d 字节）", len(got), len(libPlain))
	}
	wantSearch := "/data/user/0/app/ag/lib:" + testNativeLibDir
	if env.libPath != wantSearch {
		t.Fatalf("librarySearchPath 应为 %q，实际 %q", wantSearch, env.libPath)
	}
	foundRO := false
	for _, p := range env.readOnly {
		if p == libPath {
			foundRO = true
		}
	}
	if !foundRO {
		t.Fatalf("targetSdk ≥ 29 时落地的 .so 必须置只读（W^X），实际只读列表 %v", env.readOnly)
	}
	// DEX 与 .so 都必须落地。
	if _, ok := env.fs["/data/user/0/app/ag/d0.dex"]; !ok {
		t.Fatal("DEX 载荷未落地")
	}
	t.Logf("C2：原生库已解密到 %s，库搜索路径 %s", libPath, env.libPath)
}

// TestLoaderNoLibsKeepsNativeLibraryDir 验证未启用 C2 时库搜索路径保持
// 原 nativeLibraryDir，不引入任何 SO 相关行为（无副作用）。
func TestLoaderNoLibsKeepsNativeLibraryDir(t *testing.T) {
	blob := mustEncrypt(t, Empty(), testPackKey, testPackIV)
	ls := &LoaderSpec{
		Class: "Lx/L;", Key: testPackKey, TempDir: "ag",
		Items: []LoaderItem{{Asset: "assets/p.bin", DexName: "d0.dex", Size: len(blob)}},
	}
	env := &loaderEnv{assets: map[string][]byte{"p.bin": blob}, fs: map[string][]byte{}}
	runLoaderEntry(t, ls, env)
	if env.libPath != testNativeLibDir {
		t.Fatalf("未启用 C2 时 librarySearchPath 应保持 %q，实际 %q", testNativeLibDir, env.libPath)
	}
	if len(env.readOnly) != 0 {
		t.Fatalf("未启用 C2 时不应为 .so 置只读，实际 %v", env.readOnly)
	}
}
