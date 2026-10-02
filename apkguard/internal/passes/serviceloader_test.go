package passes

import (
	"context"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// TestServiceLoaderProviderIsNotRenamed 钉住「META-INF/services 两侧的类名都不得改名」。
//
// 真实缺陷（实测于 RustDesk 1.5.0，Flutter 应用，R8 混淆过）：
//
//	java.lang.IllegalStateException: Module with the Main dispatcher is missing.
//	  Add dependency providing the Main dispatcher, e.g. 'kotlinx-coroutines-android'
//
// 根因：ServiceLoader 的两半引用都只写在资源里，DEX 中没有对应字符串常量，
// 因此 reflectedClasses 看不见它们：
//   - 文件**名** = 服务接口类名（原包 `META-INF/services/j3.t`，即
//     kotlinx.coroutines.internal.MainDispatcherFactory）；
//   - 文件**内容** = 提供者类名（`f3.a`，即 AndroidDispatcherFactory）。
//
// A1 改名（`-package-shrink` 下还会搬包）之后，运行时 `ServiceLoader.load`
// 既找不到文件、也实例化不出提供者，主线程调度器缺失，UI 首次 attach 即崩。
//
// 断言：接口与提供者都保持原类名原包，资源文件本身也原样保留。
func TestServiceLoaderProviderIsNotRenamed(t *testing.T) {
	const iface = "com.example.svc.Factory" // 服务接口（资源文件名）
	const provider = "com.example.svc.Impl" // 提供者（资源内容）
	art := newArtifact(
		zipx.NewStored("classes.dex", buildDexClasses(t,
			"L"+slashify(iface)+";", "L"+slashify(provider)+";")),
		zipx.NewStored("META-INF/services/"+iface, []byte("# comment\n"+provider+"\n")),
	)

	opts := &config.Options{
		Enabled: map[config.FeatureID]bool{"A1": true},
		Seed:    "svc",
		// 同时开启压包，验证它也不会把二者搬走。
		PackageShrink: true,
	}
	if err := (&renameClass{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A1 执行失败: %v", err)
	}

	data, err := pipeline.Find(art, "classes.dex").Data()
	if err != nil {
		t.Fatalf("读取产物失败: %v", err)
	}
	f, err := dex.Parse(data)
	if err != nil {
		t.Fatalf("产物无法解析: %v", err)
	}
	infos, err := f.ClassInfos()
	if err != nil {
		t.Fatalf("读取类信息失败: %v", err)
	}
	have := classDescs(infos)
	for _, want := range []string{"L" + slashify(iface) + ";", "L" + slashify(provider) + ";"} {
		if !have[want] {
			t.Fatalf("ServiceLoader 的类被改名/搬走，运行时会 Main dispatcher is missing：缺 %s（实际 %v）",
				want, keysOfDesc(have))
		}
	}
	// 资源文件本身必须原样保留（文件名与内容仍需与未改名的类对应）。
	if e := pipeline.Find(art, "META-INF/services/"+iface); e == nil {
		t.Fatal("META-INF/services 资源文件丢失")
	}
	t.Logf("接口与提供者都保持原样：%v", keysOfDesc(have))
}

// buildDexClasses 造一个含多个类的 DEX。
func buildDexClasses(t *testing.T, descs ...string) []byte {
	t.Helper()
	specs := make([]dex.ClassSpec, 0, len(descs))
	for _, d := range descs {
		specs = append(specs, dex.ClassSpec{Name: d, Super: "Ljava/lang/Object;", Access: 0x0001})
	}
	d, err := dex.Build(dex.Addition{Classes: specs})
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	return d
}

// slashify 把点分类名转成斜杠形式。
func slashify(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c == '.' {
			out[i] = '/'
		}
	}
	return string(out)
}
