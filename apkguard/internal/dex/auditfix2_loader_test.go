package dex

import (
	"strings"
	"testing"
)

// 本文件收口 auditfix2 的第 4 条缺陷：ClassLoader 接管的失败路径没有任何日志。
//
// 注入的 i(ClassLoader) 会回读 LoadedApk.mClassLoader 校验接管是否生效，
// 返回 2=成功 / 1=字段被隐藏（或未找到）/ 0=字段可见但写入未生效。
// 非 debug 产物此前对该返回值不作任何处理、也不记录：Android 9+ 的隐藏 API
// 限制一旦挡掉字段，现象是「载荷解密成功、随后 Activity 找不到类」，
// 而 logcat 里毫无线索。
//
// 修复：失败路径（1/0）用 android.util.Log.w 打出 tag "APKGUARD"，
// 消息区分「被隐藏/未找到」与「写入未生效」；成功不打，避免噪声。
// debug 模式下另有 Toast（既有行为，不在此断言）。

// TestAuditFix2LoaderFailureLogs 断言写入失败时确实调用了 Log.w，且消息能区分原因。
//
// 用**非 debug** 产物执行完整壳链路：证明这个线索不依赖排障开关。
func TestAuditFix2LoaderFailureLogs(t *testing.T) {
	cases := []struct {
		name string
		// hook 在 ActivityThread 替身搭好之后制造失败环境。
		hook func(t *testing.T, clField *fakeField)
		// want 是失败消息里必须出现的关键词。
		want string
	}{
		{
			// getDeclaredFields 被隐藏 API 策略过滤 → 找不到字段，回读为 null，i() 返回 1。
			name: "hidden",
			hook: func(t *testing.T, _ *fakeField) {
				loaderFields["android.app.LoadedApk"] = nil
				fieldSetNoop = true
			},
			want: "隐藏",
		},
		{
			// 字段可见且预置旧值，但写入失效 → 回读值非空且不等于新加载器，i() 返回 0。
			name: "stale",
			hook: func(t *testing.T, clField *fakeField) {
				clField.val = &fakeObj{desc: "Ldalvik/system/PathClassLoader;"}
				fieldSetNoop = true
			},
			want: "写入未生效",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fx := buildFullShellOpts(t, false) // 非 debug：验证失败日志不依赖排障开关
			logLines = nil
			defer func() { logLines = nil }()
			e2eActivityThreadHook = func() {
				clField := loaderFields["android.app.LoadedApk"][0]
				c.hook(t, clField)
			}
			defer func() { e2eActivityThreadHook = nil; fieldSetNoop = false }()

			runFullShell(t, fx, cleanDevice(fx.cert, fx.deviceID))

			var hit string
			for _, line := range logLines {
				if strings.HasPrefix(line, loaderLogTag+"|") {
					hit = line
					if strings.Contains(line, c.want) {
						return // 命中：失败路径留下了正确的 logcat 线索
					}
				}
			}
			if hit == "" {
				t.Fatalf("ClassLoader 接管失败（%s）没有写任何 Log.w——"+
					"真机上只剩「Activity 找不到类」而无线索（logcat: %v）", c.name, logLines)
			}
			t.Fatalf("Log.w 消息未点明失败原因（应含 %q）: %s", c.want, hit)
		})
	}
}

// TestAuditFix2LoaderSuccessNoLog 防守卫误伤：接管成功时不得打印 Log.w（避免噪声）。
func TestAuditFix2LoaderSuccessNoLog(t *testing.T) {
	fx := buildFullShellOpts(t, false)
	logLines = nil
	defer func() { logLines = nil }()

	_, _, clField, _ := runFullShell(t, fx, cleanDevice(fx.cert, fx.deviceID))
	if clField.val == nil {
		t.Fatal("接管本应成功，但 mClassLoader 未写入（测试前提不成立）")
	}
	for _, line := range logLines {
		if strings.HasPrefix(line, loaderLogTag+"|") {
			t.Fatalf("接管成功仍打印了失败日志: %s", line)
		}
	}
}
