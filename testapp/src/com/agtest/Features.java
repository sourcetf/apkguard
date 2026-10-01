package com.agtest;

/**
 * 代表性业务类：存在的唯一目的是让测试固件覆盖 Dalvik 的主要指令形态。
 *
 * 为什么需要它：测试固件（testdata/sample.apk 与 sample.dex）是仓库内唯一
 * 可用的 DEX 样本。样本太单薄时，一批结构类守卫会因为「样本里没有分支指令 /
 * 没有字段名 / 没有调试信息」而**跳过**，等于没测。这个类补齐了：
 *
 *   - if/switch/for/while  → 分支指令与 packed-switch/sparse-switch，覆盖分支重定位
 *   - 数组字面量           → new-array + fill-array-data
 *   - try/catch/finally    → 异常处理器表与 try 区间
 *   - 静态/实例字段        → A1 字段改名、static_values 重排
 *   - 字符串常量           → A2/A3 与 StringUsage 统计
 *
 * 它**不是** Android 组件（不在 Manifest 里声明），因此 A1 应当把它改名。
 */
public class Features {
    public static final String NAME = "agtest-features";
    static int counter;
    public long stamp;
    protected boolean flag;
    private Object payload;

    /** 分支 + 循环 + switch：用于覆盖分支重定位与 payload。 */
    public static int classify(int[] data, int mode) {
        int sum = 0;
        for (int i = 0; i < data.length; i++) {
            if (data[i] > 0) {
                sum += data[i];
            } else {
                sum -= data[i];
            }
        }
        switch (mode) {
            case 0:
                return sum;
            case 1:
                return -sum;
            case 2:
                return sum * 2;
            default:
                return 0;
        }
    }

    /** 数组字面量：覆盖 new-array + fill-array-data。 */
    public static int[] table() {
        return new int[] {3, 1, 4, 1, 5, 9, 2, 6};
    }

    /** try/catch/finally：覆盖异常处理器与 try 区间。 */
    public static String parse(String s) {
        try {
            return String.valueOf(Integer.parseInt(s));
        } catch (NumberFormatException e) {
            return "NaN";
        } finally {
            counter++;
        }
    }

    /** while + 字符串拼接：覆盖 const-string 与 A2/A3。 */
    public String describe() {
        StringBuilder sb = new StringBuilder(NAME);
        int n = table().length;
        while (n > 0) {
            sb.append('-').append(n);
            n--;
        }
        return sb.toString();
    }

    /**
     * 嵌套类：既覆盖内部类的命名与访问，也把固件的类数抬过 B4（多 DEX 拆分）
     * 测试的「类数过少则拆分无意义」门槛——门槛之下那条测试会直接跳过。
     */
    public static class Inner {
        public int value;

        public Inner(int v) {
            this.value = v;
        }

        public int doubled() {
            return value * 2;
        }
    }

    /** 第二个嵌套类，同样是为了让分片测试有足够的类可拆。 */
    public static class Inner2 {
        public String label;

        public Inner2(String label) {
            this.label = label;
        }

        @Override
        public String toString() {
            return label + ":" + label.length();
        }
    }
}
