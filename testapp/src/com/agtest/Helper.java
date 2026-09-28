package com.agtest;

/** 被 MainActivity 调用的辅助类：用于验证跨 DEX 分片的类解析。 */
public class Helper {
    /** 返回值会显示在界面上，因此这一行能证明跨分片调用真的成功了。 */
    public static String tag() {
        return "OK-跨分片";
    }
}
