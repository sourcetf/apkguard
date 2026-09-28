package com.agtest;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.util.Log;

/**
 * 一个什么都不做的 ContentProvider。
 *
 * 存在意义：系统会在 Application.onCreate **之前**实例化 Manifest 里声明的
 * provider，且用的是 LoadedApk 的 ClassLoader。所以只要这个类被成功创建，
 * 就证明壳的 ClassLoader 接管确实生效了——它的类在加密载荷里，
 * 旧的加载器根本看不见它。
 */
public class HealthProvider extends ContentProvider {
    @Override
    public boolean onCreate() {
        Log.i("AGTEST", "HealthProvider.onCreate OK（ClassLoader 接管生效）");
        return true;
    }

    @Override
    public Cursor query(Uri u, String[] p, String s, String[] a, String o) { return null; }
    @Override
    public String getType(Uri u) { return null; }
    @Override
    public Uri insert(Uri u, ContentValues v) { return null; }
    @Override
    public int delete(Uri u, String s, String[] a) { return 0; }
    @Override
    public int update(Uri u, ContentValues v, String s, String[] a) { return 0; }
}
