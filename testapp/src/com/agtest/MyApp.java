package com.agtest;

import android.app.Application;
import android.util.Log;

/** 受控测试应用的 Application：用于验证 B2 的委托链。 */
public class MyApp extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        Log.i("AGTEST", "MyApp.onCreate OK");
    }
}
