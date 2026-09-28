package com.agtest;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

/** 受控测试应用的入口 Activity：能起来就说明壳把业务 DEX 加载成功了。 */
public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        TextView tv = new TextView(this);
        tv.setText("AGTEST " + Helper.tag());
        setContentView(tv);
        Log.i("AGTEST", "MainActivity.onCreate " + Helper.tag());
    }
}
