package com.agtest;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

/**
 * 受控测试应用的入口 Activity：能起来就说明壳把业务 DEX 加载成功了。
 *
 * 界面取自 res/layout/main.xml（R.layout.main），而不是纯代码构造：
 * 这样 DEX 里会出现真实的资源引用（R.layout / R.id / R.string），
 * A5/A11 改写资源路径时必须同步改写这些引用，否则运行时就是
 * Resources.NotFoundException——只有存在这类引用，该链路才算被验证过。
 */
public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.main);
        TextView tv = (TextView) findViewById(R.id.main_text);
        String text = getString(R.string.hello) + " " + Helper.tag() + " " + Features.NAME;
        tv.setText(text);
        Log.i("AGTEST", "MainActivity.onCreate " + Helper.tag());
        Log.i("AGTEST", "Features.classify=" + Features.classify(Features.table(), 1)
                + " parse=" + Features.parse("42"));
    }
}
