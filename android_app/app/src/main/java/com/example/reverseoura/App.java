package com.example.reverseoura;

import android.app.Application;

public class App extends Application {
    static {
        System.loadLibrary("frida-gadget");
    }

    @Override
    public void onCreate() {
        super.onCreate();
    }
}
