package com.trickhook.shadowvm;

public final class HelloJNI {
    static {
        System.loadLibrary("jni_hello");
    }

    public static native long runHello();
    public static native long runSum(long a, long b);

    private HelloJNI() {}
}
