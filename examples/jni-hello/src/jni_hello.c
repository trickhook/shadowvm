#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <android/log.h>

#include "shadowvm.h"
#include "hello_blob.h"

#define TAG "shadowvm.jni"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static int64_t svm_sys_write(svm_ctx *vm, int64_t fd, int64_t buf, int64_t len,
                             int64_t a3, int64_t a4, int64_t a5) {
    (void)vm; (void)buf; (void)a3; (void)a4; (void)a5;
    LOGI("vm.write fd=%lld len=%lld", (long long)fd, (long long)len);
    return len;
}

static int64_t svm_sys_abort(svm_ctx *vm, int64_t a0, int64_t a1, int64_t a2,
                             int64_t a3, int64_t a4, int64_t a5) {
    (void)vm; (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    LOGE("vm.abort");
    return -1;
}

JNIEXPORT jlong JNICALL
Java_com_trickhook_shadowvm_HelloJNI_runHello(JNIEnv *env, jclass klass) {
    (void)env; (void)klass;
    svm_status st = SVM_OK;
    svm_ctx *vm = svm_open_local(HELLO_SVM, HELLO_SVM_LEN,
                                 (const char *)HELLO_SVM_PASSWORD,
                                 sizeof(HELLO_SVM_PASSWORD) - 1, &st);
    if (!vm) {
        LOGE("open_local failed: %d (%s)", (int)st, svm_strerror(st));
        return (jlong)-1;
    }
    svm_set_syscall(vm, 0, svm_sys_write);
    svm_set_syscall(vm, 4, svm_sys_abort);
    int64_t result = 0;
    st = svm_run(vm, "hello", NULL, 0, &result);
    svm_close(vm);
    if (st != SVM_OK) {
        LOGE("run failed: %d (%s)", (int)st, svm_strerror(st));
        return (jlong)-1;
    }
    LOGI("vm.hello returned %lld", (long long)result);
    return (jlong)result;
}

JNIEXPORT jlong JNICALL
Java_com_trickhook_shadowvm_HelloJNI_runSum(JNIEnv *env, jclass klass, jlong a, jlong b) {
    (void)env; (void)klass;
    svm_status st = SVM_OK;
    svm_ctx *vm = svm_open_local(HELLO_SVM, HELLO_SVM_LEN,
                                 (const char *)HELLO_SVM_PASSWORD,
                                 sizeof(HELLO_SVM_PASSWORD) - 1, &st);
    if (!vm) {
        LOGE("open_local failed: %d (%s)", (int)st, svm_strerror(st));
        return (jlong)-1;
    }
    svm_set_syscall(vm, 0, svm_sys_write);
    int64_t argv[2];
    argv[0] = (int64_t)a;
    argv[1] = (int64_t)b;
    int64_t result = 0;
    st = svm_run(vm, "sum", argv, 2, &result);
    svm_close(vm);
    if (st != SVM_OK) {
        LOGE("run sum failed: %d", (int)st);
        return (jlong)-1;
    }
    return (jlong)result;
}
