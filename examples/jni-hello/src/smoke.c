#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "shadowvm.h"
#include "hello_blob.h"

static int64_t sys_write(svm_ctx *vm, int64_t fd, int64_t buf, int64_t len,
                         int64_t a3, int64_t a4, int64_t a5) {
    (void)vm; (void)buf; (void)a3; (void)a4; (void)a5;
    fprintf(stderr, "vm.write fd=%lld len=%lld\n", (long long)fd, (long long)len);
    return len;
}

int main(void) {
    svm_status st = SVM_OK;
    svm_ctx *vm = svm_open_local(HELLO_SVM, HELLO_SVM_LEN,
                                 HELLO_SVM_PASSWORD, sizeof(HELLO_SVM_PASSWORD) - 1, &st);
    if (!vm) {
        fprintf(stderr, "open: %d %s\n", (int)st, svm_strerror(st));
        return 1;
    }
    svm_set_syscall(vm, 0, sys_write);
    int64_t r = 0;
    st = svm_run(vm, "hello", NULL, 0, &r);
    if (st != SVM_OK) {
        fprintf(stderr, "run: %d %s\n", (int)st, svm_strerror(st));
        svm_close(vm);
        return 2;
    }
    printf("hello => %lld\n", (long long)r);
    int64_t argv[2] = { 100, 23 };
    int64_t r2 = 0;
    st = svm_run(vm, "sum", argv, 2, &r2);
    if (st != SVM_OK) {
        fprintf(stderr, "sum run: %d %s\n", (int)st, svm_strerror(st));
        svm_close(vm);
        return 3;
    }
    printf("sum(100,23) => %lld\n", (long long)r2);
    svm_close(vm);
    return 0;
}
