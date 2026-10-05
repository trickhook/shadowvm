#ifdef SVM_CRYPTO_SELFTEST

#include <stdio.h>

int svm_crypto_selftest(void);

int main(void) {
    int rc = svm_crypto_selftest();
    if (rc == 0) {
        printf("shadowvm crypto selftest: OK\n");
        return 0;
    }
    printf("shadowvm crypto selftest: FAIL (code %d)\n", rc);
    return rc;
}

#else

int main(void) { return 0; }

#endif
