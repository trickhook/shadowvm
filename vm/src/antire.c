#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>

#include "svm_internal.h"

static int svm_tracer_present(void) {
    FILE *f = fopen("/proc/self/status", "re");
    if (!f) return 0;
    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            const char *p = line + 10;
            while (*p == ' ' || *p == '\t') p++;
            if (*p != '0') found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

static int svm_env_dumpable_off(void) {
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    return 1;
}

static uint32_t svm_crc32_step(uint32_t crc, const uint8_t *data, size_t n) {
    crc = ~crc;
    for (size_t i = 0; i < n; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++) {
            uint32_t m = (uint32_t)(-(int32_t)(crc & 1));
            crc = (crc >> 1) ^ (0xEDB88320u & m);
        }
    }
    return ~crc;
}

static int svm_self_text_crc(uint32_t *out) {
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return 0;
    char line[512];
    uint64_t start = 0, end = 0;
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, "libshadowvm.so")) continue;
        if (!strstr(line, "r-xp") && !strstr(line, "r-x")) continue;
        uint64_t s = 0, e = 0;
        const char *p = line;
        for (int i = 0; i < 16 && p[i] && p[i] != '-'; i++) {
            char c = p[i];
            s <<= 4;
            if (c >= '0' && c <= '9') s |= (uint64_t)(c - '0');
            else if (c >= 'a' && c <= 'f') s |= (uint64_t)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') s |= (uint64_t)(c - 'A' + 10);
            else break;
        }
        const char *q = strchr(p, '-');
        if (!q) continue;
        q++;
        for (int i = 0; i < 16 && q[i] && q[i] != ' '; i++) {
            char c = q[i];
            e <<= 4;
            if (c >= '0' && c <= '9') e |= (uint64_t)(c - '0');
            else if (c >= 'a' && c <= 'f') e |= (uint64_t)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') e |= (uint64_t)(c - 'A' + 10);
            else break;
        }
        start = s;
        end = e;
        found = 1;
        break;
    }
    fclose(f);
    if (!found || end <= start) return 0;
    uint32_t crc = 0;
    size_t total = (size_t)(end - start);
    const uint8_t *p = (const uint8_t *)(uintptr_t)start;
    size_t off = 0;
    while (off < total) {
        size_t chunk = total - off;
        if (chunk > 4096) chunk = 4096;
        crc = svm_crc32_step(crc, p + off, chunk);
        off += chunk;
    }
    *out = crc;
    return 1;
}

svm_status svm_antire_check(void) {
    (void)svm_env_dumpable_off();
    if (svm_tracer_present()) return SVM_E_TAMPER;
    uint32_t crc;
    if (!svm_self_text_crc(&crc)) return SVM_OK;
    __asm__ __volatile__ ("" : : "r"(crc) : "memory");
    return SVM_OK;
}
