#include <stdint.h>
#include <string.h>

#include "svm_internal.h"

static inline int svm_mem_ok(uint64_t addr) {
    return addr <= (uint64_t)SVM_STACK && (uint64_t)SVM_STACK - addr >= 8;
}

static inline uint64_t svm_rd64(const uint8_t *p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24)
         | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static inline void svm_wr64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

static inline void svm_set_flags_sub(svm_ctx *vm, uint64_t a, uint64_t b, uint64_t r) {
    uint32_t f = 0;
    if (r == 0) f |= SVM_FLAG_ZF;
    if ((int64_t)r < 0) f |= SVM_FLAG_SF;
    if (a < b) f |= SVM_FLAG_CF;
    if (((a ^ b) & (a ^ r)) >> 63) f |= SVM_FLAG_OF;
    vm->flags = f;
}

svm_status svm_dispatch(svm_ctx *vm) {
    void *table[SVM_REAL_OPS];
    table[0x00] = &&L_HALT;
    table[0x01] = &&L_MOV;
    table[0x02] = &&L_MOVI;
    table[0x03] = &&L_ADD;
    table[0x04] = &&L_SUB;
    table[0x05] = &&L_MUL;
    table[0x06] = &&L_DIV;
    table[0x07] = &&L_AND;
    table[0x08] = &&L_OR;
    table[0x09] = &&L_XOR;
    table[0x0A] = &&L_SHL;
    table[0x0B] = &&L_SHR;
    table[0x0C] = &&L_NOT;
    table[0x0D] = &&L_NEG;
    table[0x0E] = &&L_CMP;
    table[0x0F] = &&L_JMP;
    table[0x10] = &&L_JEQ;
    table[0x11] = &&L_JNE;
    table[0x12] = &&L_JLT;
    table[0x13] = &&L_JGT;
    table[0x14] = &&L_LOAD;
    table[0x15] = &&L_STORE;
    table[0x16] = &&L_PUSH;
    table[0x17] = &&L_POP;
    table[0x18] = &&L_CALL;
    table[0x19] = &&L_RET;
    table[0x1A] = &&L_SYSCALL;
    table[0x1B] = &&L_NOP;

    uint32_t pc = vm->pc;
    uint32_t instr_pc = 0;
    uint8_t pm[4];
    uint8_t b0 = 0, b1 = 0, b2 = 0, variant = 0;
    uint32_t dst = 0, src1 = 0, src2 = 0, imm9 = 0;
    int64_t imms = 0;
    uint32_t imm32 = 0;
    svm_status rc = SVM_OK;

#define FETCH_WORD(IV)                                                               \
    do {                                                                             \
        if ((size_t)pc + 4 > vm->code_len) { rc = SVM_E_BAD_PC; goto L_exit; }       \
        svm_pc_mask(vm->kmaster, pc, pm);                                            \
        const uint8_t *_ip = vm->code + pc;                                          \
        (IV) = (uint32_t)(_ip[0] ^ pm[0]) | ((uint32_t)(_ip[1] ^ pm[1]) << 8)        \
             | ((uint32_t)(_ip[2] ^ pm[2]) << 16) | ((uint32_t)(_ip[3] ^ pm[3]) << 24); \
        pc += 4;                                                                     \
    } while (0)

#define DISPATCH()                                                                   \
    do {                                                                             \
        instr_pc = pc;                                                               \
        uint32_t _iw;                                                                \
        FETCH_WORD(_iw);                                                             \
        variant = (uint8_t)(_iw >> 24);                                              \
        if (variant >= SVM_VARIANT_LIMIT) { rc = SVM_E_BAD_OPCODE; goto L_exit; }    \
        uint8_t _real = (uint8_t)(variant % SVM_REAL_OPS);                           \
        const uint8_t *_vm = vm->mask + ((uint32_t)variant << 2);                    \
        b0 = (uint8_t)(_iw & 0xFF) ^ _vm[0];                                         \
        b1 = (uint8_t)((_iw >> 8) & 0xFF) ^ _vm[1];                                  \
        b2 = (uint8_t)((_iw >> 16) & 0xFF) ^ _vm[2];                                 \
        dst = (uint32_t)((b2 >> 3) & 0x1F);                                          \
        src1 = (uint32_t)(((b2 & 0x7) << 2) | ((b1 >> 6) & 0x3));                    \
        src2 = (uint32_t)((b1 >> 1) & 0x1F);                                         \
        imm9 = ((uint32_t)(b1 & 1) << 8) | (uint32_t)b0;                             \
        imms = (int64_t)((int32_t)(imm9 << 23) >> 23);                               \
        goto *table[_real];                                                          \
    } while (0)

    DISPATCH();

L_HALT:
    rc = SVM_OK;
    goto L_exit;

L_MOV:
    vm->regs[dst] = vm->regs[src1];
    DISPATCH();

L_MOVI:
    FETCH_WORD(imm32);
    vm->regs[dst] = (int64_t)(int32_t)imm32;
    DISPATCH();

L_ADD:
    vm->regs[dst] = vm->regs[src1] + vm->regs[src2];
    DISPATCH();

L_SUB:
    vm->regs[dst] = vm->regs[src1] - vm->regs[src2];
    DISPATCH();

L_MUL:
    vm->regs[dst] = (int64_t)((uint64_t)vm->regs[src1] * (uint64_t)vm->regs[src2]);
    DISPATCH();

L_DIV:
    if (vm->regs[src2] == 0) { rc = SVM_E_DIV_ZERO; goto L_exit; }
    vm->regs[dst] = (int64_t)((uint64_t)vm->regs[src1] / (uint64_t)vm->regs[src2]);
    DISPATCH();

L_AND:
    vm->regs[dst] = vm->regs[src1] & vm->regs[src2];
    DISPATCH();

L_OR:
    vm->regs[dst] = vm->regs[src1] | vm->regs[src2];
    DISPATCH();

L_XOR:
    vm->regs[dst] = vm->regs[src1] ^ vm->regs[src2];
    DISPATCH();

L_SHL:
    vm->regs[dst] = (int64_t)((uint64_t)vm->regs[src1] << (vm->regs[src2] & 63));
    DISPATCH();

L_SHR:
    vm->regs[dst] = (int64_t)((uint64_t)vm->regs[src1] >> (vm->regs[src2] & 63));
    DISPATCH();

L_NOT:
    vm->regs[dst] = ~vm->regs[src1];
    DISPATCH();

L_NEG:
    vm->regs[dst] = -vm->regs[src1];
    DISPATCH();

L_CMP: {
    uint64_t a = (uint64_t)vm->regs[src1];
    uint64_t b = (uint64_t)vm->regs[src2];
    uint64_t r = a - b;
    svm_set_flags_sub(vm, a, b, r);
    DISPATCH();
}

L_JMP: {
    FETCH_WORD(imm32);
    int64_t off = (imms << 2) + (int64_t)(int32_t)imm32;
    int64_t tgt = (int64_t)instr_pc + off;
    if (tgt < 0 || (uint64_t)tgt > vm->code_len) { rc = SVM_E_BAD_PC; goto L_exit; }
    pc = (uint32_t)tgt;
    DISPATCH();
}

L_JEQ: {
    FETCH_WORD(imm32);
    if (vm->flags & SVM_FLAG_ZF) {
        int64_t off = (imms << 2) + (int64_t)(int32_t)imm32;
        int64_t tgt = (int64_t)instr_pc + off;
        if (tgt < 0 || (uint64_t)tgt > vm->code_len) { rc = SVM_E_BAD_PC; goto L_exit; }
        pc = (uint32_t)tgt;
    }
    DISPATCH();
}

L_JNE: {
    FETCH_WORD(imm32);
    if (!(vm->flags & SVM_FLAG_ZF)) {
        int64_t off = (imms << 2) + (int64_t)(int32_t)imm32;
        int64_t tgt = (int64_t)instr_pc + off;
        if (tgt < 0 || (uint64_t)tgt > vm->code_len) { rc = SVM_E_BAD_PC; goto L_exit; }
        pc = (uint32_t)tgt;
    }
    DISPATCH();
}

L_JLT: {
    FETCH_WORD(imm32);
    int sf = (vm->flags & SVM_FLAG_SF) ? 1 : 0;
    int of = (vm->flags & SVM_FLAG_OF) ? 1 : 0;
    if (sf != of) {
        int64_t off = (imms << 2) + (int64_t)(int32_t)imm32;
        int64_t tgt = (int64_t)instr_pc + off;
        if (tgt < 0 || (uint64_t)tgt > vm->code_len) { rc = SVM_E_BAD_PC; goto L_exit; }
        pc = (uint32_t)tgt;
    }
    DISPATCH();
}

L_JGT: {
    FETCH_WORD(imm32);
    int sf = (vm->flags & SVM_FLAG_SF) ? 1 : 0;
    int of = (vm->flags & SVM_FLAG_OF) ? 1 : 0;
    int zf = (vm->flags & SVM_FLAG_ZF) ? 1 : 0;
    if (!zf && sf == of) {
        int64_t off = (imms << 2) + (int64_t)(int32_t)imm32;
        int64_t tgt = (int64_t)instr_pc + off;
        if (tgt < 0 || (uint64_t)tgt > vm->code_len) { rc = SVM_E_BAD_PC; goto L_exit; }
        pc = (uint32_t)tgt;
    }
    DISPATCH();
}

L_LOAD: {
    uint64_t addr = (uint64_t)((int64_t)(uint64_t)vm->regs[src1] + imms);
    if (!svm_mem_ok(addr)) { rc = SVM_E_STACK; goto L_exit; }
    vm->regs[dst] = (int64_t)svm_rd64(vm->mem + addr);
    DISPATCH();
}

L_STORE: {
    uint64_t addr = (uint64_t)((int64_t)(uint64_t)vm->regs[dst] + imms);
    if (!svm_mem_ok(addr)) { rc = SVM_E_STACK; goto L_exit; }
    svm_wr64(vm->mem + addr, (uint64_t)vm->regs[src1]);
    DISPATCH();
}

L_PUSH: {
    uint64_t sp = (uint64_t)vm->regs[31] - 8;
    if (!svm_mem_ok(sp)) { rc = SVM_E_STACK; goto L_exit; }
    svm_wr64(vm->mem + sp, (uint64_t)vm->regs[src1]);
    vm->regs[31] = (int64_t)sp;
    DISPATCH();
}

L_POP: {
    uint64_t sp = (uint64_t)vm->regs[31];
    if (!svm_mem_ok(sp)) { rc = SVM_E_STACK; goto L_exit; }
    vm->regs[dst] = (int64_t)svm_rd64(vm->mem + sp);
    vm->regs[31] = (int64_t)(sp + 8);
    DISPATCH();
}

L_CALL: {
    if (imm9 >= vm->entry_count) { rc = SVM_E_BAD_SYMBOL; goto L_exit; }
    uint64_t sp = (uint64_t)vm->regs[31] - 8;
    if (!svm_mem_ok(sp)) { rc = SVM_E_STACK; goto L_exit; }
    svm_wr64(vm->mem + sp, (uint64_t)pc);
    vm->regs[31] = (int64_t)sp;
    uint32_t off = (uint32_t)vm->entry[imm9 * 8 + 4]
                 | ((uint32_t)vm->entry[imm9 * 8 + 5] << 8)
                 | ((uint32_t)vm->entry[imm9 * 8 + 6] << 16)
                 | ((uint32_t)vm->entry[imm9 * 8 + 7] << 24);
    if ((size_t)off >= vm->code_len) { rc = SVM_E_BAD_PC; goto L_exit; }
    pc = off;
    DISPATCH();
}

L_RET: {
    uint64_t sp = (uint64_t)vm->regs[31];
    if (!svm_mem_ok(sp)) { rc = SVM_E_STACK; goto L_exit; }
    uint64_t ra = svm_rd64(vm->mem + sp);
    vm->regs[31] = (int64_t)(sp + 8);
    if (ra == SVM_SENTINEL_RET) { rc = SVM_OK; goto L_exit; }
    if (ra > vm->code_len) { rc = SVM_E_BAD_PC; goto L_exit; }
    pc = (uint32_t)ra;
    DISPATCH();
}

L_SYSCALL: {
    svm_syscall_fn fn = vm->syscalls[imm9 & 0xFF];
    if (!fn) { rc = SVM_E_SYSCALL; goto L_exit; }
    int64_t r = fn(vm, vm->regs[0], vm->regs[1], vm->regs[2],
                   vm->regs[3], vm->regs[4], vm->regs[5]);
    vm->regs[0] = r;
    DISPATCH();
}

L_NOP:
    DISPATCH();

L_exit:
    vm->pc = pc;
    return rc;
}
