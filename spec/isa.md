# ShadowVM ISA v1

## Machine

- 32 general registers R0..R31, 64-bit each
- Flags register (ZF, SF, CF, OF) set by CMP and arith ops with S variant
- PC: byte offset into the decrypted code section
- SP: R31 by convention
- Stack: 4096 bytes of VM-managed memory inside the sandbox heap

## Encoding

Fixed 32-bit words, little-endian:

```
 31      24 23  19 18  14 13   9 8               0
+----------+------+------+------+-----------------+
|  opcode  | dst  | src1 | src2 |     imm9        |
+----------+------+------+------+-----------------+
```

For wide immediates, the following 32-bit word carries imm32. SYSCALL/CALL use imm9 as index into the entry table.

## Opcodes

| hex  | mnemonic | semantics                                        |
|------|----------|--------------------------------------------------|
| 0x00 | HALT     | end of fiber                                     |
| 0x01 | MOV      | dst = src1                                       |
| 0x02 | MOVI     | dst = imm32 (next word)                          |
| 0x03 | ADD      | dst = src1 + src2                                |
| 0x04 | SUB      | dst = src1 - src2                                |
| 0x05 | MUL      | dst = src1 * src2                                |
| 0x06 | DIV      | dst = src1 / src2 (unsigned)                     |
| 0x07 | AND      | dst = src1 & src2                                |
| 0x08 | OR       | dst = src1 | src2                                |
| 0x09 | XOR      | dst = src1 ^ src2                                |
| 0x0A | SHL      | dst = src1 << (src2 & 63)                        |
| 0x0B | SHR      | dst = src1 >> (src2 & 63)                        |
| 0x0C | NOT      | dst = ~src1                                      |
| 0x0D | NEG      | dst = -src1                                      |
| 0x0E | CMP      | flags = src1 cmp src2                            |
| 0x0F | JMP      | PC += (sext imm9 << 2) + next word               |
| 0x10 | JEQ      | branch if ZF                                     |
| 0x11 | JNE      | branch if !ZF                                    |
| 0x12 | JLT      | branch if SF != OF                               |
| 0x13 | JGT      | branch if !ZF && SF == OF                        |
| 0x14 | LOAD     | dst = u64 at [src1 + sext(imm9)]                 |
| 0x15 | STORE    | u64 at [dst + sext(imm9)] = src1                 |
| 0x16 | PUSH     | SP -= 8; mem[SP] = src1                          |
| 0x17 | POP      | dst = mem[SP]; SP += 8                           |
| 0x18 | CALL     | push PC; PC = entry[imm9].offset                 |
| 0x19 | RET      | PC = pop                                         |
| 0x1A | SYSCALL  | invoke host[imm9] with R0..R5, result in R0      |
| 0x1B | NOP      |                                                  |

Opcodes 0x1C..0xFF are reserved for polymorphic variants. The compiler emits each real opcode under one of its registered variants per instruction; the dispatcher routes variants to the same semantic handler.

## Polymorphism

Each real opcode has N variants, N in [1,4]. Variant id is written into the opcode byte. The dispatcher table maps all variants to the same handler, but each handler reads a different per-variant XOR mask applied to its operand bytes before decode, so a static disassembler cannot share decoders across variants without recovering the mask table (itself encrypted in the blob).

## Syscall table (host[])

| idx | name       | arg regs   | notes                            |
|-----|------------|------------|----------------------------------|
| 0   | write      | R0=fd, R1=buf_vaddr, R2=len   |              |
| 1   | read       | R0=fd, R1=buf_vaddr, R2=len   |              |
| 2   | time_ms    |                               | result in R0 |
| 3   | rand_u64   |                               | result in R0 |
| 4   | abort      |                               |              |
