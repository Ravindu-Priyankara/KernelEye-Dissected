# Instruction classes and major opcode structures

The eBPF has 8 classes. But we can divide it into two major structures.

- Arithmetic and Jump group
- Load and Store group

## 01 Arithmetic and Jump group opcode architecture

```
|=============|========|=============|
| 4 bits(MSB) |  1 bit | 3 bits(LSB) |
|-------------|--------|-------------|
|    code     | source |    class    |
|=============|========|=============|
```

### 01.1 Classes and explanation (LSB)

| class | value | description |
|-------|-------|-------------|
| `BPF_ALU` | 0x04 | 32-bit arithmetic operations |
| `BPF_JMP` | 0x05 | 64-bit jump operations |
| `BPF_JMP32` | 0x06 | 32-bit jump operations |
| `BPF_ALU64` | 0x07 | 64-bit arithmetic operations |
|-------------|------|------------------------------|

## 02 Load and Store group opcode architecture

```
|=============|========|=============|
| 3 bits(MSB) |  2 bit | 3 bits(LSB) |
|-------------|--------|-------------|
|    mode     |  size  |    class    |
|=============|========|=============|
```

### 02.1 Classes and explanation (LSB)

| class | value | description |
|-------|-------|-------------|
| `BPF_LD` | 0x00 | non-standard load operations |
| `BPF_LDX` | 0x01 | load into register operations |
| `BPF_ST` | 0x02 | store from immediate operations |
| `BPF_STX` | 0x03 | store from register operations |
|-------------|------|------------------------------|

## References

https://www.kernel.org/doc/html/v6.4/bpf/instruction-set.html#id3