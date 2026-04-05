## 1. Dissambled eBPF instruction architecture.

`70: (61) r2 = *(u32 *) (r3 +8)`

- 70: = Program counter(line number)
- 61 = Opcode
- r2 = *(u32 *) (r3 +8) = Pseudo-C representation. (for human readability)

## 2. Breaking down the opcode

`70: (61) r2 = *(u32 *) (r3 +8)`

- To read the opcode, we need to convert the hex value to binary.
- Trick, if you have radare2
    - rax2 Bx61

0x61 = 1100001b

- Now:
    - class = 0x001

So it's a load and store group opcode, and it follows 3-2-3 architecture.

- class = 0x001
- size = 0x00
- mode = 0x011

### 2.1 Identify the class

- Class 0x001 = `BPF_LDX`
    - meaning = load into register operations

### 2.2 Identify the size

- Size 0x00 = `BPF_W`
    - word(4 bytes)

### 2.3 Identify the mode

This one little bit different than size or class. So if we need to get real value, we should follow these steps.

1. fill rest of the bytes with zeroes
    - 011 = 01100000b

2. Now convert back to hex. `rax2 01100000b`
    - 01100000b = 0x60

so now we have mode.
- 0x60 = `BPF_MEM`
    - regular load and store operations
