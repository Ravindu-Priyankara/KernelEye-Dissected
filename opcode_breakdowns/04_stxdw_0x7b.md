# Why memcpy didn’t behave like I expected in eBPF

When I manually calculate the connect probe stack in KernelEye v1.1. I saw something unexpected on the stack. That's a memory copy for an IPv6 address; it takes two 8-byte values from the stack.

- ipv6 = 16 bytes
    - `__u8 ipv6[16];`

So I thought eBPF __builtin_memcpy also behaves like userland memcpy. Because userland memcpy does a vectorized instructions (SSE/AVX), not stack usage.

## digging to the root cause

This is what grabs my attention.

<img src="./images/memcpy_0x7b.png">

So lets analyse one by one.

### 1. Load first 32-bit. chunks

- `70: (61) r2 = *(32 *) (r3 +8)`
- `71: (61) r4 = *(32 *) (r3 +12)`

- opcode:
    - 61
        - BPF_LDX | BPF_W | BPF_MEM
    - meaning:
        - Load the destination register with a 32-bit (Word) value from the memory address (source + offset).

- High-level explanation:
    - IPV6 address is 16 bytes.
    - So the R2 register holds 4 bytes of value from IPV6.
    - The R4 register holds 4 bytes of value from IPV6.
    - So that's a total of 8 bytes and its first half of the IPV6 address.

### 2. Build first 64-bit value

#### 2.1 bitwise shifting

`72: (67) r4 << 32`

- opcode:
    - 67
        - BPF_ALU64 | BPF_K | BPF_LSH
    - meaning:
        - 64-bit wide operand uses 32-bit imm values as source operand and does a bitwise left shift.

- High-level explanation
    - Total operand size is 64 bits.
    - The lower 32 bits are first loaded into r4, then shifted left by 32 bits to occupy the upper half of the register.
    - After that, the lower 32 bits from r2 are combined using a bitwise OR to reconstruct the full 64-bit value.

- Drawing:

Before shift

```
|=======================================|
|Upper 32-bit(empty)| Lower 32 bit(DATA)|
|-------------------|-------------------|
| 00 | 00 | 00 | 00 | RA | VI | ND | UP |
|=======================================|
```

After shift

```
|=======================================|
|Upper 32-bit(DATA) |Lower 32 bit(EMPTY)|
|-------------------|-------------------|
| RA | VI | ND | UP | 00 | 00 | 00 | 00 |
|=======================================|

This reconstructs a full 64-bit value from two 32-bit chunks.
```

#### 2.2 bitwise OR

`73: (4f) r4 |= r2`

- opcode:
    - 4f 
        - BPF_ALU64 | BPF_X | BPF_OR
    - meaning:
        - 64 bit wide operand use source register value as source operand to perform bitwise OR operand.

- High-Level Explanation:
    - Total operand size is 64 bits.
    - Moves R4 register lower 32 bits to r2 32 bits value

- Drawing:

R2 register

```
|=======================================|
|             R2 Register               |
|-------------------|-------------------|
| Upper 32 bits     | Lower 32 bits     |
|-------------------|-------------------|
| 00 | 00 | 00 | 00 | RI | YA | NK | AR |
|===================|===================|
```

R4 register

```
|=======================================|
|             R4 Register               |
|-------------------|-------------------|
| Upper 32 bits     | Lower 32 bits     |
|-------------------|-------------------|
| RA | VI | ND | UP | 00 | 00 | 00 | 00 |
|===================|===================|
```

After Bitwise OR
```
|=======================================|
|             R4 Register               |
|-------------------|-------------------|
| Upper 32 bits     | Lower 32 bits     |
|-------------------|-------------------|
| RA | VI | ND | UP | RI | YA | NK | AR |
|===================|===================|
```
### 3. Repeat for remaining 8 bytes

- The same pattern repeats for the second half of the IPv6 address:
    - Load two more 32-bit chunks
    - Shift one into upper 32 bits
    - Combine using OR to form the second 64-bit value

### 4. Set the flag

- `78: (b4) w2 = 2`

- opcode:
    - b4:
        - BPF_ALU | BPF_K | BPF_MOV
    - meaning:
        - 32-bit arithmetic operation uses a 32-bit imm value to move the destination register to the source value.

- High-Level Explanation:
    - r2 register 32-bit register is w2.
    - FAMILY_IPV6 = 2 {defined in: KernelEye/core/common/common_sockets.h}
    - To w2 register assign value 2.

- Drawing:

```
|===========================================|
|               W2 register                 |
|-------------------------------------------|
| 1st byte | 2nd byte | 3rd byte | 4th byte |
|----------|----------|----------|----------|
| 00000000 | 00000000 | 00000000 | 00000010 |
|===========================================|

Value: 2 (0x02)

Note:
- This is a logical register representation (MSB → LSB)
- In memory (little-endian), it is stored as:
  00000010 00000000 00000000 00000000
```
#### 4.1 partial write

- `79: (6b) *(u16 *)(r10 -80) = r2`

- opcode:
    - 6b:
        - BPF_STX | BPF_H | BPF_MEM
    - meaning:
        - Take 2 bytes of data from a register and store it in memory.

- High-Level explanation:
    - Writes the lower 16 bits of r2 into the stack at r10 - 80.

```
r2 (lower 16 bits used):
| ........ | 00000000 00000010 |

Memory (r10 - 80):
| 00000010 00000000 |   <- little-endian
```

### 5. Final Stack Write

- `80: (7b) *(u64 *)(r10 -72) = r3`
- `81: (7b) *(u64 *)(r10 -64) = r4`

- opcode:
    - 7b
        - BPF_STX | BPF_DW | BPF_MEM
    - meaning:
        - Take 8 bytes of data from a register and store it in memory.

- High-level explanation:
    - Write the IPv6 address's first 8 bytes into stack r10 -64.
    - Write the IPv6 address's second 8 bytes into stack r10 -72.

- Note:
    - IPv6 first 8 byte = Network Prefix
    - IPv6 second 8 byte = Interface ID

- Drawing:

```
Stack (r10 - offset)
|---------------------------------|
|r10 - 64  |  IPv6 first 8 bytes  |
|          |----------------------|
|r10 - 72  |  IPv6 second 8 bytes |
|---------------------------------|
```

## Final Note

What I learned is that `__builtin_memcpy` in eBPF **does not behave like userland `memcpy` at all**. Instead of a fast, vectorized copy, it performs explicit, step-by-step register loads, shifts, and stack writes.

Starting from a simple question—why does memcpy use the stack?—I ended up exploring the **instruction-level behavior** of eBPF. This is a good reminder: in kernel space, “simple” memory operations are anything but simple. Understanding these details is key to writing correct and efficient eBPF programs.



## Reference

- https://www.rfc-editor.org/rfc/rfc9669.html
- https://www.kernel.org/doc/html/v6.4/bpf/instruction-set.html
