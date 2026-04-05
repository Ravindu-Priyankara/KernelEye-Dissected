# Registers

eBPF has 11 registers

| register | purpose |
|----------|---------|
| r0 | for return value |
| r1 - r5 | argument for function call |
| r6 - r9 | callee saved registers |
| r10 | stack frame pointer |
|-----|---------------------|

## references

https://www.kernel.org/doc/html/v6.4/bpf/instruction-set.html