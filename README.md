# KernelEye Dissected

> our kernel eye into what really happens

This repository documents the internal journey behind building **KernelEye** — focusing on how things actually behave inside the Linux kernel.

Instead of high-level explanations, this repo breaks down:

- eBPF bytecode and opcode-level behavior  
- Verifier decisions and silent failures  
- Stack layout, memory access, and edge cases  
- Real crashes, bugs, and debugging stories  

---

## 🎯 Purpose

Most developers use abstractions.

This repo exists to **break them**.

Each write-up starts with an assumption, follows the investigation, and ends with what the kernel was really doing underneath.

---

## What You'll Find

- **Crash investigations**  
  Real issues faced during development and how they were debugged  

- **Opcode breakdowns**  
  Understanding instructions like `0x7b (STXDW)` from raw dumps  

- **Verifier behavior**  
  Why programs fail — even when they look correct  

- **Memory & stack analysis**  
  How data actually moves inside eBPF programs  

---

## Philosophy

> If you can read the bytecode, you don’t guess — you know.

---

## 🔗 Related Project

- KernelEye — eBPF-based system visibility tool (main project)

---

## ⚠️ Note

These are not polished tutorials.  
They are **real debugging paths**, including wrong assumptions, failed attempts, and final insights.

---