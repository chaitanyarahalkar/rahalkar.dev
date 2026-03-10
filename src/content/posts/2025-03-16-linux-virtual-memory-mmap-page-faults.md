---
title: "How mmap Really Works: Page Tables, Page Faults, and the Virtual Memory Machinery"
published: 2025-03-16 10:00:00+00:00
draft: false
description: "A deep dive into how Linux virtual memory actually works — from multi-level page tables and TLB mechanics to demand paging, copy-on-write, and the mmap implementation path through the kernel, with practical examples and performance analysis."
tags: ["Linux", "Kernel", "Virtual Memory", "mmap", "Page Tables", "Operating Systems", "Systems Programming", "Performance"]
series: ""
toc: true
---

Every time you call `mmap()`, `malloc()`, or even just run a program, you're interacting with one of the most intricate subsystems in the Linux kernel: the virtual memory manager. Most developers treat it as a black box — you ask for memory, you get a pointer, and things work. But understanding what happens beneath that abstraction is the difference between writing software that performs and software that thrashes.

This post walks through how Linux virtual memory actually works: how page tables translate addresses, what happens during a page fault, how copy-on-write enables efficient `fork()`, and how `mmap()` is implemented from the syscall entry point down to the page table manipulation.

---

## The Virtual Memory Abstraction

Every process in Linux sees its own flat, contiguous 64-bit address space. On x86-64 with 4-level paging, the usable virtual address space spans 256 TiB (48 bits), split between user space (lower half) and kernel space (upper half):

```
0xFFFFFFFFFFFFFFFF ┌──────────────────────────┐
                   │     Kernel Space          │
                   │  (direct map, vmalloc,    │
                   │   fixmap, modules, ...)   │
0xFFFF800000000000 ├──────────────────────────┤
                   │   Non-canonical hole      │
                   │   (addresses with bits    │
                   │    48-63 not sign-ext.)   │
0x00007FFFFFFFFFFF ├──────────────────────────┤
                   │     User Space            │
                   │  stack ↓                  │
                   │                           │
                   │  mmap region              │
                   │                           │
                   │  heap ↑ (brk)             │
                   │  .bss, .data, .text       │
0x0000000000000000 └──────────────────────────┘
```

None of this is physically contiguous. The kernel can map any virtual page to any physical frame, and most of the address space isn't mapped at all. The hardware that makes this work is the **MMU** (Memory Management Unit) and its **page tables**.

---

## Multi-Level Page Tables on x86-64

A single flat page table for a 48-bit address space would require 512 GiB of memory just for the table itself — clearly impossible. Instead, x86-64 uses a 4-level hierarchical page table (5-level with LA57, which extends to 57-bit / 128 PiB):

```
   Virtual Address (48-bit):
   ┌────────┬────────┬────────┬────────┬──────────────┐
   │ PGD    │ PUD    │ PMD    │ PTE    │ Page Offset  │
   │ [47:39]│ [38:30]│ [29:21]│ [20:12]│ [11:0]       │
   │ 9 bits │ 9 bits │ 9 bits │ 9 bits │ 12 bits      │
   └───┬────┴───┬────┴───┬────┴───┬────┴──────────────┘
       │        │        │        │
       ▼        ▼        ▼        ▼
   ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐
   │  PGD  │→│  PUD  │→│  PMD  │→│  PTE  │→ Physical Frame
   │ (512  │ │ (512  │ │ (512  │ │ (512  │   + Offset
   │entries)│ │entries)│ │entries)│ │entries)│
   └───────┘ └───────┘ └───────┘ └───────┘
       ↑
   CR3 register (per-process)
```

Each level is a 4 KiB page containing 512 entries of 8 bytes each. The walk goes:

1. **PGD** (Page Global Directory) — `CR3` points to the physical address of this table. Index bits [47:39] select one of 512 entries.
2. **PUD** (Page Upper Directory) — the PGD entry points here. Index bits [38:30] select the entry.
3. **PMD** (Page Middle Directory) — index bits [29:21].
4. **PTE** (Page Table Entry) — index bits [20:12]. The entry contains the physical frame number plus permission bits.

The final physical address is the frame number from the PTE concatenated with the 12-bit offset from the original virtual address.

Each page table entry contains flags that the hardware checks on every access:

```c
/* From arch/x86/include/asm/pgtable_types.h */
#define _PAGE_PRESENT   (1 << 0)   /* Page is in physical memory       */
#define _PAGE_RW        (1 << 1)   /* Writable                         */
#define _PAGE_USER      (1 << 2)   /* Accessible from user mode        */
#define _PAGE_PWT       (1 << 3)   /* Page-level write-through         */
#define _PAGE_PCD       (1 << 4)   /* Page-level cache disable         */
#define _PAGE_ACCESSED  (1 << 5)   /* Set by hardware on access        */
#define _PAGE_DIRTY     (1 << 6)   /* Set by hardware on write         */
#define _PAGE_PSE       (1 << 7)   /* Huge page (2MiB at PMD level)    */
#define _PAGE_GLOBAL    (1 << 8)   /* Don't flush from TLB on CR3 switch */
#define _PAGE_NX        (1UL << 63)/* No-execute                       */
```

The sparse hierarchical structure means you only allocate page table pages for regions that are actually mapped. A process with a small memory footprint might only have a handful of page table pages despite having a 128 TiB address space.

---

## The TLB: Why Page Table Walks Don't Kill Performance

Walking four levels of page tables on every memory access would be catastrophic — that's four extra memory reads for every load or store. The hardware avoids this with the **TLB** (Translation Lookaside Buffer): a small, fully-associative cache of recent virtual-to-physical translations.

```
   CPU Core
   ┌─────────────────────────────────────────┐
   │  ┌──────────┐                           │
   │  │ L1 ITLB  │  128 entries, 4-way       │
   │  │ L1 DTLB  │  64 entries, 4-way        │
   │  └────┬─────┘                           │
   │       │ miss                             │
   │  ┌────▼─────┐                           │
   │  │ L2 STLB  │  1536 entries, 12-way     │
   │  └────┬─────┘                           │
   │       │ miss                             │
   │  ┌────▼─────────────────────────────┐   │
   │  │ Hardware Page Table Walker       │   │
   │  │ (walks CR3 → PGD → PUD →        │   │
   │  │  PMD → PTE in memory/cache)      │   │
   │  └──────────────────────────────────┘   │
   └─────────────────────────────────────────┘
```

On a modern Intel CPU, the L1 DTLB has ~64 entries with 4-way associativity and a 1-cycle hit latency. The L2 STLB has ~1500 entries with ~7-cycle latency. A TLB miss that triggers a full 4-level walk can cost 20-30+ cycles (much more if the page table pages aren't in cache).

TLB management is critical for performance. Two key operations:

**Context switches** flush TLB entries (unless they're marked `_PAGE_GLOBAL`, which kernel pages are). Linux mitigates this with PCID (Process Context Identifiers) — each process gets a 12-bit tag so the CPU can keep multiple processes' translations in the TLB simultaneously.

**Huge pages** (2 MiB at PMD level, 1 GiB at PUD level) dramatically reduce TLB pressure. A single 2 MiB huge page replaces 512 regular TLB entries. This is why databases and large-memory applications see substantial performance gains from transparent huge pages (THP) or explicit `hugetlbfs`.

You can observe TLB behavior directly with `perf`:

```bash
# Count TLB misses for a process
perf stat -e dTLB-load-misses,dTLB-store-misses,iTLB-load-misses ./my_program

# Sample on TLB miss events to find hot spots
perf record -e dTLB-load-misses -g ./my_program
perf report
```

---

## Demand Paging: The Lazy Kernel

Linux is aggressively lazy about memory allocation. When you call `mmap()` or `malloc()` (which calls `brk()` or `mmap()` internally), the kernel doesn't allocate physical frames. It just creates a **VMA** (Virtual Memory Area) — a bookkeeping structure that says "this range of virtual addresses is valid." The page table entries remain empty.

Physical memory is allocated only when you actually *touch* the page, triggering a **page fault**. This is demand paging, and it's fundamental to Linux's memory efficiency.

```
malloc(1 GiB)  →  kernel creates VMA  →  0 physical pages allocated
                                          0 page table entries created

First write to   →  page fault  →  kernel allocates 1 physical frame
page at 0x7f...     (trap #14)     maps it in the page table
                                   returns to user space
                                   write instruction re-executes
```

### The Page Fault Handler

When the MMU encounters an address with no valid PTE (or a permission violation), it raises exception #14 (page fault) and the CPU transfers control to the kernel's fault handler. On x86-64, the flow is:

```
Hardware exception #14
       │
       ▼
exc_page_fault()                    /* arch/x86/mm/fault.c */
       │
       ▼
do_user_addr_fault()
       │
       ├─ Is the address in a valid VMA?
       │   NO → send SIGSEGV (segfault)
       │   YES ↓
       │
       ├─ Check VMA permissions vs. fault type
       │   (write to read-only? exec on non-exec?)
       │   VIOLATION → send SIGSEGV
       │   OK ↓
       │
       ▼
handle_mm_fault()                   /* mm/memory.c */
       │
       ├─ Walk page table levels, allocating
       │   intermediate tables as needed
       │
       ▼
handle_pte_fault()
       │
       ├─ PTE not present, no page:
       │   ├─ Anonymous VMA → do_anonymous_page()
       │   │   (allocate zeroed frame)
       │   └─ File-backed VMA → do_fault()
       │       (read page from file via ->fault())
       │
       ├─ PTE present, write fault, read-only:
       │   └─ do_wp_page() → Copy-on-Write
       │
       └─ PTE not present, swapped out:
           └─ do_swap_page()
              (read from swap, map back in)
```

The performance characteristics matter. A **minor fault** (page already in page cache, just needs PTE setup) takes ~1-2 microseconds. A **major fault** (page must be read from disk) takes milliseconds — three orders of magnitude slower. You can measure this:

```bash
# Watch page faults in real time
perf stat -e page-faults,minor-faults,major-faults ./my_program

# Or use /proc
cat /proc/self/stat | awk '{print "minor:", $10, "major:", $12}'
```

---

## Copy-on-Write: How fork() Doesn't Copy Memory

When a process calls `fork()`, the child gets a complete copy of the parent's address space. Naively copying all physical memory would be absurdly expensive for a large process. Instead, Linux uses **copy-on-write** (CoW):

1. `fork()` duplicates the parent's page tables, pointing to the **same** physical frames.
2. Both parent and child PTEs are marked **read-only**.
3. When either process writes to a shared page, a page fault occurs.
4. The fault handler (`do_wp_page()`) allocates a new frame, copies the content, updates the writing process's PTE to point to the new frame (now writable), and decrements the original frame's reference count.

```
Before fork():
  Parent PTE: [frame 0x1a3f00] RW

After fork():
  Parent PTE: [frame 0x1a3f00] RO  ←─┐
  Child  PTE: [frame 0x1a3f00] RO  ←─┘ same frame, both read-only

After parent writes:
  Parent PTE: [frame 0x2b7e00] RW  ← new frame, new copy
  Child  PTE: [frame 0x1a3f00] RW  ← original frame, now writable
                                      (refcount dropped to 1)
```

This is why `fork()` is fast even for processes with gigabytes of memory — the actual copying is deferred until writes happen, and pages that are never written (like code segments) are never copied at all.

The kernel tracks shared pages using a reference count in the `struct page` (or `struct folio` in modern kernels). The CoW fault path in `do_wp_page()` checks this count:

```c
/* Simplified from mm/memory.c */
static vm_fault_t do_wp_page(struct vm_fault *vmf)
{
    struct page *page = vmf->page;

    /* If we're the only reference, just make it writable */
    if (page_count(page) == 1) {
        /* Reuse the page - just flip the PTE to writable */
        pte = pte_mkwrite(pte_mkdirty(vmf->orig_pte));
        set_pte_at(vmf->vma->vm_mm, vmf->address, vmf->pte, pte);
        return 0;
    }

    /* Multiple references - must copy */
    new_page = alloc_page(GFP_HIGHUSER_MOVABLE);
    copy_user_highpage(new_page, page, vmf->address, vmf->vma);

    /* Set up the new PTE pointing to our private copy */
    pte = mk_pte(new_page, vmf->vma->vm_page_prot);
    pte = pte_mkwrite(pte_mkdirty(pte));
    set_pte_at(vmf->vma->vm_mm, vmf->address, vmf->pte, pte);

    /* Drop reference to old page */
    put_page(page);
    return 0;
}
```

A subtle detail: the optimization where `page_count(page) == 1` allows *reuse* of the page without copying. This commonly occurs after the other process has already CoW-faulted or exited. It's a significant optimization for `fork()`-then-`exec()` patterns.

---

## Inside mmap(): From Syscall to Page Table

Now let's trace what happens when you call `mmap()`. Here's a typical file-backed mapping:

```c
void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE, fd, 0);
```

### Step 1: Syscall Entry

The glibc wrapper issues `syscall(__NR_mmap, ...)`. The kernel entry point is `ksys_mmap_pgoff()` in `mm/mmap.c`, which calls `vm_mmap_pgoff()`, which eventually calls `do_mmap()`.

### Step 2: Find a Free Virtual Address Range

If the caller passes `NULL` for the address (the common case), the kernel must find a suitable hole in the process's address space. This is done by `get_unmapped_area()`, which walks the VMA tree (a maple tree in modern kernels, previously a red-black tree) to find a gap of the requested size.

The search respects ASLR (Address Space Layout Randomization) by adding a random offset to the starting search position:

```
Process VMA layout (maple tree):
                    ┌─────────┐
                    │  root   │
                    └────┬────┘
              ┌──────────┴──────────┐
        ┌─────┴─────┐        ┌─────┴─────┐
        │ [text seg] │        │  [stack]  │
        │ 0x400000-  │        │ 0x7ffd..  │
        │ 0x401000   │        │ -0x7fff.. │
        └────────────┘        └───────────┘
              gap here ← mmap lands in this region
```

### Step 3: Create the VMA

The kernel allocates a `struct vm_area_struct` and populates it:

```c
struct vm_area_struct {
    unsigned long vm_start;     /* Start address (inclusive) */
    unsigned long vm_end;       /* End address (exclusive)   */
    pgprot_t vm_page_prot;      /* Access permissions        */
    unsigned long vm_flags;     /* VM_READ, VM_WRITE, etc.   */
    struct file *vm_file;       /* Backing file (or NULL)    */
    unsigned long vm_pgoff;     /* Offset in file (pages)    */
    const struct vm_operations_struct *vm_ops; /* fault handlers */
    struct mm_struct *vm_mm;    /* Owning address space      */
    /* ... */
};
```

The VMA is inserted into the process's maple tree and linked to the `struct mm_struct`. At this point, **no page table entries are created and no physical memory is allocated.** The mapping is purely virtual.

### Step 4: Page Fault on First Access

When user space first reads or writes the mapped address, the MMU finds no PTE and faults. The handler walks the VMA tree, finds our VMA, and calls `do_fault()`:

For a **file-backed mapping**, this calls `vma->vm_ops->fault()` — typically the filesystem's `filemap_fault()` function — which:

1. Checks the **page cache** for the requested page.
2. If not cached, allocates a page frame and issues a read I/O to the block device.
3. Installs the PTE mapping the virtual address to the page cache page.

For a `MAP_PRIVATE` mapping, writes trigger CoW: the first write copies the page cache page into a private anonymous page.

For a `MAP_SHARED` mapping, writes go directly to the page cache and eventually to the file (via `msync()` or periodic writeback).

### Step 5: The Page Cache

The page cache is the key data structure that makes file-backed `mmap()` efficient. It's a per-file radix tree (xarray in modern kernels) that caches file contents in physical memory:

```
struct address_space (per-inode):
   ┌────────────────────────────┐
   │        xarray              │
   │  [0] → page (offset 0)    │ ← shared between all
   │  [1] → page (offset 4096) │   mappings of this file
   │  [2] → NULL (not cached)  │
   │  [3] → page (offset 12288)│
   │  ...                      │
   └────────────────────────────┘
```

Multiple processes mapping the same file share these page cache pages. This is why shared libraries (`.so` files) are memory-efficient — the code pages exist once in physical memory regardless of how many processes use them.

---

## Practical: Observing Virtual Memory in Action

Let's write a program that demonstrates demand paging and measure the costs:

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <time.h>

#define MAP_SIZE (256 * 1024 * 1024)  /* 256 MiB */
#define PAGE_SIZE 4096

static long get_minor_faults(void) {
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    return ru.ru_minflt;
}

static double elapsed_ms(struct timespec *start, struct timespec *end) {
    return (end->tv_sec - start->tv_sec) * 1000.0 +
           (end->tv_nsec - start->tv_nsec) / 1e6;
}

int main(void) {
    struct timespec t0, t1, t2;
    long faults_before, faults_after;

    /* Step 1: mmap a large anonymous region */
    clock_gettime(CLOCK_MONOTONIC, &t0);

    char *region = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("mmap(%d MiB): %.3f ms (no physical memory allocated)\n",
           MAP_SIZE / (1024*1024), elapsed_ms(&t0, &t1));

    /* Step 2: Touch every page to trigger demand paging */
    faults_before = get_minor_faults();
    clock_gettime(CLOCK_MONOTONIC, &t1);

    for (size_t i = 0; i < MAP_SIZE; i += PAGE_SIZE) {
        region[i] = 1;  /* Each write faults in one page */
    }

    clock_gettime(CLOCK_MONOTONIC, &t2);
    faults_after = get_minor_faults();

    printf("Touch all pages: %.3f ms\n", elapsed_ms(&t1, &t2));
    printf("Minor faults: %ld (expected ~%d)\n",
           faults_after - faults_before, MAP_SIZE / PAGE_SIZE);
    printf("Cost per fault: %.0f ns\n",
           elapsed_ms(&t1, &t2) * 1e6 / (faults_after - faults_before));

    /* Step 3: Touch again — no faults this time */
    faults_before = get_minor_faults();
    clock_gettime(CLOCK_MONOTONIC, &t1);

    for (size_t i = 0; i < MAP_SIZE; i += PAGE_SIZE) {
        region[i] = 2;
    }

    clock_gettime(CLOCK_MONOTONIC, &t2);
    faults_after = get_minor_faults();

    printf("Re-touch all pages: %.3f ms (faults: %ld)\n",
           elapsed_ms(&t1, &t2), faults_after - faults_before);

    munmap(region, MAP_SIZE);
    return 0;
}
```

Typical output on a modern system:

```
mmap(256 MiB): 0.012 ms (no physical memory allocated)
Touch all pages: 58.341 ms
Minor faults: 65536 (expected ~65536)
Cost per fault: 890 ns
Re-touch all pages: 4.217 ms (faults: 0)
```

The `mmap()` call itself is nearly instant — it just creates a VMA. The real work happens on first touch: 65,536 page faults, each taking ~890 ns. The second pass has zero faults and runs 14x faster because all PTEs are populated.

---

## /proc/[pid]/maps and /proc/[pid]/smaps

The kernel exposes the full VMA layout of every process via procfs. This is invaluable for understanding memory behavior:

```bash
# Show all VMAs for a process
cat /proc/self/maps
```

```
5614a3c00000-5614a3c01000 r--p 00000000 08:01 1234  /usr/bin/bash
5614a3c01000-5614a3ce0000 r-xp 00001000 08:01 1234  /usr/bin/bash
5614a3ce0000-5614a3d18000 r--p 000e0000 08:01 1234  /usr/bin/bash
5614a3d19000-5614a3d1d000 rw-p 00118000 08:01 1234  /usr/bin/bash
5614a4e00000-5614a4f60000 rw-p 00000000 00:00 0     [heap]
7f8c2a000000-7f8c2a021000 rw-p 00000000 00:00 0
7f8c2c000000-7f8c2c1f0000 r--p 00000000 08:01 5678  /usr/lib/locale/...
7f8c2c400000-7f8c2c428000 r--p 00000000 08:01 9012  /usr/lib/libc.so.6
7f8c2c428000-7f8c2c5b0000 r-xp 00028000 08:01 9012  /usr/lib/libc.so.6
7ffd3e800000-7ffd3e821000 rw-p 00000000 00:00 0     [stack]
```

Each line: `start-end permissions offset device inode pathname`. The permissions field encodes `r`ead/`w`rite/e`x`ecute and `p`rivate/`s`hared.

For detailed per-page information, `smaps` is more revealing:

```bash
cat /proc/self/smaps_rollup
```

```
Rss:               12340 kB    ← Physical memory actually used
Pss:                8920 kB    ← Proportional share (shared pages divided)
Shared_Clean:       5200 kB    ← Shared pages not written to
Shared_Dirty:          0 kB
Private_Clean:      2100 kB    ← Private pages not written to
Private_Dirty:      5040 kB    ← Private pages that were written
Referenced:        11800 kB    ← Pages accessed recently
Anonymous:          5040 kB    ← Not backed by a file
Swap:                  0 kB
```

**RSS** (Resident Set Size) counts all physical pages mapped to the process, including shared ones. **PSS** (Proportional Set Size) divides shared pages by the number of sharers — it's a more accurate measure of a process's true memory cost. If 10 processes share libc, each gets 1/10th of libc's pages counted in PSS.

---

## madvise() and Memory Hints

The kernel's default page fault and eviction policies work well for general workloads, but specific access patterns benefit from explicit hints via `madvise()`:

```c
/* Tell the kernel we'll access this region sequentially */
madvise(addr, length, MADV_SEQUENTIAL);
/* Kernel will read-ahead aggressively and free pages behind the cursor */

/* Tell the kernel we'll access randomly */
madvise(addr, length, MADV_RANDOM);
/* Disables read-ahead — each fault reads only the requested page */

/* Tell the kernel we won't need these pages anymore */
madvise(addr, length, MADV_DONTNEED);
/* Immediately unmaps pages and frees physical frames.
   Next access will re-fault (zeroed for anonymous, re-read for files) */

/* Mark pages as mergeable by KSM (Kernel Same-page Merging) */
madvise(addr, length, MADV_MERGEABLE);
/* KSM scans for identical pages and CoW-merges them */

/* Poison a page (for testing hardware error handling) */
madvise(addr, length, MADV_HWPOISON);
```

`MADV_DONTNEED` is particularly powerful for long-lived processes that want to release memory back to the system without unmapping. jemalloc and tcmalloc use this internally to return freed pages to the OS.

A common performance pitfall: streaming through a large file with `mmap()` without `MADV_SEQUENTIAL`. The default readahead policy doesn't know you're doing a linear scan, so it under-prefetches and pollutes the page cache. With `MADV_SEQUENTIAL`, throughput can improve by 2-3x on large file scans.

---

## Huge Pages and THP

Standard 4 KiB pages mean that a 2 GiB working set requires 524,288 TLB entries — far exceeding the TLB capacity, leading to constant misses and page table walks. Huge pages (2 MiB) reduce this to 1,024 entries:

```c
/* Explicit huge pages via mmap */
void *ptr = mmap(NULL, 2 * 1024 * 1024,
                 PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                 -1, 0);

/* Or use madvise to request THP for an existing mapping */
madvise(ptr, size, MADV_HUGEPAGE);
```

**Transparent Huge Pages (THP)** attempt to use huge pages automatically. The `khugepaged` kernel thread periodically scans for opportunities to collapse contiguous 4 KiB pages into 2 MiB huge pages. However, THP has known issues:

1. **Allocation latency spikes** — compacting memory to find a contiguous 2 MiB region can stall allocations.
2. **Memory waste** — a single dirty byte in a 2 MiB page prevents the entire page from being reclaimed.
3. **Inconsistent latency** — some accesses trigger collapse, others don't.

This is why many database systems (PostgreSQL, Redis, MongoDB) recommend disabling THP and using explicit `hugetlbfs` allocations instead. You get the TLB benefits without the unpredictable latency:

```bash
# Check current THP status
cat /sys/kernel/mm/transparent_hugepage/enabled
# [always] madvise never

# Disable THP system-wide
echo never > /sys/kernel/mm/transparent_hugepage/enabled

# Reserve explicit huge pages
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```

---

## Memory Overcommit and the OOM Killer

Linux overcommits memory by default. A `malloc(8 GiB)` on a machine with 4 GiB RAM succeeds — the kernel bets that you won't actually touch all of it (and for most workloads, that bet pays off). This is controlled by:

```bash
# 0 = heuristic overcommit (default — allows "reasonable" overcommit)
# 1 = always overcommit (never fail malloc)
# 2 = strict — commit limit = swap + (ram * overcommit_ratio/100)
cat /proc/sys/vm/overcommit_memory
```

When the system actually runs out of memory (all RAM and swap consumed), the **OOM killer** activates. It scores every process based on memory usage and kills the highest-scoring one:

```bash
# Check a process's OOM score
cat /proc/$(pidof my_app)/oom_score

# Protect a critical process from OOM killing
echo -1000 > /proc/$(pidof my_app)/oom_score_adj
```

The OOM score considers RSS, swap usage, whether the process is root-owned, and the `oom_score_adj` override. Understanding this is critical for production systems — you don't want the OOM killer taking out your database when a log processor leaks memory.

---

## Putting It All Together

Virtual memory is not a single feature — it's a layered system where hardware (MMU, TLB), kernel data structures (VMAs, page tables, page cache), and policy decisions (demand paging, CoW, overcommit) interact to create the illusion of isolated, contiguous address spaces:

```
Application calls mmap() / malloc()
         │
         ▼
Kernel creates VMA (bookkeeping only)
         │
         ▼ (no physical memory yet)
Application accesses the address
         │
         ▼
MMU walks page tables → no PTE → page fault
         │
         ▼
Kernel fault handler:
  ├─ Anonymous? → allocate zeroed frame
  ├─ File-backed? → load from page cache (or disk)
  └─ CoW? → copy and remap
         │
         ▼
PTE installed, TLB loaded
         │
         ▼
Instruction re-executes → works
```

The elegance is in the laziness: the kernel does the minimum work at each step and defers everything it can. Physical memory is allocated only when touched. Pages are copied only when written. File contents are read only when accessed. This pervasive laziness is what allows a Linux system to run thousands of processes with far less physical memory than their combined virtual address spaces would suggest.

Understanding this machinery lets you make informed decisions: when to use `mmap()` vs `read()`, when huge pages will help vs hurt, how to interpret `smaps` to find the real memory cost of your application, and why `fork()` is fast but touching memory afterward isn't free. The abstraction is powerful, but it performs best when you know what it's doing underneath.
