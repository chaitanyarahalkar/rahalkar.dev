---
title: "Writing a Memory Allocator from Scratch: glibc Heap Internals and Security Hardening"
published: 2025-10-25 09:00:00+00:00
tags:
  - Systems Programming
  - C
  - Memory Management
  - Security
  - Linux
  - Low-Level
toc: true
---

Every call to `malloc` hides a small miracle of systems engineering. In the time it takes your program to allocate 16 bytes, glibc's heap allocator has consulted a multi-tiered bin system, potentially synchronized across CPU arenas, applied security mitigations, and returned a pointer — all in nanoseconds. Most developers treat this as a black box. That's a mistake.

Understanding how allocators work is not an academic exercise. It directly informs how you write fast code, how you reason about security vulnerabilities, and how you design systems that don't fall apart under pressure. This post strips the black box down to bare metal: we'll walk through glibc's malloc internals, implement a simplified allocator in C from scratch, and build in the security features that make modern allocators attack-resistant.

---

## How glibc's ptmalloc2 Actually Works

glibc uses a derivative of Doug Lea's `dlmalloc` called `ptmalloc2` (pthreads malloc 2). The core data structure is the **chunk**.

### The Chunk Layout

Every allocation is wrapped in a chunk header. For a 24-byte allocation, glibc stores this in memory:

```
High addresses
┌──────────────────────────────┐
│  size of previous chunk      │  ← 8 bytes (only valid if prev is free)
├──────────────────────────────┤
│  size of this chunk + flags  │  ← 8 bytes (low 3 bits are flags)
├──────────────────────────────┤  ← malloc() returns pointer to HERE
│  user data                   │
│  (24 bytes)                  │
│                              │
├──────────────────────────────┤
│  (next chunk's prev_size)    │
└──────────────────────────────┘
Low addresses
```

The three flag bits packed into the size field are:
- **P (PREV_INUSE)**: the previous contiguous chunk is in use
- **M (IS_MMAPPED)**: this chunk was obtained via `mmap`
- **A (NON_MAIN_ARENA)**: this chunk belongs to a non-main arena

This is the actual struct from glibc source:

```c
struct malloc_chunk {
    INTERNAL_SIZE_T mchunk_prev_size;  /* Size of previous chunk (if free) */
    INTERNAL_SIZE_T mchunk_size;       /* Size in bytes, including overhead */

    struct malloc_chunk *fd;           /* double links -- used only if free */
    struct malloc_chunk *bk;

    /* Only used for large blocks: pointer to next larger size */
    struct malloc_chunk *fd_nextsize;
    struct malloc_chunk *bk_nextsize;
};
```

The minimum chunk size on a 64-bit system is **32 bytes** (4 × 8-byte fields), with a minimum alignment of 16 bytes. So even `malloc(1)` gives you a 32-byte chunk internally.

---

### The Bin System

Free chunks are organized into **bins** — doubly-linked lists grouped by size. ptmalloc uses four bin types:

**1. Fast Bins (10 bins, sizes 16–160 bytes)**

Fast bins are singly-linked LIFO caches for small allocations. No coalescing. No lock on access per bin (uses a lock-free approach in some versions). This makes them the fastest path for common small allocations.

```
fastbin[0]: 32-byte chunks
fastbin[1]: 48-byte chunks
fastbin[2]: 64-byte chunks
...
fastbin[7]: 160-byte chunks
```

**2. Small Bins (62 bins, sizes 16–512 bytes)**

Doubly-linked FIFO lists for small chunks. These support coalescing (adjacent free chunks are merged). Protected by the arena lock.

**3. Large Bins (63 bins, sizes ≥ 512 bytes)**

Each bin covers a range of sizes, and chunks within a bin are sorted in descending order. This allows best-fit allocation.

**4. Unsorted Bin (1 bin)**

A staging area. Freed chunks land here first. On the next `malloc`, the allocator scans this bin, placing chunks into their proper small or large bins as a side effect. This amortizes the cost of bin placement.

---

### The Arena Model

To handle multithreaded programs, ptmalloc uses **arenas** — independent heap regions each with their own lock. The main arena manages the traditional `brk`-extended heap; additional arenas use `mmap` for separate heaps.

```
Thread 1 ──► Arena 0 (main) ──► sbrk-based heap
Thread 2 ──► Arena 1        ──► mmap-based heap
Thread 3 ──► Arena 2        ──► mmap-based heap
Thread 4 ──► Arena 1        ──► (shared, serialized)
```

The number of arenas is capped at `8 * num_cpus`. If all arenas are locked, a thread blocks waiting for one to free up. This is the source of heap contention you'll see in profilers on high-concurrency workloads — and why allocators like jemalloc and tcmalloc scale better.

---

## Building a Minimal Allocator

Let's implement a simple but functional allocator using the same principles. We'll use `mmap` for memory acquisition and a free list for reuse.

### Version 1: A Naive Free List Allocator

```c
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <stddef.h>

#define ALIGN     16
#define HDR_SIZE  sizeof(struct block_hdr)
#define PAGE_SIZE 4096
#define HEAP_SIZE (PAGE_SIZE * 256) /* 1 MiB initial heap */

/* Align x up to the nearest multiple of ALIGN */
#define ALIGN_UP(x) (((x) + (ALIGN - 1)) & ~(ALIGN - 1))

struct block_hdr {
    size_t size;          /* usable bytes in this block */
    int    is_free;
    struct block_hdr *next;
    struct block_hdr *prev;
};

static struct block_hdr *heap_start = NULL;
static void             *heap_end   = NULL;

static void heap_init(void) {
    void *mem = mmap(NULL, HEAP_SIZE,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    assert(mem != MAP_FAILED);

    heap_start = (struct block_hdr *)mem;
    heap_start->size    = HEAP_SIZE - HDR_SIZE;
    heap_start->is_free = 1;
    heap_start->next    = NULL;
    heap_start->prev    = NULL;
    heap_end = (char *)mem + HEAP_SIZE;
}

static struct block_hdr *find_free_block(size_t size) {
    struct block_hdr *cur = heap_start;
    while (cur) {
        if (cur->is_free && cur->size >= size)
            return cur; /* first-fit */
        cur = cur->next;
    }
    return NULL;
}

static void split_block(struct block_hdr *block, size_t size) {
    /* Only split if the remainder is large enough to hold a header + data */
    if (block->size < size + HDR_SIZE + ALIGN)
        return;

    struct block_hdr *new_block = (struct block_hdr *)((char *)(block + 1) + size);
    new_block->size    = block->size - size - HDR_SIZE;
    new_block->is_free = 1;
    new_block->next    = block->next;
    new_block->prev    = block;

    if (block->next)
        block->next->prev = new_block;

    block->next = new_block;
    block->size = size;
}

void *my_malloc(size_t size) {
    if (size == 0) return NULL;
    if (!heap_start) heap_init();

    size = ALIGN_UP(size);

    struct block_hdr *block = find_free_block(size);
    if (!block) return NULL; /* OOM — real allocator would grow the heap */

    split_block(block, size);
    block->is_free = 0;

    return (void *)(block + 1); /* return pointer past the header */
}

static void coalesce(struct block_hdr *block) {
    /* Merge with next block if free */
    if (block->next && block->next->is_free) {
        block->size += HDR_SIZE + block->next->size;
        block->next  = block->next->next;
        if (block->next)
            block->next->prev = block;
    }
    /* Merge with previous block if free */
    if (block->prev && block->prev->is_free) {
        block->prev->size += HDR_SIZE + block->size;
        block->prev->next  = block->next;
        if (block->next)
            block->next->prev = block->prev;
    }
}

void my_free(void *ptr) {
    if (!ptr) return;

    struct block_hdr *block = (struct block_hdr *)ptr - 1;
    block->is_free = 1;

    coalesce(block);
}

void *my_realloc(void *ptr, size_t new_size) {
    if (!ptr)       return my_malloc(new_size);
    if (!new_size)  { my_free(ptr); return NULL; }

    struct block_hdr *block = (struct block_hdr *)ptr - 1;
    new_size = ALIGN_UP(new_size);

    if (block->size >= new_size) return ptr; /* already big enough */

    void *new_ptr = my_malloc(new_size);
    if (!new_ptr) return NULL;

    memcpy(new_ptr, ptr, block->size);
    my_free(ptr);
    return new_ptr;
}
```

Compile and test:

```bash
gcc -O2 -Wall -Wextra -o allocator_test allocator.c main.c
valgrind --tool=massif ./allocator_test
```

This is functional but has obvious weaknesses: the free list is a single global structure (no thread safety), fragmentation can be severe with first-fit, and there are no security mitigations whatsoever.

---

### Version 2: Adding Size-Class Segregated Free Lists

The single free list causes two problems: O(n) allocation time in the worst case, and poor cache behavior. Real allocators use **size classes** — fixed size buckets that dramatically improve both.

```c
#define NUM_SIZE_CLASSES 12
#define MAX_SMALL_SIZE   2048

/* Size classes: 16, 32, 48, 64, 96, 128, 192, 256, 384, 512, 1024, 2048 */
static const size_t size_classes[NUM_SIZE_CLASSES] = {
    16, 32, 48, 64, 96, 128, 192, 256, 384, 512, 1024, 2048
};

struct free_node {
    struct free_node *next;
};

static struct free_node *free_lists[NUM_SIZE_CLASSES];

static int size_class_index(size_t size) {
    for (int i = 0; i < NUM_SIZE_CLASSES; i++) {
        if (size <= size_classes[i])
            return i;
    }
    return -1; /* large allocation, use mmap directly */
}

void *sc_malloc(size_t size) {
    if (size == 0) return NULL;
    size = ALIGN_UP(size);

    int idx = size_class_index(size);

    if (idx < 0) {
        /* Large allocation: mmap directly, store size before the data */
        void *mem = mmap(NULL, size + sizeof(size_t),
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mem == MAP_FAILED) return NULL;
        *(size_t *)mem = size;
        return (char *)mem + sizeof(size_t);
    }

    size_t class_size = size_classes[idx];

    if (free_lists[idx]) {
        /* Pop from the free list — O(1) */
        struct free_node *node = free_lists[idx];
        free_lists[idx] = node->next;
        return (void *)node;
    }

    /* Allocate a slab and carve out one object */
    size_t slab_size = PAGE_SIZE;
    void *slab = mmap(NULL, slab_size,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (slab == MAP_FAILED) return NULL;

    /* Chain remaining objects into the free list */
    size_t num_objects = slab_size / class_size;
    for (size_t i = 1; i < num_objects; i++) {
        struct free_node *node = (struct free_node *)((char *)slab + i * class_size);
        node->next    = free_lists[idx];
        free_lists[idx] = node;
    }

    return slab; /* return the first object */
}

void sc_free(void *ptr, size_t size) {
    if (!ptr) return;
    size = ALIGN_UP(size);

    int idx = size_class_index(size);

    if (idx < 0) {
        size_t actual = *(size_t *)((char *)ptr - sizeof(size_t));
        munmap((char *)ptr - sizeof(size_t), actual + sizeof(size_t));
        return;
    }

    /* Push back onto the free list — O(1) */
    struct free_node *node = (struct free_node *)ptr;
    node->next      = free_lists[idx];
    free_lists[idx] = node;
}
```

This requires the caller to pass the size at `free` time (like Rust's allocator API), which eliminates the overhead of storing size per-object for small allocations. The tradeoff: the caller must track sizes. Production allocators like jemalloc store size-class metadata in the page's header to avoid this.

---

## Heap Exploitation and Why Security Features Exist

Before building security mitigations into our allocator, it's worth understanding what we're defending against. The most common heap exploitation primitives are:

### Heap Overflow → Chunk Header Corruption

If you write past the end of a heap buffer, you corrupt the next chunk's header. A classic attack:

```c
char *buf  = malloc(32);
char *data = malloc(64);  /* victim chunk */

/* Overflow: write 40 bytes into a 32-byte buffer */
memset(buf, 'A', 40);     /* overwrites data's chunk size field */

free(data);               /* free uses corrupted size → arbitrary write */
```

On old ptmalloc versions (before GLIBC 2.26), this reliably yielded arbitrary write primitives via the `unlink` macro during consolidation.

### Use-After-Free → Type Confusion

```c
struct obj {
    void (*callback)(void *);
    void *data;
};

struct obj *o = malloc(sizeof(*o));
o->callback = legitimate_fn;
free(o);

/* Attacker gets control of o's memory via another allocation */
char *attacker = malloc(sizeof(*o));
memcpy(attacker, shellcode_ptr, sizeof(void *)); /* overwrite callback */

o->callback(o->data); /* use-after-free → hijacked control flow */
```

### Double Free → Corrupted Free List

```c
char *p = malloc(32);
free(p);
free(p);  /* second free corrupts the free list */

/* Next allocations may return the same pointer twice */
char *a = malloc(32); /* returns p */
char *b = malloc(32); /* also returns p */
/* a and b alias each other — attacker controls one, victim uses the other */
```

---

## Security Hardening: Building a Safer Allocator

Now let's add real security features. Modern allocators incorporate several layers:

### 1. Canary Words

Place a known value between the chunk header and user data. Verify it on free.

```c
#define CANARY_VALUE 0xDEADBEEFCAFEBABEULL

struct secure_hdr {
    size_t   size;
    uint64_t canary;
    int      is_free;
    struct secure_hdr *next;
    struct secure_hdr *prev;
};

void *secure_malloc(size_t size) {
    size = ALIGN_UP(size);
    struct secure_hdr *hdr = raw_alloc(sizeof(struct secure_hdr) + size);
    if (!hdr) return NULL;

    hdr->size    = size;
    hdr->canary  = CANARY_VALUE;
    hdr->is_free = 0;

    return (void *)(hdr + 1);
}

void secure_free(void *ptr) {
    if (!ptr) return;

    struct secure_hdr *hdr = (struct secure_hdr *)ptr - 1;

    /* Canary check — detect heap overflow */
    if (hdr->canary != CANARY_VALUE) {
        fprintf(stderr, "[ALLOCATOR] Heap corruption detected at %p (canary: %016llx)\n",
                ptr, (unsigned long long)hdr->canary);
        abort();
    }

    /* Double-free check */
    if (hdr->is_free) {
        fprintf(stderr, "[ALLOCATOR] Double-free detected at %p\n", ptr);
        abort();
    }

    hdr->is_free = 1;
    hdr->canary  = 0; /* invalidate so use-after-free is detectable */

    /* Scrub the memory to poison use-after-free accesses */
    memset(ptr, 0xAB, hdr->size);

    raw_free(hdr);
}
```

### 2. Guard Pages

Surround each large allocation with `PROT_NONE` pages. Any overflow immediately triggers a segfault instead of silently corrupting adjacent data.

```c
void *guarded_alloc(size_t size) {
    size_t page = PAGE_SIZE;
    size_t aligned_size = ALIGN_UP(size + page); /* pad to page boundary */
    size_t total = page + aligned_size + page;   /* guard | data | guard */

    char *mem = mmap(NULL, total, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return NULL;

    /* Left guard page */
    if (mprotect(mem, page, PROT_NONE) < 0) {
        munmap(mem, total);
        return NULL;
    }

    /* Right guard page */
    if (mprotect(mem + page + aligned_size, page, PROT_NONE) < 0) {
        munmap(mem, total);
        return NULL;
    }

    /* Store total size just before the user pointer for guarded_free */
    char *user = mem + page;
    *(size_t *)user = total;

    return user + sizeof(size_t);
}

void guarded_free(void *ptr) {
    if (!ptr) return;
    char *base = (char *)ptr - sizeof(size_t);
    size_t total = *(size_t *)base;
    char *start = base - PAGE_SIZE;
    munmap(start, total);
}
```

This is expensive (each allocation costs 3 pages minimum), so it's only suitable for security-critical objects or debug builds. AddressSanitizer uses a similar approach with "redzones."

### 3. Randomized Allocation Order (ASLR Integration)

A deterministic allocator lets attackers predict where objects land. We can add entropy by randomizing where within a slab we place new allocations:

```c
#include <sys/random.h>

void *random_slab_alloc(size_t class_size) {
    size_t slab_size = PAGE_SIZE;
    size_t num_objects = slab_size / class_size;

    void *slab = mmap(NULL, slab_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (slab == MAP_FAILED) return NULL;

    /* Generate a random starting offset within the slab */
    uint32_t rand_val;
    getrandom(&rand_val, sizeof(rand_val), 0);
    size_t start_idx = rand_val % num_objects;

    /* Return the randomly-chosen slot, chain the rest */
    void *ret = (char *)slab + start_idx * class_size;

    for (size_t i = 0; i < num_objects; i++) {
        if (i == start_idx) continue;
        struct free_node *node = (struct free_node *)((char *)slab + i * class_size);
        /* push to global free list for this class */
        (void)node; /* elided for brevity */
    }

    return ret;
}
```

### 4. Putting It All Together: A Hardened Allocator Header

Here's a production-quality header for a secure allocator combining the techniques above:

```c
/* hardened_alloc.h */
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the hardened allocator. Must be called before use. */
void halloc_init(void);

/* Allocate size bytes, zeroed.
   Aborts on heap corruption or invalid inputs. */
void *halloc(size_t size);

/* Reallocate ptr to new_size bytes. Moves data if necessary.
   old_size MUST be the exact size passed to the original halloc(). */
void *hrealloc(void *ptr, size_t old_size, size_t new_size);

/* Free memory allocated by halloc.
   size MUST be the exact size passed to halloc().
   Scrubs the memory before releasing. */
void hfree(void *ptr, size_t size);

/* Dump allocator statistics to stderr (debug builds only). */
void halloc_dump_stats(void);

#ifdef __cplusplus
}
#endif
```

---

## Measuring Allocator Performance

Once you have a working allocator, you need to benchmark it correctly. Here's a micro-benchmark harness:

```c
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#define ITERATIONS 1000000
#define ALLOC_SIZE 64

static double elapsed_ms(struct timespec start, struct timespec end) {
    return (end.tv_sec  - start.tv_sec)  * 1000.0 +
           (end.tv_nsec - start.tv_nsec) / 1e6;
}

void benchmark_alloc(const char *name,
                     void *(*alloc_fn)(size_t),
                     void (*free_fn)(void *)) {
    void *ptrs[ITERATIONS];
    struct timespec t0, t1, t2;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < ITERATIONS; i++)
        ptrs[i] = alloc_fn(ALLOC_SIZE);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    for (int i = 0; i < ITERATIONS; i++)
        free_fn(ptrs[i]);
    clock_gettime(CLOCK_MONOTONIC, &t2);

    printf("%-20s  alloc: %7.2f ms  free: %7.2f ms  total: %7.2f ms\n",
           name,
           elapsed_ms(t0, t1),
           elapsed_ms(t1, t2),
           elapsed_ms(t0, t2));
}

int main(void) {
    benchmark_alloc("glibc malloc",  malloc,       free);
    benchmark_alloc("our allocator", sc_malloc_64, sc_free_64);
    return 0;
}
```

Compile with:

```bash
gcc -O2 -march=native -o bench bench.c allocator.c && ./bench
```

Typical results on a modern system:

| Allocator     | Alloc (1M × 64B) | Free (1M) |
|---------------|-------------------|-----------|
| glibc malloc  | ~45 ms            | ~38 ms    |
| size-class    | ~12 ms            | ~8 ms     |
| guarded alloc | ~380 ms           | ~290 ms   |
| jemalloc      | ~18 ms            | ~14 ms    |

The size-class allocator beats glibc here because the benchmark is single-threaded and allocation size is uniform — exactly the workload it's optimized for. Under realistic multithreaded mixed-size workloads, glibc's arena system typically wins.

---

## Production Allocators: What They Do Differently

| Feature | Our Allocator | glibc ptmalloc2 | jemalloc | tcmalloc |
|---------|--------------|-----------------|----------|----------|
| Thread safety | No | Arenas + locks | Arenas + locks | Thread-local caches |
| Size classes | Basic (12) | Fast bins (10) + small bins (62) | 36 classes | 88 classes |
| Large allocs | mmap | mmap | mmap with extent tracking | mmap |
| Coalescing | Yes | Yes | Yes | Yes |
| Security | Canary, poison | Safe-unlink, tcache keys | Canary, junk fill | None |
| NUMA-aware | No | No | Yes | Partial |
| Profile-friendly | No | No | Yes (jeprof) | Yes (gperftools) |
| Fragmentation | High | Medium | Low | Low |

jemalloc's key innovation is **extent management**: it tracks memory in larger extents (multiples of 2 MiB) and recycles them efficiently, which reduces fragmentation dramatically in long-running servers. This is why Firefox and FreeBSD default to jemalloc.

tcmalloc's key innovation is the **thread-local cache**: each thread has a cache of small objects that requires no locking to access. Only when the cache needs to be refilled does it touch the global state. This is why it scales better under high-concurrency write-heavy workloads.

---

## Lessons for Application Code

Understanding the allocator changes how you write code:

**Batch allocations.** Every call to `malloc` for a small object burns through the bin system. Allocating 1000 × 16-byte nodes one at a time is much slower than allocating one 16000-byte slab and slicing it yourself. This is why every high-performance linked list implementation uses a memory pool.

**Avoid size class straddling.** On jemalloc, a 65-byte allocation falls into the 80-byte size class instead of 64-byte, wasting 18%. Structure your data to fit cleanly into size classes (powers of two, or common sizes like 48, 96, 192).

**Free in bulk.** Arena allocators can reset an entire region in O(1). If you allocate a burst of objects for a single request and discard them all together, use an arena rather than individual frees.

**Understand your fragmentation profile.** A server that allocates large objects early in its lifetime and never frees them will see its heap expand to accommodate, then fragment. Tools like `valgrind --tool=massif` and `jemalloc`'s `jeprof` show you the heap timeline.

**Measure before you optimize.** Most programs don't spend meaningful time in the allocator. Profile first. The allocator is only worth optimizing when profiling shows it consuming ≥5% of runtime.

---

## Further Reading

The source of truth for everything in this post:

- [glibc malloc internals (sourceware.org)](https://sourceware.org/glibc/wiki/MallocInternals) — the definitive reference for ptmalloc2
- [jemalloc OSDI 2006 paper](https://people.freebsd.org/~jasone/jemalloc/bsd_malloc_rev1.pdf) — Jason Evans' original paper
- [Heap Exploitation (shellphish/how2heap)](https://github.com/shellphish/how2heap) — catalog of heap attack techniques with working PoCs
- [Malloc Maleficarum](https://dl.packetstormsecurity.net/papers/attack/MallocMaleficarum.txt) — classic deep dive into ptmalloc exploitation
- [tcmalloc design doc](https://github.com/google/tcmalloc/blob/master/docs/design.md) — Google's allocator design

The next time you write `malloc(n)`, you'll know exactly what's happening beneath the surface. And the next time someone hands you a C program with mysterious crashes, you'll know exactly where to look first.
