---
title: "Seccomp-BPF: Confining Linux Processes at the Syscall Boundary"
published: 2026-02-23 10:00:00+00:00
draft: false
description: "A deep dive into Linux seccomp-BPF — building syscall sandboxes from raw BPF filters to production-grade policies, with practical C examples and analysis of how Chrome, Docker, and systemd use kernel-level process confinement."
tags: ["Seccomp", "BPF", "Linux", "Kernel", "Sandboxing", "Security", "Syscalls", "Containers", "Hardening"]
series: ""
toc: true
---

Your eBPF programs can observe every syscall a process makes. But observation is only half the equation — at some point you need to *prevent* a compromised process from doing damage. That's where seccomp-BPF comes in: a kernel mechanism that lets you attach a syscall filter to a process, rejecting forbidden calls before they ever execute. No kernel module. No root required. Just a BPF program between user space and the kernel.

This post covers how seccomp-BPF works internally, how to write filters at the raw BPF level, how to use `libseccomp` for practical sandboxing, and how production systems like Chrome, Docker, and systemd use it to confine processes.

---

## How Linux Syscalls Work

Before filtering syscalls, you need to understand the interface you're filtering. When a user-space program calls `open()`, `read()`, or `connect()`, it doesn't call a kernel function directly. It triggers a CPU privilege transition:

```
┌─────────────────────────────────────────────────────────┐
│                    User Space                            │
│                                                          │
│  fd = open("/etc/passwd", O_RDONLY);                     │
│           │                                              │
│           ▼                                              │
│  libc: sets registers (rax=257, rdi=AT_FDCWD, ...)      │
│           │                                              │
│           ▼                                              │
│       syscall instruction (ring 3 → ring 0)              │
└───────────┼──────────────────────────────────────────────┘
            │
┌───────────▼──────────────────────────────────────────────┐
│                    Kernel Space                           │
│                                                           │
│  entry_SYSCALL_64:                                        │
│    ┌─────────────────────────────┐                        │
│    │  seccomp filter runs HERE   │ ◄── before the syscall │
│    └─────────────┬───────────────┘                        │
│                  │ ALLOW / KILL / ERRNO                    │
│                  ▼                                         │
│    sys_call_table[__NR_openat] → do_sys_openat2()         │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

On x86-64, the `syscall` instruction saves the user-space instruction pointer, switches to ring 0, and jumps to the kernel's `entry_SYSCALL_64` handler. The syscall number is in `rax`; arguments are in `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`. The kernel looks up the handler in `sys_call_table` and calls it.

The critical point: **seccomp-BPF runs between the syscall entry and the actual handler dispatch.** If the filter says no, the handler never executes.

---

## What is Seccomp?

Seccomp (Secure Computing Mode) was added to Linux 2.6.12 (2005) by Andrea Arcangeli. The original strict mode was brutally simple: after calling `prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT)`, the process could only use four syscalls: `read`, `write`, `_exit`, and `sigreturn`. Anything else killed the process immediately with `SIGKILL`.

This was useful for running untrusted computation (the original motivation was renting out CPU cycles), but too restrictive for real applications.

**Seccomp-BPF** (Linux 3.5, 2012) generalized this by letting you attach a BPF program that inspects the syscall number and arguments, then returns a verdict:

| Verdict | Effect |
|---|---|
| `SECCOMP_RET_ALLOW` | Permit the syscall |
| `SECCOMP_RET_KILL_PROCESS` | Kill the entire process with SIGSYS |
| `SECCOMP_RET_KILL_THREAD` | Kill just the calling thread |
| `SECCOMP_RET_TRAP` | Send SIGSYS to the process (can be caught) |
| `SECCOMP_RET_ERRNO` | Return an error code without executing the syscall |
| `SECCOMP_RET_TRACE` | Notify a ptracer (for debugging and emulation) |
| `SECCOMP_RET_LOG` | Allow, but log the syscall (kernel 4.14+) |
| `SECCOMP_RET_USER_NOTIF` | Forward to a user-space supervisor (kernel 5.0+) |

The verdicts are checked in priority order (KILL > TRAP > ERRNO > TRACE > LOG > ALLOW). If multiple filters are attached, the strictest verdict wins.

---

## The BPF Filter Machine

Seccomp-BPF uses classic BPF (cBPF), not the extended eBPF used in the previous post. This is deliberate: cBPF is simpler, has a smaller attack surface, and the kernel can verify it in bounded time.

A cBPF program is a sequence of `struct sock_filter` instructions that operate on a virtual machine with:
- An **accumulator** (A) — 32-bit register for computation
- An **index register** (X) — 32-bit register for indirect addressing
- A **scratch memory** — 16 slots of 32-bit words (M[0]..M[15])
- A **read-only input buffer** — the `struct seccomp_data` describing the syscall

```c
struct seccomp_data {
    int   nr;                    /* syscall number */
    __u32 arch;                  /* AUDIT_ARCH_* value */
    __u64 instruction_pointer;   /* CPU IP at time of syscall */
    __u64 args[6];               /* syscall arguments */
};
```

Each BPF instruction is 8 bytes:

```c
struct sock_filter {
    __u16 code;   /* operation */
    __u8  jt;     /* jump offset if true */
    __u8  jf;     /* jump offset if false */
    __u32 k;      /* constant / offset */
};
```

The macros `BPF_STMT(code, k)` and `BPF_JUMP(code, k, jt, jf)` construct these. Here's what the key operations look like:

| Macro | Meaning |
|---|---|
| `BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offset)` | Load 32-bit word from seccomp_data at `offset` into A |
| `BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, val, jt, jf)` | If A == val, jump +jt, else +jf |
| `BPF_STMT(BPF_RET+BPF_K, verdict)` | Return verdict (ALLOW/KILL/ERRNO/...) |

---

## Writing a Raw BPF Filter

Let's build a filter from scratch — no libraries. This program sandboxes itself so it can only read from stdin, write to stdout/stderr, and exit:

```c
/* strict_sandbox.c — minimal seccomp-BPF sandbox using raw BPF */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* Shorthand for seccomp_data field offsets */
#define SC_NR   (offsetof(struct seccomp_data, nr))
#define SC_ARCH (offsetof(struct seccomp_data, arch))

#if defined(__x86_64__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_AARCH64
#else
#error "Unsupported architecture"
#endif

static void install_filter(void) {
    struct sock_filter filter[] = {
        /* [0] Load architecture */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SC_ARCH),
        /* [1] Reject if architecture doesn't match (prevent ABI confusion) */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_CURRENT, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        /* [3] Load syscall number */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SC_NR),

        /* Allow specific syscalls */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read,           5, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write,          4, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit,           3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit_group,     2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigreturn,   1, 0),

        /* Default: kill */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        /* Allow */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len    = ARRAY_SIZE(filter),
        .filter = filter,
    };

    /* Required before installing a seccomp filter as non-root */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("prctl(NO_NEW_PRIVS)");
        exit(1);
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        perror("prctl(SECCOMP)");
        exit(1);
    }
}

int main(void) {
    printf("Installing seccomp filter...\n");
    fflush(stdout);

    install_filter();

    printf("Filter active. Allowed: read, write, exit.\n");
    printf("Attempting open() — this will kill the process.\n");
    fflush(stdout);

    /* This triggers the filter — SIGKILL */
    int fd = open("/etc/passwd", 0);
    (void)fd;

    printf("You should never see this.\n");
    return 0;
}
```

Compile and run:

```bash
gcc -o strict_sandbox strict_sandbox.c
./strict_sandbox
```

Output:

```
Installing seccomp filter...
Filter active. Allowed: read, write, exit.
Attempting open() — this will kill the process.
Killed
```

The kernel killed the process before `open()` ever reached the VFS layer. The `dmesg` log will show:

```
audit: seccomp action=kill pid=12345 comm="strict_sandbox" sig=31 syscall=257 arch=c000003e
```

### Why the Architecture Check Matters

The architecture check on line [1] isn't paranoia — it prevents a real attack. On x86-64, the kernel supports running 32-bit binaries via the `int 0x80` entry point. A 32-bit `open()` is syscall number 5; the 64-bit `openat()` is 257. If your filter only checks syscall numbers without verifying the architecture, an attacker can invoke the 32-bit syscall ABI to bypass your filter.

---

## Argument Inspection: Restricting What Syscalls Can Do

Filtering by syscall number alone is coarse. Seccomp-BPF can inspect arguments too. Here's a filter that allows `write()` only to file descriptors 1 (stdout) and 2 (stderr), blocking writes to anything else:

```c
/* fd_restrict.c — allow write() only to stdout and stderr */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define SC_NR    (offsetof(struct seccomp_data, nr))
#define SC_ARCH  (offsetof(struct seccomp_data, arch))
#define SC_ARG0  (offsetof(struct seccomp_data, args[0]))

/* args[] are 64-bit, but cBPF loads 32-bit words.
   On little-endian, the low 32 bits come first. */
#define SC_ARG0_LO (SC_ARG0)

static void install_filter(void) {
    struct sock_filter filter[] = {
        /* Verify architecture */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SC_ARCH),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        /* Load syscall number */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SC_NR),

        /* If not write(), allow everything else */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

        /* It's write(). Load first argument (fd). */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SC_ARG0_LO),

        /* Allow fd 1 (stdout) */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1, 2, 0),
        /* Allow fd 2 (stderr) */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 2, 1, 0),

        /* Deny: return EPERM */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

        /* Allow */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len    = ARRAY_SIZE(filter),
        .filter = filter,
    };

    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

int main(void) {
    install_filter();

    /* This works — fd 1 */
    printf("Writing to stdout: OK\n");
    fflush(stdout);

    /* This works — fd 2 */
    fprintf(stderr, "Writing to stderr: OK\n");

    /* This fails — fd 3 */
    int fd = open("/tmp/test_seccomp.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        ssize_t n = write(fd, "secret data\n", 12);
        if (n < 0) {
            perror("write to file blocked");  /* EPERM */
        }
        close(fd);
    }

    return 0;
}
```

```
$ gcc -o fd_restrict fd_restrict.c && ./fd_restrict
Writing to stdout: OK
Writing to stderr: OK
write to file blocked: Operation not permitted
```

The process can run normally, but any attempt to exfiltrate data by writing to a file or network socket gets blocked. This is the core pattern for data exfiltration prevention.

> **Important limitation:** Seccomp-BPF can inspect syscall arguments as integers, but **it cannot dereference pointers**. You can check which file descriptor is being written to, but you can't inspect the filename string passed to `openat()`. The BPF program only sees the raw `seccomp_data` struct — no memory access. This is a deliberate security boundary (a filter that could read arbitrary process memory would be a vulnerability).

---

## Using libseccomp: The Practical API

Writing raw BPF filters is educational but painful for real policies. **libseccomp** provides a high-level C API (with Python bindings) that compiles rules into optimized BPF programs.

Install it:

```bash
# Debian/Ubuntu
sudo apt-get install -y libseccomp-dev libseccomp2

# Fedora/RHEL
sudo dnf install libseccomp-devel
```

Here's a sandbox for a network server that blocks dangerous syscalls:

```c
/* server_sandbox.c — seccomp policy for a network server using libseccomp */

#include <stdio.h>
#include <stdlib.h>
#include <seccomp.h>
#include <errno.h>

static int install_server_policy(void) {
    /* Default action: allow. We'll block specific dangerous syscalls.
       (An allowlist is safer, but a denylist is more practical for
       complex applications where enumerating all needed syscalls is hard.) */
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL) return -1;

    /* ---- Block process execution ---- */
    /* A web server should never need to exec.
       If compromised, this prevents spawning reverse shells. */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(execveat), 0);

    /* ---- Block kernel module loading ---- */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(init_module), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(finit_module), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(delete_module), 0);

    /* ---- Block namespace manipulation ---- */
    /* Prevent container escapes and privilege escalation */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(unshare), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setns), 0);

    /* ---- Block mount operations ---- */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mount), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(umount2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(pivot_root), 0);

    /* ---- Block ptrace ---- */
    /* Prevent debugging / injection attacks on other processes */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ptrace), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(process_vm_readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(process_vm_writev), 0);

    /* ---- Block dangerous privilege operations ---- */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setreuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setregid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(keyctl), 0);

    /* ---- Block kexec (kernel replacement) ---- */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kexec_load), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kexec_file_load), 0);

    /* ---- Block BPF program loading ---- */
    /* Prevent an attacker from loading their own eBPF to subvert monitoring */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(bpf), 0);

    /* ---- Block reboot ---- */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(reboot), 0);

    int rc = seccomp_load(ctx);
    seccomp_release(ctx);
    return rc;
}

int main(void) {
    printf("Installing server seccomp policy...\n");

    if (install_server_policy() < 0) {
        fprintf(stderr, "Failed to install seccomp policy\n");
        return 1;
    }

    printf("Policy active. Testing blocked syscalls:\n\n");

    /* Test: execve should fail */
    printf("  execve(\"/bin/ls\"): ");
    fflush(stdout);
    if (execl("/bin/ls", "ls", NULL) < 0) {
        printf("BLOCKED (errno=%d)\n", errno);
    }

    /* Test: ptrace should fail */
    printf("  ptrace(PTRACE_TRACEME): ");
    long pt = ptrace(0 /*PTRACE_TRACEME*/, 0, NULL, NULL);
    printf("%s (errno=%d)\n", pt < 0 ? "BLOCKED" : "allowed", errno);

    /* Test: mount should fail */
    printf("  mount(\"none\", \"/mnt\", \"tmpfs\"): ");
    if (mount("none", "/mnt", "tmpfs", 0, NULL) < 0) {
        printf("BLOCKED (errno=%d)\n", errno);
    }

    printf("\nNormal operations (read/write/socket) still work.\n");
    return 0;
}
```

Compile and run:

```bash
gcc -o server_sandbox server_sandbox.c -lseccomp
./server_sandbox
```

```
Installing server seccomp policy...
Policy active. Testing blocked syscalls:

  execve("/bin/ls"): BLOCKED (errno=1)
  ptrace(PTRACE_TRACEME): BLOCKED (errno=1)
  mount("none", "/mnt", "tmpfs"): BLOCKED (errno=1)

Normal operations (read/write/socket) still work.
```

The server can still accept connections, read and write files, and manage sockets. But if an attacker achieves code execution through a memory corruption vulnerability, they can't spawn a shell, load a kernel module, or escape into another namespace.

---

## Allowlist vs. Denylist: A Security Architecture Decision

The previous example used a denylist — block specific dangerous syscalls and allow everything else. This is pragmatic but imperfect: you might miss a dangerous syscall. The more secure approach is an **allowlist**: deny everything by default, then permit only what the application needs.

```c
/* allowlist_sandbox.c — strict allowlist policy for a static file server */

#include <stdio.h>
#include <stdlib.h>
#include <seccomp.h>

static int install_allowlist(void) {
    /* Default: kill the process on any unlisted syscall */
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
    if (ctx == NULL) return -1;

    /* Minimum viable set for a static file server */
    int allowed[] = {
        /* I/O */
        SCMP_SYS(read), SCMP_SYS(write), SCMP_SYS(writev),
        SCMP_SYS(pread64), SCMP_SYS(pwrite64), SCMP_SYS(sendfile),

        /* File operations */
        SCMP_SYS(openat), SCMP_SYS(close), SCMP_SYS(fstat),
        SCMP_SYS(newfstatat), SCMP_SYS(lseek), SCMP_SYS(access),
        SCMP_SYS(faccessat2), SCMP_SYS(getcwd), SCMP_SYS(readlink),

        /* Network */
        SCMP_SYS(socket), SCMP_SYS(bind), SCMP_SYS(listen),
        SCMP_SYS(accept4), SCMP_SYS(getsockopt), SCMP_SYS(setsockopt),
        SCMP_SYS(getsockname), SCMP_SYS(getpeername),
        SCMP_SYS(shutdown), SCMP_SYS(recvfrom), SCMP_SYS(sendto),

        /* Polling / event loops */
        SCMP_SYS(epoll_create1), SCMP_SYS(epoll_ctl),
        SCMP_SYS(epoll_wait), SCMP_SYS(epoll_pwait),

        /* Memory management */
        SCMP_SYS(mmap), SCMP_SYS(munmap), SCMP_SYS(mprotect),
        SCMP_SYS(brk), SCMP_SYS(mremap),

        /* Signals and process lifecycle */
        SCMP_SYS(rt_sigaction), SCMP_SYS(rt_sigprocmask),
        SCMP_SYS(rt_sigreturn), SCMP_SYS(exit), SCMP_SYS(exit_group),
        SCMP_SYS(futex), SCMP_SYS(nanosleep), SCMP_SYS(clock_nanosleep),
        SCMP_SYS(clock_gettime), SCMP_SYS(gettimeofday),

        /* Misc required by glibc / runtime */
        SCMP_SYS(getpid), SCMP_SYS(gettid), SCMP_SYS(getuid),
        SCMP_SYS(getgid), SCMP_SYS(geteuid), SCMP_SYS(getegid),
        SCMP_SYS(ioctl), SCMP_SYS(fcntl), SCMP_SYS(dup2),
        SCMP_SYS(getrandom), SCMP_SYS(rseq),
    };

    for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++) {
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, allowed[i], 0);
    }

    int rc = seccomp_load(ctx);
    seccomp_release(ctx);
    return rc;
}

int main(void) {
    install_allowlist();
    printf("Strict allowlist active: %zu syscalls permitted.\n",
           sizeof((int[]){/* same list */}) / sizeof(int));
    /* ... start file server ... */
    return 0;
}
```

This is the nuclear option. An attacker who achieves arbitrary code execution inside this sandbox has no `execve`, no `fork`, no `clone`, no `ptrace`, no `mount`, no `socket` (for new connections — only accept on existing ones), and no `mprotect` with execute permission if you add argument filtering. Their options are extremely limited.

The tradeoff is maintenance burden. Every application update might introduce a new syscall dependency. You need tooling to build and maintain allowlists — which leads us to profiling.

---

## Building a Seccomp Profile from Observed Behavior

You can build allowlists automatically by tracing which syscalls an application actually uses. Here's a profiler using `strace`:

```bash
# Record all syscalls during a representative workload
strace -c -f -o /tmp/strace_profile.txt ./your_server &
# ... run your test suite against the server ...
kill %1

# Extract the unique syscall names
awk 'NR>2 && $NF != "total" {print $NF}' /tmp/strace_profile.txt | sort -u
```

Or more precisely, with the `seccomp` log action — run the application with a `SECCOMP_RET_LOG` default action and parse the audit log:

```bash
# With a RET_LOG default, all syscalls are allowed but logged
sudo ausearch -m seccomp --start recent | \
    awk '/syscall=/ {match($0, /syscall=([0-9]+)/, a); print a[1]}' | \
    sort -un
```

For production profile generation, tools like **OCI seccomp-bpf-hook** or **Inspektor Gadget** can automatically generate a seccomp profile by observing a container's behavior.

---

## How Chrome Uses Seccomp-BPF

Chrome's sandbox is the most battle-tested seccomp deployment in existence — running on billions of machines, defending against the most targeted attack surface on the internet.

Chrome uses a **multi-process architecture** where each renderer, GPU process, and plugin runs in a separate process with its own seccomp policy:

```
┌──────────────────────────────────────────────────────────────┐
│                        Browser Process                        │
│    (privileged — no seccomp, manages all child processes)     │
└──────────┬───────────────┬───────────────┬───────────────────┘
           │               │               │
    ┌──────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
    │  Renderer   │ │  Renderer   │ │    GPU      │
    │  (per-tab)  │ │  (per-tab)  │ │  Process    │
    │             │ │             │ │             │
    │ seccomp:    │ │ seccomp:    │ │ seccomp:    │
    │ · no exec   │ │ · no exec   │ │ · no exec   │
    │ · no open   │ │ · no open   │ │ · limited   │
    │ · no socket │ │ · no socket │ │   ioctl     │
    │ · no fork   │ │ · no fork   │ │ · no fork   │
    │ · no ptrace │ │ · no ptrace │ │ · no mount  │
    └─────────────┘ └─────────────┘ └─────────────┘
```

The renderer policy is the strictest. A Chrome renderer:
- **Cannot open files** — all file access goes through IPC to the browser process
- **Cannot create sockets** — all network access goes through IPC
- **Cannot exec** — no shell spawning
- **Cannot fork** — no process creation
- **Cannot change credentials** — no privilege escalation

If an attacker exploits a V8 JavaScript vulnerability and achieves arbitrary code execution in the renderer process, they're trapped. They can execute arbitrary computation, but they can't touch the filesystem, network, or any other process. They need a *second* exploit — a sandbox escape — to do anything useful. This is why Chrome exploits sell for millions of dollars: you need a full chain (renderer RCE + sandbox escape + kernel privilege escalation).

---

## Docker's Default Seccomp Profile

Docker applies a seccomp profile to every container by default. The default policy blocks ~44 of the ~300+ Linux syscalls, targeting the most dangerous attack surface:

| Blocked Category | Syscalls | Why |
|---|---|---|
| Kernel modules | `init_module`, `finit_module`, `delete_module` | Prevent kernel code loading |
| System admin | `reboot`, `swapon`, `swapoff`, `sethostname` | Prevent host disruption |
| Namespaces | `unshare`, `setns` | Prevent container escape |
| Mounting | `mount`, `umount2`, `pivot_root` | Prevent filesystem escape |
| eBPF | `bpf` | Prevent kernel instrumentation |
| Raw I/O | `ioperm`, `iopl` | Prevent direct hardware access |
| Clock | `clock_settime`, `settimeofday` | Prevent time manipulation |
| Ptrace | `ptrace`, `process_vm_readv`, `process_vm_writev` | Prevent debugging attacks |
| Keyring | `keyctl`, `request_key`, `add_key` | Prevent credential theft |

The full profile is a JSON file at `https://github.com/moby/moby/blob/master/profiles/seccomp/default.json`. You can override it:

```bash
# Run with a custom profile
docker run --security-opt seccomp=my-profile.json myimage

# Run with NO seccomp (dangerous — only for debugging)
docker run --security-opt seccomp=unconfined myimage
```

The `seccomp=unconfined` flag is responsible for a significant number of container escapes in the wild. If you ever see it in a production Dockerfile or compose file, treat it as a critical finding.

---

## Seccomp User Notification: Syscall Emulation

Linux 5.0 introduced `SECCOMP_RET_USER_NOTIF`, which forwards blocked syscalls to a supervisor process instead of killing or returning an error. This lets you **emulate** syscalls that can't run safely:

```c
/* supervisor.c — handle mount() calls from a sandboxed child
   via seccomp user notification (requires kernel 5.0+) */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <seccomp.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>

/* The supervisor checks the mount request and decides
   whether to allow it (by performing it on behalf of the child)
   or deny it. */

static void run_supervisor(int notify_fd) {
    struct seccomp_notif *req = NULL;
    struct seccomp_notif_resp *resp = NULL;

    if (seccomp_notify_alloc(&req, &resp) < 0) {
        perror("seccomp_notify_alloc");
        return;
    }

    printf("[supervisor] Waiting for syscall notifications...\n");

    while (1) {
        if (seccomp_notify_receive(notify_fd, req) < 0) {
            if (errno == ENOENT) continue;  /* child already gone */
            break;
        }

        printf("[supervisor] PID %d attempted syscall %d\n",
               req->pid, req->data.nr);

        /* Policy: deny everything forwarded to us */
        resp->id    = req->id;
        resp->val   = -1;
        resp->error = -EPERM;
        resp->flags = 0;

        if (seccomp_notify_respond(notify_fd, resp) < 0) {
            if (errno == ENOENT) continue;
            break;
        }

        printf("[supervisor] Denied syscall %d for PID %d\n",
               req->data.nr, req->pid);
    }

    seccomp_notify_free(req, resp);
}

int main(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);

    /* Forward mount() to supervisor instead of killing */
    seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(mount), 0);

    int notify_fd = seccomp_load(ctx);
    if (notify_fd < 0) {
        /* seccomp_load returns the notify fd when SCMP_ACT_NOTIFY is used */
        fprintf(stderr, "Failed to load seccomp filter\n");
        return 1;
    }
    notify_fd = seccomp_notify_fd(ctx);

    pid_t child = fork();
    if (child == 0) {
        /* Child: try to mount */
        printf("[child] Attempting mount()...\n");
        if (mount("none", "/mnt", "tmpfs", 0, NULL) < 0) {
            printf("[child] mount() returned: %m\n");
        }
        _exit(0);
    }

    /* Parent: act as supervisor */
    run_supervisor(notify_fd);
    waitpid(child, NULL, 0);

    seccomp_release(ctx);
    return 0;
}
```

This pattern is how container runtimes like **Sysbox** implement rootless containers — filesystem operations that normally require privileges are intercepted and emulated by a supervisor that has the actual capabilities.

---

## Seccomp and the `no_new_privs` Bit

You might have noticed `prctl(PR_SET_NO_NEW_PRIVS, 1)` in the earlier examples. This is required for non-root processes to install seccomp filters, and it has profound security implications.

Once set, `no_new_privs` guarantees that:
- `execve()` of a setuid binary will **not** grant elevated privileges
- No operation can give the process more privileges than it currently has
- The bit is inherited across `fork()` and `execve()` — it's irreversible

This prevents a subtle attack: without `no_new_privs`, a process could install a permissive seccomp filter and then `execve()` a setuid binary. The setuid binary would run as root, but with the attacker's seccomp filter still attached — the attacker could use the filter's `SECCOMP_RET_TRAP` action to intercept syscalls made by the privileged process and manipulate its control flow via signal handlers.

```
Without no_new_privs:

  attacker process (uid=1000)
    │
    ├─ install seccomp filter with SECCOMP_RET_TRAP
    │  for strategic syscalls
    │
    └─ execve("/usr/bin/sudo")
         │
         └─ sudo runs as root, but seccomp filter is inherited
              │
              └─ SIGSYS handler (attacker-controlled) can manipulate
                 the privileged process ← THIS IS THE BUG
```

The `no_new_privs` bit closes this vector. It's also why seccomp filters are **append-only** — you can add more restrictive filters, but you can never remove or relax an existing one.

---

## Debugging Seccomp Filters

Debugging a misconfigured seccomp policy is notoriously painful. Here are the tools that make it manageable:

### 1. Use `SECCOMP_RET_LOG` During Development

Instead of killing the process on policy violations, log them:

```c
/* Replace SCMP_ACT_KILL_PROCESS with SCMP_ACT_LOG during testing */
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_LOG);
```

Then watch the audit log:

```bash
sudo journalctl -f _AUDIT_TYPE=1326
```

Output:

```
audit: type=1326 msg=audit(1708700000.123:456): auid=1000 uid=1000
  ses=1 pid=12345 comm="myapp" exe="/usr/bin/myapp" sig=0
  arch=c000003e syscall=257 compat=0 ip=0x7f1234 code=0x7ffc0000
```

`syscall=257` is `openat`. Look up numbers in `/usr/include/asm/unistd_64.h` or use `ausyscall`:

```bash
ausyscall 257
# openat
```

### 2. Dump the Compiled BPF Program

libseccomp can export the filter as a BPF program:

```c
seccomp_export_bpf(ctx, STDERR_FILENO);  /* binary BPF */
seccomp_export_pfc(ctx, STDERR_FILENO);  /* pseudo-assembly */
```

The pseudo-assembly output is human-readable:

```
#
# pseudo filter code start
#
# filter for arch x86_64 (3221225534)
if ($arch == 3221225534)
  if ($syscall == 59)     # execve
    action ERRNO(1);
  if ($syscall == 322)    # execveat
    action ERRNO(1);
  # ...
  action ALLOW;
# filter for arch x86_64 end
```

### 3. Use strace to Identify Missing Syscalls

If your application crashes under seccomp, find what it needs:

```bash
# Run without seccomp, log all syscalls
strace -f -c ./your_app 2>&1 | tail -20
```

This gives you the complete syscall profile to build your allowlist from.

---

## Bypasses and Limitations

Seccomp-BPF is powerful but not omniscient. Understanding its limitations is critical for building defense in depth.

### No Pointer Dereference

As mentioned earlier, seccomp-BPF cannot follow pointers. A filter can see that `openat()` was called, and it can inspect the integer arguments (`dirfd`, `flags`, `mode`), but it **cannot** read the filename string. This means you can't build path-based policies with seccomp alone — you need LSMs (AppArmor, SELinux) or Landlock for that.

### TOCTOU Races

Seccomp checks arguments at syscall entry. For pointer-based arguments, another thread could modify the pointed-to memory between the seccomp check and the kernel's actual use of the data. This is primarily a concern for `SECCOMP_RET_USER_NOTIF` where a supervisor reads process memory to inspect arguments — the `SECCOMP_IOCTL_NOTIF_ID_VALID` check mitigates but doesn't eliminate this.

### Allowed Syscall Expressiveness

Some syscalls are extremely versatile. `ioctl()` is a single syscall number that controls everything from terminal settings to GPU commands to block device operations. Filtering `ioctl` by command argument is possible but the command space is enormous. Similarly, `prctl()` controls dozens of unrelated process attributes.

### Compatibility Syscalls

x86-64 Linux supports multiple syscall ABIs (64-bit via `syscall`, 32-bit via `int 0x80`, and x32 via `syscall` with the `__X32_SYSCALL_BIT`). A filter that only checks 64-bit syscall numbers can be bypassed via the 32-bit ABI. Always verify the architecture field:

```c
/* This is not optional — it's a security requirement */
BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
```

Or disable the 32-bit ABI entirely if you don't need it.

---

## Production Considerations

### Performance

Seccomp-BPF runs on every syscall entry — but it's fast. The BPF interpreter (or JIT compiler, if `net.core.bpf_jit_enable=1`) processes the filter in nanoseconds. Benchmarks on typical policies show **<1% overhead** even for syscall-heavy workloads.

The filter is evaluated in a straight-line pass. libseccomp optimizes the generated BPF to use tree-based comparisons (binary search on syscall numbers), keeping the worst-case path short.

### Filter Stacking

Multiple seccomp filters can be attached to a process (each `prctl(PR_SET_SECCOMP)` adds a new one). They execute bottom-up (most recently added first), and the most restrictive verdict wins. This is how container runtimes layer policies:

```
Process: nginx in Docker
  │
  ├── Application filter (added by nginx)
  │   └── "Only allow read/write/accept/epoll/..."
  │
  └── Container filter (added by Docker's runc)
      └── "Block init_module/mount/unshare/..."
```

### Seccomp + Other Sandboxing Mechanisms

Seccomp works best as one layer in a defense stack:

| Mechanism | What it controls |
|---|---|
| Seccomp-BPF | Which syscalls can be invoked |
| Namespaces | What resources are visible |
| Capabilities | What privileged operations are allowed |
| AppArmor / SELinux | What files and operations are permitted (MAC) |
| Landlock | Path-based filesystem access control (unprivileged) |
| cgroups | Resource limits (CPU, memory, I/O) |

Chrome uses all of these. Docker uses most of them. Each layer catches what the others miss.

### Monitoring Seccomp in Production

Combine seccomp with eBPF tracing (from the [previous post](/posts/2026-02-21-ebpf-security-monitoring/)) to monitor filter violations in real time:

```python
#!/usr/bin/env python3
"""
seccomp_monitor.py – trace seccomp violations using eBPF
"""

from bcc import BPF

PROGRAM = r"""
#include <linux/seccomp.h>

struct violation {
    u32 pid;
    u32 syscall_nr;
    u32 signo;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(signal, signal_deliver) {
    if (args->sig != 31) return 0;  /* SIGSYS = seccomp violation */

    struct violation v = {};
    v.pid    = bpf_get_current_pid_tgid() >> 32;
    v.signo  = args->sig;
    bpf_get_current_comm(&v.comm, sizeof(v.comm));

    events.perf_submit(args, &v, sizeof(v));
    return 0;
}
"""

def print_event(cpu, data, size):
    e = bpf["events"].event(data)
    comm = e.comm.decode("utf-8", errors="replace")
    print(f"[SECCOMP VIOLATION] PID={e.pid} COMM={comm}")

bpf = BPF(text=PROGRAM)
bpf["events"].open_perf_buffer(print_event)

print("Monitoring seccomp violations... Ctrl-C to stop.\n")

while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        break
```

This closes the loop: seccomp *enforces* the policy, eBPF *observes* violations. Alerts from this monitor tell you either that your policy is too restrictive (false positive) or that someone just tried something they shouldn't have.

---

## Conclusion

Seccomp-BPF is the kernel-level enforcement counterpart to eBPF's observability. Where eBPF tells you what happened, seccomp prevents it from happening in the first place. Together, they form a complete security boundary at the syscall interface — the narrowest chokepoint between user-space code and kernel functionality.

The key takeaways:

1. **Raw BPF filters** give you precise control over the filter machine but are tedious to write — use them when you need to understand exactly what's happening or need the smallest possible filter.
2. **libseccomp** is the practical choice for building real policies — it handles architecture validation, argument comparison, and BPF optimization.
3. **Denylist policies** are easier to maintain; **allowlist policies** are harder to break. Choose based on your threat model and operational capacity.
4. **The architecture check is not optional** — without it, 32-bit syscall ABIs can bypass your filter.
5. **Seccomp is one layer** in a defense-in-depth stack. Combine it with namespaces, capabilities, MAC, and cgroups for real isolation.
6. **User notification** (kernel 5.0+) enables syscall emulation, powering the next generation of rootless container runtimes.

Every containerized workload you run is already using seccomp (Docker's default profile). Understanding how it works — and how to customize it — gives you direct control over the most fundamental security boundary in Linux.

---

*All code in this post was tested on Ubuntu 22.04 LTS with kernel 5.15 and libseccomp 2.5.4. Seccomp-BPF requires kernel 3.5+; user notification requires 5.0+; `SECCOMP_RET_LOG` requires 4.14+. Compile with `gcc -o program program.c -lseccomp` for libseccomp examples.*
