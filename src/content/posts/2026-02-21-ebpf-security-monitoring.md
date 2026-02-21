---
title: "eBPF for Security Monitoring: Kernel-Level Visibility Without the Overhead"
published: 2026-02-21 10:00:00+00:00
draft: false
description: "A deep dive into using eBPF to build high-performance, kernel-level security monitoring tools — covering syscall tracing, network inspection, and intrusion detection with practical Python examples."
tags: ["eBPF", "Linux", "Security", "Kernel", "Observability", "BCC", "Intrusion Detection", "Syscall Tracing"]
series: ""
toc: true
---

Modern attackers operate at the kernel level — rootkits hide processes, fileless malware executes entirely in memory, and living-off-the-land techniques abuse legitimate binaries. Traditional user-space monitoring tools are often blind to this activity, and heavyweight kernel modules risk system stability. eBPF (extended Berkeley Packet Filter) offers a third path: safe, sandboxed programs that run inside the kernel with near-zero overhead and full visibility.

This post covers how eBPF works, why it matters for security, and how to build practical monitoring tools using Python and the BCC toolkit.

---

## What is eBPF?

eBPF is a virtual machine embedded in the Linux kernel (since version 3.18, with major expansions through 5.x and beyond) that lets you run sandboxed programs in response to kernel events — without writing a kernel module or rebooting the system.

The classic BPF (Berkeley Packet Filter) was originally designed for efficient packet filtering in tools like `tcpdump`. eBPF generalized that concept dramatically: you can now attach programs to:

- **kprobes / kretprobes** — arbitrary kernel function entry/exit points
- **tracepoints** — stable, versioned kernel instrumentation points
- **XDP (eXpress Data Path)** — the earliest possible network hook, before the kernel even allocates a socket buffer
- **LSM hooks** — Linux Security Module hooks for access control decisions
- **perf events** — hardware and software performance counters
- **uprobes** — user-space function probes (attach to any binary without recompilation)

The key safety guarantee is the **eBPF verifier**: before any program runs, the kernel statically analyzes it to prove it terminates, never accesses out-of-bounds memory, and cannot crash the system. This makes eBPF dramatically safer than kernel modules.

```
┌──────────────────────────────────────────────────────┐
│                  User Space                          │
│  ┌────────────────┐    ┌──────────────────────────┐ │
│  │  BCC / libbpf  │    │  Go / Python / Rust tool │ │
│  └───────┬────────┘    └─────────────┬────────────┘ │
│          │  load & attach            │ read maps     │
└──────────┼───────────────────────────┼──────────────┘
           │                           │
┌──────────▼───────────────────────────▼──────────────┐
│                  Kernel Space                        │
│  ┌───────────────────────────────────────────────┐  │
│  │           eBPF Verifier                       │  │
│  └───────────────────┬───────────────────────────┘  │
│                      │ verified                      │
│  ┌───────────────────▼───────────────────────────┐  │
│  │   JIT-compiled eBPF Program (runs in-kernel)  │  │
│  └───────────────────┬───────────────────────────┘  │
│                      │ writes to                     │
│  ┌───────────────────▼───────────────────────────┐  │
│  │        eBPF Maps (shared memory)              │  │
│  └───────────────────────────────────────────────┘  │
│                                                      │
│  kprobes │ tracepoints │ XDP │ LSM │ perf events     │
└──────────────────────────────────────────────────────┘
```

eBPF programs communicate with user space through **maps** — key-value stores backed by various data structures (hash maps, ring buffers, arrays, LRU caches). Your monitoring tool reads from these maps to get the telemetry the kernel-side program collected.

---

## Why eBPF for Security Monitoring?

Traditional security monitoring approaches each have significant drawbacks:

| Approach | Limitation |
|---|---|
| `auditd` | High overhead; audit log can be flooded or disabled by root |
| Kernel modules | Can crash the system; must be recompiled per kernel version |
| ptrace / strace | ~2–10× slowdown on traced process; can be detected |
| User-space agents | Blind to kernel-level activity; bypassable by privileged malware |
| Network taps | No process context; encrypted traffic is opaque |

eBPF avoids most of these pitfalls:

- **Performance**: JIT-compiled programs run at near-native speed. Tools like Cilium route millions of packets/second with eBPF doing the work.
- **Safety**: The verifier prevents kernel panics.
- **Tamper resistance**: An eBPF program attached to a tracepoint fires even if the traced process tries to suppress signals or mess with its own `/proc` entry.
- **Process context**: Unlike network taps, eBPF gives you PID, UID, comm, and cgroup metadata alongside every event.
- **Portability**: With CO-RE (Compile Once – Run Everywhere) and BTF (BPF Type Format), a single compiled binary can run across kernel versions without recompilation.

---

## Setting Up the Environment

We'll use **BCC** (BPF Compiler Collection), which lets you write eBPF programs in C and control them from Python. On Ubuntu/Debian:

```bash
sudo apt-get install -y bpfcc-tools linux-headers-$(uname -r) python3-bpfcc
```

For Fedora/RHEL:

```bash
sudo dnf install bcc bcc-tools python3-bcc kernel-devel
```

Verify your setup:

```bash
sudo python3 -c "from bcc import BPF; print('BCC OK')"
```

> **Note:** Most eBPF programs require `CAP_BPF` (or `CAP_SYS_ADMIN` on older kernels). Running as root is the easiest approach for development; in production, use capability-based privilege dropping.

---

## Building a Syscall Tracer

The most fundamental security primitive is knowing what system calls a process makes. `execve` launches new processes, `openat` opens files, `connect` creates network connections. Let's trace them.

### Detecting Suspicious Process Execution

```python
#!/usr/bin/env python3
"""
exec_tracer.py – trace execve() calls with process context
"""

from bcc import BPF
import ctypes

PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE  128
#define MAX_ARGS 20

struct exec_event {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[ARGSIZE];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct exec_event event = {};

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event.pid  = bpf_get_current_pid_tgid() >> 32;
    event.uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.filename, sizeof(event.filename),
                            (void *)args->filename);

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""

SUSPICIOUS_BINARIES = {
    "nc", "ncat", "nmap", "masscan",
    "python", "python3", "perl", "ruby",   # interpreter abuse
    "wget", "curl",                         # download utilities
    "bash", "sh", "dash", "zsh",           # shell spawning
    "chmod", "chown",                       # privilege changes
    "insmod", "rmmod", "modprobe",         # kernel module loading
}

def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    filename = event.filename.decode("utf-8", errors="replace")
    comm     = event.comm.decode("utf-8", errors="replace")
    binary   = filename.split("/")[-1]

    alert = " [!] SUSPICIOUS" if binary in SUSPICIOUS_BINARIES else ""
    print(f"PID={event.pid:<6} PPID={event.ppid:<6} UID={event.uid:<5} "
          f"COMM={comm:<16} EXEC={filename}{alert}")

bpf = BPF(text=PROGRAM)
bpf["events"].open_perf_buffer(print_event)

print("Tracing execve() calls... Ctrl-C to stop.\n")
print(f"{'PID':<7} {'PPID':<7} {'UID':<6} {'COMM':<17} EXEC")
print("-" * 80)

while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        break
```

Run it:

```bash
sudo python3 exec_tracer.py
```

Sample output:

```
PID     PPID    UID    COMM              EXEC
--------------------------------------------------------------------------------
12483   12481   1000   bash              /bin/ls
12484   12481   1000   bash              /usr/bin/python3
12485   12484   1000   python3           /usr/bin/wget  [!] SUSPICIOUS
12486   12484   0      python3           /usr/bin/bash  [!] SUSPICIOUS
```

The last two lines are classic indicators of a web shell or reverse shell — a Python process spawning `wget` and then `bash` as root.

---

## Network Connection Monitoring

Knowing which process made a network connection is invaluable. `netstat` and `ss` show current connections but miss short-lived ones. eBPF captures every `connect()` call.

```python
#!/usr/bin/env python3
"""
tcp_tracer.py – trace outbound TCP connections with process context
"""

from bcc import BPF
import socket
import struct

PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct ipv4_event {
    u64 ts_ns;
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u16 dport;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(ipv4_events);

int trace_connect_v4_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret != 0) return 0;   // only successful connections

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    u16 family = sk->__sk_common.skc_family;
    if (family != AF_INET) return 0;

    struct ipv4_event event = {};
    event.ts_ns = bpf_ktime_get_ns();
    event.pid   = bpf_get_current_pid_tgid() >> 32;
    event.uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.saddr = sk->__sk_common.skc_rcv_saddr;
    event.daddr = sk->__sk_common.skc_daddr;
    event.dport = ntohs(sk->__sk_common.skc_dport);
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    ipv4_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# Ports commonly associated with C2 or data exfiltration
WATCHLIST_PORTS = {4444, 1337, 31337, 6666, 8080, 9001}

def inet_ntoa(addr):
    return socket.inet_ntoa(struct.pack("I", addr))

def print_ipv4_event(cpu, data, size):
    event = bpf["ipv4_events"].event(data)
    comm  = event.comm.decode("utf-8", errors="replace")
    daddr = inet_ntoa(event.daddr)
    alert = " [!] WATCHLIST PORT" if event.dport in WATCHLIST_PORTS else ""

    print(f"PID={event.pid:<6} UID={event.uid:<5} COMM={comm:<16} "
          f"DST={daddr}:{event.dport}{alert}")

bpf = BPF(text=PROGRAM)
bpf.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
bpf["ipv4_events"].open_perf_buffer(print_ipv4_event)

print("Tracing TCP connections... Ctrl-C to stop.\n")

while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        break
```

This will catch reverse shells the moment they dial out, even before the first byte of data is sent.

---

## File Integrity Monitoring with eBPF

Traditional file integrity monitoring tools like Tripwire work on a schedule; they'll miss a file that was created and deleted between scans. eBPF lets you monitor file opens in real time.

```python
#!/usr/bin/env python3
"""
file_monitor.py – alert on access to sensitive files and directories
"""

from bcc import BPF
import os

PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>

struct open_event {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    int flags;
};

BPF_PERF_OUTPUT(open_events);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct open_event event = {};

    event.pid   = bpf_get_current_pid_tgid() >> 32;
    event.uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.flags = args->flags;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.filename, sizeof(event.filename),
                            (void *)args->filename);

    open_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""

SENSITIVE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/root/.ssh/", "/home/", "/.ssh/authorized_keys",
    "/proc/", "/sys/kernel/",
    "/var/log/auth.log", "/var/log/secure",
]

O_WRONLY = 0x1
O_RDWR   = 0x2
O_CREAT  = 0x40

def is_sensitive(filename: str) -> bool:
    return any(filename.startswith(p) for p in SENSITIVE_PATHS)

def print_event(cpu, data, size):
    event    = bpf["open_events"].event(data)
    filename = event.filename.decode("utf-8", errors="replace")
    comm     = event.comm.decode("utf-8", errors="replace")

    if not is_sensitive(filename):
        return

    write_flag = (event.flags & O_WRONLY) or (event.flags & O_RDWR)
    mode = "WRITE" if write_flag else "READ "
    alert = " [!!] WRITE TO SENSITIVE FILE" if write_flag else ""

    print(f"[{mode}] PID={event.pid:<6} UID={event.uid:<5} "
          f"COMM={comm:<16} FILE={filename}{alert}")

bpf = BPF(text=PROGRAM)
bpf["open_events"].open_perf_buffer(print_event)

print("Monitoring sensitive file access... Ctrl-C to stop.\n")

while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        break
```

This will immediately surface things like:
- A web process reading `/etc/shadow` (potential credential dumping)
- An unexpected process writing to `/root/.ssh/authorized_keys` (persistence)
- Any process modifying `/etc/sudoers` (privilege escalation)

---

## Detecting Privilege Escalation Attempts

One of the most valuable security signals is tracking when a process changes its UID, particularly from a non-root UID to UID 0. This is what happens during a successful privilege escalation.

```python
#!/usr/bin/env python3
"""
setuid_tracer.py – detect UID changes (potential privilege escalation)
"""

from bcc import BPF

PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct setuid_event {
    u32 pid;
    u32 old_uid;
    u32 new_uid;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_setuid) {
    struct setuid_event event = {};

    event.pid     = bpf_get_current_pid_tgid() >> 32;
    event.old_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.new_uid = (u32)args->uid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Only report transitions from non-root to root
    if (event.old_uid != 0 && event.new_uid == 0) {
        events.perf_submit(args, &event, sizeof(event));
    }
    return 0;
}
"""

def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    comm  = event.comm.decode("utf-8", errors="replace")
    print(f"[ALERT] PRIVILEGE ESCALATION: PID={event.pid} COMM={comm} "
          f"UID {event.old_uid} → {event.new_uid}")

bpf = BPF(text=PROGRAM)
bpf["events"].open_perf_buffer(print_event)

print("Watching for UID 0 transitions... Ctrl-C to stop.\n")

while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        break
```

This is particularly effective at catching:
- Container escape attempts
- SUID binary exploitation
- Kernel exploit payloads that manipulate credential structures

---

## Combining Signals: A Simple Behavioral Detector

Individual events are useful, but attackers are rarely caught by a single indicator. Real-world detection combines signals across time. Here's a lightweight behavioral engine that tracks process trees:

```python
#!/usr/bin/env python3
"""
behavioral_detector.py – correlate exec + connect events to detect
                          shells spawning network connections
"""

from bcc import BPF
import socket, struct
from collections import defaultdict
from datetime import datetime

PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>

// ---- exec event ----
struct exec_event { u32 pid; u32 ppid; char comm[16]; char filename[128]; };
BPF_PERF_OUTPUT(exec_events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct exec_event e = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    e.pid  = bpf_get_current_pid_tgid() >> 32;
    e.ppid = t->real_parent->tgid;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_probe_read_user_str(e.filename, sizeof(e.filename), (void *)args->filename);
    exec_events.perf_submit(args, &e, sizeof(e));
    return 0;
}

// ---- tcp connect event ----
struct tcp_event { u32 pid; u32 daddr; u16 dport; char comm[16]; };
BPF_PERF_OUTPUT(tcp_events);

int trace_tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (sk->__sk_common.skc_family != 2) return 0; // AF_INET only
    struct tcp_event e = {};
    e.pid   = bpf_get_current_pid_tgid() >> 32;
    e.daddr = sk->__sk_common.skc_daddr;
    e.dport = ntohs(sk->__sk_common.skc_dport);
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    tcp_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}
"""

SHELLS = {"bash", "sh", "dash", "zsh", "fish", "ksh", "tcsh"}

# pid -> {"comm", "ppid", "children": set, "connections": list}
process_tree = defaultdict(lambda: {"comm": "", "ppid": 0,
                                     "children": set(), "connections": []})

def handle_exec(cpu, data, size):
    e     = bpf["exec_events"].event(data)
    comm  = e.comm.decode("utf-8", errors="replace")
    fname = e.filename.decode("utf-8", errors="replace")
    process_tree[e.pid]["comm"]  = comm
    process_tree[e.pid]["ppid"]  = e.ppid
    process_tree[e.ppid]["children"].add(e.pid)

def handle_tcp(cpu, data, size):
    e    = bpf["tcp_events"].event(data)
    comm = e.comm.decode("utf-8", errors="replace")
    dst  = socket.inet_ntoa(struct.pack("I", e.daddr))

    process_tree[e.pid]["connections"].append((dst, e.dport))

    # Walk up the process tree looking for a shell ancestor
    pid = e.pid
    depth = 0
    while pid > 1 and depth < 5:
        entry = process_tree[pid]
        if entry["comm"] in SHELLS:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"\n[{ts}] BEHAVIORAL ALERT: {comm} (PID {e.pid}) "
                  f"connected to {dst}:{e.dport}")
            print(f"  Shell ancestor: {entry['comm']} (PID {pid})")
            print(f"  This may indicate a reverse shell or post-exploitation activity.")
            break
        pid = entry["ppid"]
        depth += 1

bpf = BPF(text=PROGRAM)
bpf.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_tcp_connect")
bpf["exec_events"].open_perf_buffer(handle_exec)
bpf["tcp_events"].open_perf_buffer(handle_tcp)

print("Behavioral detector running... Ctrl-C to stop.\n")

while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        break
```

This pattern — *a network connection from a process descended from a shell* — catches the overwhelming majority of interactive reverse shells, regardless of what binary the attacker uses to make the connection.

---

## Production Considerations

Moving from a development prototype to a production eBPF security agent requires addressing several concerns:

### Performance Tuning

- Use **ring buffers** (`BPF_MAP_TYPE_RINGBUF`) instead of perf event arrays in kernel 5.8+ — they have lower overhead and no per-CPU allocation.
- **Sample high-volume events** rather than capturing every one. For example, trace 1-in-N `read()` calls rather than all of them.
- Set appropriate **map sizes** — an undersized ring buffer will drop events under load; an oversized one wastes memory.

### Handling Kernel Version Differences

- **CO-RE (Compile Once – Run Everywhere)** with `libbpf` and BTF lets you ship a single binary that adapts to different kernel struct layouts.
- BCC compiles at runtime (requiring kernel headers on the target), which is fine for development but suboptimal for production deployments.
- Consider **bpftrace** for one-off investigations and `libbpf` + CO-RE for long-running production agents.

### Privilege Management

```bash
# Grant only the capabilities needed, rather than running as root
sudo setcap cap_bpf,cap_perfmon,cap_net_admin+ep ./your-agent
```

### Bypasses and Limitations

eBPF is not magic. A sophisticated attacker with root access can:
- Unload your eBPF programs (`bpf(BPF_PROG_DETACH, ...)`)
- Disable tracepoints
- Exploit kernel vulnerabilities to bypass the verifier

Defense in depth still applies. Use eBPF as one layer in a broader security stack, not your only line of defense. LSM hooks (via **BPF LSM**, available since kernel 5.7) are harder to bypass because they're integrated with the security framework and can **deny** operations rather than just observe them.

---

## Real-World Tools Built on eBPF

You don't need to build everything from scratch. Several production-grade tools already use eBPF:

| Tool | Purpose |
|---|---|
| **Falco** | Runtime security rules engine for containers and Linux |
| **Cilium** | Kubernetes networking and security with eBPF data plane |
| **Tetragon** | Security observability and enforcement from Isovalent |
| **Pixie** | Application performance monitoring with automatic instrumentation |
| **bpftrace** | High-level tracing language for one-liners and scripts |
| **Tracee** | Runtime security and forensics tool from Aqua Security |

These tools implement the patterns above — syscall tracing, network monitoring, process lineage — at scale and with production hardening. For a security team, starting with Falco or Tetragon is often more practical than building a custom agent.

---

## Conclusion

eBPF represents a fundamental shift in how we can observe and protect Linux systems. By running verified programs inside the kernel, we gain visibility that was previously only possible with intrusive kernel modules or slow user-space agents — at a fraction of the performance cost.

The examples in this post cover the core building blocks:
1. **Syscall tracing** via tracepoints for process execution visibility
2. **Network monitoring** via kprobes for connection-level telemetry
3. **File access monitoring** to catch credential and config file reads
4. **Privilege escalation detection** by watching UID transitions
5. **Behavioral correlation** by combining signals across the process tree

As kernel support for eBPF matures and tooling like CO-RE makes cross-version deployment easier, eBPF-based security monitoring is quickly becoming the standard for high-performance intrusion detection on Linux.

---

*All code in this post was tested on Ubuntu 22.04 LTS with kernel 5.15. Some eBPF features used here (BPF LSM, ring buffers) require kernel 5.7+. Check [kernel.org](https://kernel.org) or your distribution's changelog for specific version requirements.*
