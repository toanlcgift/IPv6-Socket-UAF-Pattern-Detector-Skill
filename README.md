# AI Skill: Understanding IPv6 Socket UAF and Pointer-Leak Patterns

This repository documents the conceptual model behind a kernel exploitation technique that abuses stale IPv6 socket state to leak kernel pointers and later gain arbitrary kernel read/write capability.

This is intended as an AI skill document and research note for understanding, detection, and defensive analysis. It is not a working exploit or a step-by-step exploit recipe.

## Purpose

The goal is to help an AI agent or analyst understand how this technique works conceptually:

- a socket is created, disconnected, and left dangling
- the kernel frees or partially invalidates the socket’s IPv6 option state
- later, attacker-controlled data is placed into that freed memory
- the stale socket is used as a read/write channel through `getsockopt` / `setsockopt`
- specific fields are reinterpreted as kernel pointers
- the pointer leak is then chained into a Mach port primitive, fake task port, or kernel memory read
- eventually the exploit achieves `tfp0`-like capability

This is a representative example of a low-level kernel UAF + pointer-reinterpretation primitive.

---

## Core concept

The technique is not “IPv6 exploitation” in the abstract. The real exploit is:

- use-after-free of a kernel object
- stale socket file descriptor still valid
- freed memory is reused
- socket option fields are used as a leak channel
- pointer values are reconstructed by reading 32-bit halves from option fields

The key objects involved are:

- socket object
- IPv6 option structure (conceptually `ip6_pktopts`-like)
- `in6_pktinfo`
- MTU/temp-address option fields
- Mach port spray region
- kernel task / ipc_port structures

---

## Why this class of bug is dangerous

The technique turns ordinary socket APIs into a kernel memory disclosure primitive.

Typical APIs involved:

- `socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)`
- `setsockopt(...)`
- `getsockopt(...)`
- `disconnectx(...)`
- `mach_msg(...)`
- `mach_port_allocate(...)`

The exploit relies on the fact that these APIs can operate on kernel memory that should no longer be active but is still reachable through stale references.

---

## High-level flow

### 1. Create a dangling IPv6 socket

The exploit creates an IPv6 socket and then inconsistently tears down its state:

```c
int sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
setsockopt(sock, SOL_SOCKET, SO_NP_EXTENSIONS, &sonpx, sizeof(sonpx));
disconnectx(sock, 0, 0);
