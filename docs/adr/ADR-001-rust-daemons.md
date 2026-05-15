# ADR-001: Use Rust for All System Security Daemons

**Status:** Accepted  
**Date:** 2026-05-15  
**Deciders:** HispaShield Core Team  
**Technical Area:** Systems programming, security daemons

---

## Context and Problem Statement

HispaShield requires eight security-critical daemons running in privileged positions on the
Android system partition. These daemons:
- Handle untrusted input from user apps (via Unix sockets)
- Make security-critical access control decisions
- Interact with low-level system interfaces (netlink, cgroups, `/proc`)
- Must remain available 24/7 with minimal footprint

The primary language choice for AOSP native daemons has historically been C/C++. We need to
evaluate whether to follow that tradition or adopt an alternative.

---

## Decision Drivers

1. **Memory safety** — security daemons that parse untrusted input are high-value exploit targets
2. **Correctness** — access control logic must be formally verifiable (no undefined behavior)
3. **Performance** — daemons must not introduce measurable latency for real-time decisions
4. **Ecosystem** — must integrate with Android build system and Binder IPC
5. **Team expertise** — team has strong C++, growing Rust expertise
6. **AOSP support** — Google has committed to supporting Rust in Android since AOSP 12

---

## Considered Options

### Option A: C++17 with Sanitizers

**Pros:**
- Existing AOSP precedent, abundant examples
- No additional toolchain complexity
- Excellent hardware access libraries (`libnl`, `libselinux`)
- Team familiarity

**Cons:**
- Memory unsafety by default (buffer overflows, UAF, format string bugs)
- Undefined behavior is a constant risk in security-critical code
- AddressSanitizer/UBSan cannot be enabled in `user` builds (too slow)
- ~70% of Android critical CVEs are memory-safety issues in C/C++ components

### Option B: Rust

**Pros:**
- Memory safety guaranteed by the type system (no UB in safe code)
- Ownership model prevents data races — critical for multi-threaded async daemons
- `nix` crate provides safe wrappers around all needed syscalls
- `tokio` provides battle-tested async I/O matching the socket-centric daemon pattern
- Google's Android Rust Policy ensures toolchain is maintained for AOSP
- `cargo` workspace management simplifies the multi-daemon codebase
- Fearless concurrency — async/await + `Arc<Mutex<>>` is vastly safer than pthreads + raw pointers

**Cons:**
- Larger binary size (~3–5 MB per daemon) vs. typical C++ daemon (~300 KB)
- Compile time is longer (mitigated by `rust-cache` in CI)
- Some Android-specific libraries (`libselinux` label management) require `unsafe` FFI calls
- Steeper learning curve for contributors unfamiliar with ownership/borrowing

### Option C: Go

**Pros:**
- Memory safe, garbage collected
- Easy concurrency model (goroutines)

**Cons:**
- Garbage collector introduces latency spikes — unacceptable for real-time policy decisions
- Go runtime is large (~10 MB); each daemon would embed a full runtime
- No `unsafe` escape hatch for required raw syscall access
- Not officially supported in AOSP build system (no `Android.bp` Go support)

### Option D: Java/Kotlin

**Pros:**
- Native to Android application framework
- JNI available for low-level access

**Cons:**
- JVM startup time and GC latency unsuitable for system daemons
- JNI boundary is a footgun for memory safety
- Overkill for lightweight Unix socket daemons

---

## Decision

**We adopt Rust for all eight HispaShield security daemons.**

The decisive factors:
1. **The threat model demands memory safety.** Daemons parse untrusted JSON over sockets. A
   single buffer overflow in a C++ policy daemon could grant root. Rust's safe abstractions
   eliminate this entire class of bug.
2. **AOSP officially supports Rust** (Android Rust modules, `rust_binary` in `Android.bp`).
   Google targets having 50% of new AOSP native code in Rust by 2026.
3. **`tokio` + `nix` + `serde_json`** provide a complete, production-quality stack for the
   async Unix socket server pattern used by all eight daemons.
4. **Compile-time correctness.** The Rust type system catches data race conditions, null
   pointer dereferences, and use-after-free at compile time — before any code reaches the device.

---

## Consequences

### Positive
- Eliminates memory-safety CVE class in daemon code
- Forces explicit error handling (`Result<T, E>`) — no silent failure propagation
- `cargo test` enables unit testing of policy logic without an Android device
- `cargo clippy` lints catch logic bugs during development

### Negative
- Binary size: ~40 MB total for 8 daemons (acceptable for `/vendor` partition)
- Build time: 5–10 minutes for full workspace build (mitigated by incremental builds and CI cache)
- Contributors must learn Rust ownership model (mitigated by team workshops)

### Neutral
- `unsafe` blocks are still required for certain syscalls (`reboot(2)`, raw `clone()` flags).
  These are isolated and code-reviewed with extra scrutiny.
- FFI with C Android libraries (`libselinux`, `libcutils`) uses `bindgen`-generated safe wrappers.

---

## Compliance

This decision is consistent with:
- [Google's Android Rust Policy (2021)](https://security.googleblog.com/2022/12/memory-safe-languages-in-android-13.html)
- [NSA Cybersecurity Information Sheet: Software Memory Safety (2023)](https://media.defense.gov/2023/Dec/06/2003352724/-1/-1/0/THE-CASE-FOR-MEMORY-SAFE-ROADMAPS-TLP-CLEAR.PDF)
- CISA Memory Safety Roadmap guidance
