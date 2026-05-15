# ADR-002: SELinux Default-Deny Policy for All HispaShield Domains

**Status:** Accepted  
**Date:** 2026-05-15  
**Deciders:** HispaShield Core Team  
**Technical Area:** Mandatory Access Control, security policy

---

## Context and Problem Statement

AOSP ships with SELinux in enforcing mode, but its policy is designed for compatibility with
the broad Android app ecosystem. Many domains have overly permissive rules inherited from years
of "fix the denial" reactive policy writing.

HispaShield adds eight new SELinux domains for its daemons. We must decide on the policy
philosophy: start permissive and harden, or start with minimum required permissions.

---

## Decision Drivers

1. **Principle of least privilege** — daemons should have only the permissions they need
2. **Defense in depth** — if a daemon is compromised, SELinux limits lateral movement
3. **Auditability** — a small, explicit allowlist is easier to review than a large inherited policy
4. **Compatibility** — policy must not break legitimate daemon functionality
5. **Maintenance** — policy must be maintainable as daemons evolve

---

## Considered Options

### Option A: Inherit from existing AOSP domains

Copy/extend existing domains like `system_server` or `platform_app`.

**Pros:** Less work upfront, unlikely to cause functionality regressions  
**Cons:** Inherits excess permissions; violates least privilege; hard to audit

### Option B: Permissive mode initially, harden over time

Start all `hispashield_*` domains in permissive mode; run on real hardware and collect denials
with `audit2allow`; harden incrementally.

**Pros:** Faster initial development, no functionality regressions during development  
**Cons:** Permissive policy ships in production builds; security-critical daemons with no MAC

### Option C: Default-deny — explicit allowlist only

Each `hispashield_*` domain starts with zero permissions. Every capability is explicitly
granted with a justification comment. `neverallow` rules codify invariants that must never
be violated (camera, network for settings daemon, etc.).

**Pros:** Smallest attack surface; `neverallow` violations caught at build time by `checkpolicy`;
maximum defense in depth; easy to audit  
**Cons:** More upfront effort; risk of "denial loop" during development

---

## Decision

**We adopt Option C: Default-deny for all `hispashield_*` SELinux domains.**

### Rationale

1. **Security-first design.** HispaShield's value proposition is a hardened OS. A daemon
   running with excess SELinux permissions would be a direct contradiction.

2. **`neverallow` as security contracts.** `neverallow` rules are checked at policy compile time
   by `checkpolicy`. They function as machine-checked invariants:
   - `sensor-guard` can never open a TCP socket (`neverallow hispashield_sensorguard self:tcp_socket create`)
   - `secure-settings` can never access app data files
   - `network-policy-daemon` can never access camera devices

3. **Auditability for regulatory compliance.** Explicit allowlists make it straightforward to
   answer "does this daemon have access to X?" — critical for privacy certifications.

4. **GrapheneOS precedent.** GrapheneOS applies the same philosophy to its added domains and
   has maintained it successfully over multiple Android major versions.

5. **`audit2allow` is safe to use in development.** During development, we run in permissive
   mode, collect denials with `adb logcat | grep avc`, and convert them to allow rules with
   justification comments. This converts the "denial loop" risk into a structured workflow.

---

## Policy Writing Guidelines

Following from this decision, all `hispashield_*.te` files must:

1. **Start with type declarations** — no rules before types are declared
2. **Use `init_daemon_domain()` macro** — ensures correct domain transition from `init`
3. **Group rules by category** — self, network, files, IPC, hardware, logging
4. **Justify every allow rule with a comment** when non-obvious
5. **Include a `neverallow` section** with at minimum:
   - No camera access (unless the daemon specifically manages camera)
   - No microphone access (unless the daemon specifically manages audio)
   - No network access (for non-network daemons)
   - No access to `app_data_file` (user app private storage)
   - No arbitrary code execution (only allow `hispashield_*_exec`)
   - No kernel module loading (`sys_module` capability)

6. **Review process:** All `.te` file changes require two reviewers and must pass
   `checkpolicy -M -C -o /dev/null policy.te` in CI.

---

## Consequences

### Positive
- Smallest possible attack surface for HispaShield daemons
- Build-time verification of security invariants via `neverallow`
- Clear policy audit trail
- Containment: a compromised daemon cannot pivot to camera/mic/app data

### Negative
- Longer initial development time (estimated +2 weeks for policy work)
- Policy must be updated every time a daemon's required permissions change
- Risk of denial loops in early development (mitigated by permissive mode in `eng`/`userdebug` builds)

### Mitigation of Negative Consequences
- CI step (`lint-sepolicy` in `rust-ci.yml`) catches syntax errors automatically
- Development builds (`-v userdebug`) can use domain-specific permissive mode
- Policy regression tests run on emulator in CI before each merge

---

## References

- AOSP SELinux Policy Documentation: https://source.android.com/docs/security/features/selinux
- GrapheneOS SELinux policy: https://github.com/GrapheneOS/platform_system_sepolicy
- NSA SELinux Reference Policy: https://github.com/SELinuxProject/refpolicy
- Smalley & Craig, "Configuring the SEAndroid Policy" (NDSS 2013)
- Android CDD §9.7: Kernel Security Features
