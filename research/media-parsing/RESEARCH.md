# Media Codec Attack Surface Research

## Overview

Media parsing is historically the richest source of critical Android vulnerabilities.
Processing attacker-controlled audio, video, and image data in privileged contexts
has led to remote code execution (RCE) with no user interaction — the most severe
class of mobile exploit. HispaShield's `media-isolate-coordinator` addresses this
by confining each codec to a dedicated, resource-limited process namespace.

---

## 1. Historical Stagefright-Class Vulnerabilities

### Stagefright (2015)

CVE-2015-1538 / CVE-2015-1539 / CVE-2015-3824 / CVE-2015-3826 / CVE-2015-3827 /
CVE-2015-3828 / CVE-2015-3829 (Zimperium, Joshua Drake)

**Impact:** RCE in `mediaserver` (ran as `media` UID with access to camera, microphone,
and many IPC interfaces) via crafted MMS message. No user interaction required — the phone
auto-retrieved and began parsing the MMS attachment in the background.

**Root cause:** Integer overflows and heap buffer overflows in `libstagefright`'s MPEG-4,
MP4, and 3GPP parser (C++, no bounds checking).

**Lessons:**
- Media parsing must run in an isolated process with minimal capabilities
- Auto-retrieval of media (MMS, iMessage-equivalent) is extremely dangerous
- C/C++ media libraries need compiler mitigations: `-fsanitize=address`, stack canaries, RELRO

### Subsequent Stagefright-class CVEs

| CVE | Year | Component | Impact |
|---|---|---|---|
| CVE-2015-6602 | 2015 | `libutils` integer overflow | RCE via crafted media |
| CVE-2016-0815 | 2016 | `libAACdec` AAC decoder | RCE in mediaserver |
| CVE-2016-0824 | 2016 | `libmpeg2` MPEG-2 decoder | RCE |
| CVE-2016-3741 | 2016 | `libstagefright` H.264 | RCE |
| CVE-2017-0600 | 2017 | `libhevc` HEVC decoder | RCE |
| CVE-2019-2186 | 2019 | `libFLAC` | RCE in media extractor |
| CVE-2020-0241 | 2020 | `NuPlayer` | privilege escalation |
| CVE-2021-0519 | 2021 | `libavc` H.264 decoder | OOB read/write |
| CVE-2022-20452 | 2022 | `libmpeg2` | Heap OOB write |
| CVE-2023-21273 | 2023 | Skia image decoder | RCE via crafted image |
| CVE-2024-0044 | 2024 | `ACodec` media framework | Privilege escalation |

---

## 2. Codec Sandboxing in GrapheneOS and Android 14

### Android's Existing Isolation

Starting with Android 5.0 (Lollipop), Google split `mediaserver` into multiple processes:
- `mediaextractor` — responsible for demuxing containers (MPEG-4, MKV, etc.)
- `mediacodec` — hardware/software codec access
- `mediadrmserver` — DRM key management
- `media.metrics` — metrics collection

Each runs with a separate SELinux domain and reduced capabilities. From Android 11+, hardware
codecs run inside Codec 2.0 components implemented in the HAL layer with their own sandbox.

**However**, multiple codec processes may still share address space via `ashmem`/`memfd` and
use Binder IPC extensively. A heap spray in `mediaextractor` that corrupts Binder objects can
still reach `mediacodec`.

### GrapheneOS Hardening

GrapheneOS applies additional hardening:
1. **Extended memory tagging (MTE):** On Pixel 8 (Cortex-X3), MTE is enabled for all media
   processes. MTE provides hardware tag-based memory safety that catches use-after-free and
   heap buffer overflows with ~1% overhead.
2. **Reduced Binder exposure:** GrapheneOS limits which Binder interfaces media processes
   can access, reducing lateral movement after compromise.
3. **`minijail` seccomp filters:** Media processes are confined to a strict syscall allowlist.

### HispaShield Additions

HispaShield's `media-isolate-coordinator` extends this further:

```
media-isolate-coordinator
        |
        ├── spawn_codec(VideoDecoder)
        │       └── clone(CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWIPC)
        │               └── /system/bin/mediaserver_video_dec
        │                   ├── cgroup: memory.max = 512 MiB
        │                   ├── seccomp: allowlist of ~40 syscalls
        │                   └── SELinux: hispashield_mediacodec_video_dec
        │
        ├── spawn_codec(AudioDecoder)
        │       └── clone(...) → /system/bin/mediaserver_audio_dec
        │                        └── cgroup: memory.max = 64 MiB
        │
        └── [Monitor task: restart on crash, log, alert on repeated failure]
```

**Namespace isolation flags:**
- `CLONE_NEWPID`: Codec process cannot see or signal other PIDs
- `CLONE_NEWNS`: Cannot see or bind-mount to other filesystems
- `CLONE_NEWNET`: No network access (codec processes have no legitimate network need)
- `CLONE_NEWIPC`: Separate System V IPC namespace (no IPC with other processes except via
  explicit file descriptor passing)

---

## 3. Memory-Safe Codec Development

### The Case for Rust/Memory-Safe Languages in Codecs

The root cause of ~70% of Android media vulnerabilities is memory unsafety in C/C++:
integer overflows, heap buffer overflows, use-after-free. Rewriting codecs in memory-safe
languages eliminates these entire classes.

**Existing efforts:**

| Project | Language | Codecs |
|---|---|---|
| `rav1d` (dav1d port) | Rust | AV1 video decoder |
| `symphonia` | Rust | MP3, AAC, FLAC, Vorbis, Opus |
| `image-rs` | Rust | PNG, JPEG, BMP, WebP, AVIF |
| Android's `libaom` (AV1) | C + fuzzing | AV1 (not Rust) |
| OpenSSL → Rustls | Rust | TLS (not codec but analogous pattern) |

**Proposed HispaShield codec stack:**

| Format | Current Android | HispaShield Target |
|---|---|---|
| AV1 video decode | `libaom` (C) | `rav1d` (Rust) |
| Audio (MP3/AAC/FLAC) | `libavc`, `libFLAC` (C) | `symphonia` (Rust) |
| Image (PNG/JPEG) | `libpng`, `libjpeg-turbo` (C) | `image-rs` (Rust) |
| H.264/H.265 | Hardware HAL (vendor) | Sandboxed HAL + MTE |
| VP8/VP9 | `libvpx` (C) | Sandboxed + ASAN |

### Fuzzing Investment

Even memory-safe code can have logic bugs (infinite loops, panic on integer overflow in debug
mode). HispaShield integrates `cargo-fuzz` (libFuzzer backend) for all Rust codecs:

```
cargo fuzz run fuzz_image_decode -- -max_len=50000000 -timeout=10
cargo fuzz run fuzz_audio_decode
cargo fuzz run fuzz_video_decode
```

Results are fed into OSS-Fuzz for continuous coverage.

**References:**
- Drake, "Stagefright: Scary Code in the Heart of Android" (Black Hat USA 2015)
- Android Security Bulletins: https://source.android.com/docs/security/bulletin
- Google Project Zero: "MTE as Implemented" https://googleprojectzero.blogspot.com/2023/08/mte-as-implemented.html
- Rust in Android: https://source.android.com/docs/setup/build/rust/building-rust-modules/overview
- `rav1d` Rust AV1 decoder: https://github.com/memorysafety/rav1d
- `symphonia` Rust audio: https://github.com/pdeljanov/Symphonia
- Chandler Carruth, "Garbage In, Garbage Out: Arguing about Undefined Behavior with Nasal Demons" (CppCon 2016)
- Gaynor, "Secure by Design: Google's Perspective on Memory Safety" (Google Security Blog 2024)
