# GMS Compatibility Without Tracking Research

## Overview

Running Android without Google Mobile Services (GMS) eliminates a major tracking vector but
breaks push notifications, Maps SDK, SafetyNet/Play Integrity attestation, and many third-party
apps that declare hard GMS dependencies.

HispaShield's `gms-compat-proxy` daemon implements a middle path: a sandboxed, telemetry-stripped
GMS proxy that allows safe GMS functionality while blocking privacy-invasive endpoints.

---

## 1. microG Architecture Analysis

microG is a free-software re-implementation of GMS. Key components:

| Component | microG equivalent | Notes |
|---|---|---|
| `com.google.android.gms` | `com.google.android.gms` (microG) | Spoofs GMS signatures via fake signature patch |
| `GsfProvider` (device check-in) | Partial stub | avoids check-in |
| `FCM` (Firebase Cloud Messaging) | `UnifiedPush` / mtalk stub | Push relay without Firebase |
| `FusedLocationProvider` | `NetworkLocationProvider` | Uses Mozilla Location Service |
| `SafetyNet` | Stub returning failure | Cannot fully emulate hardware attestation |

### Signature Spoofing Risk

microG requires the OS to lie about APK signature hashes (so that GMS-checking apps believe they
are talking to real Google GMS). This "fake signature" patch weakens Android's security model:
a malicious app that declares `android.permission.FAKE_PACKAGE_SIGNATURE` could impersonate any
other app if the patch is overly permissive.

**HispaShield mitigation:** The signature spoofing permission is granted only to packages in
`/system/priv-app/` and the microG package itself, enforced by a SELinux neverallow rule.

**References:**
- microG Project: https://microg.org
- Blunden, "Android Hacker's Handbook" — Chapter 11: GMS internals
- CVE-2017-13315: StagefrightMediaPlayer GMS IPC confusion (demonstrates GMS attack surface)

---

## 2. Sandboxed Google Play Approach (GrapheneOS)

GrapheneOS takes a different approach: run the real GMS inside an unprivileged user profile
(the "Google services profile"), so it cannot access the primary user's data. GMS runs with
the same constraints as any other app: no special permissions, no `FAKE_PACKAGE_SIGNATURE`.

### Architecture

```
Primary User Profile (uid 10000..19999)
  ├── User apps (no GMS access)
  └── hispashield gms-compat-proxy

Google Services Profile (uid 1010000..1019999)  [sandboxed]
  ├── com.android.vending (Play Store)
  ├── com.google.android.gms
  └── com.google.android.gsf
        │
        └── All GMS traffic → gms-compat-proxy → internet
                                    │
                            [telemetry strip]
```

**Key insight:** In this model, GMS *cannot* read files or contacts from the primary profile
without explicit cross-profile data sharing policies. Profile isolation (`profile-isolation-rs`)
enforces that no bind-mounts cross profile boundaries.

**Limitations:**
- Apps in the primary profile that talk to GMS must use IPC bridges
- Play Integrity / SafetyNet requires `hardware_backed_key` which is per-profile
- Some banking apps require GMS in the same profile (use-case decision for end user)

**References:**
- GrapheneOS "Sandboxed Google Play" documentation: https://grapheneos.org/usage#sandboxed-google-play
- Android multi-user architecture: https://source.android.com/docs/devices/admin/multi-user
- AOSP `UserManagerService` source: `frameworks/base/services/core/java/com/android/server/pm/UserManagerService.java`

---

## 3. GAID Spoofing and Mitigation

### What is the GAID?

The Google Advertising ID (GAID) is a resettable, per-device pseudonymous identifier managed by
GMS (`com.google.android.gms.ads.identifier`). Apps use it for cross-app tracking. It is
accessible via `AdvertisingIdClient.getAdvertisingIdInfo()`.

### Attack Vectors

1. **Direct API call:** App calls GMS `getAdvertisingIdInfo()` → returns real GAID
2. **Shared preferences sideload:** GMS caches GAID in `/data/data/com.google.android.gms/shared_prefs/`; a root-exploiting app could read it
3. **Network request embedding:** Apps embed GAID in analytics payloads sent to `app-measurement.com`

### HispaShield Mitigations

| Layer | Mitigation |
|---|---|
| GMS compat proxy | Strip `advertisingId` and `gaid` fields from all GMS API responses |
| Network policy daemon | Block `app-measurement.com`, `doubleclick.net` at network layer |
| Sandboxed profile | GMS in isolated profile cannot access primary user files |
| Compile-time stub | Replace `AdvertisingIdClient` with a stub returning a zeroed UUID (AOSP patch) |

### Per-App GAID Isolation

For apps that legitimately need an advertising ID (e.g., rewarded game apps), HispaShield
generates a per-app, per-install GAID using `UUID.randomUUID()` at install time and stores it
in `hispashield.gaid.<package_name>`. The GMS compat proxy intercepts GAID requests and returns
this sandboxed value instead of the real device GAID.

**References:**
- Google Play Services SDK: `AdvertisingIdClient` Javadoc
- Razaghpanah et al., "Apps, Trackers, Privacy, and Regulators" (NDSS 2018)
- Englehardt & Narayanan, "Online Tracking: A 1-million-site Measurement and Analysis" (CCS 2016)

---

## 4. Firebase Cloud Messaging (FCM) Without Tracking

FCM is the push notification backbone. Without FCM, apps that rely on push notifications break.
With FCM, Google knows which apps you have installed and when you are active.

### FCM Registration Token

When an app registers for FCM, it sends:
- Package name
- Firebase project ID
- Device token (device-unique, derived from Android ID + GSF ID)

This registration event reveals to Google: the app is installed on this device.

### UnifiedPush Alternative

UnifiedPush is a protocol that allows apps to use alternative push relay servers. HispaShield
ships with a self-hosted Gotify/UnifiedPush relay. Apps that support UnifiedPush (e.g., Element,
Molly, Tusky) bypass FCM entirely.

For apps that only support FCM, the `gms-compat-proxy` forwards registration tokens to Google
FCM but:
1. Generates a synthetic `androidId` (not the real one) for registration
2. Strips the device fingerprint from registration payloads
3. Allows only the FCM send/receive endpoints (blocks check-in, analytics)

**References:**
- UnifiedPush specification: https://unifiedpush.org
- FCM protocol: https://firebase.google.com/docs/cloud-messaging/concept-options
- Naous et al., "Having Your Privacy Cake and Eating It Too: Platform-Supported Auditing of Social Media Algorithms for Public Interest Research" (WWW 2023) — discusses notification tracking

---

## 5. Play Integrity / SafetyNet

Play Integrity (formerly SafetyNet Attestation) uses hardware-backed keys and remote attestation
to prove to an app server that the device is running unmodified Android.

HispaShield **cannot** fully pass Play Integrity in MEETS_DEVICE_INTEGRITY mode because:
1. The bootloader is unlocked (required for custom OS installation)
2. Verified Boot state changes when the AVB key is replaced with the HispaShield key

### Current approach
- Use GrapheneOS's Play Integrity spoof approach (hardware attestation with custom cert chain)
  where the OS presents its own certificate signed by a Google-approved hardware attestation key
  obtained during the ROM's key ceremony
- For banking apps that require MEETS_STRONG_INTEGRITY: document the limitation; recommend using
  a separate dedicated device for high-security banking

**References:**
- GrapheneOS Play Integrity API support: https://grapheneos.org/faq#google-play-integrity-api
- Android Compatibility Definition Document (CDD) §9.10: Device Integrity
- Sabt & Traore, "Breaking into the KeyStore: A Practical Forgery Attack Against Android KeyStore" (ESORICS 2016)
