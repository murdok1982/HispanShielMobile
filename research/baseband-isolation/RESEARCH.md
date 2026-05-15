# Baseband Isolation Research

## Overview

The baseband processor (modem) represents one of the most privileged and least understood attack
surfaces in mobile devices. It runs a real-time OS (e.g., Qualcomm's AMSS/MPSS, MediaTek's
Nucleus RTOS), has direct hardware access to RF transceivers, and historically has had little to
no memory isolation from the application processor (AP).

This document surveys techniques and prior work relevant to HispaShield's `baseband-proxy-hal`
daemon.

---

## 1. AT Command Filtering

### Protocol Background

AT commands (Hayes command set, ITU-T V.250) are the primary control plane for modems. On Android
devices, the RIL (Radio Interface Layer) daemon (`rild`) communicates with the modem via a serial
interface (physical UART, USB ACM, or virtual `/dev/smd*` channel on Qualcomm MSM).

Historically `rild` has had setuid root and broad modem access. Any process that could communicate
with `rild` or the underlying serial channel could issue arbitrary AT commands.

### Dangerous AT Command Classes

| Category | Commands | Risk |
|---|---|---|
| SIM access | `AT+CSIM`, `AT+CRSM`, `AT+CGLA` | Full SIM filesystem read/write; SIM cloning |
| SIM Toolkit | `AT+STGI`, `AT+STGR`, `AT^STKPD` | Baseband-initiated phone calls, SMS fraud |
| USSD | `AT+CUSD` | Premium USSD relay attacks (CVE-2019-16256) |
| Modem enumeration | `AT+CLAC` | Fingerprinting available AT command set |
| IMEI write | `AT+EGMR` (MediaTek) | IMEI modification |
| Network lock | `AT+CLCK` | SIM PIN bypass, facility lock manipulation |
| Direct dial | `ATD` | App-initiated phone calls bypassing TelecomManager |
| DTMF injection | `AT+VTS` | In-call audio injection |

### References

- Rupprecht et al., "Call Me Maybe: Eavesdropping Encrypted LTE Calls With ReVoLTE" (USENIX Security 2020)
- Maier et al., "BaseSAFE: Baseband SAnitized Fuzzing through Emulation" (WiSec 2020)
- CVE-2020-11261: Qualcomm MPSS heap buffer overflow via crafted QMI message
- CVE-2021-1976: Qualcomm modem out-of-bounds write in DNS response processing
- CVE-2023-24038: MediaTek `AT+EGMR` IMEI write without privilege check

### HispaShield Approach

The `baseband-proxy-hal` daemon interposes between `rild` and the modem serial device using a
virtual serial port pair (`/dev/pts`). All AT command traffic is filtered through
`CommandFilter::default_secure()` before being forwarded to the modem.

```
App / System API
     |
     v
TelecomManager → rild (patched to use proxy socket)
                   |
                   v
          baseband-proxy-hal.sock
                   |
       [AT Command Parser + Filter]
                   |
          ALLOW ──→ /dev/ttySMD0 (real modem)
          BLOCK ──→ error returned
```

---

## 2. QMI/MBIM Protocol Security

### QMI (Qualcomm MSM Interface)

QMI is a binary protocol used on Qualcomm chipsets. It operates over a shared memory transport
(`/dev/qmi_wwan`, RMNET) or IPC Router. Unlike AT commands, QMI has hundreds of services
(WDS, NAS, UIM, DMS, etc.) with complex TLV-encoded messages.

**Key risks:**
- `UIM` service: direct SIM application access (APDU tunneling)
- `NAS` service: force network deregistration (DoS), PLMN selection manipulation
- `DMS` service: device serial number access, operating mode changes (factory reset commands)
- `PDC` service: provisioning configuration — can change modem firmware behavior

**Mitigation:** HispaShield patches the kernel QMI driver to whitelist only `WDS` (data) and
`NAS` (network registration status query) services from userspace. All UIM, DMS, and PDC access
is restricted to a dedicated privileged HAL process running in its own SELinux domain
(`hispashield_sim_hal`).

### MBIM (Mobile Broadband Interface Model)

MBIM is used on Intel XMM and some Fibocom modems. The risk profile is similar to QMI.
MBIM `CID_SUBSCRIBER_READY_STATUS` can expose IMSI; `CID_SMS_SEND` allows direct SMS.

**References:**
- Tian et al., "Attention Spanned: Comprehensive Vulnerability Analysis of AT Commands within the Android Ecosystem" (USENIX Security 2018)
- "QMI: The Qualcomm Modem Interface" — Osmocom project documentation
- CVE-2020-3702: Qualcomm WLAN driver use-after-free (reached via QMI-adjacent path)

---

## 3. Separate Network Namespace for Baseband

### Motivation

On stock Android, the modem communicates over RMNET virtual network interfaces
(`rmnet_data0..7`). These share the root network namespace with the application processor.
A compromised app with `CAP_NET_ADMIN` (or exploiting a kernel vulnerability) could:
- Inject packets into RMNET, poisoning modem-visible traffic
- Read modem routing decisions via `/proc/net/route`
- Manipulate IP rules that affect how modem data is routed

### Approach: Dedicated Network Namespace

HispaShield moves all RMNET interfaces into a dedicated network namespace (`netns_baseband`)
managed by a privileged daemon. Only the data plane (forwarding user packets to the internet)
is bridged back to the default namespace via a `veth` pair with strict iptables/nftables rules.

```
netns_baseband:
  rmnet_data0 ... rmnet_data7   ← modem traffic
  veth_bb_inner                 ← bridge to default ns

default netns:
  veth_bb_outer                 ← only port-filtered traffic passes
  wlan0, eth0, etc.
```

**Linux kernel references:**
- `ip netns` (iproute2)
- `CLONE_NEWNET` in `clone(2)`
- RFC 4960 (SCTP) — used by some modem control protocols over IP

---

## 4. Firmware Attestation

Baseband firmware authenticity is critical. A malicious FOTA (Firmware Over The Air) update
to the modem could install a "silent interceptor."

### Existing Mechanisms
- Qualcomm Secure Boot: SHA-256 + RSA-4096 signature chain from QFuses → SBL → MPSS image
- MediaTek Secure Boot: similar chain via `DA` (Download Agent) and `BROM`

### HispaShield Extension
At boot, `hispashield_settings` reads the modem firmware hash from the Qualcomm Trustzone
attestation report (via the `qseecom` driver) and verifies it against a pinned expected hash
stored in the locked `hispashield.modem_firmware_hash` settings key.

If the hash mismatches, the device enters a "degraded mode" where cellular data is disabled
and the user is alerted.

---

## 5. Selected CVEs & Academic Papers

| ID | Description | Year |
|---|---|---|
| CVE-2015-0569 | Qualcomm Wi-Fi driver heap overflow reachable from modem RPC | 2015 |
| CVE-2016-2060 | Qualcomm `netd` command injection via AT command relay | 2016 |
| CVE-2019-2200 | Android modem TA (Trusted Application) OOB write | 2019 |
| CVE-2020-11261 | MPSS heap buffer overflow via QMI message | 2020 |
| CVE-2021-1976 | Qualcomm modem DNS heap OOB in data service | 2021 |
| CVE-2022-22081 | MediaTek modem out-of-bounds write, no user interaction | 2022 |
| CVE-2023-24038 | MediaTek IMEI write via `AT+EGMR` | 2023 |
| CVE-2024-20017 | MediaTek Wi-Fi heap buffer overflow | 2024 |

**Papers:**
1. Rupprecht et al., "Breaking LTE on Layer Two" (IEEE S&P 2019)
2. Maier et al., "BaseSAFE: Baseband SAnitized Fuzzing through Emulation" (WiSec 2020)
3. Kim et al., "FirmWire: Transparent Dynamic Analysis for Cellular Baseband Firmware" (NDSS 2022)
4. Tian et al., "Attention Spanned: Comprehensive Vulnerability Analysis of AT Commands within the Android Ecosystem" (USENIX Security 2018)
5. Bui et al., "SoK: Attacks on Industrial Control Logic and Formal Verification-Based Defenses" — Section on modem isolation models (IEEE EuroS&P 2022)
