<div align="center">
  <img src="docs/logo.png" alt="HispaShield Mobile Logo" width="350"/>
  <br/>
  <h1>🛡️ HispaShield Mobile OS</h1>
  <p><strong>Sistema Operativo Móvil de Grado Defensa — Privacidad Extrema / Defense-Grade Mobile OS — Extreme Privacy</strong></p>

  [![Rust](https://img.shields.io/badge/Rust-Memory%20Safe-orange.svg?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
  [![AOSP](https://img.shields.io/badge/AOSP-Based-green.svg?style=for-the-badge&logo=android)](https://source.android.com/)
  [![SELinux](https://img.shields.io/badge/SELinux-Enforcing-blue.svg?style=for-the-badge)](https://selinuxproject.org/)
  [![Post-Quantum](https://img.shields.io/badge/PQC-ML--KEM--768%20%7C%20ML--DSA--65-purple.svg?style=for-the-badge)](https://csrc.nist.gov/pubs/fips/203/final)
  [![Tor](https://img.shields.io/badge/Tor-Transparent%20Proxy-7d4698.svg?style=for-the-badge&logo=torproject)](https://www.torproject.org/)
  [![License](https://img.shields.io/badge/License-MIT-gray.svg?style=for-the-badge)](LICENSE)
</div>

<br/>

## 🧭 Arquitectura General del Sistema

```mermaid
mindmap
  root((HispaShield Mobile))
    Capa de Aplicación
        Privacy Dashboard Flutter
        Perfil Civil / Operacional
        Bypass de Emergencias
    Daemons de Seguridad Rust
        Capa de Red
            Network Policy Daemon
            VPN Kill-Switch
            Tor Transparent Proxy
        Capa de Identidad
            eSIM IMSI Rotation
            Profile Isolation
            GMS Compat Proxy
        Capa Criptográfica
            PQC Keystore ML-KEM-768
            Secure Settings Core
            Remote Attestation
        Capa de Supervivencia
            Duress PIN Daemon
            Dead-Man Switch
            Auto-Reboot Daemon
        Capa de Hardware
            Sensor Guard
            Baseband Proxy HAL
            Baseband Firmware Guard
            Media Isolate Coordinator
    Infraestructura del SO
        SELinux Strict Enforcing
        Seccomp-BPF Filters
        Android Verified Boot AVB
        Titan M2 Secure Enclave
```

<br/>

## 🏗️ Flujo de Datos y Componentes

```mermaid
graph TD
    classDef user fill:#1e1e1e,stroke:#3ddc84,stroke-width:2px,color:#fff
    classDef rust fill:#b7410e,stroke:#333,stroke-width:2px,color:#fff
    classDef pqc fill:#4b0082,stroke:#9b59b6,stroke-width:2px,color:#fff
    classDef net fill:#0d47a1,stroke:#1565c0,stroke-width:2px,color:#fff
    classDef surv fill:#1b5e20,stroke:#2e7d32,stroke-width:2px,color:#fff
    classDef hw fill:#555,stroke:#f1c40f,stroke-width:2px,color:#fff
    classDef aosp fill:#3ddc84,stroke:#333,stroke-width:2px,color:#111

    UserApp["📱 App / Perfil Aislado"]:::user
    Dashboard["🖥️ Privacy Dashboard"]:::user

    subgraph Red y Anonimato
        NPD["Network Policy Daemon"]:::net
        VPN["VPN Kill-Switch"]:::net
        TOR["Tor Transparent Proxy"]:::net
        ESIM["eSIM IMSI Rotation"]:::net
    end

    subgraph Criptografía Post-Cuántica
        PQC["PQC Keystore\nML-KEM-768 + ML-DSA-65"]:::pqc
        ATTEST["Remote Attestation"]:::pqc
        SSC["Secure Settings Core"]:::pqc
    end

    subgraph Supervivencia Operacional
        DURESS["Duress PIN Daemon"]:::surv
        DMZ["Dead-Man Switch"]:::surv
        REBOOT["Auto-Reboot Daemon"]:::surv
    end

    subgraph Hardware y Aislamiento
        SG["Sensor Guard"]:::rust
        BB["Baseband Proxy HAL"]:::rust
        BBG["Baseband Firmware Guard"]:::rust
        MEDIA["Media Isolate Coordinator"]:::rust
        PI["Profile Isolation"]:::rust
        GMS["GMS Compat Proxy"]:::rust
    end

    subgraph Kernel
        SELinux["🛡️ SELinux Default-Deny"]:::aosp
        Seccomp["🔒 Seccomp-BPF"]:::aosp
    end

    subgraph Hardware Seguro
        AVB["Verified Boot AVB"]:::hw
        Titan["Titan M2 Enclave"]:::hw
    end

    UserApp --> NPD
    UserApp --> SG
    UserApp --> PI
    NPD --> VPN --> TOR
    TOR --> ESIM
    PQC --> ATTEST
    PQC --> SSC
    DURESS --> SSC
    DMZ --> SSC
    BB --> BBG
    MEDIA --> Seccomp
    NPD --> SELinux
    SELinux --> AVB
    Seccomp --> Titan
    Dashboard --> NPD & SG & PQC & DURESS & DMZ & TOR
```

<br/>

## 🔐 Stack de Seguridad Completo

| Nivel | Componente | Tecnología | Función |
|---|---|---|---|
| **L0 — Hardware** | Titan M2 | Secure Enclave | Custodia de claves maestras |
| **L0 — Boot** | AVB + Bootloader Bloqueado | Android Verified Boot | Anti-implante firmware |
| **L1 — Kernel** | SELinux Enforcing | TE + neverallow | MAC default-deny total |
| **L1 — Kernel** | Seccomp-BPF | eBPF filters | Syscall allowlist por proceso |
| **L2 — Cripto** | PQC Keystore | ML-KEM-768 + ML-DSA-65 | Post-quantum key exchange y firma |
| **L2 — Cripto** | Remote Attestation | HMAC-SHA256 + cert chain | Zero-trust device verification |
| **L3 — Red** | Network Policy Daemon | Default Deny por UID | Cortafuegos a nivel proceso |
| **L3 — Red** | VPN Kill-Switch | iptables OUTPUT DROP | Sin fugas si VPN cae |
| **L3 — Red** | Tor Transparent Proxy | TPROXY + DNS-over-Tor | Anonimización total de tráfico |
| **L4 — Identidad** | eSIM IMSI Rotation | AT+CSIM + jitter | Anti-triangulación |
| **L4 — Identidad** | Profile Isolation | bind-mount ACL | Separación civil/operacional |
| **L4 — Identidad** | GMS Compat Proxy | Telemetry stripping | Google sin rastreo |
| **L5 — Sensores** | Sensor Guard | TTL tokens por sensor | Acceso cámara/mic bajo demanda |
| **L5 — Baseband** | Baseband Proxy HAL | AT command filter | Block 20+ comandos peligrosos |
| **L5 — Baseband** | Baseband Firmware Guard | SHA-256 integrity + IMSI heuristics | Detección IMSI Catcher |
| **L5 — Media** | Media Isolate Coordinator | Linux namespaces + cgroups | Codec crash-safe |
| **L6 — Supervivencia** | Duress PIN | SHA-256 constant-time | PIN pánico con beacon cifrado |
| **L6 — Supervivencia** | Dead-Man Switch | Heartbeat TTL | Auto-wipe si no hay check-in |
| **L6 — Supervivencia** | Auto-Reboot Daemon | Scheduled nix::reboot | Limpieza periódica de RAM |

<br/>

## 🧬 Stack Criptográfico Post-Cuántico

```mermaid
sequenceDiagram
    participant Device as 📱 HispaShield
    participant PQC as PQC Keystore
    participant Server as 🖥️ Servidor Zero-Trust

    Note over Device,Server: Establecimiento de Canal Seguro Híbrido
    Device->>PQC: generate_keypair(ML-KEM-768)
    PQC-->>Device: (pk_kyber: 1184B, sk_kyber: 2400B)

    Device->>Server: Attestation Report + pk_kyber
    Server->>Server: Verificar cadena AVB + daemon hashes
    Server-->>Device: encapsulate(pk_kyber) → ciphertext: 1088B

    Device->>PQC: decapsulate(sk_kyber, ciphertext)
    PQC-->>Device: shared_secret: 32B (Zeroizing<Vec<u8>>)

    Note over Device,Server: Canal cifrado. Claves en RAM zeroed tras uso.

    Device->>PQC: sign(ML-DSA-65, mensaje_operacional)
    PQC-->>Device: signature: 3309B
    Device->>Server: mensaje + firma
    Server->>Server: verify(pk_dsa, mensaje, firma) ✓
```

<br/>

## 🕵️ Detección de IMSI Catcher

El `Baseband Firmware Guard` implementa 6 heurísticas en tiempo real:

| Heurística | Puntos | Descripción |
|---|---|---|
| **Downgrade 4G/5G → 2G** | 35 | Forzado a GSM — técnica clásica de IMSI Catcher |
| **Señal anormalmente fuerte** | 30 | Torre desconocida con RSSI > −50 dBm (proximidad física) |
| **Rotación rápida de torres** | 20 | ≥5 torres distintas en 120 segundos (siguiendo al objetivo) |
| **LAC inválido** | 15 | LAC=0, 65535 o >60000 (no en rango operador legítimo) |
| **Cell ID centinela** | 10 | Cell ID = 0 o 1, o GSM cell_id >65535 |
| **GSM fuerte a torre nueva** | 20 | Posible proxy sin cifrado (A5/0) |

Score ≥ 70 → **CRITICAL** → alerta al Duress Daemon automáticamente.

<br/>

## 🌐 Proxy Tor Transparente

```mermaid
flowchart LR
    App["📱 App\n(cualquier UID)"]
    Bypass["🚨 Bypass UIDs\n(Emergencias 112)"]
    DNS["HISPASHIELD_TOR_DNS\nchain (iptables nat)"]
    TRANS["HISPASHIELD_TOR_TRANS\nchain (iptables nat)"]
    TorDNS["🧅 Tor DNS\n:5353"]
    TorTrans["🧅 Tor TPROXY\n:9040"]
    Exit["🌍 Exit Node\n(DE/NL/IS)\nno Five Eyes"]

    App -->|"UDP :53"| DNS --> TorDNS --> Exit
    App -->|"TCP :443/:80"| TRANS --> TorTrans --> Exit
    Bypass -->|"RETURN rule"| Exit
```

Países de salida preferidos: 🇩🇪 Alemania, 🇳🇱 Países Bajos, 🇮🇸 Islandia  
Países excluidos: 🇺🇸🇬🇧🇦🇺🇨🇦🇳🇿 (Five Eyes)

<br/>

## 🆘 Protocolo de Duress PIN

```mermaid
sequenceDiagram
    participant Op as 👤 Operador
    participant Daemon as Duress Daemon
    participant Keys as /data/hispashield/keys/
    participant Beacon as 📡 Servidor Alerta (UDP)

    Op->>Daemon: verify_pin(duress_pin_hash)
    Daemon-->>Op: {"result":"normal"} ← respuesta IDÉNTICA al PIN normal
    Note over Daemon: Detección silenciosa — el atacante no sabe
    Daemon->>Beacon: UDP cifrado XOR "DURESS:<timestamp>"
    Daemon->>Keys: remove_dir_all() — claves destruidas
    Note over Op: El dispositivo continúa aparentando funcionar (datos señuelo)
```

<br/>

## 🛠️ Compilación e Instalación

### Requisitos
- Linux (Ubuntu 22.04+ o Arch) con ≥32 GB RAM y ≥500 GB SSD
- Rust 1.75+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- Android SDK + NDK r27, `repo`, `fastboot`, `adb`
- Dispositivo referencia: **Google Pixel 8** (codename: `shiba`, SoC Tensor G3)

### Compilar los daemons Rust
```bash
# Clonar repositorio
git clone https://github.com/murdok1982/HispanShielMobile
cd HispanShielMobile

# Compilar workspace completo (16 daemons)
cargo build --workspace --release

# Ejecutar tests
cargo test --workspace

# Cross-compile para aarch64-android
rustup target add aarch64-linux-android
cargo build --workspace --release --target aarch64-linux-android
```

### Compilar la ROM AOSP
```bash
# Generar claves de firma (OFFLINE, entorno air-gapped)
bash build/scripts/generate_release_keys.sh

# Compilar ROM para Pixel 8
bash build/scripts/build_rom.sh

# Flashear
adb reboot bootloader
fastboot flashing unlock           # ⚠️ BORRA TODOS LOS DATOS
fastboot update hispashield-shiba-target_files.zip
fastboot erase avb_custom_key
fastboot flash avb_custom_key keys/avb/avb_pkmd.bin
fastboot flashing lock             # CRÍTICO: habilita Verified Boot
```

<br/>

## 📁 Estructura del Repositorio

```
HispanShielMobile/
├── Cargo.toml                        # Workspace Rust (16 miembros)
├── services/
│   ├── network-policy-daemon-rs/     # L3: Default Deny por UID
│   ├── sensor-guard-rs/              # L5: Tokens TTL por sensor
│   ├── secure-settings-core-rs/      # L2: KV store atómico
│   ├── profile-isolation-rs/         # L4: ACL cross-profile
│   ├── gms-compat-proxy-rs/          # L4: Strip telemetría Google
│   ├── auto-reboot-daemon-rs/        # L6: Reboot programado seguro
│   ├── baseband-proxy-hal-rs/        # L5: Filtro AT commands
│   ├── media-isolate-coordinator-rs/ # L5: Codec namespaces
│   ├── duress-pin-daemon-rs/         # L6: PIN pánico + beacon
│   ├── deadman-switch-rs/            # L6: Auto-wipe heartbeat
│   ├── baseband-firmware-guard-rs/   # L5: Firmware integrity + IMSI detection
│   ├── vpn-killswitch-rs/            # L3: Kill-switch + anti-DNS leak
│   ├── esim-manager-rs/              # L4: Rotación IMSI automática
│   ├── remote-attestation-rs/        # L2: Zero-trust attestation
│   ├── pqc-keystore-rs/              # L2: ML-KEM-768 + ML-DSA-65
│   └── tor-proxy-rs/                 # L3: Tor TPROXY transparente
├── sepolicy/private/                 # Políticas SELinux TE
├── build/scripts/                    # Generación de claves + build ROM
├── tests/integration/                # Tests de integración Tokio
├── ui/privacy-dashboard/             # Flutter Material 3 dashboard
├── docs/
│   ├── adr/                          # Architectural Decision Records
│   ├── threat-model/                 # STRIDE threat model
│   ├── pqc/                          # Criptografía post-cuántica
│   └── tor/                          # Integración Tor
└── research/
    ├── baseband-isolation/           # AT commands, QMI/MBIM, CVEs
    ├── compat-layer/                 # microG, sandboxed Play
    └── media-parsing/                # Stagefright, MTE, Rust codecs
```

<br/>

## 💰 Apoya el Proyecto

```text
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  ₿  Bitcoin Donation Address  ₿   ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃   bc1qqphwht25vjzlptwzjyjt3sex    ┃
┃   7e3p8twn390fkw                  ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```
**Red:** Bitcoin (BTC) · **Dirección:** `bc1qqphwht25vjzlptwzjyjt3sex7e3p8twn390fkw`

<br/>

## 🎖️ CENTRO DE COMUNICACIONES OFICIALES

**NIVEL DE ACCESO:** AUTORIZADO | **DESTINATARIO:** gustavolobatoclara@gmail.com

<details>
<summary><b>🚨 REPORTAR INCIDENCIA OPERATIVA</b></summary>
<br>Envía a <b>gustavolobatoclara@gmail.com</b>:<br>
<b>Asunto:</b> [QUEJA] Sistema - Descripción<br>
<b>Cuerpo:</b> Incidencia, impacto, evidencia (capturas/logs)
</details>

<details>
<summary><b>🛠️ REPORTE DE COMPILACIÓN / DESPLIEGUE</b></summary>
<br>Envía a <b>gustavolobatoclara@gmail.com</b>:<br>
<b>Asunto:</b> [COMPILACIÓN] Falla en &lt;OS/entorno&gt;<br>
<b>Incluir:</b> SO, versiones de dependencias, traza completa de error, pasos de reproducción
</details>

<details>
<summary><b>💡 PROPUESTAS DE DESARROLLO</b></summary>
<br>Envía a <b>gustavolobatoclara@gmail.com</b>:<br>
<b>Asunto:</b> [PROPUESTA] Módulo/Mejora<br>
<b>Incluir:</b> Objetivo táctico, problema que resuelve, viabilidad técnica
</details>
