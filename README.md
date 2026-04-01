<div align="center">
  <img src="docs/logo.png" alt="HispaShield Mobile Logo" width="300"/>
  <h1>HispaShield Mobile</h1>
  <p><strong>Sistema Operativo Móvil Enfocado en la Privacidad Defensiva / Defensive Privacy Mobile OS</strong></p>
</div>

---

## 🌍 Español

**HispaShield Mobile** es un sistema operativo móvil de grado de producción, centrado en la privacidad extrema y diseñado bajo los principios de aislamiento, mínimo privilegio y mitigación de exploits. Basado en un núcleo endurecido de AOSP, reemplaza los servicios críticos con demonios escritos en **Rust** (seguros a nivel de memoria) e impone controles de acceso obligatorios drásticos utilizando **SELinux**.

### Características Principales
*   **Aislamiento y Sandboxing Fuerte:** Separación estricta de perfiles y restricciones drásticas de red (`Default Deny`).
*   **Demonios Críticos en Rust:** Componentes nativos seguros contra vulnerabilidades de memoria (`Network Policy Daemon`, `Sensor Guard`, `Secure Settings Core`).
*   **Seguridad Defensiva y Transparencia:** Diseñado exclusivamente para proteger al usuario local. Sin utilidades ofensivas, telemetría ni puertas traseras.
*   **Protección Basada en Hardware:** Integración con *Secure Boot*, *Android Verified Boot (AVB)* y encriptación robusta gestionada desde el hardware.

### 🛠️ Requisitos de Compilación e Instalación
**Requisitos Básicos:**
*   Dispositivo de referencia soportado (Ej: Google Pixel 8 / 8 Pro, SoC Tensor G3).
*   PC con Linux (Ubuntu 22.04+ o Arch Linux) con al menos 32GB de RAM y 500GB SSD para compilar AOSP.
*   Herramientas: `git`, `repo`, `cargo` (Rust), `fastboot`, `adb`.

**Guía de Instalación Paso a Paso:**
1.  **Clonar AOSP y HispaShield**: Inicializa el árbol de AOSP e integra este monorepo en el directorio `vendor/hispashield`.
    ```bash
    repo init -u https://android.googlesource.com/platform/manifest -b android-14.0.0_rXX
    # Añadir manifest local de HispaShield y sincronizar
    repo sync -c -j8
    ```
2.  **Generar Claves Maestras (Offline)**: Ejecuta `build/scripts/generate_release_keys.sh` en un entorno seguro para crear tu cadena de confianza (AVB Secure Boot).
3.  **Compilar la ROM**:
    ```bash
    source build/envsetup.sh
    lunch hispashield_shiba-user
    m -j$(nproc)
    ```
4.  **Desbloqueo y Flasheo**:
    *   Habilita "OEM Unlocking" en tu celular.
    *   Reinicia en modo bootloader: `adb reboot bootloader`
    *   Desbloquea el bootloader: `fastboot flashing unlock` *(⚠️ ESTO BORRARÁ LOS DATOS).*
    *   Instala la ROM compilada: `fastboot update hispashield-shiba-target_files.zip`
5.  **Re-bloqueo de Bootloader (Crítico)**:
    *   Flashea tu clave pública AVB: `fastboot erase avb_custom_key && fastboot flash avb_custom_key <tu_clave.bin>`
    *   Bloquea de nuevo el bootloader para restaurar el Verified Boot: `fastboot flashing lock`

---

### 💰 Apoya mi trabajo de código abierto

Si este proyecto te ha sido útil, considera apoyarlo financieramente para mantener activo su desarrollo.

**Bitcoin**

```text
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  ₿  Bitcoin Donation Address  ₿   ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃                                   ┃
┃   bc1qqphwht25vjzlptwzjyjt3sex    ┃
┃   7e3p8twn390fkw                  ┃
┃                                   ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

**Red:** Bitcoin (BTC)  
**Dirección:** `bc1qqphwht25vjzlptwzjyjt3sex7e3p8twn390fkw`

*Escanee el código QR.*
**¡Vuestro apoyo me ayuda a dedicar más tiempo al desarrollo de código abierto! 🙏**

---
<br />

## 🇬🇧 English

**HispaShield Mobile** is a production-grade, privacy-centric mobile operating system designed around principles of strict isolation, least privilege, and exploit mitigation. Built upon a hardened AOSP foundation, it replaces critical services with memory-safe **Rust** daemons and enforces draconian mandatory access controls via **SELinux**.

### Core Features
*   **Strong Compartmentalization:** Strict profile separation and default-deny network controls.
*   **Critical Daemons in Rust:** Memory-safe native components (`Network Policy Daemon`, `Sensor Guard`, `Secure Settings Core`).
*   **Defensive Security & Transparency:** Exclusively designed to protect the local user. Zero offensive tools, zero telemetry, no backdoors.
*   **Hardware-Backed Protection:** Integration with *Secure Boot*, *Android Verified Boot (AVB)*, and robust encryption managed within hardware.

### 🛠️ Requirements & Installation Guide
**Basic Requirements:**
*   Supported reference hardware (e.g., Google Pixel 8 / 8 Pro, Tensor G3 SoC).
*   Linux Build Server (Ubuntu 22.04+ or Arch) with 32GB+ RAM and 500GB+ SSD for the AOSP tree.
*   Toolchains: `git`, `repo`, `cargo` (Rust), `fastboot`, `adb`.

**Step-by-Step Installation:**
1.  **Clone AOSP & HispaShield**: Initialize the AOSP tree and overlay this monorepo into `vendor/hispashield`.
    ```bash
    repo init -u https://android.googlesource.com/platform/manifest -b android-14.0.0_rXX
    repo sync -c -j8
    ```
2.  **Generate Master Keys (Offline)**: Run `build/scripts/generate_release_keys.sh` in an air-gapped environment to create your AVB trust chain.
3.  **Compile the OS**:
    ```bash
    source build/envsetup.sh
    lunch hispashield_shiba-user
    m -j$(nproc)
    ```
4.  **OEM Unlock & Flash**:
    *   Enable "OEM Unlocking" in Developer Settings.
    *   Reboot to bootloader: `adb reboot bootloader`
    *   Unlock bootloader: `fastboot flashing unlock` *(⚠️ THIS WIPES ALL DATA).*
    *   Flash the built ROM: `fastboot update hispashield-shiba-target_files.zip`
5.  **Re-lock Bootloader (Critical)**:
    *   Flash your custom public AVB key: `fastboot erase avb_custom_key && fastboot flash avb_custom_key <your_key.bin>`
    *   Relock the bootloader for full Verified Boot enforcement: `fastboot flashing lock`

---

### 💰 Support my open-source work

If you find this project useful, consider supporting it financially to help me dedicate more time to active open-source development.

**Bitcoin**

```text
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  ₿  Bitcoin Donation Address  ₿   ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃                                   ┃
┃   bc1qqphwht25vjzlptwzjyjt3sex    ┃
┃   7e3p8twn390fkw                  ┃
┃                                   ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

**Network:** Bitcoin (BTC)  
**Address:** `bc1qqphwht25vjzlptwzjyjt3sex7e3p8twn390fkw`

*Scan the QR code.*
**Your support helps me dedicate more time to open-source development! 🙏**
