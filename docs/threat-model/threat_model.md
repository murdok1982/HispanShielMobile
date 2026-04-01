# Modelo de Amenazas de HispaShield Mobile (Fase 1)

> [!IMPORTANT]
> Este documento rige todas las decisiones de ingeniería para el OS. Nuestro enfoque es una estricta mitigación de vulnerabilidades y reducción de superficie de ataque, con rechazo explícito de funciones engañosas o de destrucción maliciosa de evidencia.

## Matriz Principal de Amenazas

| Amenaza | Capacidad del Atacante | Vector de Ataque | Mitigación Implementada | Riesgo Residual |
|---------|------------------------|------------------|-------------------------|-----------------|
| **Aplicaciones Maliciosas** | Baja / Media. Depende de exploits de escalada. | Play Store, Sideloading. Intento de acceso a sensores o datos locales. | Sandboxing estricto (AOSP); Default Deny en red; SensorGuard en modo kill-switch; Políticas SELinux MAC. | Privilegios escalados mediante 0-days en drivers de Kernel (GPU/NPU). |
| **Ataque Baseband (Módem)** | Muy Alta (Operador o IMSI Catcher). | Ejecución de código remoto en el procesador celular (Baseband RTOS). | Aislamiento IOMMU del procesador baseband respecto a la RAM principal. Separación forzada del demonio RIL/Radio. | El atacante rastrea ubicación vía triangulación pasiva de torres móviles. |
| **Exploits de Navegador** | Alta. JavaScript/WebAssembly avanzado. | Cadenas de RCE a través del motor de renderizado (WebView). | Malloc Endurecido; Control Flow Integrity (CFI); seccomp-bpf aislando dominios del renderer. | Fugas de datos en el mismo origen / Side-channels físicos (e.g., Spectre). |
| **Compromiso de Supply Chain (Cadena de Suministro)** | Crítica (Nation State). | Inserción de código malicioso en dependencias de compilación (Rust crates, repo AOSP). | Builds reproducibles por diseño; Verificación offline de sumas de control; Servidores de CI herméticos y aislados sin red. | Vulnerabilidades subyacentes insertadas a nivel de hardware/SoC en fábrica. |
| **Ataque Físico de Duración Corta (Evil Maid)** | Media (Acceso físico temporal). | Reinicio en modo bootloader o inserción de depuradores USB maliciosos. | Android Verified Boot (AVB) bloqueado; Cifrado respaldado por hardware TEE; Bloqueo total de USB-C al bloquear pantalla (Data-Kill). | Fallos severos de hardware no documentados en Titan M2 o puertos JTAG expuestos internamente. |
| **Extracción Forense / Clonación** | Alta (Laboratorio gubernamental o comercial privado). | Uso de exploits a través de USB, JTAG o descifrados masivos de fuerza bruta con hardware acelerado (Cellebrite/GrayKey). | Cifrado FBE robusto; Deshabilitación absoluta de ADB de red/recuperación; Rate-limiting por hardware (Titan M2). **Nota**: Sin inclusión de borrado anti-forense. | Ataques de tipo Cold Boot si no se emplean perfiles efímeros y la RAM no fue purgada a tiempo. |
