# Blueprint: Baseband Isolation vía IOMMU Split-Trust

## El Problema: El Baseband Propietario Hostil
En los dispositivos móviles modernos, el procesador de radio frecuencia o *Baseband* (ej. Qualcomm, Shannon/Samsung) opera su propio RTOS (Real-Time Operating System) cerrado.
Históricamente, este chip ha poseído accesos de DMA (Direct Memory Access) a la memoria principal del teléfono para facilitar el paso rápido de buffers de red. 
**Riesgo Crítico:** Un atacante con una antena falsa tipo *Stingray* o con acceso remoto al módem puede aprovechar los accesos DMA directos para sobrescribir el kernel de Linux.

## La Solución HispaShield: IOMMU y Proxy en Rust
Asumimos que el módem *siempre será comprometido*. Por lo tanto, estableceremos una postura de "Confianza Dividida" (Split-Trust).

1.  **IOMMU Hardening:** Forzaremos en la configuración del Kernel (`defconfig` de AOSP) la restricción IOMMU (Input-Output Memory Management Unit) para el SOC del módem. El módem ya NO tendrá acceso plano a la RAM del Sistema Operativo. Se habilitará un rango minúsculo y preasignado estrictamente para los buffers (`SMMU/IOMMU Isolation`).
2.  **Radio HAL Proxy (`baseband-proxy-hal`):** La comunicación del `system_server` con el módem tradicionalmente se gestiona a través de la librería C++ `rild` propietaria. 
    *   Sustituiremos la HAL de Radio por un proxy puro y estéril escrito en Rust.
    *   Si el baseband envía *fuzzing* de buffers o tramas telco maliciosas al procesador principal (ej: para ejecutar RCE mediante el overflow de buffers AT/QMI), el parser de nuestro Proxy de Radio interceptará esto nativamente en Rust, cuya seguridad de memoria evitará que el kernel colapse.
3.  **Filtrado Estricto (Sanitación):** El HAL Proxy no solo traduce; es un guardián de validación gramatical. Si un comando de la operadora excede lo puramente necesario para LTE/5G (comportamiento anómalo), la trama es descartada silenciosamente.
