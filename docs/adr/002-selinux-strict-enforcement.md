# ADR-002: Ejecución Global de Permisos Estrictos MAC (SELinux Strict Enforcing)

**Estado:** Aprobado  
**Fecha:** 2026-04-01  

## Contexto
El modelo de Discretionary Access Control (DAC) basado en permisos UNIX tradicionales (UID/GID y capacidades POSIX) es inherentemente deficiente ante exploits de día cero. Si un atacante compromete un proceso `system` en Android base, obtiene implícitamente todos sus atributos UNIX, pudiendo pivotar y escalar lateralmente.

## Decisión
HispaShield adoptará el "Mandatory Access Control" (MAC) a nivel atómico en el Kernel usando políticas SELinux agresivas:
* Todas las políticas deben estar escritas en dominios `coredomain` para demonios.
* Ningún demonio tendrá `allow domain dac_override;` o `allow domain capability sys_admin;` de manera simultánea.
* Está terminantemente prohibido usar la directiva `permissive` en cualquier versión release o beta ("User", "Userdebug" en builds OTA).
* Los servicios Custom en Rust correrán bajo dominios con CERO capacidades heredadas (`neverallow * self:capability *`), utilizando `binders` extremadamente específicos, restringidos a un servicio-cliente 1-A-1.

## Consecuencias
* **Positivas:** Aislamiento infalible de extremo a extremo. Los demonios expuestos no pueden leer /data aunque fuesen comprometidos remotamente (e.g., RCE vía Bluetooth).
* **Negativas:** La refactorización y actualización constante requerirán resolución detallada de conflictos tipo `avc_denied`. El esfuerzo para realizar *bring-up* de dispositivos será significativamente más tedioso.
