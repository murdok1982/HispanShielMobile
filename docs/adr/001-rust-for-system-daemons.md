# ADR-001: Uso Mandatorio de Rust para Nuevos Demonios Críticos del Sistema

**Estado:** Aprobado  
**Fecha:** 2026-04-01  

## Contexto
El desarrollo de sistemas operativos (especialmente AOSP) ha estado dominado por C y C++, lenguajes que requieren un esfuerzo mental insostenible a gran escala para evitar errores de gestión de memoria (User-After-Free, Buffer Overflows), los cuales constituyen históricamente más del 65% de las vulnerabilidades reportadas.

## Decisión
En HispaShield Mobile, introducimos una política arquitectónica estricta: **Todo nuevo servicio o demonio con privilegios de sistema, o que maneje parseo de datos no confiables (Untrusted IPC/Net/File Data), deberá programarse exclusivamente en Rust.**

* Se utilizará `cxx` y la capa integrada `binder-rs` de AOSP para interoperar con los gestores de servicios de Java/Kotlin estándar.
* Queda prohibida la inclusión de código `unsafe` en la capa lógica del servicio a menos que interaccione directamente con FFIs al Hardened Kernel o TEE, debiendo estar obligatoriamente comentada su audición en un archivo central de `SAFETY.md`.

## Consecuencias
* **Positivas:** Eliminación de fallos de concurrencia y seguridad de memoria. Concurrencia sin miedos (Fearless Concurrency) permitiendo una arquitectura multi-hilo para redes de alto rendimiento de manera segura.
* **Negativas:** Mayor curva inicial de adopción por parte de ingenieros contribuyendo al repositorio. Tiempo de compilación ligeramente mayor en el árbol AOSP final. Incremento en la complejidad de bindings iniciales.
