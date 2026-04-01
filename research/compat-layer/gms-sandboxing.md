# Blueprint: Capa de Compatibilidad de GMS Sin Red (Mock Sandbox)

## El Problema: La Hegemonía y Telemetría de Play Services
GMS (Google Mobile Services) requiere de los permisos más elevados (`system`, `root`, firmas cruzadas de ROMs) en plataformas AOSP estándar. Otorgarle a GMS poder sin restricciones es incompatible con el objetivo corporativo y civil de protección pasiva dictado por HispaShield. Sin embargo, no incluirlos "rompe" un 80% del ecosistema de aplicaciones (Uber, Bancos, Mapas).

## La Solución HispaShield: Emulación Ficticia (Mock Sandbox)
Nuestro foco de diseño (y lo elegido mediante directriz por el usuario) es instalar una librería ligera de `gms-compat-proxy` que engañe a las aplicaciones.

1.  **Instalación sin Privilegios:** El demonio simulará responder al "Package ID" `com.google.android.gms`. No tendrá permisos de `INTERNET`, `READ_PHONE_STATE` ni acceso al Kernel.
2.  **Mock de Localización (Falsa pero Verosímil):** Cuando una aplicación solicite a GMS conectarse a la API de *FusedLocationProvider* de Google, nuestro proxy responderá simulando la API pero extrayendo la posición directa y sin cifrar proveniente del GPS puro local de AOSP, sin invocar servidores de red.
3.  **Mock Ciegas:** Las bibliotecas de Google Analytics (`FirebaseAnalytics`) integradas en aplicaciones de terceros recibirán del `gms-compat-proxy` un código estatus `200 OK` local (Blackhole). Creerán que su telemetría ha sido enviada con éxito, pero nuestro OS la destruirá *in-place*.
4.  **Protección Defensiva:** El atacante/proveedor o rastreador publicitario jamás consigue salir del sandbox lógico.
