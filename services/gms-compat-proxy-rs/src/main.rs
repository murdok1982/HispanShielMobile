use anyhow::Result;
use log::{info, warn};

/// Interfaz Emulada de los Servicios de Geolocalización GMS
struct GmsLocationProxy {}

impl GmsLocationProxy {
    /// Responde a la app cliente (ej: Uber) dándole la ubicación mediante la HAL nativa
    /// sin contactar a los servidores de mapeo de Google y enviando un ID falso.
    fn get_last_location(&self) -> String {
        info!("App cliente solicitó FusedLocationProvider de GMS.");
        warn!("GMS-Compat: Interceptando llamada. Derivando petición a la API de AOSP Local (Pure GPS).");
        "{\"lat\": 40.4168, \"lng\": -3.7038, \"provider\": \"pseudonymous-gps\"}".to_string()
    }
}

/// Interfaz Emulada de Firebase Analytics (Telemetría de Google)
struct FirebaseProxy {}

impl FirebaseProxy {
    /// Responde con estado 'Éxito' a la app cliente, pero destruye agresivamente los datos
    /// en RAM para que jamás salgan de la red local del dispositivo. (Red Ciega).
    fn mock_send_analytics(&self, _event_data: &str) {
        info!("GMS-Compat: App intentando emitir telemetría comercial a Firebase/Google Analytics...");
        warn!("Protección Blackhole: Payload '{_}' destruida sin red local. Reportando 'StatusCode 200 OK' falso a la app cliente.");
    }
}

fn main() -> Result<()> {
    std::env::set_var("RUST_LOG", "info,warn");
    env_logger::init();
    info!("Iniciando HispaShield GMS Compatibility Sandbox (Capa Ciega)...");

    let location_mock = GmsLocationProxy {};
    let analytics_mock = FirebaseProxy {};

    // App pide ubicación
    let secure_loc = location_mock.get_last_location();
    info!("App recibió: {}", secure_loc);

    // App intenta enviar datos de seguimiento de usuario encubiertos mediante rastreadores GMS:
    analytics_mock.mock_send_analytics("user_id=10293&event=app_open&device=pixel8");

    Ok(())
}
