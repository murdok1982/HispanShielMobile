use anyhow::Result;
use log::{info, warn};
use std::collections::HashMap;

/// Modela los tipos de perfiles en el dispositivo.
#[derive(Debug, PartialEq, Clone, Copy)]
enum ProfileType {
    Standard,     // Perfil maestro o diario
    Sensitive,    // Perfil oculto/seguro (ej. Periodista/Trabajo)
}

/// Estado criptográfico de un perfil.
#[derive(Debug, PartialEq)]
enum KeyState {
    Evicted,      // Claves borradas de la RAM (Inaccesible y Seguro)
    Decrypted,    // FBE desbloqueado (En uso)
}

struct UserProfile {
    id: u32,
    p_type: ProfileType,
    key_state: KeyState,
}

struct ProfileIsolationManager {
    profiles: HashMap<u32, UserProfile>,
    active_profile: u32,
}

impl ProfileIsolationManager {
    fn new() -> Self {
        let mut profiles = HashMap::new();
        // Insertando el perfil principal público
        profiles.insert(0, UserProfile {
            id: 0,
            p_type: ProfileType::Standard,
            key_state: KeyState::Evicted,
        });
        
        Self {
            profiles,
            active_profile: 0,
        }
    }

    fn create_sensitive_profile(&mut self, profile_id: u32) {
        info!("Creando un nuevo perfil de tipo Sensible (Multi-User) con ID: {}", profile_id);
        self.profiles.insert(profile_id, UserProfile {
            id: profile_id,
            p_type: ProfileType::Sensitive,
            key_state: KeyState::Evicted,
        });
    }

    /// Lógica central contra la extorsión física:
    /// Si el usuario ingresa a un perfil, los perfiles sensibles paralelos se DESTRUYEN en RAM
    /// (se expulsan las claves del TEE) para imposibilitar su extracción forense en caliente.
    fn switch_active_profile(&mut self, new_profile_id: u32) -> Result<()> {
        info!("Petición de cambio de perfil al ID: {}", new_profile_id);
        
        if self.active_profile != new_profile_id {
            // Expulsar claves de todos los demás perfiles sensibles si se sale de ellos
            for (id, profile) in self.profiles.iter_mut() {
                if *id != new_profile_id && profile.p_type == ProfileType::Sensitive {
                    if profile.key_state == KeyState::Decrypted {
                        warn!("Protección Anti-Extorsión (Aislamiento): Purgando claves del perfil sensible ID {} en RAM.", id);
                        // Mocking la syscall de vold para expulsar llaves FBE
                        profile.key_state = KeyState::Evicted;
                        info!("Perfil {} ahora alojado estáticamente y de forma segura como datos cifrados incomprensibles.", id);
                    }
                }
            }
        }
        
        self.active_profile = new_profile_id;
        
        if let Some(profile) = self.profiles.get_mut(&new_profile_id) {
            profile.key_state = KeyState::Decrypted;
            info!("Perfil {} ahora está Activo y sus claves desencriptadas (En uso legitimo).", new_profile_id);
        }

        Ok(())
    }
}

fn main() -> Result<()> {
    std::env::set_var("RUST_LOG", "info,warn");
    env_logger::init();
    info!("Iniciando HispaShield Profile Isolation Manager...");

    let mut manager = ProfileIsolationManager::new();
    
    // Usuario configura su perfil "secreto" de trabajo (ID 10)
    let secret_profile_id = 10;
    manager.create_sensitive_profile(secret_profile_id);

    // Simular que el usuario es forzado a dar su PIN principal (Perfil 0) 
    // bajo coacción física. El sistema cambiará al Perfil 0 y "evict" (destruirá en RAM) el Perfil 10.
    info!("Simulación: Dispositivo desbloqueado bajo coacción con el PIN del perfil principal.");
    manager.switch_active_profile(0)?;

    Ok(())
}
