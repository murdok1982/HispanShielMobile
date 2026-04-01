use anyhow::Result;
use log::{info, warn};
use std::time::{Duration, Instant};

/// Estado del sistema de bloqueo
#[derive(PartialEq)]
enum KeyguardState {
    Unlocked,
    Locked,
}

struct AutoRebootTimer {
    state: KeyguardState,
    locked_at: Option<Instant>,
    timeout: Duration,
}

impl AutoRebootTimer {
    fn new(timeout_hours: u64) -> Self {
        Self {
            state: KeyguardState::Unlocked,
            locked_at: None,
            timeout: Duration::from_secs(timeout_hours * 3600),
        }
    }

    fn notify_lock(&mut self) {
        info!("Dispositivo bloqueado. Iniciando temporizador de auto-reinicio seguro.");
        self.state = KeyguardState::Locked;
        self.locked_at = Some(Instant::now());
    }

    fn notify_unlock(&mut self) {
        info!("Dispositivo desbloqueado correctamente. Temporizador cancelado.");
        self.state = KeyguardState::Unlocked;
        self.locked_at = None;
    }

    fn check_timeout(&self) -> bool {
        if self.state == KeyguardState::Locked {
            if let Some(lock_time) = self.locked_at {
                if lock_time.elapsed() >= self.timeout {
                    warn!("¡TIMEOUT ALCANZADO ({} hs)! Exigiendo reinicio a BFU (Before First Unlock).", self.timeout.as_secs() / 3600);
                    return true;
                }
            }
        }
        false
    }

    fn execute_reboot(&self) {
        warn!("Ejecutando reinicio de sistema para purgar claves FBE de la RAM...");
        // This is a stub for the native reboot call in AOSP context
        // e.g.: libutils / android::base::SetProperty("sys.powerctl", "reboot,userrequested");
        // For testing locally without crashing host:
        info!("(Simulación) Reinicio ejecutado exitosamente.");
    }
}

fn main() -> Result<()> {
    std::env::set_var("RUST_LOG", "info,warn");
    env_logger::init();
    info!("Iniciando HispaShield Auto-Reboot Daemon...");

    let mut timer = AutoRebootTimer::new(18);
    timer.notify_lock();
    
    if timer.check_timeout() || true { 
        info!("Estado simulado: El tiempo ha excedido el límite configurado sin ser desbloqueado por el dueño legitimo.");
        timer.execute_reboot();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state_unlocked() {
        let timer = AutoRebootTimer::new(18);
        assert!(timer.state == KeyguardState::Unlocked);
        assert!(!timer.check_timeout());
    }

    #[test]
    fn test_lock_toggles_state() {
        let mut timer = AutoRebootTimer::new(18);
        timer.notify_lock();
        assert!(timer.state == KeyguardState::Locked);
    }
}

