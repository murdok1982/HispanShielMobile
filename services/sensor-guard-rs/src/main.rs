use anyhow::{bail, Result};
use log::{info, warn, error};

/// Defines the hardware sensor types we protect.
#[derive(Debug, Clone, Copy)]
enum SensorType {
    Camera,
    Microphone,
    Location,
}

/// Represents the global hardware kill-switch state.
struct SensorKillSwitch {
    camera_disabled: bool,
    mic_disabled: bool,
    location_disabled: bool,
}

impl SensorKillSwitch {
    fn new() -> Self {
        Self {
            camera_disabled: true, // Secure default: disabled on boot until unlocked
            mic_disabled: true,
            location_disabled: true,
        }
    }

    /// Validates if a specific UID is allowed to access the sensor.
    fn request_access(&self, uid: u32, sensor: SensorType) -> Result<()> {
        match sensor {
            SensorType::Camera if self.camera_disabled => {
                warn!("Blocked camera access for UID {} (System kill-switch is ON)", uid);
                bail!("Camera access is globally disabled.");
            }
            SensorType::Microphone if self.mic_disabled => {
                warn!("Blocked microphone access for UID {} (System kill-switch is ON)", uid);
                bail!("Microphone access is globally disabled.");
            }
            SensorType::Location if self.location_disabled => {
                warn!("Blocked location access for UID {} (System kill-switch is ON)", uid);
                bail!("Location access is globally disabled.");
            }
            _ => {
                info!("Granted access to {:?} for UID {}", sensor, uid);
                Ok(())
            }
        }
    }

    fn toggle_sensor(&mut self, sensor: SensorType, disabled: bool) {
        info!("Toggling {:?} state to Disabled: {}", sensor, disabled);
        match sensor {
            SensorType::Camera => self.camera_disabled = disabled,
            SensorType::Microphone => self.mic_disabled = disabled,
            SensorType::Location => self.location_disabled = disabled,
        }
    }
}

fn main() -> Result<()> {
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();
    info!("Starting HispaShield Sensor Guard Service...");

    let mut guard = SensorKillSwitch::new();

    let untrusted_app_uid = 10100;
    info!("App UID {} requesting microphone access...", untrusted_app_uid);
    if let Err(e) = guard.request_access(untrusted_app_uid, SensorType::Microphone) {
        error!("Access Denied: {}", e);
    }

    guard.toggle_sensor(SensorType::Microphone, false);
    info!("App UID {} requesting microphone access again...", untrusted_app_uid);
    match guard.request_access(untrusted_app_uid, SensorType::Microphone) {
        Ok(_) => info!("Access successful."),
        Err(e) => error!("Access Denied: {}", e),
    }

    Ok(())
}
