use anyhow::{Context, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tracing::{debug, info, warn};

/// A single eSIM identity profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsimProfile {
    pub id: String,
    /// Human-readable codename, e.g. "operacion-alfa" or "perfil-civil".
    pub nickname: String,
    pub iccid: String,
    pub operator: String,
    pub country: String,
    pub active: bool,
}

/// Configuration for the IMSI rotation scheduler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsimRotationConfig {
    pub profiles: Vec<EsimProfile>,
    /// Base interval in seconds between rotations.
    pub rotation_interval_seconds: u64,
    /// If true, a random jitter is added/subtracted to defeat timing-correlation attacks.
    pub randomize_jitter: bool,
    /// Maximum jitter in seconds (±jitter applied symmetrically around the base interval).
    pub jitter_seconds: u64,
}

impl Default for EsimRotationConfig {
    fn default() -> Self {
        Self {
            profiles: Vec::new(),
            rotation_interval_seconds: 3600, // 1 hour
            randomize_jitter: true,
            jitter_seconds: 1800, // ±30 minutes
        }
    }
}

/// Core IMSI rotation state machine.
pub struct EsimManager {
    pub config: EsimRotationConfig,
    pub current_profile_idx: usize,
    pub last_rotation: Instant,
    /// Pre-computed next rotation interval (includes jitter).
    next_interval: Duration,
}

impl EsimManager {
    pub fn new(config: EsimRotationConfig) -> Self {
        let next_interval = compute_next_interval(&config);
        let mut mgr = Self {
            config,
            current_profile_idx: 0,
            last_rotation: Instant::now(),
            next_interval,
        };
        // Mark initial profile as active
        if !mgr.config.profiles.is_empty() {
            mgr.config.profiles[0].active = true;
        }
        mgr
    }

    /// Advances to the next profile in round-robin order and returns a reference to it.
    pub fn rotate(&mut self) -> &EsimProfile {
        if self.config.profiles.is_empty() {
            panic!("No eSIM profiles configured");
        }
        // Deactivate current
        self.config.profiles[self.current_profile_idx].active = false;
        // Advance index
        self.current_profile_idx =
            (self.current_profile_idx + 1) % self.config.profiles.len();
        // Activate new
        self.config.profiles[self.current_profile_idx].active = true;
        self.last_rotation = Instant::now();
        // Pre-compute next interval with fresh jitter
        self.next_interval = compute_next_interval(&self.config);
        info!(
            profile = %self.config.profiles[self.current_profile_idx].nickname,
            next_rotation_secs = self.next_interval.as_secs(),
            "IMSI rotated to new profile"
        );
        &self.config.profiles[self.current_profile_idx]
    }

    /// Returns a reference to the currently active profile.
    pub fn current(&self) -> &EsimProfile {
        &self.config.profiles[self.current_profile_idx]
    }

    /// Returns how long until the next scheduled rotation.
    pub fn time_until_next_rotation(&self) -> Duration {
        let elapsed = self.last_rotation.elapsed();
        if elapsed >= self.next_interval {
            Duration::ZERO
        } else {
            self.next_interval - elapsed
        }
    }

    /// Returns true if the manager should rotate now.
    pub fn should_rotate(&self) -> bool {
        self.config.profiles.len() > 1 && self.last_rotation.elapsed() >= self.next_interval
    }

    /// Applies the rotation: selects the next profile and sends the AT command
    /// to the baseband proxy via its Unix socket.
    pub async fn apply_rotation(&mut self) -> Result<()> {
        let profile = self.rotate().clone();
        info!(
            iccid = %profile.iccid,
            nickname = %profile.nickname,
            "Applying eSIM rotation"
        );
        send_at_command_to_baseband(&profile).await?;
        Ok(())
    }
}

/// Computes the next rotation interval, optionally adding uniform random jitter.
fn compute_next_interval(config: &EsimRotationConfig) -> Duration {
    let base = config.rotation_interval_seconds;
    if !config.randomize_jitter || config.jitter_seconds == 0 {
        return Duration::from_secs(base);
    }
    let mut rng = rand::thread_rng();
    // Jitter in range [-jitter_seconds, +jitter_seconds]
    let max_j = config.jitter_seconds as i64;
    let jitter: i64 = rng.gen_range(-max_j..=max_j);
    let total = (base as i64 + jitter).max(60) as u64; // Never less than 60 s
    debug!(base_secs = base, jitter_secs = jitter, total_secs = total, "Computed next rotation interval");
    Duration::from_secs(total)
}

/// Sends an AT command to the baseband proxy asking it to switch the active eSIM profile.
///
/// The proxy is expected to listen on `/run/hispashield/baseband.sock` and accept
/// newline-delimited JSON commands of the form:
///   {"action": "at_command", "command": "AT+CUSD=..."}
async fn send_at_command_to_baseband(profile: &EsimProfile) -> Result<()> {
    let socket_path = "/run/hispashield/baseband.sock";

    // Build the AT command. In a real device this would be an LPA (Local Profile
    // Assistant) command or a proprietary RIL command that activates the ICCID.
    // We simulate with a well-known AT+CSIM envelope.
    let at_cmd = format!(
        "AT+CSIM=10,\"80E28900{}{}\"",
        profile.iccid.len() / 2,
        profile.iccid
    );

    let payload = serde_json::json!({
        "action": "at_command",
        "command": at_cmd,
        "iccid": profile.iccid,
        "profile_id": profile.id
    });
    let mut line = serde_json::to_string(&payload)?;
    line.push('\n');

    match UnixStream::connect(socket_path).await {
        Err(e) => {
            warn!(
                socket = socket_path,
                err = %e,
                "Baseband proxy not available; AT command queued (simulated)"
            );
            // In production this would queue the command for retry.
        }
        Ok(mut stream) => {
            stream
                .write_all(line.as_bytes())
                .await
                .context("write to baseband proxy")?;

            // Read acknowledgement
            let mut buf = String::new();
            BufReader::new(&mut stream)
                .read_line(&mut buf)
                .await
                .context("read ack from baseband proxy")?;
            debug!(ack = %buf.trim(), "Baseband proxy acknowledged AT command");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(n: usize) -> EsimRotationConfig {
        let profiles = (0..n)
            .map(|i| EsimProfile {
                id: format!("profile-{i}"),
                nickname: format!("codename-{i}"),
                iccid: format!("8901{:014}", i),
                operator: "TestOp".to_string(),
                country: "ES".to_string(),
                active: i == 0,
            })
            .collect();
        EsimRotationConfig {
            profiles,
            rotation_interval_seconds: 3600,
            randomize_jitter: false,
            jitter_seconds: 0,
        }
    }

    #[test]
    fn test_new_sets_first_active() {
        let mgr = EsimManager::new(make_config(3));
        assert!(mgr.current().active);
        assert_eq!(mgr.current_profile_idx, 0);
    }

    #[test]
    fn test_rotate_round_robin() {
        let mut mgr = EsimManager::new(make_config(3));
        assert_eq!(mgr.current().id, "profile-0");
        mgr.rotate();
        assert_eq!(mgr.current().id, "profile-1");
        mgr.rotate();
        assert_eq!(mgr.current().id, "profile-2");
        mgr.rotate();
        // Wraps around
        assert_eq!(mgr.current().id, "profile-0");
    }

    #[test]
    fn test_rotate_deactivates_old() {
        let mut mgr = EsimManager::new(make_config(2));
        assert!(mgr.config.profiles[0].active);
        assert!(!mgr.config.profiles[1].active);
        mgr.rotate();
        assert!(!mgr.config.profiles[0].active);
        assert!(mgr.config.profiles[1].active);
    }

    #[test]
    fn test_should_rotate_false_immediately() {
        let mgr = EsimManager::new(make_config(2));
        // Just created, should not rotate yet
        assert!(!mgr.should_rotate());
    }

    #[test]
    fn test_time_until_next_rotation_positive() {
        let mgr = EsimManager::new(make_config(2));
        let remaining = mgr.time_until_next_rotation();
        assert!(remaining.as_secs() > 0);
    }

    #[test]
    fn test_jitter_range() {
        let config = EsimRotationConfig {
            profiles: vec![],
            rotation_interval_seconds: 3600,
            randomize_jitter: true,
            jitter_seconds: 1800,
        };
        // Run 100 iterations and verify the interval stays in [60, 5400]
        for _ in 0..100 {
            let interval = compute_next_interval(&config);
            assert!(interval.as_secs() >= 60);
            assert!(interval.as_secs() <= 5400); // 3600 + 1800
        }
    }

    #[test]
    fn test_no_jitter() {
        let config = EsimRotationConfig {
            profiles: vec![],
            rotation_interval_seconds: 3600,
            randomize_jitter: false,
            jitter_seconds: 0,
        };
        let interval = compute_next_interval(&config);
        assert_eq!(interval.as_secs(), 3600);
    }

    #[test]
    fn test_esim_profile_serialization() {
        let profile = EsimProfile {
            id: "p1".to_string(),
            nickname: "operacion-alfa".to_string(),
            iccid: "89014103211118510720".to_string(),
            operator: "HispaNet".to_string(),
            country: "ES".to_string(),
            active: true,
        };
        let json = serde_json::to_string(&profile).unwrap();
        let restored: EsimProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.iccid, profile.iccid);
        assert_eq!(restored.nickname, profile.nickname);
    }
}
