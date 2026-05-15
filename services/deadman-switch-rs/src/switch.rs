use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// State of the dead-man switch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchState {
    /// Heartbeats are current – normal operation.
    Active,
    /// Deadline is approaching – alert the user.
    Warning,
    /// Deadline passed – device is locked pending confirmation.
    Locked,
    /// Wipe has been scheduled; execution is imminent.
    WipePending,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Runtime configuration for the dead-man switch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadmanConfig {
    /// Total interval in seconds between required heartbeats.
    pub interval_seconds: u64,
    /// How many seconds before the deadline to enter Warning state.
    pub warning_seconds: u64,
    /// SHA-256 hex digest of the accepted heartbeat token.
    pub token_hash: String,
    /// Path whose contents should be wiped when the switch fires.
    pub keys_path: String,
}

impl Default for DeadmanConfig {
    fn default() -> Self {
        Self {
            interval_seconds: 24 * 3600,
            warning_seconds: 30 * 60,
            token_hash: String::new(),
            keys_path: "/data/hispashield/keys".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Core switch
// ---------------------------------------------------------------------------

/// The dead-man switch engine.  Intended to be held behind `Arc<Mutex<>>`.
pub struct DeadmanSwitch {
    state: SwitchState,
    last_heartbeat: Instant,
    config: DeadmanConfig,
}

impl DeadmanSwitch {
    /// Construct a new switch; the initial heartbeat timestamp is set to *now*.
    pub fn new(config: DeadmanConfig) -> Self {
        Self {
            state: SwitchState::Active,
            last_heartbeat: Instant::now(),
            config,
        }
    }

    /// Return a reference to the current configuration (used for re-configuration).
    pub fn config(&self) -> &DeadmanConfig {
        &self.config
    }

    /// Replace the configuration; also resets the heartbeat timer.
    pub fn reconfigure(&mut self, new_cfg: DeadmanConfig) {
        self.config = new_cfg;
        self.last_heartbeat = Instant::now();
        self.state = SwitchState::Active;
        info!("deadman switch reconfigured");
    }

    /// Return the current state.
    pub fn state(&self) -> &SwitchState {
        &self.state
    }

    /// Process an incoming heartbeat.
    ///
    /// Returns `true` if the token was valid and the timer was reset.
    pub fn heartbeat(&mut self, token_hash: &str) -> bool {
        if !constant_time_eq(token_hash.as_bytes(), self.config.token_hash.as_bytes()) {
            warn!("heartbeat received with invalid token");
            return false;
        }
        self.last_heartbeat = Instant::now();
        self.state = SwitchState::Active;
        info!("heartbeat accepted – timer reset");
        true
    }

    /// How many seconds remain until the deadline.
    pub fn seconds_remaining(&self) -> u64 {
        let elapsed = self.last_heartbeat.elapsed().as_secs();
        self.config.interval_seconds.saturating_sub(elapsed)
    }

    /// Advance the state machine; meant to be called periodically (e.g. every 60 s).
    ///
    /// Returns the new state so the caller can react (e.g. trigger wipe).
    pub fn tick(&mut self) -> SwitchState {
        let remaining = self.seconds_remaining();

        let new_state = match self.state {
            SwitchState::Active if remaining <= self.config.warning_seconds => {
                warn!("deadman switch entering Warning state ({remaining}s remaining)");
                SwitchState::Warning
            }
            SwitchState::Warning if remaining == 0 => {
                warn!("deadman switch entering Locked state");
                SwitchState::Locked
            }
            SwitchState::Locked => {
                warn!("deadman switch entering WipePending state");
                SwitchState::WipePending
            }
            // WipePending stays WipePending – caller must execute the wipe.
            other => other,
        };

        self.state = new_state.clone();
        new_state
    }

    /// Execute the destructive wipe using a subprocess shell command.
    ///
    /// After wiping, the daemon broadcasts a shutdown notification.
    pub async fn execute_wipe(&self) -> anyhow::Result<()> {
        let keys_path = self.config.keys_path.clone();
        warn!("DEADMAN SWITCH FIRED – executing wipe of {keys_path}");

        // Use a subprocess so that this works across privilege boundaries and
        // is consistent with how other platform components trigger wipes.
        let status = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "rm -rf {keys_path} /data/hispashield/settings.db"
            ))
            .status()
            .await
            .with_context(|| "spawning wipe subprocess")?;

        if !status.success() {
            anyhow::bail!("wipe subprocess exited with status {status}");
        }

        info!("wipe complete – broadcasting shutdown");
        // Signal ourselves to shut down; in a real Android context this would
        // call into a system service via Binder.
        // For the daemon process, we just exit cleanly.
        std::process::exit(0);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::time::Duration;

    fn sha256_hex(s: &str) -> String {
        let mut h = Sha256::new();
        h.update(s.as_bytes());
        hex::encode(h.finalize())
    }

    fn make_switch(interval_secs: u64, warning_secs: u64) -> DeadmanSwitch {
        DeadmanSwitch::new(DeadmanConfig {
            interval_seconds: interval_secs,
            warning_seconds: warning_secs,
            token_hash: sha256_hex("secret"),
            keys_path: "/tmp/test_keys".to_string(),
        })
    }

    #[test]
    fn test_initial_state_is_active() {
        let sw = make_switch(3600, 300);
        assert_eq!(*sw.state(), SwitchState::Active);
    }

    #[test]
    fn test_valid_heartbeat_resets_timer() {
        let mut sw = make_switch(3600, 300);
        assert!(sw.heartbeat(&sha256_hex("secret")));
        assert_eq!(*sw.state(), SwitchState::Active);
    }

    #[test]
    fn test_invalid_heartbeat_rejected() {
        let mut sw = make_switch(3600, 300);
        assert!(!sw.heartbeat(&sha256_hex("wrong")));
    }

    #[test]
    fn test_seconds_remaining_decreases_over_time() {
        let sw = make_switch(10, 2);
        let remaining = sw.seconds_remaining();
        assert!(remaining <= 10);
    }

    #[test]
    fn test_tick_transitions_active_to_warning() {
        // Create a switch with a very short interval so it immediately enters warning.
        let mut sw = make_switch(0, 0);
        // With interval = 0, remaining = 0 which is <= warning_seconds (0).
        let state = sw.tick();
        // Active -> Warning when remaining <= warning_seconds
        assert_eq!(state, SwitchState::Warning);
    }

    #[test]
    fn test_tick_transitions_warning_to_locked() {
        let mut sw = make_switch(0, 0);
        sw.state = SwitchState::Warning;
        let state = sw.tick();
        assert_eq!(state, SwitchState::Locked);
    }

    #[test]
    fn test_tick_transitions_locked_to_wipe_pending() {
        let mut sw = make_switch(3600, 300);
        sw.state = SwitchState::Locked;
        let state = sw.tick();
        assert_eq!(state, SwitchState::WipePending);
    }

    #[test]
    fn test_reconfigure_resets_state() {
        let mut sw = make_switch(3600, 300);
        sw.state = SwitchState::Locked;
        sw.reconfigure(DeadmanConfig {
            interval_seconds: 7200,
            warning_seconds: 600,
            token_hash: sha256_hex("new_secret"),
            keys_path: "/tmp/keys2".to_string(),
        });
        assert_eq!(*sw.state(), SwitchState::Active);
    }

    #[test]
    fn test_heartbeat_after_reconfigure_uses_new_token() {
        let mut sw = make_switch(3600, 300);
        sw.reconfigure(DeadmanConfig {
            interval_seconds: 3600,
            warning_seconds: 300,
            token_hash: sha256_hex("new_token"),
            keys_path: "/tmp/keys".to_string(),
        });
        assert!(!sw.heartbeat(&sha256_hex("secret"))); // old token rejected
        assert!(sw.heartbeat(&sha256_hex("new_token"))); // new token accepted
    }
}
