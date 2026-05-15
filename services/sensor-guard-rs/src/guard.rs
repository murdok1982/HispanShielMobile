use std::collections::HashMap;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

#[derive(Debug, Error)]
pub enum GuardError {
    #[error("Permission denied for UID {uid} sensor {sensor:?}")]
    PermissionDenied { uid: u32, sensor: SensorKind },
    #[error("Token expired")]
    TokenExpired,
    #[error("Unknown token")]
    UnknownToken,
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorKind {
    Camera,
    Microphone,
    Gps,
    Accelerometer,
    Gyroscope,
    Barometer,
}

impl std::fmt::Display for SensorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            SensorKind::Camera => "camera",
            SensorKind::Microphone => "microphone",
            SensorKind::Gps => "gps",
            SensorKind::Accelerometer => "accelerometer",
            SensorKind::Gyroscope => "gyroscope",
            SensorKind::Barometer => "barometer",
        };
        write!(f, "{}", name)
    }
}

/// A time-limited access token granting a specific UID access to a specific sensor.
#[derive(Debug, Clone)]
pub struct AccessToken {
    pub token_id: u64,
    pub uid: u32,
    pub sensor: SensorKind,
    pub granted_at: Instant,
    pub ttl: Duration,
}

impl AccessToken {
    pub fn is_valid(&self) -> bool {
        self.granted_at.elapsed() < self.ttl
    }

    pub fn remaining(&self) -> Duration {
        let elapsed = self.granted_at.elapsed();
        if elapsed >= self.ttl {
            Duration::ZERO
        } else {
            self.ttl - elapsed
        }
    }
}

/// Per-UID sensor permissions configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SensorPermissions {
    pub uid: u32,
    pub allowed_sensors: Vec<SensorKind>,
    /// Default TTL in seconds for granted tokens
    #[serde(default = "default_ttl_secs")]
    pub token_ttl_secs: u64,
}

fn default_ttl_secs() -> u64 {
    300 // 5 minutes
}

pub struct SensorGuard {
    /// Permissions indexed by UID
    permissions: HashMap<u32, SensorPermissions>,
    /// Active access tokens indexed by token_id
    active_tokens: HashMap<u64, AccessToken>,
    /// Monotonically increasing token ID counter
    next_token_id: u64,
}

impl SensorGuard {
    pub fn new() -> Self {
        Self {
            permissions: HashMap::new(),
            active_tokens: HashMap::new(),
            next_token_id: 1,
        }
    }

    pub fn load_permissions(&mut self, perms: Vec<SensorPermissions>) {
        for perm in perms {
            self.permissions.insert(perm.uid, perm);
        }
        info!("Loaded permissions for {} UIDs", self.permissions.len());
    }

    /// Request access to a sensor. Returns an AccessToken on success.
    pub fn request_access(
        &mut self,
        uid: u32,
        sensor: SensorKind,
    ) -> Result<AccessToken, GuardError> {
        // Log the attempt regardless of outcome
        info!(
            uid,
            sensor = %sensor,
            "Sensor access requested"
        );

        let perms = self.permissions.get(&uid);
        let allowed = perms
            .map(|p| p.allowed_sensors.contains(&sensor))
            .unwrap_or(false);

        if !allowed {
            warn!(uid, sensor = %sensor, "Sensor access DENIED");
            return Err(GuardError::PermissionDenied { uid, sensor });
        }

        let ttl_secs = perms.map(|p| p.token_ttl_secs).unwrap_or(300);
        let token_id = self.next_token_id;
        self.next_token_id += 1;

        let token = AccessToken {
            token_id,
            uid,
            sensor,
            granted_at: Instant::now(),
            ttl: Duration::from_secs(ttl_secs),
        };

        info!(
            uid,
            sensor = %sensor,
            token_id,
            ttl_secs,
            "Sensor access GRANTED"
        );

        self.active_tokens.insert(token_id, token.clone());
        Ok(token)
    }

    /// Validate an existing token by ID.
    pub fn validate_token(&self, token_id: u64) -> Result<&AccessToken, GuardError> {
        match self.active_tokens.get(&token_id) {
            None => {
                warn!(token_id, "Token validation failed: unknown token");
                Err(GuardError::UnknownToken)
            }
            Some(token) if !token.is_valid() => {
                warn!(token_id, uid = token.uid, sensor = %token.sensor, "Token validation failed: expired");
                Err(GuardError::TokenExpired)
            }
            Some(token) => {
                debug!(
                    token_id,
                    remaining_secs = token.remaining().as_secs(),
                    "Token valid"
                );
                Ok(token)
            }
        }
    }

    /// Revoke a token explicitly.
    pub fn revoke_token(&mut self, token_id: u64) -> bool {
        if self.active_tokens.remove(&token_id).is_some() {
            info!(token_id, "Token revoked");
            true
        } else {
            false
        }
    }

    /// Purge all expired tokens (garbage collection).
    pub fn purge_expired(&mut self) -> usize {
        let before = self.active_tokens.len();
        self.active_tokens.retain(|_, t| t.is_valid());
        let purged = before - self.active_tokens.len();
        if purged > 0 {
            info!(purged, "Expired tokens purged");
        }
        purged
    }

    pub fn active_token_count(&self) -> usize {
        self.active_tokens.len()
    }
}

impl Default for SensorGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_perms(uid: u32, sensors: &[SensorKind]) -> SensorPermissions {
        SensorPermissions {
            uid,
            allowed_sensors: sensors.to_vec(),
            token_ttl_secs: 300,
        }
    }

    #[test]
    fn test_grant_and_validate() {
        let mut guard = SensorGuard::new();
        guard.load_permissions(vec![make_perms(1000, &[SensorKind::Camera])]);
        let token = guard.request_access(1000, SensorKind::Camera).unwrap();
        assert!(guard.validate_token(token.token_id).is_ok());
    }

    #[test]
    fn test_deny_unpermitted_sensor() {
        let mut guard = SensorGuard::new();
        guard.load_permissions(vec![make_perms(1000, &[SensorKind::Camera])]);
        assert!(matches!(
            guard.request_access(1000, SensorKind::Microphone),
            Err(GuardError::PermissionDenied { .. })
        ));
    }

    #[test]
    fn test_revoke_token() {
        let mut guard = SensorGuard::new();
        guard.load_permissions(vec![make_perms(1000, &[SensorKind::Gps])]);
        let token = guard.request_access(1000, SensorKind::Gps).unwrap();
        guard.revoke_token(token.token_id);
        assert!(matches!(
            guard.validate_token(token.token_id),
            Err(GuardError::UnknownToken)
        ));
    }

    #[test]
    fn test_unknown_uid_denied() {
        let mut guard = SensorGuard::new();
        assert!(matches!(
            guard.request_access(9999, SensorKind::Accelerometer),
            Err(GuardError::PermissionDenied { .. })
        ));
    }
}
