//! Integration tests for HispaShield security daemon components.
//!
//! These tests spin up real sockets and components to exercise the full
//! request/response cycle, not just unit-level logic.

#![allow(unused_imports)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, RwLock};

// ---------------------------------------------------------------------------
// Paths to shared source modules — adjust if running from workspace root
// ---------------------------------------------------------------------------
// NOTE: In a real workspace these tests would be declared in Cargo.toml as
// integration tests under the respective crate. Here we directly include the
// source modules for a self-contained integration test file.

// ============================================================
// 1. NetworkPolicyEngine tests
// ============================================================
mod network_policy {
    use std::collections::HashMap;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct NetworkRule {
        pub uid: u32,
        pub allow_domains: Vec<String>,
        pub deny_domains: Vec<String>,
        pub deny_all: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Decision {
        Allow,
        Deny,
        DefaultDeny,
    }

    pub struct PolicyEngine {
        rules: HashMap<u32, NetworkRule>,
    }

    impl PolicyEngine {
        pub fn new() -> Self {
            Self { rules: HashMap::new() }
        }

        pub fn load_from_json(json: &str) -> anyhow::Result<Self> {
            let rule_list: Vec<NetworkRule> = serde_json::from_str(json)?;
            let mut rules = HashMap::new();
            for r in rule_list {
                rules.insert(r.uid, r);
            }
            Ok(Self { rules })
        }

        pub fn add_rule(&mut self, rule: NetworkRule) {
            self.rules.insert(rule.uid, rule);
        }

        pub fn evaluate(&self, uid: u32, dest: &str) -> Decision {
            match self.rules.get(&uid) {
                None => Decision::DefaultDeny,
                Some(rule) => {
                    if rule.deny_all {
                        return Decision::Deny;
                    }
                    if rule.deny_domains.iter().any(|d| Self::matches(d, dest)) {
                        return Decision::Deny;
                    }
                    if rule.allow_domains.iter().any(|d| Self::matches(d, dest)) {
                        return Decision::Allow;
                    }
                    Decision::DefaultDeny
                }
            }
        }

        fn matches(pattern: &str, dest: &str) -> bool {
            if pattern == dest {
                return true;
            }
            if let Some(suffix) = pattern.strip_prefix("*.") {
                return dest.ends_with(suffix) || dest == suffix;
            }
            false
        }
    }

    // --- Tests ---
    #[cfg(test)]
    mod tests {
        use super::*;

        fn rule(uid: u32, allow: &[&str], deny: &[&str], deny_all: bool) -> NetworkRule {
            NetworkRule {
                uid,
                allow_domains: allow.iter().map(|s| s.to_string()).collect(),
                deny_domains: deny.iter().map(|s| s.to_string()).collect(),
                deny_all,
            }
        }

        #[test]
        fn unknown_uid_is_default_deny() {
            let engine = PolicyEngine::new();
            assert_eq!(engine.evaluate(9999, "example.com"), Decision::DefaultDeny);
        }

        #[test]
        fn exact_domain_allow() {
            let mut engine = PolicyEngine::new();
            engine.add_rule(rule(1000, &["example.com"], &[], false));
            assert_eq!(engine.evaluate(1000, "example.com"), Decision::Allow);
        }

        #[test]
        fn wildcard_subdomain_allow() {
            let mut engine = PolicyEngine::new();
            engine.add_rule(rule(1000, &["*.google.com"], &[], false));
            assert_eq!(engine.evaluate(1000, "maps.google.com"), Decision::Allow);
            assert_eq!(engine.evaluate(1000, "api.google.com"), Decision::Allow);
            assert_eq!(engine.evaluate(1000, "evil.com"), Decision::DefaultDeny);
        }

        #[test]
        fn deny_all_overrides_allow_list() {
            let mut engine = PolicyEngine::new();
            engine.add_rule(rule(1001, &["ok.com"], &[], true));
            assert_eq!(engine.evaluate(1001, "ok.com"), Decision::Deny);
        }

        #[test]
        fn deny_list_beats_allow_list() {
            let mut engine = PolicyEngine::new();
            engine.add_rule(rule(1002, &["*.safe.net"], &["tracker.safe.net"], false));
            assert_eq!(engine.evaluate(1002, "cdn.safe.net"), Decision::Allow);
            assert_eq!(engine.evaluate(1002, "tracker.safe.net"), Decision::Deny);
        }

        #[test]
        fn load_from_json() {
            let json = r#"[
                {"uid": 2000, "allow_domains": ["update.example.com"], "deny_domains": [], "deny_all": false},
                {"uid": 2001, "allow_domains": [], "deny_domains": [], "deny_all": true}
            ]"#;
            let engine = PolicyEngine::load_from_json(json).unwrap();
            assert_eq!(engine.evaluate(2000, "update.example.com"), Decision::Allow);
            assert_eq!(engine.evaluate(2000, "other.com"), Decision::DefaultDeny);
            assert_eq!(engine.evaluate(2001, "any.com"), Decision::Deny);
        }

        #[test]
        fn ip_address_exact_match() {
            let mut engine = PolicyEngine::new();
            engine.add_rule(rule(3000, &["192.168.1.1"], &[], false));
            assert_eq!(engine.evaluate(3000, "192.168.1.1"), Decision::Allow);
            assert_eq!(engine.evaluate(3000, "192.168.1.2"), Decision::DefaultDeny);
        }
    }
}

// ============================================================
// 2. SensorGuard token tests
// ============================================================
mod sensor_guard_tests {
    use std::time::{Duration, Instant};
    use std::collections::HashMap;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum SensorKind {
        Camera,
        Microphone,
        Gps,
        Accelerometer,
        Gyroscope,
        Barometer,
    }

    #[derive(Debug, Clone)]
    pub struct AccessToken {
        pub token_id: u64,
        pub uid: u32,
        pub sensor: SensorKind,
        granted_at: Instant,
        ttl: Duration,
    }

    impl AccessToken {
        pub fn new(id: u64, uid: u32, sensor: SensorKind, ttl: Duration) -> Self {
            Self { token_id: id, uid, sensor, granted_at: Instant::now(), ttl }
        }

        pub fn is_valid(&self) -> bool {
            self.granted_at.elapsed() < self.ttl
        }
    }

    pub struct Guard {
        permissions: HashMap<u32, Vec<SensorKind>>,
        tokens: HashMap<u64, AccessToken>,
        next_id: u64,
    }

    impl Guard {
        pub fn new() -> Self {
            Self { permissions: HashMap::new(), tokens: HashMap::new(), next_id: 1 }
        }

        pub fn grant_permission(&mut self, uid: u32, sensors: Vec<SensorKind>) {
            self.permissions.insert(uid, sensors);
        }

        pub fn request(&mut self, uid: u32, sensor: SensorKind, ttl: Duration) -> Option<u64> {
            let allowed = self.permissions.get(&uid)
                .map(|s| s.contains(&sensor))
                .unwrap_or(false);
            if !allowed {
                return None;
            }
            let id = self.next_id;
            self.next_id += 1;
            self.tokens.insert(id, AccessToken::new(id, uid, sensor, ttl));
            Some(id)
        }

        pub fn validate(&self, token_id: u64) -> Option<&AccessToken> {
            self.tokens.get(&token_id).filter(|t| t.is_valid())
        }

        pub fn revoke(&mut self, token_id: u64) -> bool {
            self.tokens.remove(&token_id).is_some()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn token_grant_and_validate() {
            let mut g = Guard::new();
            g.grant_permission(1000, vec![SensorKind::Camera]);
            let id = g.request(1000, SensorKind::Camera, Duration::from_secs(300)).unwrap();
            assert!(g.validate(id).is_some());
        }

        #[test]
        fn deny_unpermitted_sensor() {
            let mut g = Guard::new();
            g.grant_permission(1000, vec![SensorKind::Gps]);
            assert!(g.request(1000, SensorKind::Microphone, Duration::from_secs(60)).is_none());
        }

        #[test]
        fn revoke_removes_token() {
            let mut g = Guard::new();
            g.grant_permission(2000, vec![SensorKind::Accelerometer]);
            let id = g.request(2000, SensorKind::Accelerometer, Duration::from_secs(60)).unwrap();
            assert!(g.validate(id).is_some());
            g.revoke(id);
            assert!(g.validate(id).is_none());
        }

        #[test]
        fn expired_token_invalid() {
            let mut g = Guard::new();
            g.grant_permission(3000, vec![SensorKind::Gyroscope]);
            let id = g.request(3000, SensorKind::Gyroscope, Duration::from_nanos(1)).unwrap();
            // Sleep enough to let the 1ns TTL expire
            std::thread::sleep(Duration::from_millis(10));
            assert!(g.validate(id).is_none());
        }

        #[test]
        fn unknown_uid_denied() {
            let mut g = Guard::new();
            assert!(g.request(9999, SensorKind::Barometer, Duration::from_secs(60)).is_none());
        }

        #[test]
        fn multiple_sensors_for_uid() {
            let mut g = Guard::new();
            g.grant_permission(4000, vec![SensorKind::Camera, SensorKind::Microphone, SensorKind::Gps]);
            let t1 = g.request(4000, SensorKind::Camera, Duration::from_secs(60)).unwrap();
            let t2 = g.request(4000, SensorKind::Gps, Duration::from_secs(60)).unwrap();
            assert_ne!(t1, t2);
            assert!(g.validate(t1).is_some());
            assert!(g.validate(t2).is_some());
        }
    }
}

// ============================================================
// 3. SecureStore atomic write tests
// ============================================================
mod secure_store_tests {
    use std::collections::{HashMap, HashSet};
    use std::path::{Path, PathBuf};

    #[derive(Debug, Default)]
    struct StorageData {
        settings: HashMap<String, String>,
        locked: HashSet<String>,
    }

    pub struct SecureStore {
        data: StorageData,
        path: PathBuf,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub enum StoreError {
        InvalidNamespace,
        KeyLocked,
        NotFound,
        Io(String),
        Json(String),
    }

    const NAMESPACES: &[&str] = &["system.", "secure.", "global.", "hispashield."];

    fn valid_ns(key: &str) -> bool {
        NAMESPACES.iter().any(|ns| key.starts_with(ns) && key.len() > ns.len())
    }

    impl SecureStore {
        pub fn new(path: impl Into<PathBuf>) -> Self {
            Self { data: StorageData::default(), path: path.into() }
        }

        pub fn set(&mut self, key: &str, val: String) -> Result<(), StoreError> {
            if !valid_ns(key) { return Err(StoreError::InvalidNamespace); }
            if self.data.locked.contains(key) { return Err(StoreError::KeyLocked); }
            self.data.settings.insert(key.to_string(), val);
            self.flush()
        }

        pub fn get(&self, key: &str) -> Result<String, StoreError> {
            if !valid_ns(key) { return Err(StoreError::InvalidNamespace); }
            self.data.settings.get(key).cloned().ok_or(StoreError::NotFound)
        }

        pub fn delete(&mut self, key: &str) -> Result<(), StoreError> {
            if !valid_ns(key) { return Err(StoreError::InvalidNamespace); }
            if self.data.locked.contains(key) { return Err(StoreError::KeyLocked); }
            self.data.settings.remove(key);
            self.flush()
        }

        pub fn lock(&mut self, key: &str) -> Result<(), StoreError> {
            if !valid_ns(key) { return Err(StoreError::InvalidNamespace); }
            self.data.locked.insert(key.to_string());
            self.flush()
        }

        fn flush(&self) -> Result<(), StoreError> {
            // Atomic write: write to .tmp then rename
            let tmp = self.path.with_extension("tmp");
            let json = format!(
                "{{\"settings\":{:?},\"locked\":{:?}}}",
                self.data.settings,
                self.data.locked
            );
            std::fs::write(&tmp, json.as_bytes())
                .map_err(|e| StoreError::Io(e.to_string()))?;
            std::fs::rename(&tmp, &self.path)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::env;

        fn tmp_store() -> SecureStore {
            let mut p = env::temp_dir();
            p.push(format!("hispashield_store_test_{}.json", std::process::id()));
            SecureStore::new(p)
        }

        #[test]
        fn basic_set_get() {
            let mut s = tmp_store();
            s.set("system.theme", "dark".into()).unwrap();
            assert_eq!(s.get("system.theme").unwrap(), "dark");
        }

        #[test]
        fn invalid_namespace_rejected() {
            let mut s = tmp_store();
            assert_eq!(s.set("unknown.key", "v".into()), Err(StoreError::InvalidNamespace));
            assert_eq!(s.get("bad"), Err(StoreError::InvalidNamespace));
        }

        #[test]
        fn locked_key_immutable() {
            let mut s = tmp_store();
            s.set("hispashield.boot_mode", "verified".into()).unwrap();
            s.lock("hispashield.boot_mode").unwrap();
            assert_eq!(
                s.set("hispashield.boot_mode", "unverified".into()),
                Err(StoreError::KeyLocked)
            );
            assert_eq!(
                s.delete("hispashield.boot_mode"),
                Err(StoreError::KeyLocked)
            );
            // Still readable
            assert_eq!(s.get("hispashield.boot_mode").unwrap(), "verified");
        }

        #[test]
        fn delete_removes_key() {
            let mut s = tmp_store();
            s.set("global.wifi_enabled", "true".into()).unwrap();
            s.delete("global.wifi_enabled").unwrap();
            assert_eq!(s.get("global.wifi_enabled"), Err(StoreError::NotFound));
        }

        #[test]
        fn atomic_write_leaves_no_tmp_on_success() {
            let mut s = tmp_store();
            s.set("secure.test_key", "value".into()).unwrap();
            // The .tmp file should not exist after a successful write
            let tmp = s.path.with_extension("tmp");
            assert!(!tmp.exists(), ".tmp file should have been renamed away");
        }

        #[test]
        fn all_valid_namespaces_accepted() {
            let mut s = tmp_store();
            for key in &["system.a", "secure.b", "global.c", "hispashield.d"] {
                assert!(s.set(key, "v".into()).is_ok(), "Namespace should be valid: {}", key);
            }
        }
    }
}

// ============================================================
// 4. Async socket round-trip test (Tokio)
// ============================================================
#[cfg(test)]
mod socket_roundtrip_tests {
    use std::path::PathBuf;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};

    /// Minimal echo server that we use to verify the line-delimited JSON
    /// protocol framing works correctly end-to-end.
    async fn run_echo_server(path: PathBuf) {
        if path.exists() { std::fs::remove_file(&path).unwrap(); }
        let listener = UnixListener::bind(&path).unwrap();
        // Accept exactly one connection
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        while let Some(line) = lines.next_line().await.unwrap() {
            let mut resp = line;
            resp.push('\n');
            writer.write_all(resp.as_bytes()).await.unwrap();
        }
    }

    #[tokio::test]
    async fn unix_socket_echo_roundtrip() {
        let mut sock_path = std::env::temp_dir();
        sock_path.push(format!("hispashield_echo_test_{}.sock", std::process::id()));

        let server_path = sock_path.clone();
        tokio::spawn(async move { run_echo_server(server_path).await });

        // Give server a moment to bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut stream = UnixStream::connect(&sock_path).await.unwrap();
        let msg = "{\"uid\": 1000, \"dest\": \"example.com\"}\n";
        stream.write_all(msg.as_bytes()).await.unwrap();

        let (reader, _) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        let response = lines.next_line().await.unwrap().unwrap();

        assert_eq!(response, "{\"uid\": 1000, \"dest\": \"example.com\"}");

        // Cleanup
        let _ = std::fs::remove_file(&sock_path);
    }
}
