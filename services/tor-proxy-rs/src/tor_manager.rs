//! Tor process lifecycle manager.
//!
//! Writes a `torrc`, spawns the Tor binary, monitors stdout for the
//! "Bootstrapped 100%" line, and exposes control-port helpers.

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tracing::{debug, error, info, warn};

use crate::torrc::TorrcGenerator;

// ─── TorConfig ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TorConfig {
    /// SOCKS5 proxy port — default 9050.
    pub socks_port: u16,
    /// Control port — default 9051.
    pub control_port: u16,
    /// DNS-over-Tor port — default 5353.
    pub dns_port: u16,
    /// Transparent proxy (TransPort) — default 9040.
    pub transparent_port: u16,
    /// Directory for Tor state, keys, and logs.
    pub data_dir: String,
    /// Preferred exit-node country codes, e.g. `["{DE}", "{NL}"]`.
    pub exit_nodes: Vec<String>,
    /// Country codes to avoid as exit nodes, e.g. `["{US}", "{GB}"]`.
    pub exclude_exit_nodes: Vec<String>,
    /// Android application UIDs routed directly (emergency services, VoIP, etc.).
    pub bypass_uids: Vec<u32>,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            socks_port: 9050,
            control_port: 9051,
            dns_port: 5353,
            transparent_port: 9040,
            data_dir: "/data/hispashield/tor".to_string(),
            exit_nodes: vec!["{DE}".to_string(), "{NL}".to_string(), "{IS}".to_string()],
            exclude_exit_nodes: vec![
                "{US}".to_string(),
                "{GB}".to_string(),
                "{AU}".to_string(),
                "{CA}".to_string(),
                "{NZ}".to_string(),
            ],
            bypass_uids: vec![],
        }
    }
}

// ─── TorManager ──────────────────────────────────────────────────────────────

pub struct TorManager {
    pub config: TorConfig,
    tor_process: Option<Child>,
    pub circuit_established: bool,
    pub exit_country: Option<String>,
}

impl TorManager {
    pub fn new(config: TorConfig) -> Self {
        Self {
            config,
            tor_process: None,
            circuit_established: false,
            exit_country: None,
        }
    }

    /// Start Tor: write torrc → spawn process → wait for 100% bootstrap.
    pub async fn start(&mut self) -> Result<()> {
        if self.tor_process.is_some() {
            bail!("Tor is already running");
        }

        // Create data directory and write torrc
        std::fs::create_dir_all(&self.config.data_dir)
            .with_context(|| format!("Creating Tor data dir: {}", self.config.data_dir))?;
        TorrcGenerator::write(&self.config).context("Writing torrc")?;

        let torrc_path = format!("{}/torrc", self.config.data_dir);
        info!(torrc = %torrc_path, "Spawning Tor process");

        let mut child = Command::new("tor")
            .arg("-f")
            .arg(&torrc_path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("Spawning tor binary (is `tor` in PATH?)")?;

        // Monitor stdout for bootstrap completion
        let stdout = child
            .stdout
            .take()
            .context("Could not capture Tor stdout")?;

        let mut lines = BufReader::new(stdout).lines();
        let timeout = tokio::time::Duration::from_secs(120);

        let bootstrap_result = tokio::time::timeout(timeout, async {
            while let Ok(Some(line)) = lines.next_line().await {
                debug!(tor_log = %line);
                if line.contains("Bootstrapped 100%") {
                    return true;
                }
                if line.contains("Problem bootstrapping") || line.contains("[err]") {
                    error!(tor_log = %line, "Tor bootstrap error");
                    return false;
                }
            }
            false
        })
        .await;

        match bootstrap_result {
            Ok(true) => {
                info!("Tor bootstrapped successfully (100%)");
                self.circuit_established = true;
                self.exit_country = self.config.exit_nodes.first().map(|s| {
                    // Strip the {} brackets from e.g. "{DE}" → "DE"
                    s.trim_matches(|c| c == '{' || c == '}').to_string()
                });
            }
            Ok(false) => {
                let _ = child.kill().await;
                bail!("Tor failed to bootstrap");
            }
            Err(_elapsed) => {
                let _ = child.kill().await;
                bail!("Tor bootstrap timed out after 120 seconds");
            }
        }

        self.tor_process = Some(child);
        Ok(())
    }

    /// Gracefully stop Tor: SIGTERM → wait → SIGKILL if needed.
    pub async fn stop(&mut self) -> Result<()> {
        if let Some(mut child) = self.tor_process.take() {
            info!("Stopping Tor process");
            // Try graceful shutdown via control port first
            let _ = self.send_control_command("SIGNAL SHUTDOWN").await;

            // Give Tor 5 seconds to shut down gracefully
            let shutdown = tokio::time::timeout(
                tokio::time::Duration::from_secs(5),
                child.wait(),
            )
            .await;

            match shutdown {
                Ok(Ok(status)) => {
                    info!(status = ?status, "Tor exited cleanly");
                }
                _ => {
                    warn!("Tor did not exit in time, killing");
                    let _ = child.kill().await;
                }
            }
        } else {
            bail!("Tor is not running");
        }

        self.circuit_established = false;
        self.exit_country = None;
        Ok(())
    }

    /// Request a new Tor circuit via the control port (NEWNYM signal).
    ///
    /// Returns a human-readable confirmation string.
    pub async fn new_circuit(&self) -> Result<String> {
        if !self.is_running() {
            bail!("Tor is not running");
        }
        info!("Requesting new Tor circuit (NEWNYM)");
        let response = self
            .send_control_command("SIGNAL NEWNYM")
            .await
            .context("Sending NEWNYM to control port")?;
        Ok(response)
    }

    /// Query the control port for the current exit node info.
    ///
    /// Returns `(exit_fingerprint, exit_country)`.
    pub async fn get_exit_info(&self) -> Result<(String, String)> {
        if !self.is_running() {
            bail!("Tor is not running");
        }
        let response = self
            .send_control_command("GETINFO circuit-status")
            .await
            .context("Querying circuit status")?;

        // Parse out the last router fingerprint and country from the response
        // In a real implementation we would parse the full circuit-status reply.
        let country = self
            .exit_country
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

        // Extract a fingerprint-like token from the response
        let fingerprint = extract_fingerprint(&response)
            .unwrap_or_else(|| "UNKNOWN_FINGERPRINT".to_string());

        Ok((fingerprint, country))
    }

    /// Returns `true` if the Tor process is running.
    pub fn is_running(&self) -> bool {
        self.tor_process.is_some()
    }

    // ── Control port helpers ──────────────────────────────────────────────────

    /// Connect to the Tor control port, authenticate, send `command`, return reply.
    async fn send_control_command(&self, command: &str) -> Result<String> {
        let addr = format!("127.0.0.1:{}", self.config.control_port);
        let stream = TcpStream::connect(&addr)
            .await
            .with_context(|| format!("Connecting to Tor control port at {addr}"))?;

        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();

        // Cookie-based authentication is the default (see torrc).
        // For this simulation we use AUTHENTICATE with an empty password.
        writer
            .write_all(b"AUTHENTICATE\r\n")
            .await
            .context("Sending AUTHENTICATE")?;

        // Read auth response
        if let Ok(Some(auth_line)) = lines.next_line().await {
            if !auth_line.starts_with("250") {
                bail!("Authentication failed: {auth_line}");
            }
        }

        // Send the actual command
        writer
            .write_all(format!("{command}\r\n").as_bytes())
            .await
            .with_context(|| format!("Sending command: {command}"))?;

        // Collect response lines until we hit a terminal "250 OK" or "250-..." sequence
        let mut response_lines = Vec::new();
        while let Ok(Some(line)) = lines.next_line().await {
            let terminal = line.starts_with("250 ") || line.starts_with("5") || line.starts_with("4");
            response_lines.push(line);
            if terminal {
                break;
            }
        }

        // Send QUIT to close the connection cleanly
        let _ = writer.write_all(b"QUIT\r\n").await;

        Ok(response_lines.join("\n"))
    }
}

// ─── Parsing helpers ─────────────────────────────────────────────────────────

/// Extract a hex fingerprint from a circuit-status response (best-effort).
fn extract_fingerprint(response: &str) -> Option<String> {
    for token in response.split_whitespace() {
        // Fingerprints appear as $<40 hex chars> or just 40 hex chars
        let candidate = token.trim_start_matches('$');
        if candidate.len() == 40 && candidate.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(candidate.to_uppercase());
        }
    }
    None
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_ports() {
        let cfg = TorConfig::default();
        assert_eq!(cfg.socks_port, 9050);
        assert_eq!(cfg.control_port, 9051);
        assert_eq!(cfg.dns_port, 5353);
        assert_eq!(cfg.transparent_port, 9040);
    }

    #[test]
    fn default_config_excluded_countries() {
        let cfg = TorConfig::default();
        assert!(cfg.exclude_exit_nodes.contains(&"{US}".to_string()));
        assert!(cfg.exclude_exit_nodes.contains(&"{GB}".to_string()));
    }

    #[test]
    fn is_running_false_initially() {
        let mgr = TorManager::new(TorConfig::default());
        assert!(!mgr.is_running());
    }

    #[test]
    fn extract_fingerprint_valid() {
        let response = "250-circuit-status 1 BUILT $AABBCCDDEEFF00112233445566778899AABBCCDD~relay GENERAL";
        let fp = extract_fingerprint(response);
        assert_eq!(fp, Some("AABBCCDDEEFF00112233445566778899AABBCCDD".to_string()));
    }

    #[test]
    fn extract_fingerprint_none() {
        let response = "250 OK";
        let fp = extract_fingerprint(response);
        assert!(fp.is_none());
    }

    #[tokio::test]
    async fn new_circuit_fails_when_not_running() {
        let mgr = TorManager::new(TorConfig::default());
        assert!(mgr.new_circuit().await.is_err());
    }

    #[tokio::test]
    async fn stop_fails_when_not_running() {
        let mut mgr = TorManager::new(TorConfig::default());
        assert!(mgr.stop().await.is_err());
    }

    #[test]
    fn new_tor_manager() {
        let cfg = TorConfig {
            socks_port: 9150,
            control_port: 9151,
            dns_port: 5354,
            transparent_port: 9141,
            data_dir: "/tmp/tor-test".to_string(),
            exit_nodes: vec!["{CH}".to_string()],
            exclude_exit_nodes: vec!["{CN}".to_string()],
            bypass_uids: vec![2000, 3000],
        };
        let mgr = TorManager::new(cfg.clone());
        assert_eq!(mgr.config.socks_port, 9150);
        assert_eq!(mgr.config.bypass_uids, vec![2000, 3000]);
        assert!(!mgr.circuit_established);
        assert!(mgr.exit_country.is_none());
    }
}
