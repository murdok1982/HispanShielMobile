use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use tracing::warn;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// A single cellular network observation collected from the modem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellObservation {
    /// Received signal strength indicator in dBm (typical range −140 to −40).
    pub rssi: i32,
    /// Cell ID reported by the base station.
    pub cell_id: u32,
    /// Location Area Code (GSM/UMTS) or Tracking Area Code (LTE/NR).
    pub lac: u16,
    /// Mobile Country Code.
    pub mcc: u16,
    /// Mobile Network Code.
    pub mnc: u16,
    /// Radio access technology: "GSM", "UMTS", "LTE", "NR".
    pub tech: String,
    /// Unix timestamp (seconds) when this observation was recorded.
    #[serde(default)]
    pub timestamp: u64,
}

impl CellObservation {
    /// Return current Unix time as a convenience for constructing observations.
    pub fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Risk assessment result produced by the detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImsiCatcherRisk {
    /// Composite risk score from 0 (no risk) to 100 (high confidence).
    pub score: u8,
    /// Human-readable indicators that contributed to the score.
    pub indicators: Vec<String>,
    /// Recommended user action.
    pub recommendation: String,
}

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

/// Sliding-window IMSI Catcher detector.
///
/// Maintains a ring buffer of the last 100 cell observations and applies
/// multiple heuristic checks on each `analyze()` call.
pub struct ImsiCatcherDetector {
    history: VecDeque<CellObservation>,
}

impl ImsiCatcherDetector {
    /// Maximum number of observations retained in the sliding window.
    const MAX_HISTORY: usize = 100;

    /// RSSI threshold above which a signal is considered suspiciously strong
    /// (typical legitimate cells stay below −60 dBm at street level).
    const SUSPICIOUSLY_STRONG_RSSI_DBM: i32 = -50;

    /// Maximum number of distinct cell towers seen in a short window before
    /// flagging rapid-tower-change behaviour.
    const RAPID_CHANGE_COUNT: usize = 5;

    /// Time window (seconds) for rapid-tower-change analysis.
    const RAPID_CHANGE_WINDOW_SECS: u64 = 120;

    pub fn new() -> Self {
        Self {
            history: VecDeque::with_capacity(Self::MAX_HISTORY),
        }
    }

    /// Record a new observation.  Oldest entries are evicted when the buffer
    /// is full.
    pub fn observe(&mut self, obs: CellObservation) {
        if self.history.len() >= Self::MAX_HISTORY {
            self.history.pop_front();
        }
        self.history.push_back(obs);
    }

    /// Run all heuristic checks and return a composite risk assessment.
    pub fn analyze(&self) -> ImsiCatcherRisk {
        let mut score: u32 = 0;
        let mut indicators: Vec<String> = Vec::new();

        // -----------------------------------------------------------------
        // Heuristic 1 — forced 2G downgrade (classic IMSI catcher trick)
        // -----------------------------------------------------------------
        // An IMSI catcher typically forces the phone to connect via GSM (2G)
        // because UMTS/LTE mutual authentication is harder to bypass.
        if let Some(downgrade) = self.detect_tech_downgrade() {
            score += 35;
            indicators.push(downgrade);
        }

        // -----------------------------------------------------------------
        // Heuristic 2 — suspiciously strong signal from an unfamiliar cell
        // -----------------------------------------------------------------
        // An IMSI catcher is physically close to the target, so its signal
        // is abnormally strong.  Combined with an unknown cell ID, this is
        // a strong indicator.
        if let Some(strong) = self.detect_strong_unknown_cell() {
            score += 30;
            indicators.push(strong);
        }

        // -----------------------------------------------------------------
        // Heuristic 3 — rapid cell tower changes (device is being followed)
        // -----------------------------------------------------------------
        if let Some(rapid) = self.detect_rapid_tower_changes() {
            score += 20;
            indicators.push(rapid);
        }

        // -----------------------------------------------------------------
        // Heuristic 4 — unusual LAC for the observed MCC/MNC
        // -----------------------------------------------------------------
        // Many public LAC databases are available; here we use a minimal
        // embedded heuristic (LAC 0 or LAC > 65000 are suspicious).
        if let Some(lac) = self.detect_unusual_lac() {
            score += 15;
            indicators.push(lac);
        }

        // -----------------------------------------------------------------
        // Heuristic 5 — cell ID outside plausible range for the area
        // -----------------------------------------------------------------
        // Some IMSI catchers use cell IDs that are conspicuously low (0, 1)
        // or far outside the range expected for the operator's network plan.
        if let Some(cid) = self.detect_suspicious_cell_id() {
            score += 10;
            indicators.push(cid);
        }

        // -----------------------------------------------------------------
        // Heuristic 6 — encryption mode indication (GSM A5/0 – no encryption)
        // -----------------------------------------------------------------
        // Real operators almost never disable encryption; IMSI catchers often
        // do to enable eavesdropping.  We can only detect this if the modem
        // exposes the cipher indicator – we flag if the current connection is
        // GSM with no encryption field set (tech == "GSM" and rssi very strong).
        if let Some(enc) = self.detect_possible_no_encryption() {
            score += 20;
            indicators.push(enc);
        }

        let score = score.min(100) as u8;

        let recommendation = if score >= 70 {
            warn!("IMSI Catcher risk HIGH (score={score}) – recommend enabling airplane mode");
            "HIGH RISK: Enable airplane mode immediately and move to a different location."
                .to_string()
        } else if score >= 40 {
            "MODERATE RISK: Avoid sensitive calls. Consider enabling airplane mode.".to_string()
        } else if score > 0 {
            "LOW RISK: Some anomalies detected. Continue monitoring.".to_string()
        } else {
            "No indicators detected. Network appears legitimate.".to_string()
        };

        ImsiCatcherRisk {
            score,
            indicators,
            recommendation,
        }
    }

    // -----------------------------------------------------------------------
    // Individual heuristic methods
    // -----------------------------------------------------------------------

    /// Detect a transition from a higher-generation technology (LTE/NR) down
    /// to GSM within the observation window.
    fn detect_tech_downgrade(&self) -> Option<String> {
        if self.history.len() < 2 {
            return None;
        }
        // Walk backwards; look for a LTE/NR→GSM transition in the most recent
        // observations.
        let recent: Vec<&CellObservation> = self.history.iter().rev().take(10).collect();
        let current_tech = &recent[0].tech;
        let current_is_2g = current_tech.eq_ignore_ascii_case("GSM");

        if !current_is_2g {
            return None;
        }

        let previously_higher = recent.iter().skip(1).any(|o| {
            let t = o.tech.to_uppercase();
            t == "LTE" || t == "NR" || t == "UMTS"
        });

        if previously_higher {
            Some(format!(
                "Technology downgrade to GSM detected (was previously connected via LTE/NR/UMTS)"
            ))
        } else {
            None
        }
    }

    /// Detect an abnormally strong signal from a cell that has not appeared
    /// in previous observations (implying a new, physically-close transmitter).
    fn detect_strong_unknown_cell(&self) -> Option<String> {
        let latest = self.history.back()?;
        if latest.rssi > Self::SUSPICIOUSLY_STRONG_RSSI_DBM {
            // Check whether this cell_id appeared in earlier observations.
            let seen_before = self
                .history
                .iter()
                .rev()
                .skip(1)
                .any(|o| o.cell_id == latest.cell_id);
            if !seen_before {
                return Some(format!(
                    "Unusually strong signal ({} dBm) from previously-unseen cell_id={}",
                    latest.rssi, latest.cell_id
                ));
            }
        }
        None
    }

    /// Detect an unusually high number of distinct cell towers in a short time
    /// window, which may indicate that a mobile IMSI catcher is following the
    /// target.
    fn detect_rapid_tower_changes(&self) -> Option<String> {
        let now = self
            .history
            .back()
            .map(|o| o.timestamp)
            .unwrap_or_else(CellObservation::now_secs);

        let window_start = now.saturating_sub(Self::RAPID_CHANGE_WINDOW_SECS);
        let recent: Vec<&CellObservation> = self
            .history
            .iter()
            .filter(|o| o.timestamp >= window_start)
            .collect();

        let mut unique_cells: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for obs in &recent {
            unique_cells.insert(obs.cell_id);
        }

        if unique_cells.len() >= Self::RAPID_CHANGE_COUNT {
            Some(format!(
                "Rapid cell tower changes: {} distinct cells in {}s window",
                unique_cells.len(),
                Self::RAPID_CHANGE_WINDOW_SECS
            ))
        } else {
            None
        }
    }

    /// Detect a LAC that is outside the expected range for the observed
    /// MCC/MNC, or is one of the commonly-abused sentinel values (0, 65535).
    fn detect_unusual_lac(&self) -> Option<String> {
        let latest = self.history.back()?;
        // LAC 0 or 65535 (0xFFFF) are invalid in 3GPP specs and used by
        // some IMSI catchers.
        if latest.lac == 0 || latest.lac == 0xFFFF {
            return Some(format!(
                "Invalid LAC value {} (must not be 0 or 65535 per 3GPP TS 24.008)",
                latest.lac
            ));
        }
        // Very high LAC values (above 60000) are allocated only sparsely in
        // most European/North-American operator plans.
        if latest.lac > 60_000 {
            return Some(format!(
                "Unusually high LAC={} for MCC={} MNC={} – possible fake base station",
                latest.lac, latest.mcc, latest.mnc
            ));
        }
        None
    }

    /// Detect suspicious cell IDs.  In GSM, cell IDs above 65535 are invalid.
    /// IMSI catchers often use low sentinel values (0, 1) or values that
    /// appear to be randomly generated outside the operator's assignment range.
    fn detect_suspicious_cell_id(&self) -> Option<String> {
        let latest = self.history.back()?;
        if latest.cell_id == 0 || latest.cell_id == 1 {
            return Some(format!(
                "Suspicious cell_id={} – very low value rarely used by legitimate operators",
                latest.cell_id
            ));
        }
        // For GSM, valid cell IDs are 0–65535; values above that indicate a
        // protocol violation that some IMSI catchers exhibit.
        let is_gsm = latest.tech.eq_ignore_ascii_case("GSM");
        if is_gsm && latest.cell_id > 65_535 {
            return Some(format!(
                "Cell ID {} exceeds GSM maximum (65535) – protocol anomaly",
                latest.cell_id
            ));
        }
        None
    }

    /// Heuristic proxy for detecting unencrypted GSM connections.
    ///
    /// Real modems expose an encryption indicator, but since we only have
    /// RSSI + metadata here, we flag the combination of: GSM technology,
    /// abnormally high signal strength, and a cell that was not seen before.
    /// This is a weaker signal than the dedicated cipher indicator but adds
    /// to the composite score appropriately.
    fn detect_possible_no_encryption(&self) -> Option<String> {
        let latest = self.history.back()?;
        let is_gsm = latest.tech.eq_ignore_ascii_case("GSM");
        if is_gsm && latest.rssi > -60 {
            // Combine with unknown cell check.
            let seen_before = self
                .history
                .iter()
                .rev()
                .skip(1)
                .any(|o| o.cell_id == latest.cell_id);
            if !seen_before {
                return Some(format!(
                    "GSM connection ({} dBm) to unknown cell – possible A5/0 no-encryption IMSI catcher",
                    latest.rssi
                ));
            }
        }
        None
    }

    /// Return the number of observations currently in the history buffer.
    pub fn observation_count(&self) -> usize {
        self.history.len()
    }
}

impl Default for ImsiCatcherDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(rssi: i32, cell_id: u32, lac: u16, mcc: u16, mnc: u16, tech: &str, ts: u64) -> CellObservation {
        CellObservation {
            rssi,
            cell_id,
            lac,
            mcc,
            mnc,
            tech: tech.to_string(),
            timestamp: ts,
        }
    }

    #[test]
    fn test_no_observations_gives_zero_score() {
        let detector = ImsiCatcherDetector::new();
        let risk = detector.analyze();
        assert_eq!(risk.score, 0);
        assert!(risk.indicators.is_empty());
    }

    #[test]
    fn test_single_normal_observation() {
        let mut det = ImsiCatcherDetector::new();
        det.observe(obs(-85, 54321, 1234, 214, 7, "LTE", 1000));
        let risk = det.analyze();
        assert_eq!(risk.score, 0, "single normal LTE observation should score 0");
    }

    #[test]
    fn test_tech_downgrade_lte_to_gsm_detected() {
        let mut det = ImsiCatcherDetector::new();
        det.observe(obs(-85, 54321, 1234, 214, 7, "LTE", 1000));
        det.observe(obs(-85, 54321, 1234, 214, 7, "LTE", 1010));
        det.observe(obs(-90, 99999, 1234, 214, 7, "GSM", 1020));
        let risk = det.analyze();
        assert!(risk.score > 0);
        assert!(risk.indicators.iter().any(|i| i.contains("downgrade")));
    }

    #[test]
    fn test_strong_unknown_cell_detected() {
        let mut det = ImsiCatcherDetector::new();
        det.observe(obs(-85, 10000, 5000, 214, 7, "LTE", 1000));
        // New cell with very strong signal
        det.observe(obs(-30, 99999, 5000, 214, 7, "LTE", 1010));
        let risk = det.analyze();
        assert!(risk.indicators.iter().any(|i| i.contains("strong signal")));
    }

    #[test]
    fn test_invalid_lac_zero_detected() {
        let mut det = ImsiCatcherDetector::new();
        det.observe(obs(-85, 54321, 0, 214, 7, "LTE", 1000));
        let risk = det.analyze();
        assert!(risk.indicators.iter().any(|i| i.contains("Invalid LAC")));
    }

    #[test]
    fn test_invalid_lac_65535_detected() {
        let mut det = ImsiCatcherDetector::new();
        det.observe(obs(-85, 54321, 0xFFFF, 214, 7, "LTE", 1000));
        let risk = det.analyze();
        assert!(risk.indicators.iter().any(|i| i.contains("Invalid LAC")));
    }

    #[test]
    fn test_suspicious_cell_id_zero() {
        let mut det = ImsiCatcherDetector::new();
        det.observe(obs(-85, 0, 5000, 214, 7, "GSM", 1000));
        let risk = det.analyze();
        assert!(risk.indicators.iter().any(|i| i.contains("cell_id=0")));
    }

    #[test]
    fn test_rapid_tower_changes_detected() {
        let mut det = ImsiCatcherDetector::new();
        let base_ts = 1_000_000u64;
        // 6 different cells within 2-minute window
        for cell_id in 1000..1006 {
            det.observe(obs(-85, cell_id, 5000, 214, 7, "LTE", base_ts + cell_id as u64 * 10));
        }
        let risk = det.analyze();
        assert!(risk.indicators.iter().any(|i| i.contains("Rapid cell")));
    }

    #[test]
    fn test_high_score_for_combined_indicators() {
        let mut det = ImsiCatcherDetector::new();
        let ts = 1_000_000u64;
        // Start on LTE
        det.observe(obs(-85, 54321, 1234, 214, 7, "LTE", ts));
        // Downgrade to GSM with invalid LAC, strong signal, new unknown cell
        det.observe(obs(-30, 0, 0, 214, 7, "GSM", ts + 10));
        let risk = det.analyze();
        assert!(
            risk.score >= 50,
            "combined indicators should yield high score, got {}",
            risk.score
        );
    }

    #[test]
    fn test_history_capped_at_max() {
        let mut det = ImsiCatcherDetector::new();
        for i in 0..150u32 {
            det.observe(obs(-85, i, 1000, 214, 7, "LTE", i as u64 * 10));
        }
        assert_eq!(det.observation_count(), ImsiCatcherDetector::MAX_HISTORY);
    }

    #[test]
    fn test_recommendation_high_risk() {
        let mut det = ImsiCatcherDetector::new();
        let ts = 1_000_000u64;
        det.observe(obs(-85, 54321, 1234, 214, 7, "LTE", ts));
        det.observe(obs(-30, 0, 0, 214, 7, "GSM", ts + 10));
        let risk = det.analyze();
        if risk.score >= 70 {
            assert!(risk.recommendation.contains("airplane mode"));
        }
    }
}
