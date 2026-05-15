use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Qualitative risk levels for IMSI-based triangulation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "Low"),
            RiskLevel::Medium => write!(f, "Medium"),
            RiskLevel::High => write!(f, "High"),
            RiskLevel::Critical => write!(f, "Critical"),
        }
    }
}

/// Output of the triangulation risk assessment.
#[derive(Debug, Serialize, Deserialize)]
pub struct TriangulationRisk {
    pub risk_level: RiskLevel,
    pub reasons: Vec<String>,
    pub recommended_action: String,
}

/// Heuristic engine that analyses the IMSI rotation history to estimate how
/// susceptible the device is to cell-tower triangulation and IMSI-based tracking.
pub struct AntiTriangulationEngine {
    /// Chronological log of (timestamp, imsi_prefix) pairs.
    pub rotation_history: Vec<(DateTime<Utc>, String)>,
}

impl AntiTriangulationEngine {
    pub fn new() -> Self {
        Self {
            rotation_history: Vec::new(),
        }
    }

    /// Records that an IMSI rotation happened, storing only the first 6 digits
    /// (MCC+MNC) of the IMSI so the full identity is never kept in RAM.
    pub fn record_rotation(&mut self, imsi_prefix: &str) {
        let prefix = imsi_prefix.chars().take(6).collect::<String>();
        self.rotation_history.push((Utc::now(), prefix));
        debug!(
            prefix = %prefix,
            total_rotations = self.rotation_history.len(),
            "Rotation recorded in anti-triangulation engine"
        );
    }

    /// Analyses the rotation history and returns a risk assessment.
    ///
    /// Heuristics applied (in order of severity):
    /// 1. No rotation in 24 hours → Critical
    /// 2. Same IMSI (prefix) used for more than 2 hours → High
    /// 3. Rotations not randomised (perfectly regular spacing) → Medium
    /// 4. Rotation interval < 30 min → Low (good hygiene, but note it for completeness)
    pub fn assess_risk(&self) -> TriangulationRisk {
        let now = Utc::now();
        let mut reasons: Vec<String> = Vec::new();
        let mut risk_level = RiskLevel::Low;

        // ── Heuristic 1: no rotation in 24 h ─────────────────────────────────
        let twenty_four_h = chrono::Duration::hours(24);
        match self.rotation_history.last() {
            None => {
                // Never rotated
                reasons.push(
                    "No IMSI rotation has ever occurred; device is using a static identity."
                        .to_string(),
                );
                risk_level = RiskLevel::Critical;
            }
            Some((last_ts, _)) => {
                let since_last = now.signed_duration_since(*last_ts);
                if since_last > twenty_four_h {
                    reasons.push(format!(
                        "No IMSI rotation in {:.1} hours (threshold: 24 h). \
                         Prolonged exposure allows precise location history reconstruction.",
                        since_last.num_minutes() as f64 / 60.0
                    ));
                    risk_level = risk_level.max(RiskLevel::Critical);
                }
            }
        }

        // ── Heuristic 2: single IMSI prefix used for > 2 h ───────────────────
        if let Some(streak) = longest_same_prefix_streak(&self.rotation_history, now) {
            if streak.duration_minutes > 120 {
                reasons.push(format!(
                    "IMSI prefix '{}' in use for {:.1} h without rotation. \
                     Urban cell density allows triangulation within ~50 m after ~2 h.",
                    streak.prefix,
                    streak.duration_minutes as f64 / 60.0
                ));
                risk_level = risk_level.max(RiskLevel::High);
            }
        }

        // ── Heuristic 3: rotation timing is too regular ───────────────────────
        if is_rotation_too_regular(&self.rotation_history) {
            reasons.push(
                "Rotation intervals are highly regular (std-dev < 5 %). \
                 A passive observer can predict rotation times and correlate identities \
                 across rotations via timing analysis."
                    .to_string(),
            );
            risk_level = risk_level.max(RiskLevel::Medium);
        }

        // ── Heuristic 4: rotation happening rapidly (possibly good, but note it) ─
        if self.rotation_history.len() >= 2 {
            let intervals = inter_rotation_intervals(&self.rotation_history);
            if let Some(&min_interval) = intervals.iter().min() {
                if min_interval < 30 {
                    reasons.push(format!(
                        "Shortest rotation interval is {} min. \
                         Very frequent rotations may trigger network authentication anomalies.",
                        min_interval
                    ));
                    // This is low risk on its own
                    if risk_level < RiskLevel::Low {
                        risk_level = RiskLevel::Low;
                    }
                }
            }
        }

        if reasons.is_empty() {
            reasons.push("Rotation schedule appears healthy.".to_string());
        }

        let recommended_action = build_recommendation(&risk_level);

        TriangulationRisk {
            risk_level,
            reasons,
            recommended_action,
        }
    }
}

impl Default for AntiTriangulationEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

struct PrefixStreak {
    prefix: String,
    duration_minutes: i64,
}

/// Finds the longest uninterrupted streak of the same IMSI prefix and returns
/// how many minutes it has been (or was) in use.
fn longest_same_prefix_streak(
    history: &[(DateTime<Utc>, String)],
    now: DateTime<Utc>,
) -> Option<PrefixStreak> {
    if history.is_empty() {
        return None;
    }

    let mut best: Option<PrefixStreak> = None;
    let mut streak_start = history[0].0;
    let mut streak_prefix = history[0].1.clone();

    for i in 1..history.len() {
        if history[i].1 != streak_prefix {
            let dur = history[i].0.signed_duration_since(streak_start).num_minutes();
            if best.as_ref().map_or(true, |b| dur > b.duration_minutes) {
                best = Some(PrefixStreak {
                    prefix: streak_prefix.clone(),
                    duration_minutes: dur,
                });
            }
            streak_start = history[i].0;
            streak_prefix = history[i].1.clone();
        }
    }
    // Include time since last rotation
    let dur = now
        .signed_duration_since(streak_start)
        .num_minutes()
        .max(0);
    if best.as_ref().map_or(true, |b| dur > b.duration_minutes) {
        best = Some(PrefixStreak {
            prefix: streak_prefix,
            duration_minutes: dur,
        });
    }
    best
}

/// Returns the inter-rotation intervals in minutes.
fn inter_rotation_intervals(history: &[(DateTime<Utc>, String)]) -> Vec<i64> {
    history
        .windows(2)
        .map(|w| {
            w[1].0
                .signed_duration_since(w[0].0)
                .num_minutes()
                .max(0)
        })
        .collect()
}

/// Returns true if the rotation intervals are suspiciously regular:
/// coefficient of variation < 5 % and at least 3 data points.
fn is_rotation_too_regular(history: &[(DateTime<Utc>, String)]) -> bool {
    if history.len() < 4 {
        return false; // Not enough data
    }
    let intervals: Vec<f64> = inter_rotation_intervals(history)
        .into_iter()
        .map(|i| i as f64)
        .collect();
    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    if mean < 1.0 {
        return false; // Degenerate
    }
    let variance =
        intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
    let cv = variance.sqrt() / mean; // coefficient of variation
    cv < 0.05
}

fn build_recommendation(risk: &RiskLevel) -> String {
    match risk {
        RiskLevel::Low => {
            "Current rotation policy is adequate. \
             Maintain jitter and monitor for anomalies."
                .to_string()
        }
        RiskLevel::Medium => {
            "Increase rotation jitter to at least ±30 min. \
             Avoid predictable rotation schedules. \
             Consider switching to event-based rotation (Wi-Fi connect/disconnect)."
                .to_string()
        }
        RiskLevel::High => {
            "Rotate IMSI immediately. \
             Reduce rotation interval to ≤1 h with full jitter enabled. \
             Avoid extended stay in high-density urban areas with the same identity."
                .to_string()
        }
        RiskLevel::Critical => {
            "IMMEDIATE ACTION REQUIRED: rotate IMSI now. \
             Enable automatic rotation with a short interval (≤30 min). \
             Check baseband connectivity and ensure the LPA can activate profiles."
                .to_string()
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_history(entries: &[(i64, &str)]) -> Vec<(DateTime<Utc>, String)> {
        // entries: (minutes_ago, prefix)
        let now = Utc::now();
        entries
            .iter()
            .map(|(minutes_ago, prefix)| {
                (now - Duration::minutes(*minutes_ago), prefix.to_string())
            })
            .collect()
    }

    #[test]
    fn test_no_history_critical() {
        let engine = AntiTriangulationEngine::new();
        let risk = engine.assess_risk();
        assert_eq!(risk.risk_level, RiskLevel::Critical);
        assert!(risk.reasons.iter().any(|r| r.contains("No IMSI rotation")));
    }

    #[test]
    fn test_recent_rotation_low_risk() {
        let mut engine = AntiTriangulationEngine::new();
        // One rotation 10 minutes ago
        engine.rotation_history = make_history(&[(10, "234015"), (0, "234020")]);
        let risk = engine.assess_risk();
        assert!(risk.risk_level <= RiskLevel::Medium);
    }

    #[test]
    fn test_old_rotation_critical() {
        let mut engine = AntiTriangulationEngine::new();
        // Last rotation was 30 hours ago
        engine.rotation_history = make_history(&[(1800, "234015")]);
        let risk = engine.assess_risk();
        assert_eq!(risk.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_long_same_prefix_high_risk() {
        let mut engine = AntiTriangulationEngine::new();
        // Same prefix for 150 minutes (2.5 h), then different one
        let now = Utc::now();
        engine.rotation_history = vec![
            (now - Duration::minutes(150), "234015".to_string()),
            (now - Duration::minutes(1), "234020".to_string()),
            (now, "234020".to_string()),
        ];
        let risk = engine.assess_risk();
        assert!(risk.risk_level >= RiskLevel::High);
    }

    #[test]
    fn test_regular_rotation_medium_risk() {
        let mut engine = AntiTriangulationEngine::new();
        // Perfectly regular 60-minute rotations (5 entries)
        let now = Utc::now();
        engine.rotation_history = vec![
            (now - Duration::minutes(300), "234015".to_string()),
            (now - Duration::minutes(240), "234020".to_string()),
            (now - Duration::minutes(180), "234025".to_string()),
            (now - Duration::minutes(120), "234030".to_string()),
            (now - Duration::minutes(60), "234035".to_string()),
            (now, "234040".to_string()),
        ];
        let risk = engine.assess_risk();
        // Should detect regularity → at least Medium
        assert!(risk.risk_level >= RiskLevel::Medium);
    }

    #[test]
    fn test_record_rotation_truncates_to_6_chars() {
        let mut engine = AntiTriangulationEngine::new();
        engine.record_rotation("234015123456789");
        assert_eq!(engine.rotation_history[0].1.len(), 6);
        assert_eq!(engine.rotation_history[0].1, "234015");
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }

    #[test]
    fn test_inter_rotation_intervals() {
        let now = Utc::now();
        let history = vec![
            (now - Duration::minutes(120), "A".to_string()),
            (now - Duration::minutes(60), "B".to_string()),
            (now, "C".to_string()),
        ];
        let intervals = inter_rotation_intervals(&history);
        assert_eq!(intervals.len(), 2);
        assert_eq!(intervals[0], 60);
        assert_eq!(intervals[1], 60);
    }

    #[test]
    fn test_triangulation_risk_serialization() {
        let risk = TriangulationRisk {
            risk_level: RiskLevel::High,
            reasons: vec!["test reason".to_string()],
            recommended_action: "test action".to_string(),
        };
        let json = serde_json::to_string(&risk).unwrap();
        assert!(json.contains("High"));
        assert!(json.contains("test reason"));
    }
}
