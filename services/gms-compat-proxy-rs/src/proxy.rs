use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("Endpoint '{0}' is blocked")]
    EndpointBlocked(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// A GMS API request from an app, forwarded to this proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmsRequest {
    /// Destination GMS endpoint (e.g. "https://fcm.googleapis.com/v1/projects/...")
    pub endpoint: String,
    /// HTTP method
    pub method: String,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// JSON body (may be null)
    pub body: Option<serde_json::Value>,
}

/// The proxy's decision on a GMS request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmsResponse {
    pub allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sanitized_body: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sanitized_headers: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Fields in GMS payloads that carry tracking/fingerprinting data.
const TELEMETRY_FIELDS: &[&str] = &[
    "advertisingId",
    "gaid",
    "deviceFingerprint",
    "androidId",
    "gsf_id",
    "build_fingerprint",
    "device_id",
    "serial",
    "imei",
    "meid",
];

/// Headers that reveal device identity.
const TRACKING_HEADERS: &[&str] = &[
    "X-Android-Client-ID",
    "X-Device-ID",
    "X-Goog-Device-ID",
    "Android-ID",
];

pub struct EndpointFilter {
    /// Endpoints that are always allowed (substring match)
    allowlist: Vec<String>,
    /// Endpoints that are always blocked (substring match)
    blocklist: Vec<String>,
}

impl EndpointFilter {
    pub fn new(allowlist: Vec<String>, blocklist: Vec<String>) -> Self {
        Self { allowlist, blocklist }
    }

    pub fn default_production() -> Self {
        Self {
            allowlist: vec![
                "fcm.googleapis.com".into(),
                "firebase.googleapis.com".into(),
                "maps.googleapis.com".into(),
                "www.googleapis.com/oauth2".into(),
                "accounts.google.com".into(),
                "play.googleapis.com/log".into(), // Play Store crash reports only
            ],
            blocklist: vec![
                "play.googleapis.com/log/batch".into(), // Batch analytics
                "android.googleapis.com/checkin".into(), // Device check-in telemetry
                "mtalk.google.com".into(),               // Always route through FCM, not MTALK
                "app-measurement.com".into(),
                "doubleclick.net".into(),
                "googlesyndication.com".into(),
                "analytics.google.com".into(),
            ],
        }
    }

    pub fn is_blocked(&self, endpoint: &str) -> bool {
        // Blocklist checked first
        for blocked in &self.blocklist {
            if endpoint.contains(blocked.as_str()) {
                return true;
            }
        }
        false
    }

    pub fn is_allowed(&self, endpoint: &str) -> bool {
        for allowed in &self.allowlist {
            if endpoint.contains(allowed.as_str()) {
                return true;
            }
        }
        false
    }
}

pub struct TelemetryStrip;

impl TelemetryStrip {
    /// Remove telemetry fields from a JSON value recursively.
    pub fn strip(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(mut map) => {
                map.retain(|key, _| {
                    let blocked = TELEMETRY_FIELDS.iter().any(|f| {
                        key.eq_ignore_ascii_case(f)
                    });
                    if blocked {
                        debug!(field = %key, "Stripped telemetry field from GMS payload");
                    }
                    !blocked
                });
                // Recurse into remaining values
                let stripped: serde_json::Map<String, serde_json::Value> = map
                    .into_iter()
                    .map(|(k, v)| (k, Self::strip(v)))
                    .collect();
                serde_json::Value::Object(stripped)
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.into_iter().map(Self::strip).collect())
            }
            other => other,
        }
    }

    /// Remove tracking headers from a header map.
    pub fn strip_headers(mut headers: HashMap<String, String>) -> HashMap<String, String> {
        headers.retain(|key, _| {
            let blocked = TRACKING_HEADERS.iter().any(|h| {
                key.eq_ignore_ascii_case(h)
            });
            if blocked {
                debug!(header = %key, "Stripped tracking header from GMS request");
            }
            !blocked
        });
        headers
    }
}

pub struct GmsProxy {
    filter: EndpointFilter,
}

impl GmsProxy {
    pub fn new(filter: EndpointFilter) -> Self {
        Self { filter }
    }

    pub fn process_request(&self, req: GmsRequest) -> GmsResponse {
        // Check blocklist
        if self.filter.is_blocked(&req.endpoint) {
            warn!(endpoint = %req.endpoint, "GMS endpoint BLOCKED");
            return GmsResponse {
                allowed: false,
                sanitized_body: None,
                sanitized_headers: None,
                reason: Some(format!("endpoint '{}' is blocked", req.endpoint)),
            };
        }

        // Check allowlist — if not explicitly allowed, deny
        if !self.filter.is_allowed(&req.endpoint) {
            warn!(endpoint = %req.endpoint, "GMS endpoint not in allowlist — DENIED");
            return GmsResponse {
                allowed: false,
                sanitized_body: None,
                sanitized_headers: None,
                reason: Some(format!("endpoint '{}' not in allowlist", req.endpoint)),
            };
        }

        // Strip telemetry from body
        let sanitized_body = req.body.map(TelemetryStrip::strip);
        // Strip tracking headers
        let sanitized_headers = TelemetryStrip::strip_headers(req.headers);

        info!(endpoint = %req.endpoint, "GMS request ALLOWED (telemetry stripped)");

        GmsResponse {
            allowed: true,
            sanitized_body,
            sanitized_headers: Some(sanitized_headers),
            reason: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_analytics() {
        let proxy = GmsProxy::new(EndpointFilter::default_production());
        let req = GmsRequest {
            endpoint: "https://app-measurement.com/collect".into(),
            method: "POST".into(),
            headers: HashMap::new(),
            body: None,
        };
        let resp = proxy.process_request(req);
        assert!(!resp.allowed);
    }

    #[test]
    fn test_allow_fcm() {
        let proxy = GmsProxy::new(EndpointFilter::default_production());
        let req = GmsRequest {
            endpoint: "https://fcm.googleapis.com/v1/projects/test/messages:send".into(),
            method: "POST".into(),
            headers: HashMap::new(),
            body: None,
        };
        let resp = proxy.process_request(req);
        assert!(resp.allowed);
    }

    #[test]
    fn test_strip_gaid_from_body() {
        let proxy = GmsProxy::new(EndpointFilter::default_production());
        let mut body = serde_json::Map::new();
        body.insert("message".into(), serde_json::Value::String("hello".into()));
        body.insert("advertisingId".into(), serde_json::Value::String("dead-beef".into()));
        let req = GmsRequest {
            endpoint: "https://fcm.googleapis.com/v1/projects/test/messages:send".into(),
            method: "POST".into(),
            headers: HashMap::new(),
            body: Some(serde_json::Value::Object(body)),
        };
        let resp = proxy.process_request(req);
        assert!(resp.allowed);
        let body = resp.sanitized_body.unwrap();
        assert!(body.get("advertisingId").is_none());
        assert!(body.get("message").is_some());
    }

    #[test]
    fn test_strip_tracking_headers() {
        let mut headers = HashMap::new();
        headers.insert("X-Android-Client-ID".into(), "device123".into());
        headers.insert("Content-Type".into(), "application/json".into());
        let stripped = TelemetryStrip::strip_headers(headers);
        assert!(!stripped.contains_key("X-Android-Client-ID"));
        assert!(stripped.contains_key("Content-Type"));
    }
}
