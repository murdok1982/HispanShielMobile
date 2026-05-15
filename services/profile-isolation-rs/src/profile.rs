use std::collections::HashMap;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};

#[derive(Debug, Error)]
pub enum IsolationError {
    #[error("Profile '{0}' not found")]
    ProfileNotFound(String),
    #[error("Cross-profile access denied: profile '{from}' cannot access '{to}'")]
    CrossProfileDenied { from: String, to: String },
    #[error("Path '{path}' belongs to profile '{owner}' which denies access from '{accessor}'")]
    PathAccessDenied { path: String, owner: String, accessor: String },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileKind {
    Personal,
    Work,
    Guest,
    System,
}

impl std::fmt::Display for ProfileKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileKind::Personal => write!(f, "personal"),
            ProfileKind::Work => write!(f, "work"),
            ProfileKind::Guest => write!(f, "guest"),
            ProfileKind::System => write!(f, "system"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub kind: ProfileKind,
    /// Filesystem data root for this profile (e.g. /data/user/0)
    pub data_root: PathBuf,
    /// UIDs belonging to this profile
    pub uid_range_start: u32,
    pub uid_range_end: u32,
}

impl Profile {
    pub fn contains_uid(&self, uid: u32) -> bool {
        uid >= self.uid_range_start && uid <= self.uid_range_end
    }

    pub fn contains_path(&self, path: &str) -> bool {
        path.starts_with(self.data_root.to_string_lossy().as_ref())
    }
}

/// Defines which profiles may share data with which other profiles.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IsolationPolicy {
    /// Map of `from_profile_id -> [allowed_to_profile_id]`
    pub allowed_cross_profile: HashMap<String, Vec<String>>,
}

impl IsolationPolicy {
    pub fn is_cross_profile_allowed(&self, from: &str, to: &str) -> bool {
        if from == to {
            return true;
        }
        self.allowed_cross_profile
            .get(from)
            .map(|allowed| allowed.iter().any(|t| t == to))
            .unwrap_or(false)
    }
}

pub struct ProfileManager {
    profiles: HashMap<String, Profile>,
    policy: IsolationPolicy,
}

impl ProfileManager {
    pub fn new(policy: IsolationPolicy) -> Self {
        Self {
            profiles: HashMap::new(),
            policy,
        }
    }

    pub fn load_from_file(path: &str) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        struct Config {
            profiles: Vec<Profile>,
            policy: IsolationPolicy,
        }
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&content)?;
        let mut profiles = HashMap::new();
        for p in config.profiles {
            profiles.insert(p.id.clone(), p);
        }
        info!(count = profiles.len(), "Profiles loaded");
        Ok(Self { profiles, policy: config.policy })
    }

    pub fn add_profile(&mut self, profile: Profile) {
        info!(id = %profile.id, kind = %profile.kind, "Profile registered");
        self.profiles.insert(profile.id.clone(), profile);
    }

    /// Determine which profile owns a given UID.
    pub fn profile_for_uid(&self, uid: u32) -> Option<&Profile> {
        self.profiles.values().find(|p| p.contains_uid(uid))
    }

    /// Determine which profile owns a given filesystem path.
    pub fn profile_for_path(&self, path: &str) -> Option<&Profile> {
        self.profiles.values().find(|p| p.contains_path(path))
    }

    /// Check whether `accessor_uid` may access `target_path`.
    pub fn check_path_access(&self, accessor_uid: u32, target_path: &str) -> Result<(), IsolationError> {
        let accessor_profile = self.profile_for_uid(accessor_uid);
        let path_profile = self.profile_for_path(target_path);

        match (accessor_profile, path_profile) {
            (None, _) | (_, None) => {
                // System UIDs or paths outside profiles are not constrained here
                Ok(())
            }
            (Some(accessor), Some(owner)) => {
                if self.policy.is_cross_profile_allowed(&accessor.id, &owner.id) {
                    Ok(())
                } else {
                    warn!(
                        accessor = %accessor.id,
                        owner = %owner.id,
                        path = target_path,
                        "Cross-profile path access DENIED"
                    );
                    Err(IsolationError::PathAccessDenied {
                        path: target_path.to_string(),
                        owner: owner.id.clone(),
                        accessor: accessor.id.clone(),
                    })
                }
            }
        }
    }

    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }

    pub fn profile_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.profiles.keys().cloned().collect();
        names.sort();
        names
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager() -> ProfileManager {
        let mut pm = ProfileManager::new(IsolationPolicy::default());
        pm.add_profile(Profile {
            id: "personal".into(),
            kind: ProfileKind::Personal,
            data_root: PathBuf::from("/data/user/0"),
            uid_range_start: 10000,
            uid_range_end: 19999,
        });
        pm.add_profile(Profile {
            id: "work".into(),
            kind: ProfileKind::Work,
            data_root: PathBuf::from("/data/user/10"),
            uid_range_start: 1010000,
            uid_range_end: 1019999,
        });
        pm
    }

    #[test]
    fn test_same_profile_access_allowed() {
        let pm = make_manager();
        assert!(pm.check_path_access(10000, "/data/user/0/com.example.app").is_ok());
    }

    #[test]
    fn test_cross_profile_access_denied() {
        let pm = make_manager();
        assert!(matches!(
            pm.check_path_access(10000, "/data/user/10/com.corp.app"),
            Err(IsolationError::PathAccessDenied { .. })
        ));
    }

    #[test]
    fn test_policy_allows_cross_profile() {
        let mut policy = IsolationPolicy::default();
        policy.allowed_cross_profile.insert(
            "work".into(),
            vec!["personal".into()],
        );
        let mut pm = ProfileManager::new(policy);
        pm.add_profile(Profile {
            id: "personal".into(),
            kind: ProfileKind::Personal,
            data_root: PathBuf::from("/data/user/0"),
            uid_range_start: 10000,
            uid_range_end: 19999,
        });
        pm.add_profile(Profile {
            id: "work".into(),
            kind: ProfileKind::Work,
            data_root: PathBuf::from("/data/user/10"),
            uid_range_start: 1010000,
            uid_range_end: 1019999,
        });
        // work uid accessing personal path should be OK
        assert!(pm.check_path_access(1010000, "/data/user/0/shared").is_ok());
        // personal uid accessing work path should still be denied
        assert!(pm.check_path_access(10000, "/data/user/10/secret").is_err());
    }
}
