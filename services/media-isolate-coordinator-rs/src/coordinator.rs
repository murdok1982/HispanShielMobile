use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{error, info, warn};

#[derive(Debug, Error)]
pub enum CoordinatorError {
    #[error("Codec '{0}' not found")]
    CodecNotFound(String),
    #[error("Process spawn failed: {0}")]
    SpawnFailed(#[from] std::io::Error),
    #[error("Cgroup operation failed: {0}")]
    CgroupError(String),
    #[error("Process has exited")]
    ProcessExited,
}

static PROCESS_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Identifies what kind of media codec this process handles.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodecKind {
    VideoDecoder,
    VideoEncoder,
    AudioDecoder,
    AudioEncoder,
    ImageDecoder,
}

impl std::fmt::Display for CodecKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodecKind::VideoDecoder => write!(f, "video_decoder"),
            CodecKind::VideoEncoder => write!(f, "video_encoder"),
            CodecKind::AudioDecoder => write!(f, "audio_decoder"),
            CodecKind::AudioEncoder => write!(f, "audio_encoder"),
            CodecKind::ImageDecoder => write!(f, "image_decoder"),
        }
    }
}

/// Configuration for an isolated codec process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationConfig {
    pub kind: CodecKind,
    /// Path to the codec executable
    pub executable: PathBuf,
    /// Memory limit in bytes (enforced via cgroups)
    pub memory_limit_bytes: u64,
    /// Maximum number of restarts before giving up
    pub max_restarts: u32,
    /// Whether to drop all Linux capabilities
    pub drop_capabilities: bool,
    /// Whether to use a new network namespace (isolates from network)
    pub isolate_network: bool,
}

impl IsolationConfig {
    pub fn default_for_kind(kind: CodecKind) -> Self {
        let (mem_limit, executable) = match kind {
            CodecKind::VideoDecoder => (512 * 1024 * 1024, PathBuf::from("/system/bin/mediaserver_video_dec")),
            CodecKind::VideoEncoder => (256 * 1024 * 1024, PathBuf::from("/system/bin/mediaserver_video_enc")),
            CodecKind::AudioDecoder => (64 * 1024 * 1024, PathBuf::from("/system/bin/mediaserver_audio_dec")),
            CodecKind::AudioEncoder => (32 * 1024 * 1024, PathBuf::from("/system/bin/mediaserver_audio_enc")),
            CodecKind::ImageDecoder => (128 * 1024 * 1024, PathBuf::from("/system/bin/mediaserver_image_dec")),
        };
        Self {
            kind,
            executable,
            memory_limit_bytes: mem_limit,
            max_restarts: 5,
            drop_capabilities: true,
            isolate_network: true,
        }
    }
}

/// Represents a running isolated codec process.
#[derive(Debug)]
pub struct CodecProcess {
    pub id: u64,
    pub config: IsolationConfig,
    pub pid: u32,
    pub restart_count: u32,
    pub cgroup_path: PathBuf,
}

impl CodecProcess {
    /// Apply memory limit via cgroup v2 memory.max
    pub fn apply_cgroup_limits(&self) -> Result<(), CoordinatorError> {
        let memory_max_path = self.cgroup_path.join("memory.max");
        std::fs::write(&memory_max_path, self.config.memory_limit_bytes.to_string())
            .map_err(|e| CoordinatorError::CgroupError(format!(
                "Failed to write memory.max at {}: {}",
                memory_max_path.display(), e
            )))?;
        info!(
            pid = self.pid,
            limit_bytes = self.config.memory_limit_bytes,
            "Cgroup memory limit applied"
        );
        Ok(())
    }

    /// Add this process's PID to the cgroup.
    pub fn join_cgroup(&self) -> Result<(), CoordinatorError> {
        let procs_path = self.cgroup_path.join("cgroup.procs");
        std::fs::write(&procs_path, self.pid.to_string())
            .map_err(|e| CoordinatorError::CgroupError(format!(
                "Failed to join cgroup {}: {}",
                procs_path.display(), e
            )))?;
        info!(pid = self.pid, cgroup = %self.cgroup_path.display(), "Process joined cgroup");
        Ok(())
    }
}

pub struct ProcessManager {
    processes: HashMap<u64, CodecProcess>,
    cgroup_base: PathBuf,
}

impl ProcessManager {
    pub fn new(cgroup_base: impl Into<PathBuf>) -> Self {
        Self {
            processes: HashMap::new(),
            cgroup_base: cgroup_base.into(),
        }
    }

    /// Spawn a new isolated codec process.
    /// On Linux this uses nix::unistd::fork() + exec with namespace flags.
    /// For portability and testability we use std::process::Command here
    /// with the understanding that in production the spawner applies clone() flags.
    pub fn spawn_codec(&mut self, config: IsolationConfig) -> Result<u64, CoordinatorError> {
        let id = PROCESS_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
        let cgroup_path = self.cgroup_base.join(format!("mediacodec_{}", id));

        // Create cgroup directory
        if let Err(e) = std::fs::create_dir_all(&cgroup_path) {
            warn!("Could not create cgroup dir {}: {} — continuing without cgroup isolation", cgroup_path.display(), e);
        }

        info!(
            id,
            codec = %config.kind,
            executable = %config.executable.display(),
            "Spawning isolated codec process"
        );

        // Build the command — in production this would be a custom spawner
        // that calls clone() with CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWNS
        let mut cmd = std::process::Command::new(&config.executable);
        cmd.arg("--isolated");
        cmd.arg("--codec-id").arg(id.to_string());

        let child = cmd.spawn().map_err(|e| {
            error!(id, error = %e, "Failed to spawn codec process");
            CoordinatorError::SpawnFailed(e)
        })?;

        let pid = child.id();
        // We intentionally don't wait on the child here — the monitor task does that.
        // Leak the Child handle; the OS will clean up when pid is reaped.
        std::mem::forget(child);

        let proc = CodecProcess {
            id,
            config,
            pid,
            restart_count: 0,
            cgroup_path,
        };

        // Apply cgroup limits — best-effort
        let _ = proc.join_cgroup();
        let _ = proc.apply_cgroup_limits();

        self.processes.insert(id, proc);
        Ok(id)
    }

    /// Kill a codec process and clean up its cgroup.
    pub fn kill_codec(&mut self, id: u64) -> bool {
        if let Some(proc) = self.processes.remove(&id) {
            info!(id, pid = proc.pid, "Killing codec process");
            #[cfg(unix)]
            {
                use nix::sys::signal::{kill, Signal};
                use nix::unistd::Pid;
                let _ = kill(Pid::from_raw(proc.pid as i32), Signal::SIGKILL);
            }
            // Remove cgroup
            let _ = std::fs::remove_dir_all(&proc.cgroup_path);
            true
        } else {
            false
        }
    }

    /// Check if process is still alive; if not, restart it.
    pub fn check_and_restart(&mut self, id: u64) -> Result<Option<u64>, CoordinatorError> {
        let is_alive = self.processes.get(&id).map(|p| is_pid_alive(p.pid)).unwrap_or(false);
        if is_alive {
            return Ok(None);
        }

        let old_proc = match self.processes.remove(&id) {
            None => return Err(CoordinatorError::CodecNotFound(id.to_string())),
            Some(p) => p,
        };

        if old_proc.restart_count >= old_proc.config.max_restarts {
            error!(
                id,
                pid = old_proc.pid,
                restart_count = old_proc.restart_count,
                "Codec process exceeded max restarts — not restarting"
            );
            return Err(CoordinatorError::ProcessExited);
        }

        warn!(
            id,
            pid = old_proc.pid,
            restart_count = old_proc.restart_count,
            "Codec process died — restarting"
        );

        let mut new_config = old_proc.config;
        let _ = std::fs::remove_dir_all(&old_proc.cgroup_path);

        let new_id = PROCESS_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
        let cgroup_path = self.cgroup_base.join(format!("mediacodec_{}", new_id));
        let _ = std::fs::create_dir_all(&cgroup_path);

        let mut cmd = std::process::Command::new(&new_config.executable);
        cmd.arg("--isolated").arg("--codec-id").arg(new_id.to_string());

        let child = cmd.spawn().map_err(CoordinatorError::SpawnFailed)?;
        let pid = child.id();
        std::mem::forget(child);

        let proc = CodecProcess {
            id: new_id,
            config: new_config,
            pid,
            restart_count: old_proc.restart_count + 1,
            cgroup_path,
        };

        let _ = proc.join_cgroup();
        let _ = proc.apply_cgroup_limits();

        self.processes.insert(new_id, proc);
        info!(old_id = id, new_id, pid, "Codec process restarted");
        Ok(Some(new_id))
    }

    pub fn active_count(&self) -> usize {
        self.processes.len()
    }

    pub fn list_ids(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self.processes.keys().copied().collect();
        ids.sort_unstable();
        ids
    }
}

/// Check whether a PID is still alive by sending signal 0.
fn is_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;
        // Signal 0 doesn't actually send a signal but checks if the process exists
        kill(Pid::from_raw(pid as i32), None).is_ok()
    }
    #[cfg(not(unix))]
    false
}
