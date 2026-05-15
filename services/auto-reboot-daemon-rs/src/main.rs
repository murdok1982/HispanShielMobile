use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

const SOCKET_PATH: &str = "/run/hispashield/autoreboot.sock";
const SCHEDULE_FILE: &str = "/data/hispashield/reboot_schedule.json";
const SHUTDOWN_WAIT_SECS: u64 = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Frequency {
    Daily,
    Weekly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebootSchedule {
    pub enabled: bool,
    pub frequency: Frequency,
    /// Hour of day (0–23) in local time
    pub hour: u8,
    /// Minute (0–59)
    pub minute: u8,
    /// For weekly: day of week 0=Sun..6=Sat
    #[serde(default)]
    pub day_of_week: Option<u8>,
    /// Maintenance window: number of seconds during which reboots may be postponed
    #[serde(default = "default_window")]
    pub maintenance_window_secs: u64,
}

fn default_window() -> u64 {
    3600 // 1 hour window
}

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum ControlCommand {
    Cancel,
    Status,
    TriggerNow,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    reboot_pending: bool,
    countdown_secs: Option<u64>,
    schedule_enabled: bool,
}

struct RebootState {
    pending: bool,
    countdown_secs: u64,
    cancelled: bool,
}

impl RebootState {
    fn new() -> Self {
        Self { pending: false, countdown_secs: 0, cancelled: false }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("auto_reboot_daemon=debug".parse().unwrap()),
        )
        .json()
        .init();

    info!("HispaShield Auto-Reboot Daemon starting");

    let schedule = load_schedule().unwrap_or_else(|e| {
        warn!("Could not load schedule ({}), using default", e);
        RebootSchedule {
            enabled: true,
            frequency: Frequency::Daily,
            hour: 3,
            minute: 0,
            day_of_week: None,
            maintenance_window_secs: 3600,
        }
    });

    let schedule = Arc::new(schedule);
    let state = Arc::new(Mutex::new(RebootState::new()));

    // Spawn socket control server
    let state_sock = Arc::clone(&state);
    let schedule_sock = Arc::clone(&schedule);
    tokio::spawn(async move {
        if let Err(e) = run_control_socket(state_sock, schedule_sock).await {
            error!("Control socket error: {}", e);
        }
    });

    // Main scheduling loop
    run_scheduler(schedule, state).await;

    Ok(())
}

fn load_schedule() -> anyhow::Result<RebootSchedule> {
    let content = std::fs::read_to_string(SCHEDULE_FILE)
        .context("Reading schedule file")?;
    let schedule = serde_json::from_str(&content)?;
    Ok(schedule)
}

async fn run_scheduler(schedule: Arc<RebootSchedule>, state: Arc<Mutex<RebootState>>) {
    if !schedule.enabled {
        info!("Auto-reboot is disabled in schedule");
        // Just sleep forever — socket still handles manual triggers
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    }

    loop {
        let sleep_secs = seconds_until_next_reboot(&schedule);
        info!(sleep_secs, "Next scheduled reboot in {} seconds", sleep_secs);
        tokio::time::sleep(Duration::from_secs(sleep_secs)).await;

        // Initiate reboot countdown
        {
            let mut st = state.lock().await;
            st.pending = true;
            st.countdown_secs = schedule.maintenance_window_secs;
            st.cancelled = false;
        }

        info!("Reboot countdown started ({} seconds)", schedule.maintenance_window_secs);

        // Countdown loop — checks every second for cancellation
        let window = schedule.maintenance_window_secs;
        let mut remaining = window;
        let mut cancelled = false;
        while remaining > 0 {
            tokio::time::sleep(Duration::from_secs(1)).await;
            remaining -= 1;
            let mut st = state.lock().await;
            st.countdown_secs = remaining;
            if st.cancelled {
                cancelled = true;
                st.pending = false;
                break;
            }
        }

        if cancelled {
            warn!("Scheduled reboot was cancelled");
            continue;
        }

        // Perform the reboot
        perform_reboot().await;
    }
}

async fn perform_reboot() {
    info!("Initiating system reboot sequence");

    // Gracefully notify all user processes with SIGTERM
    info!("Sending SIGTERM to all user processes");
    #[cfg(target_os = "linux")]
    {
        use nix::sys::signal::{self, Signal};
        use nix::unistd::Pid;
        // Kill process group -1 sends to all processes except pid 1 and ourselves
        // In practice on Android, init manages this; we signal user session
        let _ = signal::kill(Pid::from_raw(-1), Signal::SIGTERM);
    }

    // Wait for processes to terminate
    info!("Waiting {}s for processes to terminate", SHUTDOWN_WAIT_SECS);
    tokio::time::sleep(Duration::from_secs(SHUTDOWN_WAIT_SECS)).await;

    info!("Calling reboot(2) now");
    #[cfg(target_os = "linux")]
    {
        use nix::sys::reboot::{reboot, RebootMode};
        if let Err(e) = reboot(RebootMode::RB_AUTOBOOT) {
            error!("reboot() syscall failed: {}", e);
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        warn!("Reboot not supported on this platform — simulating");
        std::process::exit(0);
    }
}

async fn run_control_socket(
    state: Arc<Mutex<RebootState>>,
    schedule: Arc<RebootSchedule>,
) -> anyhow::Result<()> {
    let path = Path::new(SOCKET_PATH);
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(path)?;
    info!(socket = SOCKET_PATH, "Reboot control socket listening");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let state = Arc::clone(&state);
                let schedule = Arc::clone(&schedule);
                tokio::spawn(async move {
                    if let Err(e) = handle_control(stream, state, schedule).await {
                        error!("Control client error: {}", e);
                    }
                });
            }
            Err(e) => error!("Accept error: {}", e),
        }
    }
}

async fn handle_control(
    stream: UnixStream,
    state: Arc<Mutex<RebootState>>,
    schedule: Arc<RebootSchedule>,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let response: serde_json::Value = match serde_json::from_str::<ControlCommand>(&line) {
            Err(e) => serde_json::json!({ "error": format!("parse error: {}", e) }),
            Ok(cmd) => {
                let mut st = state.lock().await;
                match cmd {
                    ControlCommand::Cancel => {
                        if st.pending {
                            st.cancelled = true;
                            info!("Reboot cancelled via control socket");
                            serde_json::json!({ "ok": true, "message": "reboot cancelled" })
                        } else {
                            serde_json::json!({ "ok": false, "message": "no reboot pending" })
                        }
                    }
                    ControlCommand::Status => {
                        let resp = StatusResponse {
                            reboot_pending: st.pending,
                            countdown_secs: if st.pending { Some(st.countdown_secs) } else { None },
                            schedule_enabled: schedule.enabled,
                        };
                        serde_json::to_value(&resp).unwrap_or_default()
                    }
                    ControlCommand::TriggerNow => {
                        info!("Manual reboot triggered via control socket");
                        // Spawn so we can respond before rebooting
                        tokio::spawn(async {
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            perform_reboot().await;
                        });
                        serde_json::json!({ "ok": true, "message": "reboot triggered in 2s" })
                    }
                }
            }
        };

        let mut json = serde_json::to_string(&response)?;
        json.push('\n');
        writer.write_all(json.as_bytes()).await?;
    }
    Ok(())
}

/// Compute seconds until next scheduled reboot based on current time.
fn seconds_until_next_reboot(schedule: &RebootSchedule) -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Simple heuristic: target = next occurrence of HH:MM
    // Compute seconds since midnight using UTC (production would use local time)
    let secs_in_day = 86400u64;
    let day_secs = now_secs % secs_in_day;
    let target_secs = (schedule.hour as u64) * 3600 + (schedule.minute as u64) * 60;

    let until_today = if target_secs > day_secs {
        target_secs - day_secs
    } else {
        secs_in_day - day_secs + target_secs
    };

    match schedule.frequency {
        Frequency::Daily => until_today,
        Frequency::Weekly => {
            // day_of_week: 0=Sun..6=Sat
            let target_dow = schedule.day_of_week.unwrap_or(0) as u64;
            let current_dow = (now_secs / secs_in_day + 4) % 7; // epoch was Thursday
            let days_until = (target_dow + 7 - current_dow) % 7;
            if days_until == 0 && until_today < secs_in_day {
                until_today
            } else if days_until == 0 {
                7 * secs_in_day + until_today
            } else {
                days_until * secs_in_day + until_today
            }
        }
    }
}
