//! Running as a Windows service: `service install|uninstall|start|stop` for the installer, and the
//! hidden `service run` the Service Control Manager launches. Under the SCM there is no console, so
//! logs go to a daily file in `%ProgramData%\Fleetboard\logs`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::config::ClientConfig;

pub const SERVICE_NAME: &str = "FleetboardClient";
const DISPLAY_NAME: &str = "Fleetboard client";
const DESCRIPTION: &str =
    "Answers Fleetboard's polls with this machine's CPU, memory, disk, network and GPU stats.";

/// `service install --config PATH`: register with the SCM as LocalService, auto-start, restart on failure.
pub fn install(exe: &Path, config: &Path) -> anyhow::Result<()> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)
            .context("can't open the Service Control Manager (run as administrator)")?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.to_path_buf(),
        launch_arguments: vec![
            "service".into(),
            "run".into(),
            "--config".into(),
            config.as_os_str().to_owned(),
        ],
        dependencies: vec![],
        account_name: Some(OsString::from(r"NT AUTHORITY\LocalService")),
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .context("can't create the service (does it already exist? `service uninstall` first)")?;
    service.set_description(DESCRIPTION)?;
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(5)
            };
            3
        ]),
    })?;
    println!(
        "installed {SERVICE_NAME} ({DISPLAY_NAME}) running {}",
        exe.display()
    );
    Ok(())
}

/// `service uninstall`: stop it if needed and remove it.
pub fn uninstall() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .context("the service isn't installed")?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
        std::thread::sleep(Duration::from_secs(2));
    }
    service.delete()?;
    println!("removed {SERVICE_NAME}");
    Ok(())
}

pub fn start() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::START)
        .context("the service isn't installed")?;
    service.start::<&str>(&[])?;
    println!("started {SERVICE_NAME}");
    Ok(())
}

pub fn stop() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::STOP)
        .context("the service isn't installed")?;
    service.stop()?;
    println!("stopped {SERVICE_NAME}");
    Ok(())
}

/// `service run`: hand control to the SCM; it calls `service_main` on its own thread.
pub fn run() -> anyhow::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("not started by the Service Control Manager")?;
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

/// What the SCM runs: set up file logging, report Running, serve until Stop, report Stopped.
fn service_main(args: Vec<OsString>) {
    let config = config_from_args(&args).unwrap_or_else(ClientConfig::default_path);
    let (log_guard, log_ok) = init_file_logging();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let mut stop_tx = Some(stop_tx);
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(tx) = stop_tx.take() {
                let _ = tx.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(status) = service_control_handler::register(SERVICE_NAME, handler) else {
        return;
    };
    let report = |state: ServiceState, code: u32| {
        let _ = status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        });
    };
    report(ServiceState::Running, 0);
    if !log_ok {
        tracing::warn!("couldn't open the log file; logging to nowhere");
    }
    let outcome = ClientConfig::load(&config).and_then(|cfg| {
        tracing::info!(
            "fleetboard-client {} starting as a service with {}",
            crate::VERSION,
            config.display()
        );
        crate::run::serve(cfg, async {
            let _ = stop_rx.await;
        })
    });
    let code = match outcome {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!("{e:#}");
            1
        }
    };
    report(ServiceState::Stopped, code);
    drop(log_guard);
}

/// The `--config PATH` the SCM passes back to us.
fn config_from_args(args: &[OsString]) -> Option<PathBuf> {
    let pos = args.iter().position(|a| a == "--config")?;
    args.get(pos + 1).map(PathBuf::from)
}

/// A daily rolling file in %ProgramData%\Fleetboard\logs; returns the guard that flushes it.
fn init_file_logging() -> (Option<tracing_appender::non_blocking::WorkerGuard>, bool) {
    let dir = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Fleetboard")
        .join("logs");
    if std::fs::create_dir_all(&dir).is_err() {
        return (None, false);
    }
    let appender = tracing_appender::rolling::daily(&dir, "client.log");
    let (writer, guard) = tracing_appender::non_blocking(appender);
    let ok = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .with_target(false)
        .try_init()
        .is_ok();
    (Some(guard), ok)
}
