use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use pnet::datalink::{MacAddr, NetworkInterface};

use haunter::core::scanner;
use haunter::core::spoofer::Spoofer;
use haunter::net::interface;
use haunter::net::Device;

const SCAN_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Interfaces,
    Scanner,
    Spoofer,
}

impl Tab {
    pub const ALL: [Tab; 3] = [Tab::Interfaces, Tab::Scanner, Tab::Spoofer];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Interfaces => "Interfaces",
            Tab::Scanner => "Scanner",
            Tab::Spoofer => "Spoofer",
        }
    }

    pub fn next(self) -> Tab {
        match self {
            Tab::Interfaces => Tab::Scanner,
            Tab::Scanner => Tab::Spoofer,
            Tab::Spoofer => Tab::Interfaces,
        }
    }

    pub fn prev(self) -> Tab {
        match self {
            Tab::Interfaces => Tab::Spoofer,
            Tab::Scanner => Tab::Interfaces,
            Tab::Spoofer => Tab::Scanner,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpooferState {
    Idle,
    Running,
    Stopping,
}

/// Events sent from background threads to the main TUI loop.
pub enum AppEvent {
    ScanComplete(Vec<Device>),
    ScanError(String),
    SpooferLog(String),
    SpooferStopped,
    SpooferError(String),
}

pub struct App {
    pub running: bool,
    pub tab: Tab,

    // Interfaces tab
    pub interfaces: Vec<NetworkInterface>,
    pub iface_index: usize,
    pub selected_iface: Option<NetworkInterface>,

    // Scanner tab
    pub scan_results: Vec<Device>,
    pub scan_index: usize,
    pub scanning: bool,

    // Spoofer tab
    pub gateway_ip: Option<Ipv4Addr>,
    pub gateway_mac: Option<MacAddr>,
    pub target_ip: Option<Ipv4Addr>,
    pub target_mac: Option<MacAddr>,
    pub forward: bool,
    pub spoofer_state: SpooferState,
    pub spoof_stop: Option<Arc<AtomicBool>>,

    // Log panel
    pub logs: Vec<String>,

    // Background event channel
    pub event_tx: Sender<AppEvent>,
    pub event_rx: Receiver<AppEvent>,
}

impl App {
    pub fn new() -> Self {
        let (event_tx, event_rx) = mpsc::channel();
        let interfaces = interface::list();
        Self {
            running: true,
            tab: Tab::Interfaces,
            interfaces,
            iface_index: 0,
            selected_iface: None,
            scan_results: Vec::new(),
            scan_index: 0,
            scanning: false,
            gateway_ip: None,
            gateway_mac: None,
            target_ip: None,
            target_mac: None,
            forward: true,
            spoofer_state: SpooferState::Idle,
            spoof_stop: None,
            logs: Vec::new(),
            event_tx,
            event_rx,
        }
    }

    pub fn log(&mut self, msg: impl Into<String>) {
        self.logs.push(msg.into());
    }

    /// Select the currently highlighted interface.
    pub fn select_interface(&mut self) {
        if let Some(iface) = self.interfaces.get(self.iface_index) {
            self.selected_iface = Some(iface.clone());
            self.log(format!("[*] Selected interface: {}", iface.name));
        }
    }

    /// Start a background network scan.
    pub fn start_scan(&mut self) {
        let iface = match &self.selected_iface {
            Some(i) => i.clone(),
            None => {
                self.log("[!] No interface selected. Go to Interfaces tab and press Enter.");
                return;
            }
        };

        if self.scanning {
            self.log("[!] Scan already in progress.");
            return;
        }

        self.scanning = true;
        self.scan_results.clear();
        self.scan_index = 0;
        self.log(format!("[*] Scanning on {}...", iface.name));

        let tx = self.event_tx.clone();
        thread::spawn(move || {
            match scanner::scan(&iface, SCAN_TIMEOUT) {
                Ok(devices) => {
                    let _ = tx.send(AppEvent::ScanComplete(devices));
                }
                Err(e) => {
                    let _ = tx.send(AppEvent::ScanError(e.to_string()));
                }
            }
        });
    }

    /// Set gateway from currently selected scan result.
    pub fn set_gateway_from_scan(&mut self) {
        if let Some(device) = self.scan_results.get(self.scan_index) {
            self.gateway_ip = Some(device.ip);
            self.gateway_mac = Some(device.mac);
            self.log(format!("[*] Gateway set: {} ({})", device.ip, device.mac));
        }
    }

    /// Set target from currently selected scan result.
    pub fn set_target_from_scan(&mut self) {
        if let Some(device) = self.scan_results.get(self.scan_index) {
            self.target_ip = Some(device.ip);
            self.target_mac = Some(device.mac);
            self.log(format!("[*] Target set: {} ({})", device.ip, device.mac));
        }
    }

    /// Clear the target (spoof all devices).
    pub fn clear_target(&mut self) {
        self.target_ip = None;
        self.target_mac = None;
        self.log("[*] Target cleared (will spoof all devices).");
    }

    /// Toggle IP forwarding setting.
    pub fn toggle_forward(&mut self) {
        self.forward = !self.forward;
        let state = if self.forward { "ON" } else { "OFF" };
        self.log(format!("[*] IP forwarding: {state}"));
    }

    /// Start the spoofer in a background thread.
    pub fn start_spoofer(&mut self) {
        let iface = match &self.selected_iface {
            Some(i) => i.clone(),
            None => {
                self.log("[!] No interface selected.");
                return;
            }
        };

        let gateway_ip = match self.gateway_ip {
            Some(ip) => ip,
            None => {
                self.log("[!] No gateway set. Scan the network and press 'g' on a device.");
                return;
            }
        };

        if self.spoofer_state != SpooferState::Idle {
            self.log("[!] Spoofer is already running.");
            return;
        }

        self.spoofer_state = SpooferState::Running;
        let target_ip = self.target_ip;
        let forward = self.forward;
        let tx = self.event_tx.clone();
        let stop = Arc::new(AtomicBool::new(false));
        self.spoof_stop = Some(stop.clone());

        self.log("[*] Starting spoofer...");

        thread::spawn(move || {
            let spoofer = match Spoofer::new(iface, gateway_ip, target_ip, forward) {
                Ok(s) => s,
                Err(e) => {
                    let _ = tx.send(AppEvent::SpooferError(e.to_string()));
                    return;
                }
            };

            let log_tx = tx.clone();
            let result = spoofer.run(stop, move |msg| {
                let _ = log_tx.send(AppEvent::SpooferLog(msg.to_string()));
            });

            match result {
                Ok(()) => {
                    let _ = tx.send(AppEvent::SpooferStopped);
                }
                Err(e) => {
                    let _ = tx.send(AppEvent::SpooferError(e.to_string()));
                }
            }
        });
    }

    /// Signal the spoofer to stop.
    pub fn stop_spoofer(&mut self) {
        if let Some(stop) = &self.spoof_stop {
            if self.spoofer_state == SpooferState::Running {
                self.spoofer_state = SpooferState::Stopping;
                stop.store(true, Ordering::Relaxed);
                self.log("[*] Stopping spoofer...");
            }
        }
    }

    /// Process events from background threads.
    pub fn process_events(&mut self) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                AppEvent::ScanComplete(devices) => {
                    self.scanning = false;
                    let count = devices.len();
                    self.scan_results = devices;
                    self.scan_index = 0;
                    self.log(format!("[*] Scan complete: {count} device(s) found."));
                }
                AppEvent::ScanError(e) => {
                    self.scanning = false;
                    self.log(format!("[!] Scan error: {e}"));
                }
                AppEvent::SpooferLog(msg) => {
                    self.logs.push(msg);
                }
                AppEvent::SpooferStopped => {
                    self.spoofer_state = SpooferState::Idle;
                    self.spoof_stop = None;
                    self.log("[*] Spoofer stopped.");
                }
                AppEvent::SpooferError(e) => {
                    self.spoofer_state = SpooferState::Idle;
                    self.spoof_stop = None;
                    self.log(format!("[!] Spoofer error: {e}"));
                }
            }
        }
    }
}
