pub mod args;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;

use haunter::core::scanner;
use haunter::core::spoofer::Spoofer;
use haunter::error::HaunterError;
use haunter::net::interface;

use crate::cli::args::{Args, Command};

pub fn run() -> haunter::error::Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Interfaces => {
            interface::list();
            Ok(())
        }
        Command::Scan {
            interface,
            timeout,
        } => {
            let iface = interface::resolve(&interface)?;
            let network = interface::ipv4_network(&iface)?;

            println!("[*] Scanning {network} on {interface}...\n");

            let devices = scanner::scan(&iface, Duration::from_secs(timeout))?;

            if devices.is_empty() {
                println!("No devices found.");
            } else {
                println!("{:<16} {}", "IP", "MAC");
                println!("{}", "\u{2500}".repeat(36));
                for device in &devices {
                    println!("{device}");
                }
                println!("\n[*] Found {} device(s).", devices.len());
            }

            Ok(())
        }
        Command::Spoof {
            interface,
            gateway,
            target,
            forward,
        } => {
            let iface = interface::resolve(&interface)?;

            println!("[*] Resolving gateway {gateway}...");
            let spoofer = Spoofer::new(iface, gateway, target, forward)?;
            println!(
                "[*] Gateway: {} ({})",
                spoofer.gateway_ip, spoofer.gateway_mac,
            );

            if spoofer.targets.len() == 1 {
                let t = &spoofer.targets[0];
                println!("[*] Target: {} ({})", t.ip, t.mac);
            } else {
                for t in &spoofer.targets {
                    println!("    {t}");
                }
                println!("[*] Found {} target(s).", spoofer.targets.len());
            }

            let stop = Arc::new(AtomicBool::new(false));
            let flag = stop.clone();
            ctrlc::set_handler(move || {
                flag.store(true, Ordering::Relaxed);
            })
            .map_err(|e| HaunterError::Network(format!("failed to set signal handler: {e}")))?;

            println!(
                "[*] Spoofing {} target(s). Press Ctrl+C to stop and restore.\n",
                spoofer.targets.len(),
            );

            spoofer.run(stop, |msg| println!("{msg}"))
        }
    }
}
