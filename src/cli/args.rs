use std::net::Ipv4Addr;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "haunter",
    about = "ARP spoofing tool for network security research",
    version
)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// List available network interfaces
    Interfaces,

    /// Scan the local network for active devices
    Scan {
        /// Network interface to scan on
        #[arg(short, long)]
        interface: String,

        /// Scan timeout in seconds
        #[arg(short = 'T', long, default_value = "2")]
        timeout: u64,
    },

    /// Start ARP spoofing
    Spoof {
        /// Network interface to use
        #[arg(short, long)]
        interface: String,

        /// Gateway IP address
        #[arg(short, long)]
        gateway: Ipv4Addr,

        /// Target IP address (omit to target all devices)
        #[arg(short, long)]
        target: Option<Ipv4Addr>,

        /// Forward intercepted traffic instead of dropping it (MITM mode)
        #[arg(short, long)]
        forward: bool,
    },
}
