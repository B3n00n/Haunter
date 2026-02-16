use std::time::Duration;

use pnet::datalink::{self, Config, DataLinkReceiver, DataLinkSender, NetworkInterface};

use crate::error::{HaunterError, Result};

/// Owned wrapper around a pnet datalink channel.
pub struct Channel {
    tx: Box<dyn DataLinkSender>,
    rx: Box<dyn DataLinkReceiver>,
}

impl Channel {
    /// Open an Ethernet channel on the given interface.
    pub fn open(iface: &NetworkInterface, read_timeout: Duration) -> Result<Self> {
        let config = Config {
            read_timeout: Some(read_timeout),
            ..Default::default()
        };
        match datalink::channel(iface, config) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => Ok(Self { tx, rx }),
            Ok(_) => Err(HaunterError::Network("unsupported channel type".into())),
            Err(e) => Err(match e.kind() {
                std::io::ErrorKind::PermissionDenied => HaunterError::PermissionDenied,
                _ => HaunterError::Network(e.to_string()),
            }),
        }
    }

    /// Send a raw Ethernet frame.
    pub fn send(&mut self, frame: &[u8]) -> Result<()> {
        self.tx
            .send_to(frame, None)
            .ok_or_else(|| HaunterError::Network("send returned no result".into()))?
            .map_err(|e| HaunterError::Network(e.to_string()))
    }

    /// Receive the next Ethernet frame, or `None` if the read timed out.
    pub fn receive(&mut self) -> Result<Option<&[u8]>> {
        match self.rx.next() {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(None),
            Err(e) => Err(HaunterError::Network(e.to_string())),
        }
    }
}
