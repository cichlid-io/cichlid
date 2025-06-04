use serde::{Deserialize, Serialize};

use futures_util::Stream;
use std::pin::Pin;

// Ensure ConfigItem is defined and public
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConfigItem {
    pub id: String,
    pub server_ip: String,
    pub ssh_user: String,
    pub ssh_port: u16,
    pub commands: Vec<String>,
}

// New type for client authentication status
#[derive(Clone, Debug)]
pub struct ClientAuthStatus {
    pub cert_presented: bool,
    pub cert_verified_ok: bool,
}

// Ensure GenericBoxedStream type alias is public
pub type GenericBoxedStream<T> = Pin<Box<dyn Stream<Item = T> + Send>>;
