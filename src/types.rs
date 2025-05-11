use serde::{Deserialize, Serialize};
use std::pin::Pin;
use futures_util::Stream;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigItem {
    pub id: String,
    pub server_ip: String,
    pub ssh_user: String,
    pub ssh_port: u16,
    pub commands: Vec<String>,
}

/// Generic boxed stream type for any item.
pub type GenericBoxedStream<T> = Pin<Box<dyn Stream<Item = T> + Send>>;
