use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PeerRecord {
    pub ip: String,
    pub port: u16,
    pub health: String, // raw JSON or summary from /health
    pub last_observed: i64,
}
