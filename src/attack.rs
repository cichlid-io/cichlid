use serde::{
    Deserialize,
    Serialize,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Attack {
    pub source_ip: String,
    pub target_port: u32,
    pub threat: String,
    pub timestamp: u64,
}