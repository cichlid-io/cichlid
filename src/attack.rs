use chrono::{
    DateTime,
    Utc,
};
use serde::{
    Deserialize,
    Serialize,
};

use crate::time_period::TimePeriod;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Attack {
    pub source_ip: String,
    pub target_port: u32,
    pub threat: String,
    pub timestamp: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttackRecords {
    pub period: TimePeriod,
    pub list: Vec<Attack>,
}

impl AttackRecords {
    pub fn new(period: TimePeriod) -> Self {
        AttackRecords {
            period: period,
            list: vec![],
        }
    }
}
