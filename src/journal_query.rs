use chrono::{
    DateTime,
    Utc,
};
use serde::Deserialize;
use crate::journal_fields::{
    MESSAGE,
    SOURCE_REALTIME_TIMESTAMP,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JournalQuery {
    pub fields: Vec<String>,
    pub priority: u32,
    pub limit: u64,
    pub quick_search: String,
    pub reset_position: bool,
    pub services: Vec<String>,
    pub transports: Vec<String>,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub boot_ids: Vec<String>,
}

impl JournalQuery {
    pub fn new(service: &str, grep: &str, from: DateTime<Utc>, to: DateTime<Utc>) -> Self {
        JournalQuery {
            services: vec![service.to_string()],
            quick_search: grep.to_string(),
            fields: vec![SOURCE_REALTIME_TIMESTAMP.to_string(), MESSAGE.to_string()],
            limit: 0,
            priority: 0,
            reset_position: true,
            transports: vec![],
            from: from,
            to: to,
            boot_ids: vec![],
        }
    }
}