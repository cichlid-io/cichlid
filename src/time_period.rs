use chrono::{
    DateTime,
    Utc,
};
use serde::{
    Deserialize,
    Serialize,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimePeriod {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

impl TimePeriod {
    pub fn new(from: DateTime<Utc>, to: DateTime<Utc>) -> Self {
        TimePeriod {
            from: from,
            to: to,
        }
    }
}
