use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub host: String,
    pub action: String,
    pub commands: Vec<String>,
}
