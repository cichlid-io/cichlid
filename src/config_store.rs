use crate::types::ConfigItem;
use std::sync::{Arc, Mutex};

pub type ConfigStore = Arc<Mutex<Vec<ConfigItem>>>;

pub fn new_store() -> ConfigStore {
    Arc::new(Mutex::new(vec![]))
}
