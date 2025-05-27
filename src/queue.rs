use crate::task::Task;
use serde_json;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub struct FsQueue {
    root: PathBuf,
}

impl FsQueue {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        fs::create_dir_all(root.join("queued")).ok();
        fs::create_dir_all(root.join("processing")).ok();
        fs::create_dir_all(root.join("completed")).ok();
        fs::create_dir_all(root.join("failed")).ok();
        Self { root }
    }

    pub fn enqueue(&self, task: &Task) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(task)?;
        let filename = format!("{}.json", task.id);
        let tmp_path = self.root.join("tmp").join(format!("{}.tmp", Uuid::new_v4()));
        let final_path = self.root.join("queued").join(filename);

        fs::create_dir_all(tmp_path.parent().unwrap())?;
        fs::create_dir_all(final_path.parent().unwrap())?;

        let mut f = File::create(&tmp_path)?;
        f.write_all(json.as_bytes())?;
        f.sync_all()?;
        fs::rename(&tmp_path, &final_path)?;
        Ok(())
    }

    pub fn dequeue(&self) -> Option<(PathBuf, Task)> {
        let entries = fs::read_dir(self.root.join("queued")).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            let file_name = path.file_name().unwrap();
            let processing_path = self.root.join("processing").join(file_name);

            if fs::rename(&path, &processing_path).is_err() {
                continue;
            }

            let mut file = File::open(&processing_path).ok()?;
            let mut contents = String::new();
            file.read_to_string(&mut contents).ok()?;
            let task: Task = serde_json::from_str(&contents).ok()?;
            return Some((processing_path, task));
        }
        None
    }

    pub fn complete(&self, path: &Path) {
        let target = self.root.join("completed").join(path.file_name().unwrap());
        let _ = fs::rename(path, target);
    }

    pub fn fail(&self, path: &Path) {
        let target = self.root.join("failed").join(path.file_name().unwrap());
        let _ = fs::rename(path, target);
    }
}
