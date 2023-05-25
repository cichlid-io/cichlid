#![allow(dead_code)]

mod boot;
mod journal;
mod journal_entries;
mod journal_fields;
mod libsdjournal;
mod libsdjournal_bindings;
mod query;
mod query_builder;
mod unit;

#[macro_use]
extern crate log;

use journal::{
    Journal,
    OpenFlags
};
use std::time::Duration;
use std::thread;

fn main() {
    loop {
        let j = Journal::open(
            OpenFlags::SD_JOURNAL_LOCAL_ONLY
                | OpenFlags::SD_JOURNAL_SYSTEM
                | OpenFlags::SD_JOURNAL_CURRENT_USER,
        )
        .unwrap();
        println!("no threat sources observed");
        thread::sleep(Duration::from_millis(10000))
    }
}
