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

use boot::Boot;
use chrono::{
    DateTime,
    Duration,
    Utc,
};
use crate::query_builder::QueryBuilder;
use journal::{
    Journal,
    OpenFlags,
};
use journal_entries::{
    JournalEntries,
    JournalEntry,
};
use libsdjournal::JournalError;
use regex::Regex;
use serde::Deserialize;
use unit::Unit;

#[tokio::main]
async fn main() {
    /*
    journalctl \
      -u ssh \
      -g 'authentication failure' \
      --output json \
      --output-fields _SOURCE_REALTIME_TIMESTAMP,MESSAGE,PRIORITY
    */
    let q = JournalQuery {
        fields: vec![journal_fields::SOURCE_REALTIME_TIMESTAMP.to_string(), journal_fields::MESSAGE.to_string()],
        services: vec!["ssh.service".to_string()],
        limit: 0,
        priority: 5,
        quick_search: "authentication failure".to_string(),
        reset_position: true,
        transports: vec!["syslog".to_string()],
        datetime_from: "".to_string(),
        datetime_to: "".to_string(),
        boot_ids: vec![],
    };
    let re: Regex = Regex::new(r#"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"#).unwrap();
    let mut attacks: Vec<Attack> = Vec::new();
    match get_logs(q).await {
        Ok(entries) => {
            for row in entries.rows {
                let attack = Attack {
                    source_ip: match re.find(&row[1]) {
                        Some(ip) => ip.as_str().to_string(),
                        _ => "".to_string(),
                    },
                    timestamp: row[0].parse::<u64>().unwrap_or(0),
                    target_port: 22,
                    note: "ssh auth failure".to_string(),
                };
                println!("{} {} {} {}", attack.timestamp, attack.target_port, attack.source_ip, attack.note);
                attacks.push(attack);
            }
            println!("{} threat sources observed", attacks.len());
        },
        journal_error => {},
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Attack {
    source_ip: String,
    target_port: u32,
    note: String,
    timestamp: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JournalQuery {
    fields: Vec<String>,
    priority: u32,
    limit: u64,
    quick_search: String,
    reset_position: bool,
    services: Vec<String>,
    transports: Vec<String>,
    datetime_from: String,
    datetime_to: String,
    boot_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SummaryQuery {
    priority: u32,
}

async fn get_logs(query: JournalQuery) -> Result<JournalEntries, JournalError> {
    debug!("get_logs(query)");

    let mut qb = QueryBuilder::default();
    let q = qb
        .with_fields(query.fields)
        .with_limit(query.limit)
        .with_quick_search(query.quick_search)
        .reset_position(query.reset_position)
        .with_priority_above_or_equal_to(query.priority)
        .with_units(query.services)
        .with_transports(query.transports)
        .with_boot_ids(query.boot_ids);

    let date_from = DateTime::parse_from_rfc3339(&query.datetime_from).ok();
    let date_to = DateTime::parse_from_rfc3339(&query.datetime_to).ok();

    if let Some(x) = date_from {
        q.with_date_not_more_recent_than(x.timestamp_micros() as u64);
    }

    if let Some(x) = date_to {
        q.with_date_not_older_than(x.timestamp_micros() as u64);
    }

    let q = q.build();

    let j = Journal::open(
        OpenFlags::SD_JOURNAL_LOCAL_ONLY
            | OpenFlags::SD_JOURNAL_SYSTEM,
    ).unwrap();
    //let lock = j.lock().await;
    let logs = j.query_logs(&q)?;
    debug!("found {} entries.", logs.rows.len());

    Ok(logs)
}

#[tauri::command]
async fn get_full_entry(timestamp: u64) -> Result<JournalEntry, JournalError> {
    debug!("get_full_entry(timestamp: {})", timestamp);

    let j = Journal::open(
        OpenFlags::SD_JOURNAL_LOCAL_ONLY
            | OpenFlags::SD_JOURNAL_SYSTEM
            | OpenFlags::SD_JOURNAL_CURRENT_USER,
    ).unwrap();
    let entry = j.get_full_entry(timestamp)?;

    debug!("Found entry for timestamp {}", timestamp);

    Ok(entry)
}

async fn get_summary(query: SummaryQuery) -> Result<JournalEntries, JournalError> {
    debug!("Getting summary...");
    let j = Journal::open(
        OpenFlags::SD_JOURNAL_LOCAL_ONLY
            | OpenFlags::SD_JOURNAL_SYSTEM
            | OpenFlags::SD_JOURNAL_CURRENT_USER,
    )
    .unwrap();

    let datetime_to = Utc::now() - Duration::days(1);
    let mut qb = QueryBuilder::default();
    let q = qb
        .with_fields(vec!["__REALTIME".into()])
        .with_limit(10_000)
        .with_date_not_older_than(datetime_to.timestamp_micros() as u64)
        .with_priority_above_or_equal_to(query.priority)
        .build();

    let logs = j.query_logs(&q)?;
    debug!("Found {} entries.", logs.rows.len());

    Ok(logs)
}

async fn get_services() -> Result<Vec<Unit>, JournalError> {
    debug!("Getting services...");
    let services = Journal::list_services();
    debug!("found {} services", services.len());

    Ok(services)
}

async fn get_boots() -> Result<Vec<Boot>, JournalError> {
    debug!("Getting boots...");
    let boots = Journal::list_boots();
    debug!("found {} boots", boots.len());

    Ok(boots)
}
