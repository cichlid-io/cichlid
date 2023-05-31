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

use chrono::DateTime;
use crate::query_builder::QueryBuilder;
use journal::{
    Journal,
    OpenFlags,
};
use journal_entries::JournalEntries;
use libsdjournal::JournalError;
use regex::Regex;
use serde::Deserialize;

#[tokio::main]
async fn main() {
    let threats = vec!["scan", "ssh"];
    let ports_regex: Regex = Regex::new(r#"ports ([\d,\s]+),\s\.\.\.,"#).unwrap();
    let ip_regex: Regex = Regex::new(r#"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"#).unwrap();
    let mut attacks: Vec<Attack> = Vec::new();
    for threat in threats {
        match get_logs(match threat {
            "scan" => JournalQuery::new("scanlogd.service", "tos"),
            "ssh" => JournalQuery::new("ssh.service", "authentication failure"),
            _ => JournalQuery::new("scanlogd.service", "tos"),
        }).await {
            Ok(entries) => {
                for row in entries.rows {
                    match threat {
                        "scan" => {
                            //journalctl -u scanlogd -g 'tos' --output json --output-fields MESSAGE,_SOURCE_REALTIME_TIMESTAMP,_HOSTNAME
                            let ports: Vec<u32> = ports_regex.captures(&row[1]).unwrap()
                              .get(1).map_or("", |m| m.as_str())
                              .split(", ").map(|s| s.parse::<u32>().unwrap()).collect();
                            let ip = match ip_regex.find(&row[1]) {
                                Some(x) => x.as_str(),
                                _ => "",
                            };
                            for port in ports {
                                let attack = Attack {
                                    source_ip: ip.to_string(),
                                    timestamp: row[0].parse::<u64>().unwrap_or(0),
                                    target_port: port,
                                    threat: threat.to_string(),
                                };
                                //println!("{} {} {} {}", attack.timestamp, attack.target_port, attack.source_ip, attack.note);
                                attacks.push(attack);
                            }
                        },
                        "ssh" => {
                            //journalctl -u ssh.service -g 'authentication failure' --output json --output-fields MESSAGE,_SOURCE_REALTIME_TIMESTAMP,_HOSTNAME
                            let attack = Attack {
                                source_ip: match ip_regex.find(&row[1]) {
                                    Some(ip) => ip.as_str().to_string(),
                                    _ => "".to_string(),
                                },
                                timestamp: row[0].parse::<u64>().unwrap_or(0),
                                target_port: 22,
                                threat: threat.to_string(),
                            };
                            //println!("{} {} {} {}", attack.timestamp, attack.target_port, attack.source_ip, attack.note);
                            attacks.push(attack);
                        },
                        _ => {}
                    }
                }
            },
            journal_error => {
                println!("{:#?}", journal_error);
            },
        }
        println!("{} {} attacks observed", attacks.iter().filter(|&n| *n.threat == threat.to_string()).count(), threat);
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Attack {
    source_ip: String,
    target_port: u32,
    threat: String,
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

impl JournalQuery {
    fn new(service: &str, grep: &str) -> Self {
        JournalQuery {
            services: vec![service.to_string()],
            quick_search: grep.to_string(),
            fields: vec![journal_fields::SOURCE_REALTIME_TIMESTAMP.to_string(), journal_fields::MESSAGE.to_string()],
            limit: 0,
            priority: 0,
            reset_position: true,
            transports: vec![],
            datetime_from: "".to_string(),
            datetime_to: "".to_string(),
            boot_ids: vec![],
        }
    }
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
    let j = Journal::open(OpenFlags::SD_JOURNAL_LOCAL_ONLY | OpenFlags::SD_JOURNAL_SYSTEM).unwrap();
    //let lock = j.lock().await;
    let logs = j.query_logs(&q)?;
    debug!("found {} entries.", logs.rows.len());

    Ok(logs)
}
