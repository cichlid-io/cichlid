mod attack;
mod boot;
mod journal;
mod journal_entries;
mod journal_fields;
mod journal_query;
mod libsdjournal;
mod libsdjournal_bindings;
mod query;
mod query_builder;
mod time_period;
mod unit;

#[macro_use]
extern crate rocket;

use attack::Attack;
use journal::{
    Journal,
    OpenFlags,
};
use journal_entries::JournalEntries;
use journal_query::JournalQuery;
use libsdjournal::JournalError;
use query_builder::QueryBuilder;

use chrono::{
    DateTime,
    Utc,
};
use regex::Regex;
use rocket::serde::json::{
    json,
    Value
};

#[get("/attacks/<since>")]
async fn attacks(since: String) -> Value {
    match DateTime::parse_from_rfc3339(&since).ok() {
        Some(date_since) => match get_attacks(date_since.into(), Utc::now()).await {
            Ok(result) => json!(result),
            _ => json!({ "error": "journal lookup failure" })
        },
        _ => json!({ "error": "date parse failure" })
    }
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![attacks])
}

async fn get_attacks(from: DateTime<Utc>, to: DateTime<Utc>) -> Result<Vec<Attack>, JournalError> {
    let threats = vec!["scan", "ssh"];
    let ports_regex: Regex = Regex::new(r#"ports ([\d,\s]+),\s\.\.\.,"#).unwrap();
    let ip_regex: Regex = Regex::new(r#"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"#).unwrap();
    let mut attacks: Vec<Attack> = Vec::new();
    for threat in threats {
        let journal_query_or_error = match threat {
            "scan" => Ok(JournalQuery::new("scanlogd.service", "tos", from, to)),
            "ssh" => Ok(JournalQuery::new("ssh.service", "authentication failure", from, to)),
            _ => Err("unrecognised threat"),
        };
        match journal_query_or_error {
            Ok(journal_query) => {
                match get_logs(journal_query).await {
                    Ok(entries) => {
                        for row in entries.rows {
                            match threat {
                                "scan" => {
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
                                        debug!("{} {} {} {}", attack.timestamp, attack.target_port, attack.source_ip, attack.threat);
                                        attacks.push(attack);
                                    }
                                },
                                "ssh" => {
                                    let attack = Attack {
                                        source_ip: match ip_regex.find(&row[1]) {
                                            Some(ip) => ip.as_str().to_string(),
                                            _ => "".to_string(),
                                        },
                                        timestamp: row[0].parse::<u64>().unwrap_or(0),
                                        target_port: 22,
                                        threat: threat.to_string(),
                                    };
                                    debug!("{} {} {} {}", attack.timestamp, attack.target_port, attack.source_ip, attack.threat);
                                    attacks.push(attack);
                                },
                                _ => {},
                            }
                        }
                    },
                    _ => (),
                }
                println!("{} {} attacks observed between {} and {}", attacks.iter().filter(|&n| *n.threat == threat.to_string()).count(), threat, from, to);
            },
            _ => {},
        }
    }

    Ok(attacks)
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
        .with_boot_ids(query.boot_ids)
        .with_date_not_more_recent_than(query.to.timestamp_micros() as u64)
        .with_date_not_older_than(query.from.timestamp_micros() as u64);

    let q = q.build();
    let j = Journal::open(OpenFlags::SD_JOURNAL_LOCAL_ONLY | OpenFlags::SD_JOURNAL_SYSTEM).unwrap();
    let logs = j.query_logs(&q)?;
    debug!("found {} entries.", logs.rows.len());

    Ok(logs)
}
