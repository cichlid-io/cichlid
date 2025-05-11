use std::process::Command;
use std::io;

pub fn list_pq_signature_algorithms() -> io::Result<Vec<String>> {
    let output = Command::new("openssl")
        .args(["list", "-signature-algorithms", "-provider", "default", "-provider", "oqsprovider"])
        .output()?;

    if !output.status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "openssl command failed"));
    }

    let list = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.strip_suffix(" @ oqsprovider"))
        .map(|s| s.trim().to_string())
        .collect();

    Ok(list)
}
