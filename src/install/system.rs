use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::Command;

/// Run the install flow for cichlid, returning Ok(()) on success, or printing errors and exiting on failure.
use std::path::PathBuf;

pub fn install(
    overwrite: bool,
    cert_path: PathBuf,
    key_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    // Root check
    if unsafe { libc::geteuid() } != 0 {
        tracing::error!("Install must be run as root (e.g., with sudo)");
        std::process::exit(1);
    }

    // 1. Ensure system user cichlid exists.
    let output = Command::new("id").arg("-u").arg("cichlid").output();
    if let Ok(out) = &output {
        if !out.status.success() {
            // useradd if doesn't exist
            let status = Command::new("useradd")
                .args(&[
                    "-r",
                    "-m",
                    "-d",
                    "/var/lib/cichlid",
                    "-G",
                    "wheel",
                    "cichlid",
                ])
                .status()
                .expect("failed to create user cichlid");
            if !status.success() {
                tracing::error!("Failed to create cichlid user");
                std::process::exit(1);
            }
        }
    } else {
        tracing::error!("User lookup failed.");
        std::process::exit(1);
    }

    // 2. Add passwordless sudo to /etc/sudoers.d/cichlid
    let sudoers_content = "cichlid ALL=(ALL) NOPASSWD:ALL\n";
    {
        let mut file = File::create("/etc/sudoers.d/cichlid")
            .expect("Failed to write /etc/sudoers.d/cichlid -- need root?");
        file.write_all(sudoers_content.as_bytes())
            .expect("Failed to write sudoers line");
    }
    let _ = Command::new("chmod")
        .args(&["0440", "/etc/sudoers.d/cichlid"])
        .status();

    // 3. Copy binary to /usr/local/bin/cichlid, stopping service if active and overwrite is required.
    let bin_dest = "/usr/local/bin/cichlid";
    let exe_path =
        fs::read_link("/proc/self/exe").expect("Failed to determine running binary location");
    if Path::new(bin_dest).exists() && !overwrite {
        tracing::error!(
            "Binary {} already exists. Use --overwrite to replace.",
            bin_dest
        );
        std::process::exit(1);
    }
    if Path::new(bin_dest).exists() && overwrite {
        let status = Command::new("systemctl")
            .args(&["is-active", "--quiet", "cichlid.service"])
            .status();
        if let Ok(st) = status {
            if st.success() {
                let _ = Command::new("systemctl")
                    .args(&["stop", "cichlid.service"])
                    .status();
            }
        }
    }
    // Always copy binary (overwrite if necessary).
    fs::copy(&exe_path, bin_dest)
        .expect("Failed to copy binary to /usr/local/bin/cichlid -- need root?");

    // 4. Make cert directory and generate cert/key at provided paths
    if cert_path.as_os_str().is_empty() || key_path.as_os_str().is_empty() {
        tracing::error!("cert_path and key_path must be provided to install(); no default is set internally.");
        std::process::exit(1);
    }
    let cert_dir = cert_path.parent().unwrap_or_else(|| {
        tracing::error!("Failed to determine cert directory from cert_path: '{}'", cert_path.display());
        std::process::exit(1);
    });
    if let Err(e) = fs::create_dir_all(cert_dir) {
        tracing::error!("Failed to create cert directory {}: {}", cert_dir.display(), e);
        std::process::exit(1);
    }

    let cert_exists = cert_path.exists();
    let key_exists = key_path.exists();
    if cert_exists || key_exists {
        tracing::info!(
            "Cert and/or key already exist at cert: file://{}, key: file://{}; not overwriting.",
            cert_path.display(),
            key_path.display()
        );
    } else {
        // Default SANs: localhost and 127.0.0.1; in practice, allow setting via args/env/config as desired.
        let subject_names = &["localhost", "127.0.0.1"];
        match crate::certs::generate_self_signed_cert(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            subject_names,
        ) {
            Ok(_) => tracing::info!(
                "Cert and key generated at\n  cert: file://{}\n  key: file://{}",
                cert_path.display(),
                key_path.display()
            ),
            Err(e) => {
                tracing::error!("Failed to generate TLS cert/key: {}", e);
                std::process::exit(1);
            }
        }
    }

    // 5. Create or overwrite a systemd unit file pointing to the cert/key
    let systemd_unit = format!(
        r#"[Unit]
Description=Cichlid Service
After=network.target

[Service]
User=cichlid
ExecStart=/usr/local/bin/cichlid --cert-path {} --key-path {}
WorkingDirectory=/var/lib/cichlid
Restart=on-failure
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
"#,
        cert_path.display(), key_path.display()
    );
    {
        let mut unit = File::create("/etc/systemd/system/cichlid.service")
            .expect("Failed to write file:///etc/systemd/system/cichlid.service -- need root?");
        unit.write_all(systemd_unit.as_bytes())
            .expect("Failed to write systemd file");
    }

    // 6. Reload systemd and enable/start service
    let _ = Command::new("systemctl").args(&["daemon-reload"]).status();
    let _ = Command::new("systemctl")
        .args(&["enable", "--now", "cichlid.service"])
        .status();

    tracing::info!("Cichlid installed, system user, sudoers, binary, cert/key, and service set up.");
    Ok(())
}

/// Run the uninstall flow for cichlid. If `purge` is set, remove everything; otherwise just stop/disable service.
pub fn uninstall(purge: bool) -> Result<(), Box<dyn std::error::Error>> {
    if unsafe { libc::geteuid() } != 0 {
        tracing::error!("Uninstall must be run as root (e.g., with sudo)");
        std::process::exit(1);
    }

    // Stop and disable the service
    let _ = Command::new("systemctl")
        .args(&["stop", "cichlid.service"])
        .status();
    let _ = Command::new("systemctl")
        .args(&["disable", "cichlid.service"])
        .status();

    if purge {
        // Remove systemd service unit
        let _ = fs::remove_file("/etc/systemd/system/cichlid.service");
        let _ = Command::new("systemctl").args(&["daemon-reload"]).status();

        // Remove sudoer file
        let _ = fs::remove_file("/etc/sudoers.d/cichlid");

        // Remove binary
        let _ = fs::remove_file("/usr/local/bin/cichlid");

        // Remove config folder and certs
        let _ = fs::remove_dir_all("/etc/cichlid");

        // Delete user
        let _ = Command::new("userdel").args(&["-r", "cichlid"]).status();

        tracing::info!("Cichlid service, files, user, and config purged.");
    } else {
        tracing::info!("Cichlid service stopped and disabled. (user, binary, and config left intact)");
    }
    Ok(())
}
