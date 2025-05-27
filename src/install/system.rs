use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::Command;

/// Run the install flow for cichlid, returning Ok(()) on success, or printing errors and exiting on failure.
pub fn install(overwrite: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Root check
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Install must be run as root (e.g., with sudo)");
        std::process::exit(1);
    }

    // 1. Ensure system user cichlid exists.
    let output = Command::new("id").arg("-u").arg("cichlid").output();
    if let Ok(out) = &output {
        if !out.status.success() {
            // useradd if doesn't exist
            let status = Command::new("useradd")
                .args(&[
                    "-r", "-m", "-d", "/var/lib/cichlid", "-G", "wheel", "cichlid"])
                .status()
                .expect("failed to create user cichlid");
            if !status.success() {
                eprintln!("Failed to create cichlid user");
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("User lookup failed.");
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
    let _ = Command::new("chmod").args(&["0440", "/etc/sudoers.d/cichlid"]).status();

    // 3. Copy binary to /usr/local/bin/cichlid, stopping service if active and overwrite is required.
    let bin_dest = "/usr/local/bin/cichlid";
    let exe_path = fs::read_link("/proc/self/exe").expect("Failed to determine running binary location");
    if Path::new(bin_dest).exists() && !overwrite {
        eprintln!("Binary {} already exists. Use --overwrite to replace.", bin_dest);
        std::process::exit(1);
    }
    if overwrite {
        let status = Command::new("systemctl")
            .args(&["is-active", "--quiet", "cichlid.service"])
            .status();
        if let Ok(st) = status {
            if st.success() {
                let _ = Command::new("systemctl").args(&["stop", "cichlid.service"]).status();
            }
        }
    }
    fs::copy(&exe_path, bin_dest)
        .expect("Failed to copy binary to /usr/local/bin/cichlid -- need root?");

    // 4. Make /etc/cichlid/cert and generate default cert/key
    let cert_dir = "/etc/cichlid/cert";
    let default_cert = "/etc/cichlid/cert/default-cert.pem";
    let default_key = "/etc/cichlid/cert/default-key.pem";
    if let Err(e) = fs::create_dir_all(cert_dir) {
        eprintln!("Failed to create cert directory {}: {}", cert_dir, e);
        std::process::exit(1);
    }
    let cert_exists = Path::new(default_cert).exists();
    let key_exists = Path::new(default_key).exists();
    if (cert_exists || key_exists) && !overwrite {
        eprintln!("Default cert or key already exists in {}. Use --overwrite to replace.", cert_dir);
        std::process::exit(1);
    }
    match crate::certs::generate_self_signed_cert(default_cert, default_key) {
        Ok(_) => println!("Default cert and key generated at {}/", cert_dir),
        Err(e) => {
            eprintln!("Failed to generate default TLS cert/key: {}", e);
            std::process::exit(1);
        }
    }

    // 5. Create or overwrite a systemd unit file pointing to the cert/key
    let systemd_unit = format!(r#"[Unit]
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
"#, default_cert, default_key);
    {
        let mut unit = File::create("/etc/systemd/system/cichlid.service")
            .expect("Failed to write /etc/systemd/system/cichlid.service -- need root?");
        unit.write_all(systemd_unit.as_bytes())
            .expect("Failed to write systemd file");
    }

    // 6. Reload systemd and enable/start service
    let _ = Command::new("systemctl").args(&["daemon-reload"]).status();
    let _ = Command::new("systemctl").args(&["enable", "--now", "cichlid.service"]).status();

    println!("Cichlid installed, system user, sudoers, binary, cert/key, and service set up.");
    Ok(())
}

/// Run the uninstall flow for cichlid. If `purge` is set, remove everything; otherwise just stop/disable service.
pub fn uninstall(purge: bool) -> Result<(), Box<dyn std::error::Error>> {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Uninstall must be run as root (e.g., with sudo)");
        std::process::exit(1);
    }

    // Stop and disable the service
    let _ = Command::new("systemctl").args(&["stop", "cichlid.service"]).status();
    let _ = Command::new("systemctl").args(&["disable", "cichlid.service"]).status();

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

        println!("Cichlid service, files, user, and config purged.");
    } else {
        println!("Cichlid service stopped and disabled. (user, binary, and config left intact)");
    }
    Ok(())
}
