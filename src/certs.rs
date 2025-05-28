use rcgen::CertificateParams;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Command;

pub fn generate_self_signed_cert(
    cert_out: &str,
    key_out: &str,
    subject_names: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut params = CertificateParams::new(
        subject_names
            .iter()
            .cloned()
            .map(String::from)
            .collect::<Vec<_>>(),
    );
    params.is_ca = rcgen::IsCa::SelfSignedOnly;
    let cert = rcgen::Certificate::from_params(params)?;

    let cert_pem = cert.serialize_pem()?;
    let key_pem = cert.serialize_private_key_pem();

    File::create(Path::new(cert_out))?.write_all(cert_pem.as_bytes())?;
    File::create(Path::new(key_out))?.write_all(key_pem.as_bytes())?;

    Ok(())
}

/// Generate a normal (RSA) CA certificate and key.
pub fn generate_normal_ca_cert(
    ca_cert_out: &str,
    ca_key_out: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Generate private key
    let key_output = Command::new("openssl")
        .args(&[
            "genpkey",
            "-algorithm",
            "RSA",
            "-out",
            ca_key_out,
            "-pkeyopt",
            "rsa_keygen_bits:4096",
        ])
        .output()?;
    if !key_output.status.success() {
        return Err("Failed to generate CA private key with openssl".into());
    }

    // Generate self-signed CA cert
    let cert_status = Command::new("openssl")
        .args(&[
            "req",
            "-x509",
            "-new",
            "-key",
            ca_key_out,
            "-out",
            ca_cert_out,
            "-days",
            "3650",
            "-sha256",
            "-subj",
            "/CN=cichlid-ca",
        ])
        .status()?;
    if !cert_status.success() {
        return Err("Failed to generate CA cert with openssl".into());
    }

    Ok(())
}

/// Generate a PQ CA certificate and key using the specified PQ algorithm.
pub fn generate_pq_ca_cert(
    ca_cert_out: &str,
    ca_key_out: &str,
    pq_alg: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Generate key + self-signed PQ cert with openssl+oqs
    let status = Command::new("openssl")
        .args(&[
            "req",
            "-x509",
            "-newkey",
            pq_alg,
            "-keyout",
            ca_key_out,
            "-out",
            ca_cert_out,
            "-days",
            "3650",
            "-sha256",
            "-nodes",
            "-subj",
            "/CN=cichlid-ca",
            "-provider",
            "default",
            "-provider",
            "oqsprovider",
        ])
        .status()?;
    if !status.success() {
        return Err("Failed to generate PQ CA cert/key with openssl".into());
    }
    Ok(())
}

/// Generate a certificate/key pair and sign the certificate with the given CA.
pub fn generate_cert_signed_by_ca(
    cert_out: &str,
    key_out: &str,
    ca_cert_path: &str,
    ca_key_path: &str,
    subject_names: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    // Generate private key
    let key_output = Command::new("openssl")
        .args(&[
            "genpkey",
            "-algorithm",
            "RSA",
            "-out",
            key_out,
            "-pkeyopt",
            "rsa_keygen_bits:4096",
        ])
        .output()?;
    if !key_output.status.success() {
        return Err("Failed to generate private key with openssl".into());
    }

    // Generate OpenSSL config file for SANs
    let openssl_config = format!(
        "[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
[ req_distinguished_name ]
[ v3_req ]
subjectAltName = {}
",
        subject_names
            .iter()
            .enumerate()
            .map(|(i, name)| {
                if name.parse::<std::net::IpAddr>().is_ok() {
                    format!("IP.{}:{}", i + 1, name)
                } else {
                    format!("DNS.{}:{}", i + 1, name)
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    );
    let config_path = format!("{}.openssl.cnf", cert_out);
    std::fs::write(&config_path, &openssl_config)?;

    // Use the first subject name as CN for compatibility
    let cn = subject_names.get(0).copied().unwrap_or("localhost");

    // Generate CSR
    let csr_path = format!("{}.csr", cert_out);
    let csr_status = Command::new("openssl")
        .args(&[
            "req",
            "-new",
            "-key",
            key_out,
            "-out",
            &csr_path,
            "-subj",
            &format!("/CN={}", cn),
            "-config",
            &config_path,
            "-reqexts",
            "v3_req",
        ])
        .status()?;
    if !csr_status.success() {
        return Err("Failed to generate CSR with openssl".into());
    }

    // Sign CSR with CA, including the SANs extension
    let sign_status = Command::new("openssl")
        .args(&[
            "x509",
            "-req",
            "-in",
            &csr_path,
            "-CA",
            ca_cert_path,
            "-CAkey",
            ca_key_path,
            "-CAcreateserial",
            "-out",
            cert_out,
            "-days",
            "365",
            "-sha256",
            "-extensions",
            "v3_req",
            "-extfile",
            &config_path,
        ])
        .status()?;
    if !sign_status.success() {
        return Err("Failed to sign certificate with openssl CA".into());
    }

    // Cleanup CSR, config, and .srl
    let _ = std::fs::remove_file(&csr_path);
    let _ = std::fs::remove_file(&config_path);
    let srl_path = format!("{}.srl", ca_cert_path.trim_end_matches(".pem"));
    let _ = std::fs::remove_file(&srl_path);

    Ok(())
}

/// Generate a post-quantum certificate/key pair and sign with the given CA using openssl.
pub fn generate_pq_cert_signed_by_ca(
    cert_out: &str,
    key_out: &str,
    ca_cert_path: &str,
    ca_key_path: &str,
    pq_alg: &str,
    subject_names: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    // Generate OpenSSL config file for SANs
    let openssl_config = format!(
        "[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
[ req_distinguished_name ]
[ v3_req ]
subjectAltName = {}
",
        subject_names
            .iter()
            .enumerate()
            .map(|(i, name)| {
                if name.parse::<std::net::IpAddr>().is_ok() {
                    format!("IP.{}:{}", i + 1, name)
                } else {
                    format!("DNS.{}:{}", i + 1, name)
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    );
    let config_path = format!("{}.openssl.cnf", cert_out);
    std::fs::write(&config_path, &openssl_config)?;

    // Use the first subject name as CN for compatibility
    let cn = subject_names.get(0).copied().unwrap_or("localhost");

    // Generate PQ key and CSR
    let csr_path = format!("{}.csr", cert_out);
    let pq_key_status = Command::new("openssl")
        .args(&[
            "req",
            "-new",
            "-newkey",
            pq_alg,
            "-keyout",
            key_out,
            "-out",
            &csr_path,
            "-nodes",
            "-subj",
            &format!("/CN={}", cn),
            "-provider",
            "default",
            "-provider",
            "oqsprovider",
            "-config",
            &config_path,
            "-reqexts",
            "v3_req",
        ])
        .status()?;
    if !pq_key_status.success() {
        return Err(format!(
            "Failed to generate PQ key/csr with openssl for alg: {}",
            pq_alg
        )
        .into());
    }

    // Sign CSR with CA, including the SANs extension
    let sign_status = Command::new("openssl")
        .args(&[
            "x509",
            "-req",
            "-in",
            &csr_path,
            "-CA",
            ca_cert_path,
            "-CAkey",
            ca_key_path,
            "-CAcreateserial",
            "-out",
            cert_out,
            "-days",
            "365",
            "-sha256",
            "-extensions",
            "v3_req",
            "-extfile",
            &config_path,
        ])
        .status()?;
    if !sign_status.success() {
        return Err("Failed to sign PQ certificate with CA".into());
    }

    // Cleanup CSR, config, and .srl
    let _ = std::fs::remove_file(&csr_path);
    let _ = std::fs::remove_file(&config_path);
    let srl_path = format!("{}.srl", ca_cert_path.trim_end_matches(".pem"));
    let _ = std::fs::remove_file(&srl_path);

    Ok(())
}
