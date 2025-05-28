use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use rcgen::{generate_simple_self_signed, CertificateParams};

pub fn generate_self_signed_cert(cert_out: &str, key_out: &str) -> Result<(), Box<dyn std::error::Error>> {
    let subject_alt_names = vec!["localhost".to_string()];
    let mut params = CertificateParams::new(subject_alt_names);
    params.is_ca = rcgen::IsCa::SelfSignedOnly;
    let cert = generate_simple_self_signed(vec!["localhost".into()])?;

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
       .args(&["genpkey", "-algorithm", "RSA", "-out", ca_key_out, "-pkeyopt", "rsa_keygen_bits:4096"])
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
           "-key", ca_key_out,
           "-out", ca_cert_out,
           "-days", "3650",
           "-sha256",
           "-subj", "/CN=cichlid-ca"
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
           "-keyout", ca_key_out,
           "-out", ca_cert_out,
           "-days", "3650",
           "-sha256",
           "-nodes",
           "-subj", "/CN=cichlid-ca",
           "-provider", "default",
           "-provider", "oqsprovider",
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
) -> Result<(), Box<dyn std::error::Error>> {
    // Generate private key
    let key_output = Command::new("openssl")
        .args(&["genpkey", "-algorithm", "RSA", "-out", key_out, "-pkeyopt", "rsa_keygen_bits:4096"])
        .output()?;
    if !key_output.status.success() {
        return Err("Failed to generate private key with openssl".into());
    }

    // Generate CSR
    let csr_path = format!("{}.csr", cert_out);
    let csr_status = Command::new("openssl")
        .args(&[
            "req",
            "-new",
            "-key", key_out,
            "-out", &csr_path,
            "-subj", "/CN=localhost"
        ])
        .status()?;
    if !csr_status.success() {
        return Err("Failed to generate CSR with openssl".into());
    }

    // Sign CSR with CA
    let sign_status = Command::new("openssl")
        .args(&[
            "x509",
            "-req",
            "-in", &csr_path,
            "-CA", ca_cert_path,
            "-CAkey", ca_key_path,
            "-CAcreateserial",
            "-out", cert_out,
            "-days", "365",
            "-sha256",
        ])
        .status()?;
    if !sign_status.success() {
        return Err("Failed to sign certificate with openssl CA".into());
    }

    // Cleanup CSR and .srl
    let _ = std::fs::remove_file(&csr_path);
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
) -> Result<(), Box<dyn std::error::Error>> {
    // Generate PQ key and CSR
    let pq_key_status = Command::new("openssl")
        .args(&[
            "req",
            "-new",
            "-newkey",
            pq_alg,
            "-keyout", key_out,
            "-out", &format!("{}.csr", cert_out),
            "-nodes",
            "-subj", "/CN=localhost",
            "-provider", "default",
            "-provider", "oqsprovider",
        ])
        .status()?;
    if !pq_key_status.success() {
        return Err(format!("Failed to generate PQ key/csr with openssl for alg: {}", pq_alg).into());
    }

    // Sign CSR with CA
    let csr_path = format!("{}.csr", cert_out);
    let sign_status = Command::new("openssl")
        .args(&[
            "x509",
            "-req",
            "-in", &csr_path,
            "-CA", ca_cert_path,
            "-CAkey", ca_key_path,
            "-CAcreateserial",
            "-out", cert_out,
            "-days", "365",
            "-sha256",
        ])
        .status()?;
    if !sign_status.success() {
        return Err("Failed to sign PQ certificate with CA".into());
    }

    // Cleanup CSR and .srl
    let _ = std::fs::remove_file(&csr_path);
    let srl_path = format!("{}.srl", ca_cert_path.trim_end_matches(".pem"));
    let _ = std::fs::remove_file(&srl_path);

    Ok(())
}
