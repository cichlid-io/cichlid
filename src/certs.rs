use std::fs::File;
use std::io::Write;
use std::path::Path;
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
