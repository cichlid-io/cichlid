use std::process::Command;

fn main() {
    // Get git SHA
    let output = Command::new("git")
        .args(&["rev-parse", "HEAD"])
        .output()
        .expect("Failed to execute git");

    let git_hash = if output.status.success() {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        "unknown".to_string()
    };

    // Set as environment variable for use in option_env!
    println!("cargo:rustc-env=GIT_COMMIT_HASH={}", git_hash);

    // If you want to rerun when git HEAD changes:
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");
}
