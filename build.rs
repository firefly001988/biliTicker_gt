use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile proto files for gRPC.
    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(
            &["proto/captcha.proto", "proto/health.proto"],
            &["proto"],
        )?;

    // Embed git commit hash at compile time.
    let git_commit = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=GIT_COMMIT={}", git_commit);
    println!("cargo:rerun-if-changed=.git/HEAD");

    Ok(())
}
