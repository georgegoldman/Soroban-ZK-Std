use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_scaffold_shielded_token_compiles() {
    let temp = tempdir().expect("Failed to create temp dir");
    let project_name = "test-shielded-app";
    let project_path = temp.path().join(project_name);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-zk"))
        .arg("init")
        .arg(project_name)
        .arg("--template")
        .arg("shielded-token")
        .current_dir(temp.path())
        .output()
        .expect("Failed to execute CLI");

    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let test_output = Command::new("cargo")
        .arg("test")
        .current_dir(&project_path)
        .output()
        .expect("Failed to run cargo test on scaffolded project");

    assert!(
        test_output.status.success(),
        "Scaffolded project failed to compile/test: {}",
        String::from_utf8_lossy(&test_output.stderr)
    );
}
