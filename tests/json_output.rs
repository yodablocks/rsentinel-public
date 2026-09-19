use std::process::Command;

fn cargo_run(args: &[&str]) -> std::process::Output {
    Command::new("cargo")
        .arg("run")
        .arg("--")
        .args(args)
        .output()
        .expect("failed to execute cargo run")
}

#[test]
fn test_demo_json_is_valid_json() {
    let output = cargo_run(&["demo", "--json"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("demo --json output is not valid JSON");
    assert!(parsed.is_object());
}

#[test]
fn test_demo_json_has_required_fields() {
    let output = cargo_run(&["demo", "--json"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert!(parsed.get("target").is_some(), "missing 'target'");
    assert!(parsed.get("scan_time").is_some(), "missing 'scan_time'");
    assert!(parsed.get("findings").is_some(), "missing 'findings'");
    assert!(parsed.get("summary").is_some(), "missing 'summary'");
}

#[test]
fn test_demo_json_has_4_findings() {
    let output = cargo_run(&["demo", "--json"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let findings = parsed["findings"]
        .as_array()
        .expect("findings is not an array");
    assert_eq!(findings.len(), 4, "demo should produce exactly 4 findings");
}

#[test]
fn test_demo_json_no_progress_lines() {
    let output = cargo_run(&["demo", "--json"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // JSON mode should suppress emoji progress lines
    assert!(
        !stdout.contains("Running demo"),
        "progress line leaked into JSON output"
    );
    assert!(
        !stdout.contains("🔍"),
        "emoji progress line leaked into JSON output"
    );
}

#[test]
fn test_demo_sarif_is_valid_json() {
    let output = cargo_run(&["demo", "--sarif"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("demo --sarif output is not valid JSON");
    assert_eq!(parsed["version"], "2.1.0");
    assert!(parsed["runs"].as_array().is_some());
}

#[test]
fn test_demo_quiet_suppresses_progress() {
    let output = cargo_run(&["demo", "-Q"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Quiet mode should suppress progress but still show the report
    assert!(
        !stdout.contains("Running demo"),
        "progress line not suppressed by -Q"
    );
    assert!(
        stdout.contains("RSENTINEL SECURITY EXPOSURE REPORT"),
        "report missing in quiet mode"
    );
}

#[test]
fn test_demo_fail_on_medium_exits_nonzero() {
    let output = cargo_run(&["demo", "--fail-on", "medium"]);
    assert!(
        !output.status.success(),
        "--fail-on medium should exit non-zero for demo (has critical+high+medium)"
    );
}

#[test]
fn test_demo_html_export() {
    let path = "/tmp/rsentinel_test_report.html";
    let _ = std::fs::remove_file(path);
    let output = cargo_run(&["demo", "--html", path]);
    assert!(output.status.success(), "demo --html failed");
    let html = std::fs::read_to_string(path).expect("HTML file not created");
    assert!(html.contains("RSENTINEL SECURITY EXPOSURE REPORT"));
    assert!(html.contains("Critical"));
    let _ = std::fs::remove_file(path);
}
