use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn binary_path() -> PathBuf {
    std::env::var_os("CARGO_BIN_EXE_fantastic-pr")
        .or_else(|| std::env::var_os("CARGO_BIN_EXE_fantastic_pr"))
        .map(PathBuf::from)
        .or_else(|| {
            let mut path = std::env::current_exe().ok()?;
            path.pop();
            if path.ends_with("deps") {
                path.pop();
            }
            let binary_name = if cfg!(windows) {
                "fantastic-pr.exe"
            } else {
                "fantastic-pr"
            };
            let candidate = path.join(binary_name);
            candidate.exists().then_some(candidate)
        })
        .expect("failed to locate fantastic-pr binary for integration tests")
}

fn unique_temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "fantastic-pr-cli-blackbox-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn write_config(path: &Path, body: &str) {
    std::fs::write(path, body).expect("write config fixture");
}

fn run_in(dir: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(binary_path());
    command
        .current_dir(dir)
        .args(args)
        .env_remove("GITHUB_EVENT_PATH")
        .env_remove("GITHUB_REPOSITORY")
        .env_remove("GITHUB_TOKEN");
    command.output().expect("execute fantastic-pr")
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout:\n{}\n\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn arg_str(path: &Path) -> &str {
    path.as_os_str()
        .to_str()
        .expect("test path should be valid utf-8")
}

fn ensure_exists(path: &Path) {
    assert!(
        path.exists(),
        "expected path to exist: {}",
        path.to_string_lossy()
    );
}

fn run_git(repo: &Path, args: &[&str]) {
    let output = Command::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .expect("execute git command");
    assert!(
        output.status.success(),
        "git {:?} failed\nstdout:\n{}\nstderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn validate_config_subcommand_succeeds_with_minimal_config() {
    let dir = unique_temp_dir("validate-ok");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let config_path = dir.join("cfg.yaml");
    write_config(&config_path, "{}\n");

    let output = run_in(
        &dir,
        &["--config", arg_str(&config_path), "validate-config"],
    );
    let text = output_text(&output);
    assert!(output.status.success(), "{text}");
    assert!(text.contains("Config valid:"), "{text}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn migrate_config_subcommand_writes_output_file() {
    let dir = unique_temp_dir("migrate");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let in_path = dir.join("in.yaml");
    let out_path = dir.join("out.yaml");
    write_config(&in_path, "{}\n");

    let output = run_in(
        &dir,
        &[
            "migrate-config",
            "--from",
            arg_str(&in_path),
            "--to",
            arg_str(&out_path),
        ],
    );
    let text = output_text(&output);
    assert!(output.status.success(), "{text}");
    ensure_exists(&out_path);

    let rendered = std::fs::read_to_string(&out_path).expect("read migrated config");
    assert!(rendered.contains("profile:"), "{rendered}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scan_subcommand_fails_without_base_ref_or_git_default_branch() {
    let dir = unique_temp_dir("scan-no-base-ref");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let config_path = dir.join("cfg.yaml");
    write_config(&config_path, "{}\n");

    let output = run_in(&dir, &["scan", "--config", arg_str(&config_path)]);
    let text = output_text(&output);
    assert!(!output.status.success(), "{text}");
    assert!(
        text.contains("base ref not provided and no default remote branch was found"),
        "{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn validate_config_subcommand_fails_for_invalid_config_file() {
    let dir = unique_temp_dir("validate-invalid");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let config_path = dir.join("invalid.yaml");
    write_config(&config_path, "unknown_key: true\n");

    let output = run_in(
        &dir,
        &["validate-config", "--config", arg_str(&config_path)],
    );
    let text = output_text(&output);
    assert!(!output.status.success(), "{text}");
    assert!(
        text.contains("failed to decode merged config")
            || text.contains("unknown field")
            || text.contains("unknown_key"),
        "{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scan_llm_uses_embedded_prompt_defaults_without_repo_prompt_pack() {
    let dir = unique_temp_dir("scan-llm-embedded-prompts");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    run_git(&dir, &["init"]);
    run_git(
        &dir,
        &["config", "user.email", "fantastic-pr-test@example.com"],
    );
    run_git(&dir, &["config", "user.name", "Fantastic PR Test"]);

    std::fs::write(
        dir.join("main.rs"),
        "fn main() {\n    println!(\"v1\");\n}\n",
    )
    .expect("write first revision");
    run_git(&dir, &["add", "main.rs"]);
    run_git(&dir, &["commit", "-m", "initial"]);

    std::fs::write(
        dir.join("main.rs"),
        "fn main(){\n    println!(\"v2\");\n}\n",
    )
    .expect("write second revision");
    run_git(&dir, &["add", "main.rs"]);
    run_git(&dir, &["commit", "-m", "update"]);

    let config_path = dir.join("cfg.yaml");
    write_config(
        &config_path,
        r#"
llm:
  enabled: true
  provider: codex-cli
  cli_command: sh
  cli_args:
    - -lc
    - "cat >/dev/null; printf '{\"findings\": []}'"
"#,
    );

    let output = run_in(
        &dir,
        &[
            "scan",
            "--config",
            arg_str(&config_path),
            "--base-ref",
            "HEAD~1",
        ],
    );
    let text = output_text(&output);
    assert!(output.status.success(), "{text}");
    assert!(
        !text.contains("LLM pass skipped"),
        "expected embedded prompt defaults to avoid LLM skip\n{text}"
    );
    assert!(text.contains("Fantastic PR Report"), "{text}");

    let _ = std::fs::remove_dir_all(&dir);
}
