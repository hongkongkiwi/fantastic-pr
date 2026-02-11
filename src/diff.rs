use std::collections::HashMap;
use std::process::Command;

use anyhow::{Context, bail};
use regex::Regex;

#[derive(Debug, Clone)]
pub struct AddedLine {
    pub file: String,
    pub line: usize,
    pub content: String,
}

#[derive(Debug, Clone, Default)]
pub struct FileChangeStats {
    pub added: usize,
    pub removed: usize,
}

#[derive(Debug, Clone, Default)]
pub struct DiffData {
    pub added_lines: Vec<AddedLine>,
    pub files: HashMap<String, FileChangeStats>,
    pub total_added: usize,
    pub total_removed: usize,
}

#[derive(Debug, Clone)]
pub struct FileSnapshot {
    pub path: String,
    pub content: String,
}

pub fn collect_diff(base_ref: &str) -> anyhow::Result<DiffData> {
    let output = Command::new("git")
        .arg("diff")
        .arg("--unified=0")
        .arg("--no-color")
        .arg(format!("{base_ref}...HEAD"))
        .output()
        .context("failed to execute git diff")?;

    if !output.status.success() {
        bail!(
            "git diff failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    parse_unified_diff(&String::from_utf8_lossy(&output.stdout))
}

pub fn parse_unified_diff(input: &str) -> anyhow::Result<DiffData> {
    let mut data = DiffData::default();

    let mut current_file = String::new();
    let mut current_new_line: usize = 0;

    let hunk_re = Regex::new(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
        .context("failed to compile hunk regex")?;

    for raw_line in input.lines() {
        if raw_line.starts_with("diff --git ") {
            continue;
        }

        if let Some(path) = raw_line.strip_prefix("+++ ") {
            if path == "/dev/null" {
                current_file.clear();
            } else {
                let normalized = path.strip_prefix("b/").unwrap_or(path);
                current_file = normalized.to_string();
                data.files.entry(current_file.clone()).or_default();
            }
            continue;
        }

        if let Some(caps) = hunk_re.captures(raw_line) {
            current_new_line = caps
                .get(1)
                .and_then(|m| m.as_str().parse::<usize>().ok())
                .unwrap_or(1);
            continue;
        }

        if raw_line.starts_with("+++") || raw_line.starts_with("---") {
            continue;
        }

        if current_file.is_empty() {
            continue;
        }

        if let Some(content) = raw_line.strip_prefix('+') {
            data.total_added += 1;
            if let Some(stats) = data.files.get_mut(&current_file) {
                stats.added += 1;
            }
            data.added_lines.push(AddedLine {
                file: current_file.clone(),
                line: current_new_line,
                content: content.to_string(),
            });
            current_new_line += 1;
            continue;
        }

        if raw_line.starts_with('-') {
            data.total_removed += 1;
            if let Some(stats) = data.files.get_mut(&current_file) {
                stats.removed += 1;
            }
            continue;
        }

        if raw_line.starts_with(' ') {
            current_new_line += 1;
        }
    }

    Ok(data)
}

pub fn read_changed_files(base_ref: &str) -> anyhow::Result<Vec<FileSnapshot>> {
    let output = Command::new("git")
        .arg("diff")
        .arg("--name-only")
        .arg(format!("{base_ref}...HEAD"))
        .output()
        .context("failed to execute git diff --name-only")?;

    if !output.status.success() {
        bail!(
            "git diff --name-only failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let mut snapshots = Vec::new();
    for path in String::from_utf8_lossy(&output.stdout).lines() {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            continue;
        }

        let object = format!("HEAD:{trimmed}");
        let content_output = Command::new("git")
            .arg("show")
            .arg(&object)
            .output()
            .with_context(|| format!("failed to read changed file snapshot '{trimmed}'"))?;
        if !content_output.status.success() {
            continue;
        }

        let Ok(content) = String::from_utf8(content_output.stdout) else {
            continue;
        };

        snapshots.push(FileSnapshot {
            path: trimmed.to_string(),
            content,
        });
    }

    Ok(snapshots)
}

pub fn guess_base_ref() -> Option<String> {
    for candidate in ["origin/main", "origin/master"] {
        let status = Command::new("git")
            .arg("rev-parse")
            .arg("--verify")
            .arg(candidate)
            .output()
            .ok()?;
        if status.status.success() {
            return Some(candidate.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{collect_diff, guess_base_ref, parse_unified_diff, read_changed_files};

    struct CwdGuard {
        original: PathBuf,
    }

    impl CwdGuard {
        fn push(path: &Path) -> Self {
            let original = std::env::current_dir().expect("get current dir");
            std::env::set_current_dir(path).expect("set current dir");
            Self { original }
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.original);
        }
    }

    fn unique_temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "fantastic-pr-diff-{name}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn run_git(repo: &Path, args: &[&str]) {
        let output = Command::new("git")
            .args(args)
            .current_dir(repo)
            .output()
            .expect("git command should execute");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn setup_repo_with_two_commits(name: &str) -> PathBuf {
        let repo = unique_temp_dir(name);
        std::fs::create_dir_all(&repo).expect("create repo dir");

        run_git(&repo, &["init"]);
        run_git(&repo, &["config", "user.email", "fantastic-pr@example.com"]);
        run_git(&repo, &["config", "user.name", "Fantastic PR"]);

        std::fs::create_dir_all(repo.join("src")).expect("create src dir");
        std::fs::write(repo.join("src/lib.rs"), "pub fn a() {}\n").expect("write lib");
        std::fs::write(repo.join("old.txt"), "legacy\n").expect("write old file");
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "initial"]);

        std::fs::write(repo.join("src/lib.rs"), "pub fn a() {}\npub fn b() {}\n")
            .expect("update lib");
        let _ = std::fs::remove_file(repo.join("old.txt"));
        std::fs::write(repo.join("src/new.rs"), "pub fn c() {}\n").expect("write new file");
        run_git(&repo, &["add", "-A"]);
        run_git(&repo, &["commit", "-m", "change"]);

        repo
    }

    #[test]
    fn parses_added_lines_and_counts() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
index abc..def 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,2 +1,3 @@
 pub fn a() {}
+pub fn b() {}
-pub fn old() {}
@@ -10,0 +12,2 @@
+let x = 1;
+let y = 2;
"#;

        let parsed = parse_unified_diff(diff).expect("parse should succeed");
        assert_eq!(parsed.total_added, 3);
        assert_eq!(parsed.total_removed, 1);
        assert_eq!(parsed.added_lines.len(), 3);
        assert_eq!(parsed.added_lines[0].file, "src/lib.rs");
        assert_eq!(parsed.added_lines[0].line, 2);
    }

    #[test]
    fn tracks_line_numbers_with_context_and_multiple_files() {
        let diff = r#"diff --git a/src/a.rs b/src/a.rs
index 111..222 100644
--- a/src/a.rs
+++ b/src/a.rs
@@ -1,3 +1,4 @@
 keep
+add1
 keep2
+add2
diff --git a/src/b.rs b/src/b.rs
index 333..444 100644
--- a/src/b.rs
+++ b/src/b.rs
@@ -10,0 +11,1 @@
+newb
"#;

        let parsed = parse_unified_diff(diff).expect("parse should succeed");
        assert_eq!(parsed.total_added, 3);
        assert_eq!(parsed.total_removed, 0);
        assert_eq!(parsed.added_lines.len(), 3);
        assert_eq!(parsed.added_lines[0].file, "src/a.rs");
        assert_eq!(parsed.added_lines[0].line, 2);
        assert_eq!(parsed.added_lines[1].file, "src/a.rs");
        assert_eq!(parsed.added_lines[1].line, 4);
        assert_eq!(parsed.added_lines[2].file, "src/b.rs");
        assert_eq!(parsed.added_lines[2].line, 11);
        assert_eq!(parsed.files.get("src/a.rs").expect("a stats").added, 2);
        assert_eq!(parsed.files.get("src/b.rs").expect("b stats").added, 1);
    }

    #[test]
    fn handles_dev_null_paths_without_collecting_added_lines_for_deleted_file() {
        let diff = r#"diff --git a/src/new.rs b/src/new.rs
new file mode 100644
--- /dev/null
+++ b/src/new.rs
@@ -0,0 +1,2 @@
+hello
+world
diff --git a/src/old.rs b/src/old.rs
deleted file mode 100644
--- a/src/old.rs
+++ /dev/null
@@ -1,2 +0,0 @@
-gone1
-gone2
"#;

        let parsed = parse_unified_diff(diff).expect("parse should succeed");
        assert_eq!(parsed.total_added, 2);
        assert_eq!(parsed.total_removed, 0);
        assert_eq!(parsed.added_lines.len(), 2);
        assert_eq!(parsed.added_lines[0].file, "src/new.rs");
        assert!(parsed.files.contains_key("src/new.rs"));
        assert!(!parsed.files.contains_key("src/old.rs"));
    }

    #[test]
    fn collect_diff_and_read_changed_files_work_in_real_git_repo() {
        let _guard = crate::test_global_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let repo = setup_repo_with_two_commits("collect-read");
        let _cwd = CwdGuard::push(&repo);

        let diff = collect_diff("HEAD~1").expect("collect diff");
        assert!(diff.total_added >= 2);
        assert!(diff.files.contains_key("src/lib.rs"));
        assert!(diff.files.contains_key("src/new.rs"));

        let snapshots = read_changed_files("HEAD~1").expect("read changed files");
        assert!(snapshots.iter().any(|s| s.path == "src/lib.rs"));
        assert!(snapshots.iter().any(|s| s.path == "src/new.rs"));
        assert!(!snapshots.iter().any(|s| s.path == "old.txt"));

        drop(_cwd);
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn read_changed_files_uses_head_snapshot_not_worktree_state() {
        let _guard = crate::test_global_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let repo = setup_repo_with_two_commits("snapshot-head");
        let _cwd = CwdGuard::push(&repo);

        std::fs::write(repo.join("src/lib.rs"), "DIRTY WORKTREE CHANGE\n")
            .expect("write dirty worktree change");

        let snapshots = read_changed_files("HEAD~1").expect("read changed files");
        let lib = snapshots
            .iter()
            .find(|s| s.path == "src/lib.rs")
            .expect("snapshot for src/lib.rs");

        assert!(lib.content.contains("pub fn b()"));
        assert!(!lib.content.contains("DIRTY WORKTREE CHANGE"));

        drop(_cwd);
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn collect_diff_returns_error_for_invalid_base_ref() {
        let _guard = crate::test_global_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let repo = setup_repo_with_two_commits("collect-error");
        let _cwd = CwdGuard::push(&repo);

        let err = collect_diff("not-a-real-ref").expect_err("invalid ref should fail");
        assert!(err.to_string().contains("git diff failed"));

        drop(_cwd);
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn guess_base_ref_prefers_origin_main_then_master() {
        let _guard = crate::test_global_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let repo = setup_repo_with_two_commits("guess-base");

        run_git(&repo, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
        run_git(&repo, &["update-ref", "refs/remotes/origin/master", "HEAD"]);

        let _cwd = CwdGuard::push(&repo);
        assert_eq!(guess_base_ref().as_deref(), Some("origin/main"));

        run_git(&repo, &["update-ref", "-d", "refs/remotes/origin/main"]);
        assert_eq!(guess_base_ref().as_deref(), Some("origin/master"));

        run_git(&repo, &["update-ref", "-d", "refs/remotes/origin/master"]);
        assert_eq!(guess_base_ref(), None);

        drop(_cwd);
        let _ = std::fs::remove_dir_all(&repo);
    }
}
