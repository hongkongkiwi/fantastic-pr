use std::fs;
use std::path::Path;

use anyhow::Context;
use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::config::FilterConfig;

pub struct FileFilter {
    include: Option<GlobSet>,
    exclude: GlobSet,
}

impl FileFilter {
    pub fn from_config(config: &FilterConfig) -> anyhow::Result<Self> {
        let include = if config.include_globs.is_empty() {
            None
        } else {
            Some(
                build_glob_set(&config.include_globs)
                    .context("failed to build include glob set")?,
            )
        };

        let mut excludes = default_exclude_globs();
        excludes.extend(config.exclude_globs.clone());

        let ignore_path = Path::new(&config.ignore_file);
        if ignore_path.exists() {
            excludes.extend(read_ignore_patterns(ignore_path)?);
        }

        let exclude = build_glob_set(&excludes).context("failed to build exclude glob set")?;

        Ok(Self { include, exclude })
    }

    pub fn is_reviewable_file(&self, path: &str) -> bool {
        let norm = normalize(path);
        if !self.passes_path_filters(&norm) {
            return false;
        }

        source_ext(&norm).is_some_and(|ext| is_reviewable_ext(&ext)) || is_reviewable_name(&norm)
    }

    pub fn is_source_file(&self, path: &str) -> bool {
        let norm = normalize(path);
        self.passes_path_filters(&norm) && source_ext(&norm).is_some_and(|ext| is_source_ext(&ext))
    }

    pub fn is_allowed_path(&self, path: &str) -> bool {
        let norm = normalize(path);
        self.passes_path_filters(&norm)
    }

    fn passes_path_filters(&self, norm: &str) -> bool {
        if let Some(include) = &self.include
            && !include.is_match(norm)
        {
            return false;
        }

        if self.exclude.is_match(norm) {
            return false;
        }

        if is_lockfile(norm) {
            return false;
        }

        true
    }
}

fn build_glob_set(patterns: &[String]) -> anyhow::Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        if pattern.trim().is_empty() {
            continue;
        }
        builder.add(Glob::new(pattern).with_context(|| format!("invalid glob '{pattern}'"))?);
    }

    builder.build().context("glob set build failed")
}

fn read_ignore_patterns(path: &Path) -> anyhow::Result<Vec<String>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read ignore file {}", path.display()))?;

    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.ends_with('/') {
            out.push(format!("{}**", line));
        } else {
            out.push(line.to_string());
        }
    }

    Ok(out)
}

fn normalize(path: &str) -> String {
    path.replace('\\', "/")
}

fn default_exclude_globs() -> Vec<String> {
    vec![
        "**/node_modules/**".to_string(),
        "**/vendor/**".to_string(),
        "**/dist/**".to_string(),
        "**/build/**".to_string(),
        "**/target/**".to_string(),
        "**/coverage/**".to_string(),
        "**/*.min.js".to_string(),
        "**/*.map".to_string(),
    ]
}

fn is_lockfile(path: &str) -> bool {
    path.ends_with("package-lock.json")
        || path.ends_with("pnpm-lock.yaml")
        || path.ends_with("yarn.lock")
        || path.ends_with("Cargo.lock")
        || path.ends_with("composer.lock")
        || path.ends_with("Gemfile.lock")
        || path.ends_with("poetry.lock")
        || path.ends_with("packages.lock.json")
        || path.ends_with("go.sum")
}

fn source_ext(path: &str) -> Option<String> {
    let (_, ext) = path.rsplit_once('.')?;
    if ext.is_empty() {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

fn is_source_ext(ext: &str) -> bool {
    matches!(
        ext,
        "rs" | "js"
            | "jsx"
            | "ts"
            | "tsx"
            | "py"
            | "go"
            | "java"
            | "kt"
            | "swift"
            | "cs"
            | "rb"
            | "php"
            | "c"
            | "cc"
            | "cpp"
            | "h"
            | "hpp"
            | "m"
            | "mm"
            | "scala"
            | "sql"
            | "sh"
    )
}

fn is_reviewable_ext(ext: &str) -> bool {
    is_source_ext(ext)
        || matches!(
            ext,
            "yaml" | "yml" | "toml" | "json" | "md" | "tf" | "tfvars" | "hcl"
        )
}

fn is_reviewable_name(path: &str) -> bool {
    path.ends_with("Dockerfile")
}

#[cfg(test)]
mod tests {
    use crate::config::FilterConfig;

    use super::{FileFilter, normalize};

    #[test]
    fn filter_excludes_generated_files() {
        let filter = FileFilter::from_config(&FilterConfig::default()).expect("filter build");
        assert!(!filter.is_reviewable_file("dist/app.min.js"));
        assert!(filter.is_reviewable_file("src/lib.rs"));
    }

    #[test]
    fn filter_respects_include_globs() {
        let cfg = FilterConfig {
            include_globs: vec!["src/**/*.rs".to_string()],
            ..FilterConfig::default()
        };
        let filter = FileFilter::from_config(&cfg).expect("filter build");

        assert!(filter.is_reviewable_file("src/foo/mod.rs"));
        assert!(!filter.is_reviewable_file("scripts/tool.py"));
    }

    #[test]
    fn normalize_handles_windows_paths() {
        // Windows paths use backslashes
        assert_eq!(normalize("src\\main.rs"), "src/main.rs");
        assert_eq!(normalize("foo\\bar\\baz.txt"), "foo/bar/baz.txt");
    }

    #[test]
    fn normalize_handles_mixed_separators() {
        assert_eq!(normalize("src/foo\\bar/baz"), "src/foo/bar/baz");
    }

    #[test]
    fn filter_matches_extensions_case_insensitively() {
        let filter = FileFilter::from_config(&FilterConfig::default()).expect("filter build");

        assert!(filter.is_reviewable_file("src/lib.RS"));
        assert!(filter.is_source_file("src/lib.RS"));
        assert!(filter.is_reviewable_file("README.MD"));
        assert!(filter.is_reviewable_file("src\\MAIN.CPP"));
        assert!(filter.is_source_file("src\\MAIN.CPP"));
    }
}
