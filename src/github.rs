use anyhow::{Context, bail};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::collections::BTreeSet;
use std::time::Duration;

use crate::checks::InlineComment;

pub const REPORT_MARKER: &str = "<!-- fantastic-pr-report -->";
pub const INLINE_MARKER_PREFIX: &str = "fantastic-pr:inline-output-key";

#[derive(Debug, Clone)]
pub struct PrContext {
    pub repo: String,
    pub number: u64,
    pub base_ref: String,
    pub base_branch: String,
    pub head_sha: String,
    pub action: String,
    pub title: String,
    pub draft: bool,
    pub labels: Vec<String>,
    pub author_login: String,
    pub is_fork: bool,
}

#[derive(Debug, Deserialize)]
struct PullRequestEvent {
    action: Option<String>,
    pull_request: PullRequest,
}

#[derive(Debug, Deserialize)]
struct PullRequest {
    number: u64,
    base: RefBranch,
    head: HeadBranch,
    title: Option<String>,
    draft: Option<bool>,
    labels: Option<Vec<LabelInfo>>,
    user: Option<UserInfo>,
}

#[derive(Debug, Deserialize)]
struct RefBranch {
    #[serde(rename = "ref")]
    branch: String,
}

#[derive(Debug, Deserialize)]
struct HeadBranch {
    sha: String,
    repo: Option<PullRequestRepo>,
}

#[derive(Debug, Deserialize)]
struct PullRequestRepo {
    fork: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct LabelInfo {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UserInfo {
    login: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IssueComment {
    id: u64,
    body: String,
    user: Option<UserInfo>,
}

#[derive(Debug, Deserialize)]
struct PullReview {
    body: Option<String>,
    user: Option<UserInfo>,
}

#[derive(Debug, Deserialize)]
struct PullReviewComment {
    body: Option<String>,
    user: Option<UserInfo>,
}

pub fn read_pr_context(event_path: &str, repo: &str) -> anyhow::Result<PrContext> {
    let event_data = std::fs::read_to_string(event_path)
        .with_context(|| format!("failed to read event payload at {event_path}"))?;

    let parsed: PullRequestEvent =
        serde_json::from_str(&event_data).context("failed to parse pull_request event payload")?;
    let is_fork = parsed
        .pull_request
        .head
        .repo
        .as_ref()
        .and_then(|repo| repo.fork)
        .unwrap_or(false);

    Ok(PrContext {
        repo: repo.to_string(),
        number: parsed.pull_request.number,
        base_ref: format!("origin/{}", parsed.pull_request.base.branch),
        base_branch: parsed.pull_request.base.branch,
        head_sha: parsed.pull_request.head.sha.clone(),
        action: parsed.action.unwrap_or_default(),
        title: parsed.pull_request.title.unwrap_or_default(),
        draft: parsed.pull_request.draft.unwrap_or(false),
        labels: parsed
            .pull_request
            .labels
            .unwrap_or_default()
            .into_iter()
            .filter_map(|l| l.name)
            .collect(),
        author_login: parsed
            .pull_request
            .user
            .and_then(|u| u.login)
            .unwrap_or_default(),
        is_fork,
    })
}

pub fn build_inline_output_key(ctx: &PrContext) -> String {
    format!(
        "fantastic-pr-inline:v2:{}:pr-{}",
        ctx.repo.to_lowercase(),
        ctx.number
    )
}

fn build_inline_comment_output_key(output_key: &str, comment: &InlineComment) -> String {
    format!(
        "{}:file={}:line={}:rule={}",
        output_key,
        comment.path.to_lowercase(),
        comment.line,
        comment.rule.to_lowercase()
    )
}

pub fn build_inline_output_marker(output_key: &str) -> String {
    format!("<!-- {INLINE_MARKER_PREFIX}:{output_key} -->")
}

pub fn upsert_comment(token: &str, ctx: &PrContext, body: &str) -> anyhow::Result<()> {
    upsert_comment_with_base(token, ctx, body, &api_base())
}

pub fn publish_inline_comments_once(
    token: &str,
    ctx: &PrContext,
    output_key: &str,
    comments: &[InlineComment],
) -> anyhow::Result<bool> {
    publish_inline_comments_once_with_base(token, ctx, output_key, comments, &api_base())
}

fn api_base() -> String {
    std::env::var("FANTASTIC_PR_GITHUB_API_BASE")
        .unwrap_or_else(|_| "https://api.github.com".to_string())
}

fn append_pagination_params(url: &str, page: usize, per_page: usize) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}per_page={per_page}&page={page}")
}

fn fetch_paginated<T: DeserializeOwned>(
    client: &Client,
    token: &str,
    url: &str,
    label: &str,
) -> anyhow::Result<Vec<T>> {
    const PER_PAGE: usize = 100;
    const MAX_PAGES: usize = 1000;

    let mut all = Vec::new();
    let mut page = 1usize;
    loop {
        let paged_url = append_pagination_params(url, page, PER_PAGE);
        let response = with_headers(client.get(&paged_url), token)
            .send()
            .with_context(|| format!("failed to list {label} (page {page})"))?;
        if !response.status().is_success() {
            bail!("failed to list {label}: HTTP {}", response.status());
        }

        let mut items: Vec<T> = response
            .json()
            .with_context(|| format!("failed to decode {label} response (page {page})"))?;
        let count = items.len();
        all.append(&mut items);
        if count < PER_PAGE {
            break;
        }
        page += 1;
        if page > MAX_PAGES {
            bail!("failed to list {label}: exceeded pagination safety limit");
        }
    }

    Ok(all)
}

fn upsert_comment_with_base(
    token: &str,
    ctx: &PrContext,
    body: &str,
    api_base: &str,
) -> anyhow::Result<()> {
    let client = new_http_client(api_base)?;

    let comments_url = format!(
        "{}/repos/{}/issues/{}/comments",
        api_base.trim_end_matches('/'),
        ctx.repo,
        ctx.number
    );

    let comments: Vec<IssueComment> =
        fetch_paginated(&client, token, &comments_url, "issue comments")?;
    let trusted_authors = trusted_marker_authors();

    let payload = json!({ "body": body });

    if let Some(comment) = comments.into_iter().find(|c| {
        c.body.contains(REPORT_MARKER)
            && is_trusted_marker_author(c.user.as_ref(), &trusted_authors)
    }) {
        let patch_url = format!(
            "{}/repos/{}/issues/comments/{}",
            api_base.trim_end_matches('/'),
            ctx.repo,
            comment.id
        );
        let response = with_headers(client.patch(&patch_url), token)
            .json(&payload)
            .send()
            .context("failed to update existing Fantastic PR comment")?;

        if !response.status().is_success() {
            bail!("failed to update issue comment: HTTP {}", response.status());
        }

        return Ok(());
    }

    let post_url = format!(
        "{}/repos/{}/issues/{}/comments",
        api_base.trim_end_matches('/'),
        ctx.repo,
        ctx.number
    );

    let response = with_headers(client.post(post_url), token)
        .json(&payload)
        .send()
        .context("failed to create Fantastic PR comment")?;

    if !response.status().is_success() {
        bail!("failed to create issue comment: HTTP {}", response.status());
    }

    Ok(())
}

fn publish_inline_comments_once_with_base(
    token: &str,
    ctx: &PrContext,
    output_key: &str,
    comments: &[InlineComment],
    api_base: &str,
) -> anyhow::Result<bool> {
    if comments.is_empty() {
        return Ok(false);
    }

    let client = new_http_client(api_base)?;
    let existing_markers = collect_existing_inline_markers(&client, token, ctx, api_base)?;
    let mut pending = Vec::new();
    for comment in comments {
        let comment_key = build_inline_comment_output_key(output_key, comment);
        let marker = build_inline_output_marker(&comment_key);
        if existing_markers.contains(&marker) {
            continue;
        }
        pending.push((comment, marker));
    }
    if pending.is_empty() {
        return Ok(false);
    }

    let mut review_comments = Vec::new();
    for (comment, marker) in &pending {
        let body = format!("{}\n\n{}", comment.body, marker);
        review_comments.push(json!({
            "path": comment.path.clone(),
            "line": comment.line,
            "side": "RIGHT",
            "body": body,
        }));
    }

    let url = format!(
        "{}/repos/{}/pulls/{}/reviews",
        api_base.trim_end_matches('/'),
        ctx.repo,
        ctx.number
    );

    let response = with_headers(client.post(&url), token)
        .json(&json!({
            "event": "COMMENT",
            "commit_id": ctx.head_sha,
            "comments": review_comments,
        }))
        .send()
        .context("failed to publish inline review comments")?;

    if response.status().is_success() {
        return Ok(true);
    }

    for (comment, marker) in &pending {
        let body = format!("{}\n\n{}", comment.body, marker);

        let single = with_headers(client.post(&url), token)
            .json(&json!({
                "event": "COMMENT",
                "commit_id": ctx.head_sha,
                "comments": [{
                    "path": comment.path.clone(),
                    "line": comment.line,
                    "side": "RIGHT",
                    "body": body,
                }]
            }))
            .send()
            .with_context(|| {
                format!(
                    "failed posting inline comment for {}:{}",
                    comment.path, comment.line
                )
            })?;

        if !single.status().is_success() {
            bail!(
                "failed posting inline comment for {}:{} (HTTP {})",
                comment.path,
                comment.line,
                single.status()
            );
        }
    }

    Ok(true)
}

fn collect_existing_inline_markers(
    client: &Client,
    token: &str,
    ctx: &PrContext,
    api_base: &str,
) -> anyhow::Result<BTreeSet<String>> {
    let mut markers = BTreeSet::new();
    let trusted_authors = trusted_marker_authors();
    let reviews_url = format!(
        "{}/repos/{}/pulls/{}/reviews",
        api_base.trim_end_matches('/'),
        ctx.repo,
        ctx.number
    );

    let reviews: Vec<PullReview> = fetch_paginated(client, token, &reviews_url, "PR reviews")?;
    for review in reviews {
        if is_trusted_marker_author(review.user.as_ref(), &trusted_authors)
            && let Some(body) = review.body
        {
            markers.extend(extract_inline_markers(&body));
        }
    }

    let review_comments_url = format!(
        "{}/repos/{}/pulls/{}/comments",
        api_base.trim_end_matches('/'),
        ctx.repo,
        ctx.number
    );
    let review_comments: Vec<PullReviewComment> =
        fetch_paginated(client, token, &review_comments_url, "PR review comments")?;
    for comment in review_comments {
        if is_trusted_marker_author(comment.user.as_ref(), &trusted_authors)
            && let Some(body) = comment.body
        {
            markers.extend(extract_inline_markers(&body));
        }
    }

    let issue_comments_url = format!(
        "{}/repos/{}/issues/{}/comments",
        api_base.trim_end_matches('/'),
        ctx.repo,
        ctx.number
    );

    let issue_comments: Vec<IssueComment> = fetch_paginated(
        client,
        token,
        &issue_comments_url,
        "issue comments for idempotency",
    )?;

    for comment in issue_comments {
        if is_trusted_marker_author(comment.user.as_ref(), &trusted_authors) {
            markers.extend(extract_inline_markers(&comment.body));
        }
    }

    Ok(markers)
}

fn trusted_marker_authors() -> BTreeSet<String> {
    let mut out = BTreeSet::from(["github-actions[bot]".to_string()]);
    if let Ok(actor) = std::env::var("GITHUB_ACTOR") {
        let actor = actor.trim();
        if !actor.is_empty() {
            out.insert(actor.to_ascii_lowercase());
        }
    }
    out
}

fn is_trusted_marker_author(user: Option<&UserInfo>, trusted_authors: &BTreeSet<String>) -> bool {
    let Some(login) = user.and_then(|u| u.login.as_deref()) else {
        return false;
    };
    trusted_authors.contains(&login.to_ascii_lowercase())
}

fn extract_inline_markers(body: &str) -> Vec<String> {
    let start_marker = format!("<!-- {INLINE_MARKER_PREFIX}:");
    let mut out = Vec::new();
    let mut cursor = body;
    while let Some(start_idx) = cursor.find(&start_marker) {
        let remaining = &cursor[start_idx..];
        let Some(end_idx) = remaining.find("-->") else {
            break;
        };
        out.push(remaining[..end_idx + 3].to_string());
        cursor = &remaining[end_idx + 3..];
    }
    out
}

fn with_headers(
    request: reqwest::blocking::RequestBuilder,
    token: &str,
) -> reqwest::blocking::RequestBuilder {
    request
        .header(USER_AGENT, "fantastic-pr")
        .header(ACCEPT, "application/vnd.github+json")
        .header(AUTHORIZATION, format!("Bearer {token}"))
}

fn new_http_client(api_base: &str) -> anyhow::Result<Client> {
    let mut builder = Client::builder().timeout(Duration::from_secs(30));
    if api_base.contains("://127.0.0.1")
        || api_base.contains("://localhost")
        || api_base.contains("://[::1]")
    {
        builder = builder.no_proxy();
    }
    builder.build().context("failed to build HTTP client")
}

#[cfg(test)]
mod tests {
    use mockito::{Matcher, Server};

    use crate::checks::InlineComment;

    use super::{
        INLINE_MARKER_PREFIX, PrContext, REPORT_MARKER, build_inline_comment_output_key,
        build_inline_output_key, build_inline_output_marker, extract_inline_markers,
        publish_inline_comments_once_with_base, upsert_comment_with_base,
    };

    fn test_ctx() -> PrContext {
        PrContext {
            repo: "owner/repo".to_string(),
            number: 42,
            base_ref: "origin/main".to_string(),
            base_branch: "main".to_string(),
            head_sha: "abc123".to_string(),
            action: "opened".to_string(),
            title: "test".to_string(),
            draft: false,
            labels: vec![],
            author_login: "octocat".to_string(),
            is_fork: false,
        }
    }

    fn issue_comments_body(count: usize, with_report_marker: bool) -> String {
        let mut out = Vec::with_capacity(count);
        for idx in 0..count {
            let body = if with_report_marker {
                format!("{REPORT_MARKER} marker-{idx}")
            } else {
                format!("unrelated-{idx}")
            };
            out.push(serde_json::json!({
                "id": idx as u64 + 1,
                "body": body,
                "user": { "login": "github-actions[bot]" },
            }));
        }
        serde_json::to_string(&out).expect("serialize issue comments")
    }

    fn pull_reviews_body(count: usize, marker: Option<&str>) -> String {
        let mut out = Vec::with_capacity(count);
        for idx in 0..count {
            let body = marker.map(|m| format!("{m}-{idx}"));
            out.push(serde_json::json!({
                "body": body,
                "user": { "login": "github-actions[bot]" },
            }));
        }
        serde_json::to_string(&out).expect("serialize pull reviews")
    }

    fn page_query(page: usize) -> Matcher {
        Matcher::AllOf(vec![
            Matcher::UrlEncoded("per_page".to_string(), "100".to_string()),
            Matcher::UrlEncoded("page".to_string(), page.to_string()),
        ])
    }

    #[test]
    fn builds_stable_output_key_and_marker() {
        let ctx_a = PrContext {
            repo: "Owner/Repo".to_string(),
            number: 42,
            base_ref: "origin/main".to_string(),
            base_branch: "main".to_string(),
            head_sha: "ABC123".to_string(),
            action: "opened".to_string(),
            title: "title".to_string(),
            draft: false,
            labels: vec![],
            author_login: "octocat".to_string(),
            is_fork: false,
        };
        let mut ctx_b = ctx_a.clone();
        ctx_b.head_sha = "DEF456".to_string();

        let key_a = build_inline_output_key(&ctx_a);
        let key_b = build_inline_output_key(&ctx_b);
        let marker = build_inline_output_marker(&key_a);

        assert_eq!(key_a, key_b);
        assert!(key_a.contains("owner/repo"));
        assert!(key_a.contains("pr-42"));
        assert!(!key_a.contains("head-"));
        assert!(marker.contains(INLINE_MARKER_PREFIX));
    }

    #[test]
    fn upsert_updates_existing_report_comment() {
        let mut server = Server::new();
        let ctx = test_ctx();

        let _list = server
            .mock("GET", "/repos/owner/repo/issues/42/comments")
            .match_query(page_query(1))
            .with_status(200)
            .with_body(
                r#"[{"id":99,"body":"<!-- fantastic-pr-report --> old","user":{"login":"github-actions[bot]"}}]"#,
            )
            .create();

        let patch_mock = server
            .mock("PATCH", "/repos/owner/repo/issues/comments/99")
            .with_status(200)
            .create();

        upsert_comment_with_base("t", &ctx, "<!-- fantastic-pr-report --> new", &server.url())
            .expect("upsert should patch existing comment");

        patch_mock.assert();
    }

    #[test]
    fn upsert_creates_report_comment_when_none_exists() {
        let mut server = Server::new();
        let ctx = test_ctx();

        let _list = server
            .mock("GET", "/repos/owner/repo/issues/42/comments")
            .match_query(page_query(1))
            .with_status(200)
            .with_body(r#"[{"id":99,"body":"unrelated"}]"#)
            .create();

        let create_mock = server
            .mock("POST", "/repos/owner/repo/issues/42/comments")
            .match_body(Matcher::Regex(format!(
                r#""body":"{} new""#,
                regex::escape(REPORT_MARKER)
            )))
            .with_status(201)
            .create();

        upsert_comment_with_base("t", &ctx, &format!("{REPORT_MARKER} new"), &server.url())
            .expect("upsert should create comment");

        create_mock.assert();
    }

    #[test]
    fn upsert_ignores_untrusted_existing_report_marker() {
        let mut server = Server::new();
        let ctx = test_ctx();

        let _list = server
            .mock("GET", "/repos/owner/repo/issues/42/comments")
            .match_query(page_query(1))
            .with_status(200)
            .with_body(
                r#"[{"id":99,"body":"<!-- fantastic-pr-report --> from user","user":{"login":"octocat"}}]"#,
            )
            .create();

        let create_mock = server
            .mock("POST", "/repos/owner/repo/issues/42/comments")
            .match_body(Matcher::Regex(format!(
                r#""body":"{} new""#,
                regex::escape(REPORT_MARKER)
            )))
            .with_status(201)
            .create();

        upsert_comment_with_base("t", &ctx, &format!("{REPORT_MARKER} new"), &server.url())
            .expect("untrusted marker should not block create");

        create_mock.assert();
    }

    #[test]
    fn upsert_paginates_issue_comments_when_finding_existing_report() {
        let mut server = Server::new();
        let ctx = test_ctx();

        let _page_1 = server
            .mock("GET", "/repos/owner/repo/issues/42/comments")
            .match_query(page_query(1))
            .with_status(200)
            .with_body(issue_comments_body(100, false))
            .create();

        let _page_2 = server
            .mock("GET", "/repos/owner/repo/issues/42/comments")
            .match_query(page_query(2))
            .with_status(200)
            .with_body(format!(
                r#"[{{"id":777,"body":"{} old","user":{{"login":"github-actions[bot]"}}}}]"#,
                REPORT_MARKER
            ))
            .create();

        let patch_mock = server
            .mock("PATCH", "/repos/owner/repo/issues/comments/777")
            .with_status(200)
            .create();

        upsert_comment_with_base("t", &ctx, &format!("{REPORT_MARKER} new"), &server.url())
            .expect("upsert should patch paginated existing comment");
        patch_mock.assert();
    }

    #[test]
    fn upsert_fails_when_listing_comments_fails() {
        let mut server = Server::new();
        let ctx = test_ctx();

        let _list = server
            .mock("GET", "/repos/owner/repo/issues/42/comments")
            .match_query(page_query(1))
            .with_status(500)
            .with_body("boom")
            .create();

        let err = upsert_comment_with_base("t", &ctx, "body", &server.url())
            .expect_err("upsert should fail when list endpoint fails");

        assert!(
            err.to_string()
                .contains("failed to list issue comments: HTTP")
        );
    }

    #[test]
    fn inline_publish_skips_when_marker_already_exists() {
        let mut server = Server::new();
        let ctx = test_ctx();
        let key = build_inline_output_key(&ctx);
        let marker = build_inline_output_marker(&build_inline_comment_output_key(
            &key,
            &InlineComment {
                rule: "r".to_string(),
                path: "src/lib.rs".to_string(),
                line: 10,
                body: "body".to_string(),
            },
        ));

        let _reviews = server
            .mock("GET", "/repos/owner/repo/pulls/42/reviews")
            .match_query(page_query(1))
            .with_status(200)
            .with_body(format!(
                r#"[{{"body":"{}","user":{{"login":"github-actions[bot]"}}}}]"#,
                marker
            ))
            .create();
        let _review_comments = server
            .mock("GET", "/repos/owner/repo/pulls/42/comments")
            .match_query(page_query(1))
            .with_status(200)
            .with_body("[]")
            .create();
        let _issue_comments = server
            .mock("GET", "/repos/owner/repo/issues/42/comments")
            .match_query(page_query(1))
            .with_status(200)
            .with_body("[]")
            .create();

        let comments = vec![InlineComment {
            rule: "r".to_string(),
            path: "src/lib.rs".to_string(),
            line: 10,
            body: "body".to_string(),
        }];

        let posted =
            publish_inline_comments_once_with_base("t", &ctx, &key, &comments, &server.url())
                .expect("publish should succeed with skip");

        assert!(!posted);
    }

    #[test]
    fn inline_publish_checks_paginated_reviews_for_existing_markers() {
        let mut server = Server::new();
        let ctx = test_ctx();
        let key = build_inline_output_key(&ctx);
        let marker = build_inline_output_marker(&build_inline_comment_output_key(
            &key,
            &InlineComment {
                rule: "r".to_string(),
                path: "src/lib.rs".to_string(),
                line: 10,
                body: "body".to_string(),
            },
        ));

        let _reviews_page_1 = server
            .mock("GET", "/repos/owner/repo/pulls/42/reviews")
            .match_query(page_query(1))
            .with_status(200)
            .with_body(pull_reviews_body(100, None))
            .create();
        let _reviews_page_2 = server
            .mock("GET", "/repos/owner/repo/pulls/42/reviews")
            .match_query(page_query(2))
            .with_status(200)
            .with_body(format!(
                r#"[{{"body":"{}","user":{{"login":"github-actions[bot]"}}}}]"#,
                marker
            ))
            .create();
        let _review_comments = server
            .mock("GET", "/repos/owner/repo/pulls/42/comments")
            .match_query(page_query(1))
            .with_status(200)
            .with_body("[]")
            .create();
        let _issue_comments = server
            .mock("GET", "/repos/owner/repo/issues/42/comments")
            .match_query(page_query(1))
            .with_status(200)
            .with_body("[]")
            .create();

        let comments = vec![InlineComment {
            rule: "r".to_string(),
            path: "src/lib.rs".to_string(),
            line: 10,
            body: "body".to_string(),
        }];

        let posted =
            publish_inline_comments_once_with_base("t", &ctx, &key, &comments, &server.url())
                .expect("publish should succeed with paginated skip");
        assert!(!posted);
    }

    #[test]
    fn inline_publish_falls_back_to_single_comments_after_bulk_failure() {
        let mut server = Server::new();
        let ctx = test_ctx();
        let key = build_inline_output_key(&ctx);

        let _reviews = server
            .mock("GET", "/repos/owner/repo/pulls/42/reviews")
            .match_query(page_query(1))
            .with_status(200)
            .with_body("[]")
            .create();

        let _issue_comments = server
            .mock("GET", "/repos/owner/repo/issues/42/comments")
            .match_query(page_query(1))
            .with_status(200)
            .with_body("[]")
            .create();

        let _review_comments = server
            .mock("GET", "/repos/owner/repo/pulls/42/comments")
            .match_query(page_query(1))
            .with_status(200)
            .with_body("[]")
            .create();

        let bulk_fail = server
            .mock("POST", "/repos/owner/repo/pulls/42/reviews")
            .match_body(Matcher::AllOf(vec![
                Matcher::Regex(r#"\"line\":10"#.to_string()),
                Matcher::Regex(r#"\"line\":11"#.to_string()),
            ]))
            .with_status(422)
            .create();

        let single_a = server
            .mock("POST", "/repos/owner/repo/pulls/42/reviews")
            .match_body(Matcher::Regex(r#"\"line\":10"#.to_string()))
            .with_status(200)
            .create();

        let single_b = server
            .mock("POST", "/repos/owner/repo/pulls/42/reviews")
            .match_body(Matcher::Regex(r#"\"line\":11"#.to_string()))
            .with_status(200)
            .create();

        let comments = vec![
            InlineComment {
                rule: "r1".to_string(),
                path: "src/lib.rs".to_string(),
                line: 10,
                body: "first".to_string(),
            },
            InlineComment {
                rule: "r2".to_string(),
                path: "src/lib.rs".to_string(),
                line: 11,
                body: "second".to_string(),
            },
        ];

        let posted =
            publish_inline_comments_once_with_base("t", &ctx, &key, &comments, &server.url())
                .expect("publish should succeed after fallback");

        assert!(posted);
        bulk_fail.assert();
        single_a.assert();
        single_b.assert();
    }

    #[test]
    fn inline_publish_skips_when_marker_exists_in_review_comment_body() {
        let mut server = Server::new();
        let ctx = test_ctx();
        let key = build_inline_output_key(&ctx);
        let marker = build_inline_output_marker(&build_inline_comment_output_key(
            &key,
            &InlineComment {
                rule: "r".to_string(),
                path: "src/lib.rs".to_string(),
                line: 10,
                body: "body".to_string(),
            },
        ));

        let _reviews = server
            .mock("GET", "/repos/owner/repo/pulls/42/reviews")
            .match_query(page_query(1))
            .with_status(200)
            .with_body("[]")
            .create();
        let _review_comments = server
            .mock("GET", "/repos/owner/repo/pulls/42/comments")
            .match_query(page_query(1))
            .with_status(200)
            .with_body(format!(
                r#"[{{"body":"{}","user":{{"login":"github-actions[bot]"}}}}]"#,
                marker
            ))
            .create();
        let _issue_comments = server
            .mock("GET", "/repos/owner/repo/issues/42/comments")
            .match_query(page_query(1))
            .with_status(200)
            .with_body("[]")
            .create();

        let comments = vec![InlineComment {
            rule: "r".to_string(),
            path: "src/lib.rs".to_string(),
            line: 10,
            body: "body".to_string(),
        }];

        let posted =
            publish_inline_comments_once_with_base("t", &ctx, &key, &comments, &server.url())
                .expect("publish should succeed with skip");
        assert!(!posted);
    }

    #[test]
    fn inline_publish_ignores_markers_from_untrusted_authors() {
        let mut server = Server::new();
        let ctx = test_ctx();
        let key = build_inline_output_key(&ctx);
        let marker = build_inline_output_marker(&build_inline_comment_output_key(
            &key,
            &InlineComment {
                rule: "r".to_string(),
                path: "src/lib.rs".to_string(),
                line: 10,
                body: "body".to_string(),
            },
        ));

        let _reviews = server
            .mock("GET", "/repos/owner/repo/pulls/42/reviews")
            .match_query(page_query(1))
            .with_status(200)
            .with_body(format!(
                r#"[{{"body":"{}","user":{{"login":"octocat"}}}}]"#,
                marker
            ))
            .create();
        let _review_comments = server
            .mock("GET", "/repos/owner/repo/pulls/42/comments")
            .match_query(page_query(1))
            .with_status(200)
            .with_body("[]")
            .create();
        let _issue_comments = server
            .mock("GET", "/repos/owner/repo/issues/42/comments")
            .match_query(page_query(1))
            .with_status(200)
            .with_body("[]")
            .create();

        let post_mock = server
            .mock("POST", "/repos/owner/repo/pulls/42/reviews")
            .with_status(200)
            .create();

        let comments = vec![InlineComment {
            rule: "r".to_string(),
            path: "src/lib.rs".to_string(),
            line: 10,
            body: "body".to_string(),
        }];

        let posted =
            publish_inline_comments_once_with_base("t", &ctx, &key, &comments, &server.url())
                .expect("publish should succeed");
        assert!(posted);
        post_mock.assert();
    }

    #[test]
    fn extract_inline_markers_reads_multiple_markers_and_ignores_truncated() {
        let marker_a = build_inline_output_marker("k1");
        let marker_b = build_inline_output_marker("k2");
        let body =
            format!("prefix {marker_a} middle {marker_b} tail <!-- {INLINE_MARKER_PREFIX}:k3");

        let markers = extract_inline_markers(&body);

        assert_eq!(markers, vec![marker_a, marker_b]);
    }
}
