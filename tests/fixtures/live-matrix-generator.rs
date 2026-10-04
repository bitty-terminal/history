//! Live-host behavior matrix generator for history-plugin CTX-0004 verification.
//!
//! SCRATCH-ONLY: this file lives in a read-only `git archive` export of
//! bitty @ 76fa42d6 (PR #1673, W-139 host surface) and is never committed to
//! any repository. It drives the LIVE `HistoryGate` through a probe battery
//! mirroring the history plugin's mock-suite seeds and prints one JSON
//! object to stdout (or to `$HISTORY_MATRIX_OUT`).
//!
//! The emitted JSON is stored as the history repo's
//! `tests/fixtures/live-host-matrix.json` (with provenance) and the committed
//! `tests/live-host-parity.test.ts` replays equivalent probes against the
//! SDK MockHost, asserting identical codes and page shapes.
//!
//! Run: `HISTORY_MATRIX_OUT=/tmp/matrix.json cargo test -p bitty-plugin-host
//! --test history_live_matrix -- --nocapture`

use std::collections::BTreeMap;

use bitty_plugin_host::history_read::{
    Attribution, HistoryCaps, HistoryDenialKind, HistoryError, HistoryGate,
    HistoryGrant, HistoryScope, HistorySnapshot, HistorySource,
    QueryOp, SnapshotQuery, StoredRow, HISTORY_READ_VERSION,
};
use bitty_plugin_host::manifest::PluginId;
use bitty_plugin_host::trust_levels::TrustLevel;

fn pid(s: &str) -> PluginId {
    PluginId::new(s).unwrap()
}

fn caps() -> HistoryCaps {
    HistoryCaps::new(16, 4096, 256, 4, 8192).unwrap()
}

fn row(panel: &str, workspace: &str, seq: u64, body: &str) -> StoredRow {
    StoredRow {
        owner: None,
        panel: panel.to_string(),
        workspace: workspace.to_string(),
        seq,
        redacted_body: body.to_string(),
        attribution: Attribution {
            panel: panel.to_string(),
            workspace: workspace.to_string(),
            command: None,
            recorded_at: seq,
            actor: None,
        },
        purged: false,
    }
}

fn purged_row(panel: &str, workspace: &str, seq: u64, body: &str) -> StoredRow {
    StoredRow { purged: true, ..row(panel, workspace, seq, body) }
}

fn kv_row(owner: &PluginId, seq: u64, body: &str) -> StoredRow {
    StoredRow {
        owner: Some(owner.clone()),
        panel: String::new(),
        workspace: String::new(),
        seq,
        redacted_body: body.to_string(),
        attribution: Attribution {
            panel: String::new(),
            workspace: String::new(),
            command: None,
            recorded_at: seq,
            actor: None,
        },
        purged: false,
    }
}

fn seed_store(plugin: &PluginId) -> HistorySnapshot {
    let mut store = HistorySnapshot::new();
    store.push(HistorySource::Transcript, row("pane-a", "ws-1", 0, "redacted output line one"));
    store.push(HistorySource::Transcript, row("pane-a", "ws-1", 1, "redacted output line two"));
    store.push(HistorySource::Transcript, row("pane-b", "ws-1", 2, "foreign panel bytes never cross"));
    store.push(HistorySource::Transcript, row("pane-a", "ws-1", 3, "s3cr3t-corpus-bytes"));
    store.push(HistorySource::CommandHistory, row("pane-a", "ws-1", 0, "make check"));
    store.push(HistorySource::CommandHistory, row("pane-a", "ws-1", 1, "bun test"));
    store.push(HistorySource::CommandHistory, row("pane-a", "ws-1", 2, "make lint"));
    store.push(HistorySource::PluginKv, kv_row(plugin, 0, "own state"));
    store.push(
        HistorySource::PluginKv,
        kv_row(&pid("example.foreign"), 1, "foreign state"),
    );
    store
}

fn scope(source: HistorySource, panel: Option<&str>, workspace: Option<&str>) -> HistoryScope {
    HistoryScope::new(source, panel, workspace).unwrap()
}

fn query(scope: HistoryScope, row_count: u32, max_bytes: u32, op: QueryOp) -> SnapshotQuery {
    SnapshotQuery {
        client_version: HISTORY_READ_VERSION,
        scope,
        row_start: 0,
        row_count,
        max_bytes,
        op,
    }
}

fn full_gate(plugin: &PluginId) -> (HistoryGate, HistorySnapshot) {
    let mut gate = HistoryGate::new(caps());
    gate.set_capture(HistorySource::Transcript, true);
    gate.set_capture(HistorySource::CommandHistory, true);
    for source in [HistorySource::Transcript, HistorySource::CommandHistory] {
        gate.issue_grant(HistoryGrant::standing(
            plugin.clone(),
            scope(source, Some("pane-a"), Some("ws-1")),
        ));
    }
    gate.issue_grant(HistoryGrant::standing(
        plugin.clone(),
        HistoryScope::new(HistorySource::PluginKv, None, None).unwrap(),
    ));
    (gate, seed_store(plugin))
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 32 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn outcome_of(result: Result<bitty_plugin_host::history_read::SnapshotPage, HistoryError>) -> String {
    match result {
        Ok(page) => {
            let bodies: Vec<String> = page.records.iter().map(|r| format!("\"{}\"", esc(&r.body))).collect();
            let labels: Vec<String> = page.records.iter().map(|r| format!("\"{}\"", r.label.as_str())).collect();
            let redacted: Vec<String> = page.records.iter().map(|r| r.redacted.to_string()).collect();
            let truncated: Vec<String> = page.records.iter().map(|r| r.truncated.to_string()).collect();
            let seqs: Vec<String> = page.records.iter().map(|r| r.seq.to_string()).collect();
            format!(
                "{{\"status\":\"ok\",\"bodies\":[{}],\"labels\":[{}],\"redacted\":[{}],\"truncated\":[{}],\"seqs\":[{}],\"total_in_scope\":{},\"freshness\":\"{:?}\"}}",
                bodies.join(","),
                labels.join(","),
                redacted.join(","),
                truncated.join(","),
                seqs.join(","),
                page.total_in_scope,
                page.freshness,
            )
        }
        Err(HistoryError::Denied(d)) => {
            format!("{{\"status\":\"denied\",\"code\":\"{}\",\"message\":\"{}\"}}", d.kind().code(), esc(&d.message()))
        }
        Err(HistoryError::Disabled { diagnostic }) => {
            format!("{{\"status\":\"disabled\",\"code\":null,\"message\":\"history surface disabled: {}\"}}", esc(&diagnostic))
        }
    }
}

fn denial_codes() -> String {
    HistoryDenialKind::all()
        .iter()
        .map(|k| format!("\"{}\"", k.code()))
        .collect::<Vec<_>>()
        .join(",")
}

#[test]
fn emit_live_matrix() {
    let plugin = pid("bitty-terminal.history");
    let mut probes: Vec<String> = Vec::new();
    let mut probe = |name: &str, body: String| {
        probes.push(format!("{{\"name\":\"{name}\",\"outcome\":{body}}}"));
    };

    // 1. Happy paths, one per source.
    {
        let (mut gate, store) = full_gate(&plugin);
        let r = gate.query(
            &plugin,
            TrustLevel::ThirdPartyLua,
            &query(scope(HistorySource::Transcript, Some("pane-a"), Some("ws-1")), 4, 4096, QueryOp::List),
            &store,
        );
        probe("transcript-list", outcome_of(r));
    }
    {
        let (mut gate, store) = full_gate(&plugin);
        let r = gate.query(
            &plugin,
            TrustLevel::ThirdPartyLua,
            &query(scope(HistorySource::CommandHistory, Some("pane-a"), Some("ws-1")), 2, 4096, QueryOp::Tail),
            &store,
        );
        probe("commands-tail", outcome_of(r));
    }
    {
        let (mut gate, store) = full_gate(&plugin);
        let r = gate.query(
            &plugin,
            TrustLevel::ThirdPartyLua,
            &query(
                HistoryScope::new(HistorySource::PluginKv, None, None).unwrap(),
                4,
                4096,
                QueryOp::List,
            ),
            &store,
        );
        probe("kv-list", outcome_of(r));
    }
    {
        let (mut gate, store) = full_gate(&plugin);
        let r = gate.query(
            &plugin,
            TrustLevel::ThirdPartyLua,
            &query(
                scope(HistorySource::CommandHistory, Some("pane-a"), Some("ws-1")),
                4,
                4096,
                QueryOp::Search { needle: "make".to_string() },
            ),
            &store,
        );
        probe("commands-search-make", outcome_of(r));
    }

    // 2. Missing / revoked grants.
    {
        let (mut gate, store) = full_gate(&plugin);
        let other = pid("example.history-clone");
        let r = gate.query(
            &other,
            TrustLevel::ThirdPartyLua,
            &query(scope(HistorySource::Transcript, Some("pane-a"), Some("ws-1")), 4, 4096, QueryOp::List),
            &store,
        );
        probe("missing-grant", outcome_of(r));
    }
    {
        let (mut gate, store) = full_gate(&plugin);
        gate.revoke(&plugin, HistorySource::Transcript);
        let r = gate.query(
            &plugin,
            TrustLevel::ThirdPartyLua,
            &query(scope(HistorySource::Transcript, Some("pane-a"), Some("ws-1")), 4, 4096, QueryOp::List),
            &store,
        );
        probe("revoked-grant", outcome_of(r));
    }

    // 3. Source isolation: transcript grant never implies commands.
    {
        let mut gate = HistoryGate::new(caps());
        gate.set_capture(HistorySource::Transcript, true);
        gate.set_capture(HistorySource::CommandHistory, true);
        gate.issue_grant(HistoryGrant::standing(
            plugin.clone(),
            scope(HistorySource::Transcript, Some("pane-a"), Some("ws-1")),
        ));
        let store = seed_store(&plugin);
        let r = gate.query(
            &plugin,
            TrustLevel::ThirdPartyLua,
            &query(scope(HistorySource::CommandHistory, Some("pane-a"), Some("ws-1")), 4, 4096, QueryOp::List),
            &store,
        );
        probe("source-isolation", outcome_of(r));
    }

    // 4. Scope mismatch: grant pane-a, query pane-b.
    {
        let (mut gate, store) = full_gate(&plugin);
        let r = gate.query(
            &plugin,
            TrustLevel::ThirdPartyLua,
            &query(scope(HistorySource::Transcript, Some("pane-b"), Some("ws-1")), 4, 4096, QueryOp::List),
            &store,
        );
        probe("scope-mismatch", outcome_of(r));
    }

    // 5. Scope construction failures (Disabled diagnostics, no E_ code).
    {
        let r = HistoryScope::new(HistorySource::Transcript, None, None);
        probe(
            "unscoped-scope",
            match r {
                Ok(_) => "{\"status\":\"ok\"}".to_string(),
                Err(e) => outcome_of(Err(e)),
            },
        );
    }
    {
        let r = HistoryScope::new(HistorySource::Transcript, Some("*"), Some("ws-1"));
        probe(
            "wildcard-scope",
            match r {
                Ok(_) => "{\"status\":\"ok\"}".to_string(),
                Err(e) => outcome_of(Err(e)),
            },
        );
    }
    {
        let r = HistoryScope::new(HistorySource::PluginKv, Some("pane-a"), None);
        probe(
            "kv-extent-scope",
            match r {
                Ok(_) => "{\"status\":\"ok\"}".to_string(),
                Err(e) => outcome_of(Err(e)),
            },
        );
    }

    // 6. Over-bound requests.
    for (name, rc, mb) in [
        ("over-rows", 17u32, 4096u32),
        ("over-bytes", 4u32, 5000u32),
        ("zero-rows", 0u32, 4096u32),
        ("zero-bytes", 4u32, 0u32),
    ] {
        let (mut gate, store) = full_gate(&plugin);
        let r = gate.query(
            &plugin,
            TrustLevel::ThirdPartyLua,
            &query(scope(HistorySource::Transcript, Some("pane-a"), Some("ws-1")), rc, mb, QueryOp::List),
            &store,
        );
        probe(name, outcome_of(r));
    }
    {
        let (mut gate, store) = full_gate(&plugin);
        let r = gate.query(
            &plugin,
            TrustLevel::ThirdPartyLua,
            &query(
                scope(HistorySource::Transcript, Some("pane-a"), Some("ws-1")),
                4,
                4096,
                QueryOp::Search { needle: String::new() },
            ),
            &store,
        );
        probe("empty-needle", outcome_of(r));
    }

    // 7. Capture disabled.
    {
        let mut gate = HistoryGate::new(caps());
        gate.issue_grant(HistoryGrant::standing(
            plugin.clone(),
            scope(HistorySource::Transcript, Some("pane-a"), Some("ws-1")),
        ));
        let store = seed_store(&plugin);
        let r = gate.query(
            &plugin,
            TrustLevel::ThirdPartyLua,
            &query(scope(HistorySource::Transcript, Some("pane-a"), Some("ws-1")), 4, 4096, QueryOp::List),
            &store,
        );
        probe("capture-disabled", outcome_of(r));
    }

    // 8. Purge / expiry.
    {
        let mut gate = HistoryGate::new(caps());
        gate.set_capture(HistorySource::Transcript, true);
        gate.issue_grant(HistoryGrant::standing(
            plugin.clone(),
            scope(HistorySource::Transcript, Some("pane-a"), Some("ws-1")),
        ));
        let mut store = HistorySnapshot::new();
        store.push(HistorySource::Transcript, purged_row("pane-a", "ws-1", 0, "expired bytes"));
        let r = gate.query(
            &plugin,
            TrustLevel::ThirdPartyLua,
            &query(scope(HistorySource::Transcript, Some("pane-a"), Some("ws-1")), 4, 4096, QueryOp::List),
            &store,
        );
        probe("purged-list", outcome_of(r));
        let r = gate.query(
            &plugin,
            TrustLevel::ThirdPartyLua,
            &query(
                scope(HistorySource::Transcript, Some("pane-a"), Some("ws-1")),
                4,
                4096,
                QueryOp::Search { needle: "expired".to_string() },
            ),
            &store,
        );
        probe("purged-search", outcome_of(r));
    }

    // 9. Forbidden sources.
    for name in ["session", "snapshot", "session-snapshot", "nope"] {
        let r = bitty_plugin_host::history_read::HistorySource::parse(name);
        probe(
            &format!("forbidden-{name}"),
            match r {
                Ok(_) => "{\"status\":\"ok\"}".to_string(),
                Err(e) => outcome_of(Err(e)),
            },
        );
    }

    // 10. Safe mode + trust levels.
    {
        let (mut gate, store) = full_gate(&plugin);
        gate.set_safe_mode(true);
        let r = gate.query(
            &plugin,
            TrustLevel::ThirdPartyLua,
            &query(scope(HistorySource::Transcript, Some("pane-a"), Some("ws-1")), 4, 4096, QueryOp::List),
            &store,
        );
        probe("safe-mode", outcome_of(r));
    }
    for (name, level) in [
        ("trust-core", TrustLevel::Core),
        ("trust-l1", TrustLevel::BundledLua),
        ("trust-l2", TrustLevel::ThirdPartyLua),
        ("trust-l3-standing", TrustLevel::NativeSidecar),
        ("trust-l4", TrustLevel::ExternalTool),
    ] {
        let (mut gate, store) = full_gate(&plugin);
        let r = gate.query(
            &plugin,
            level,
            &query(scope(HistorySource::Transcript, Some("pane-a"), Some("ws-1")), 4, 4096, QueryOp::List),
            &store,
        );
        probe(name, outcome_of(r));
    }
    {
        // L3 with a live per-request grant allows exactly once.
        let mut gate = HistoryGate::new(caps());
        gate.set_capture(HistorySource::Transcript, true);
        gate.issue_grant(HistoryGrant::per_request(
            plugin.clone(),
            scope(HistorySource::Transcript, Some("pane-a"), Some("ws-1")),
        ));
        let store = seed_store(&plugin);
        let q = query(scope(HistorySource::Transcript, Some("pane-a"), Some("ws-1")), 4, 4096, QueryOp::List);
        let first = outcome_of(gate.query(&plugin, TrustLevel::NativeSidecar, &q, &store));
        let second = outcome_of(gate.query(&plugin, TrustLevel::NativeSidecar, &q, &store));
        probe("trust-l3-per-request", format!("{{\"first\":{first},\"second\":{second}}}"));
    }

    // 11. Version mismatch.
    {
        let (mut gate, store) = full_gate(&plugin);
        let mut q = query(scope(HistorySource::Transcript, Some("pane-a"), Some("ws-1")), 4, 4096, QueryOp::List);
        q.client_version = 99;
        let r = gate.query(&plugin, TrustLevel::ThirdPartyLua, &q, &store);
        probe("version-mismatch", outcome_of(r));
    }

    // 12. Window budget: 4 succeed, 5th denies.
    {
        let (mut gate, store) = full_gate(&plugin);
        let q = query(scope(HistorySource::Transcript, Some("pane-a"), Some("ws-1")), 4, 4096, QueryOp::List);
        let mut codes: Vec<String> = Vec::new();
        for _ in 0..5 {
            match gate.query(&plugin, TrustLevel::ThirdPartyLua, &q, &store) {
                Ok(_) => codes.push("\"ok\"".to_string()),
                Err(HistoryError::Denied(d)) => codes.push(format!("\"{}\"", d.kind().code())),
                Err(_) => codes.push("\"disabled\"".to_string()),
            }
        }
        probe("window-budget", format!("{{\"sequence\":[{}]}}", codes.join(",")));
    }

    // 13. Truncation at char boundary with label intact.
    {
        let mut gate = HistoryGate::new(caps());
        gate.set_capture(HistorySource::Transcript, true);
        gate.issue_grant(HistoryGrant::standing(
            plugin.clone(),
            scope(HistorySource::Transcript, Some("pane-a"), Some("ws-1")),
        ));
        let mut store = HistorySnapshot::new();
        let long_body = "é".repeat(200);
        store.push(HistorySource::Transcript, row("pane-a", "ws-1", 0, &long_body));
        let r = gate.query(
            &plugin,
            TrustLevel::ThirdPartyLua,
            &query(scope(HistorySource::Transcript, Some("pane-a"), Some("ws-1")), 4, 4096, QueryOp::List),
            &store,
        );
        probe("truncation", outcome_of(r));
    }

    let doc = format!(
        "{{\"provenance\":{{\"core_commit\":\"76fa42d6\",\"core_pr\":1673,\"surface\":\"history_read.rs\",\"caps\":{{\"max_rows_per_query\":16,\"max_bytes_per_query\":4096,\"max_bytes_per_row\":256,\"max_queries_per_window\":4,\"max_bytes_per_window\":8192}},\"denial_codes\":[{}],\"label\":\"untrusted-observation\",\"sdk_freshness\":\"point-in-time-no-guarantee\"}},\"probes\":[{}]}}",
        denial_codes(),
        probes.join(",")
    );
    if let Ok(path) = std::env::var("HISTORY_MATRIX_OUT") {
        std::fs::write(&path, &doc).unwrap();
    }
    println!("{doc}");
}
