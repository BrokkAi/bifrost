use super::*;
use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, BuildProgressEvent, BuildProgressPhase};
use brokk_bifrost_mcp::SearchToolsService;

const KEY: &str = "io.bifrost/workspace-build";

fn fixture() -> common::BuiltInlineTestProject {
    let mut project = InlineTestProject::new();
    for index in 0..24 {
        project = project.file(
            format!("private_source_{index}.py"),
            format!("def private_source_{index}(value):\n    return value + {index}\n"),
        );
    }
    project
        .file(
            "private_other.js",
            "function private_other() { return 42; }\n",
        )
        .build()
}

fn phase(event: &BuildProgressEvent) -> &'static str {
    match event.phase {
        BuildProgressPhase::Enumerate => "enumerate",
        BuildProgressPhase::Reconcile => "reconcile",
        BuildProgressPhase::Parse => "parse",
        BuildProgressPhase::Persist => "persist",
        BuildProgressPhase::Index => "index",
    }
}

#[test]
fn measured_cold_refresh_matches_producers_and_warm_refresh_does_not_reparse() {
    // Independent cache roots: observing the oracle must not warm the wire fixture.
    let oracle = fixture();
    let events = Arc::new(Mutex::new(Vec::<BuildProgressEvent>::new()));
    let captured = Arc::clone(&events);
    let service = SearchToolsService::new_manual_persisted_with_progress_for_project(
        oracle.project_dyn(),
        AnalyzerConfig::default(),
        move |event| captured.lock().unwrap().push(event),
    )
    .unwrap();
    drop(service);
    let expected = events.lock().unwrap();
    assert!(
        expected
            .iter()
            .any(|event| event.phase == BuildProgressPhase::Parse
                && event.completed > 0
                && event.completed < event.total)
    );

    let workspace = fixture();
    let mut child = mcp_server_command(workspace.root(), "searchtools", &[])
        .env("BIFROST_MCP_FILE_WATCHER", "off")
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    initialize_session(&mut stdin, &mut reader, &mut stderr);
    write_line(
        &mut stdin,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"refresh", "arguments":{}, "_meta":{"progressToken":"measured"}
        }}),
    );
    let (response, progress) = read_response_collecting_progress(&mut reader, &mut stderr, 2);
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert_progress_is_monotonic(&progress);
    let snapshots = progress
        .iter()
        .filter_map(|notification| notification["_meta"].get(KEY))
        .collect::<Vec<_>>();
    assert!(!snapshots.is_empty(), "{progress:?}");
    let cold = snapshots
        .iter()
        .filter(|snapshot| snapshot["generation"] == 1)
        .collect::<Vec<_>>();
    assert!(
        cold.iter()
            .any(|snapshot| snapshot["status"] == "completed"),
        "{snapshots:?}"
    );
    let terminal = cold
        .iter()
        .find(|snapshot| snapshot["status"] == "completed")
        .unwrap();
    for counter in terminal["counters"].as_array().unwrap() {
        let producer = expected
            .iter()
            .rev()
            .find(|event| {
                json!(event.language) == counter["language"]
                    && phase(event) == counter["phase"].as_str().unwrap()
            })
            .unwrap();
        assert_eq!(counter["completed"], producer.completed);
        assert_eq!(counter["total"], producer.total);
    }
    let intermediate = terminal["intermediate"].as_array().unwrap();
    assert!(
        intermediate
            .iter()
            .any(|counter| counter["phase"] == "parse"
                && counter["completed"].as_u64().unwrap() < counter["total"].as_u64().unwrap()),
        "{terminal}"
    );
    for counter in intermediate {
        assert!(
            expected
                .iter()
                .any(|event| json!(event.language) == counter["language"]
                    && phase(event) == counter["phase"].as_str().unwrap()
                    && json!(event.completed) == counter["completed"]
                    && json!(event.total) == counter["total"]),
            "{counter}"
        );
    }
    for snapshot in &snapshots {
        assert_eq!(snapshot["request_id"], 2);
        assert_eq!(snapshot["workspace_generation"], 1);
        let encoded = snapshot.to_string();
        assert!(
            !encoded.contains("private_"),
            "source or file label leaked: {encoded}"
        );
        assert!(
            !encoded.contains(&workspace.root().to_string_lossy().to_string()),
            "absolute root leaked"
        );
    }
    // The refresh itself is a separate generation and reads warm facts.
    let refreshed = snapshots
        .iter()
        .find(|snapshot| snapshot["generation"] == 2 && snapshot["status"] == "completed")
        .unwrap();
    assert!(
        refreshed["counters"]
            .as_array()
            .unwrap()
            .iter()
            .all(|counter| counter["phase"] != "parse"),
        "{refreshed}"
    );

    write_line(
        &mut stdin,
        json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{
            "name":"refresh", "arguments":{}, "_meta":{"progressToken":"warm-refresh"}
        }}),
    );
    let (response, warm_progress) = read_response_collecting_progress(&mut reader, &mut stderr, 6);
    assert_eq!(response["result"]["isError"], false, "{response}");
    let warm = warm_progress
        .iter()
        .filter_map(|notification| notification["_meta"].get(KEY))
        .collect::<Vec<_>>();
    assert!(!warm.is_empty());
    for snapshot in warm {
        assert_eq!(
            snapshot["generation"], 3,
            "warm refresh must not replay a previous build"
        );
        assert!(
            snapshot["counters"]
                .as_array()
                .unwrap()
                .iter()
                .all(|counter| counter["phase"] != "parse"),
            "{snapshot}"
        );
    }

    write_line(
        &mut stdin,
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
            "name":"run_policy", "arguments":{"policy_ids":["bifrost.correctness.dynamic-evaluation"],"evaluation_date":"2026-10-02","fail_on":"warning"}, "_meta":{"progressToken":7}
        }}),
    );
    let (response, progress) = read_response_collecting_progress(&mut reader, &mut stderr, 3);
    assert!(response["error"].is_null(), "{response}");
    let completed = progress
        .iter()
        .position(|notification| notification["_meta"][KEY]["status"] == "completed")
        .unwrap();
    let executing = progress
        .iter()
        .position(|notification| notification["message"] == "executing run_policy")
        .unwrap();
    assert!(completed < executing, "{progress:?}");
    assert!(
        progress
            .iter()
            .all(|notification| notification["progressToken"] == 7)
    );

    write_line(
        &mut stdin,
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"refresh","arguments":{}}}),
    );
    let (response, progress) = read_response_collecting_progress(&mut reader, &mut stderr, 4);
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert!(progress.is_empty());
    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[test]
fn measured_tasks_preserve_original_request_and_task_identity() {
    let workspace = fixture();
    // The task request is stateless; no initialize delay is needed before
    // observing a cold build that started before the request arrived.
    let mut child = spawn_server(workspace.root(), "searchtools", &[]);
    let mut stdin = child.stdin.take().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    discover_tasks_server(&mut stdin, &mut reader, &mut stderr);
    let mut request = malformed_run_policy_request(1);
    request["params"]["_meta"] = common::mcp_server::stateless_tasks_meta();
    request["params"]["_meta"]["progressToken"] = json!("task-counts");
    write_line(&mut stdin, request);
    let (created, mut observations) =
        read_response_collecting_progress(&mut reader, &mut stderr, 1);
    assert_eq!(created["result"]["resultType"], "task", "{created}");
    let task_id = created["result"]["taskId"].as_str().unwrap();
    for id in 10..100 {
        write_line(
            &mut stdin,
            json!({"jsonrpc":"2.0","id":id,"method":"tasks/get","params":{
                "taskId":task_id,"_meta":common::mcp_server::stateless_tasks_meta()
            }}),
        );
        let (response, progress) = read_response_collecting_progress(&mut reader, &mut stderr, id);
        observations.extend(progress);
        if response["result"]["status"] == "completed" {
            break;
        }
        assert_eq!(response["result"]["status"], "working", "{response}");
        thread::sleep(Duration::from_millis(50));
    }
    let measured = observations
        .iter()
        .filter_map(|notification| notification["_meta"].get(KEY))
        .collect::<Vec<_>>();
    assert!(!measured.is_empty(), "{observations:?}");
    assert!(
        measured
            .iter()
            .any(|snapshot| snapshot["status"] == "completed"),
        "{measured:?}"
    );
    for snapshot in measured {
        assert_eq!(snapshot["request_id"], 1);
        assert_eq!(snapshot["task_id"], task_id);
    }
    assert!(
        observations
            .iter()
            .all(|notification| notification["progressToken"] == "task-counts")
    );
    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[test]
fn a_cancelled_readiness_observer_stops_while_the_shared_build_remains_pending() {
    let workspace = fixture();
    drop(
        SearchToolsService::new_manual_persisted_for_project(
            workspace.project_dyn(),
            AnalyzerConfig::default(),
        )
        .unwrap(),
    );
    let (held, _) = hold_analyzer_cache_build_lock(workspace.root());
    let mut child = spawn_server(workspace.root(), "searchtools", &[]);
    let mut stdin = child.stdin.take().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    initialize_session(&mut stdin, &mut reader, &mut stderr);
    write_line(
        &mut stdin,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"search_symbols","arguments":{"patterns":["private_source_1"]},"_meta":{"progressToken":"cancel-build"}
        }}),
    );
    loop {
        let notification = read_line(&mut reader, &mut stderr);
        assert_eq!(
            notification["method"], "notifications/progress",
            "{notification}"
        );
        if notification["params"]["_meta"][KEY]["status"] == "running" {
            break;
        }
    }
    // Leave the subscriber unread across several delivery ticks. An unchanged
    // snapshot must not be re-enqueued on every tick.
    thread::sleep(Duration::from_millis(250));
    write_line(
        &mut stdin,
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2}}),
    );
    // Cancellation can suppress the cancelled request's response. A stateless
    // tool supplies a barrier without waiting for the held analyzer build.
    write_line(
        &mut stdin,
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
            "name":"list_policies","arguments":{}
        }}),
    );
    let mut observations = Vec::new();
    loop {
        let message = read_line(&mut reader, &mut stderr);
        if message["id"] == 3 {
            break;
        }
        if message["id"] == 2 {
            continue;
        }
        assert_eq!(message["method"], "notifications/progress", "{message}");
        observations.push(message["params"].clone());
    }
    assert!(
        observations.len() <= 1,
        "unchanged snapshots should be coalesced: {observations:?}"
    );
    for observation in observations {
        assert_eq!(observation["_meta"][KEY]["request_status"], "cancelled");
        assert_eq!(
            observation["_meta"][KEY]["status"], "running",
            "a waiter must not cancel the shared producer"
        );
    }
    drop(held);
    write_line(
        &mut stdin,
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{
            "name":"search_symbols","arguments":{"patterns":["private_source_1"]}
        }}),
    );
    loop {
        let message = read_line(&mut reader, &mut stderr);
        if message["id"] == 2 {
            continue;
        }
        assert_eq!(
            message["id"], 4,
            "cancelled observers must not survive the request: {message}"
        );
        assert_eq!(message["result"]["isError"], false, "{message}");
        break;
    }
    drop(stdin);
    assert!(child.wait().unwrap().success());
}
