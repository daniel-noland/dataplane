// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Custom test harness for fuzz test discovery and execution.
//!
//! This module implements the `main()` function for `harness = false` integration test binaries.
//! It provides subcommands for listing registered fuzz tests and running them via `cargo-bolero`.

use crate::{Test, TESTS};
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::process::ExitCode;

/// Color palette for distinguishing concurrent test output.
const TEST_COLORS: &[colored::Color] = &[
    colored::Color::Cyan,
    colored::Color::Green,
    colored::Color::Yellow,
    colored::Color::Blue,
    colored::Color::Magenta,
    colored::Color::BrightCyan,
    colored::Color::BrightGreen,
    colored::Color::BrightYellow,
    colored::Color::BrightBlue,
    colored::Color::BrightMagenta,
];

/// Assign a color to a test based on its index.
fn test_color(index: usize) -> colored::Color {
    TEST_COLORS[index % TEST_COLORS.len()]
}

/// Fuzz test harness -- list, build, and run bolero fuzz tests.
#[derive(Parser)]
#[command(name = "fuzz", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List registered fuzz tests.
    List {
        /// Filter tests by substring match on the test name.
        filter: Option<String>,

        /// Output as JSON (one object per line).
        #[arg(long)]
        json: bool,
    },

    /// Run a fuzz test via cargo-bolero (execs, replacing this process).
    Run {
        /// Filter to select a single fuzz test (substring match, must match exactly one).
        filter: String,

        #[command(flatten)]
        build_opts: BuildOpts,

        #[command(flatten)]
        run_opts: RunOpts,
    },

    /// Build an instrumented fuzz binary without running it.
    ///
    /// Prints the path to the built binary on stdout.
    Build {
        /// Filter to select fuzz tests (substring match).
        /// If omitted, builds the full test binary.
        filter: Option<String>,

        #[command(flatten)]
        build_opts: BuildOpts,
    },

    /// Run fuzz tests in CI mode with a process supervisor.
    ///
    /// Spawns each matching fuzz test as a child process, respecting the per-test
    /// `jobs` and `timeout` annotations.  Uses a semaphore to limit total concurrency
    /// to the available cores (or `--max-jobs`).
    ///
    /// If `--binary` is not provided, builds the instrumented binary first (same as
    /// the `build` subcommand).
    Ci {
        /// Filter tests by substring match.  If omitted, runs all registered tests.
        filter: Option<String>,

        /// Path to a pre-built instrumented test binary.
        /// If omitted, builds one using the same logic as the `build` subcommand.
        #[arg(long)]
        binary: Option<String>,

        /// Minimum time (seconds) per test.  Tests requesting less will be promoted.
        #[arg(long, default_value = "1")]
        min_time: u32,

        /// Maximum time (seconds) per test.  Tests requesting more will be capped.
        #[arg(long, default_value = "300")]
        max_time: u32,

        /// Maximum total concurrent fuzzer jobs across all tests.
        /// Defaults to the number of logical CPUs.
        #[arg(long)]
        max_jobs: Option<u32>,

        /// Corpus root directory.  Per-test corpus dirs are created as subdirectories.
        #[arg(long, default_value = "./fuzz/corpus")]
        corpus_dir: String,

        /// Crashes root directory.  Per-test crash dirs are created as subdirectories.
        #[arg(long, default_value = "./fuzz/crashes")]
        crashes_dir: String,

        /// Number of fuzzer iterations per test (if unset, runs until timeout).
        #[arg(long, short = 'r')]
        runs: Option<u64>,

        /// Write a `JUnit` XML report to the given path after the run.
        #[arg(long)]
        junit: Option<String>,

        /// Build options (used when --binary is not provided).
        #[command(flatten)]
        build_opts: BuildOpts,
    },
}

/// Options shared between `run` and `build` subcommands.
#[derive(Parser)]
struct BuildOpts {
    /// Override sanitizer (address, thread, none).
    #[arg(long, short = 's')]
    sanitizer: Option<String>,

    /// Build profile.
    #[arg(long, default_value = "fuzz")]
    profile: String,

    /// Target triple (defaults to host).
    #[arg(long)]
    target: Option<String>,

    /// Override target directory.
    #[arg(long)]
    target_dir: Option<String>,
}

/// Options specific to the `run` subcommand.
#[derive(Parser)]
struct RunOpts {
    /// Max duration for the fuzzer (e.g., 200s).
    #[arg(long, short = 'T')]
    timeout: Option<String>,

    /// Number of parallel jobs.
    #[arg(long, short = 'j')]
    jobs: Option<String>,

    /// Number of fuzzer iterations.
    #[arg(long, short = 'r')]
    runs: Option<String>,

    /// Max input length in bytes.
    #[arg(long, short = 'l')]
    max_len: Option<String>,

    /// Corpus directory.
    #[arg(long)]
    corpus_dir: Option<String>,

    /// Crashes directory.
    #[arg(long)]
    crashes_dir: Option<String>,

    /// Additional arguments to pass to the fuzzing engine (repeatable).
    #[arg(long, short = 'E')]
    engine_args: Vec<String>,
}

/// Entry point for the fuzz test harness.
///
/// Parses command-line arguments and dispatches to subcommands.
#[allow(clippy::missing_panics_doc)]
pub fn main() -> ! {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::List { filter, json } => cmd_list(filter.as_deref(), json),
        Command::Run {
            filter,
            build_opts,
            run_opts,
        } => cmd_run(&filter, &build_opts, &run_opts),
        Command::Build {
            filter,
            build_opts,
        } => cmd_build(filter.as_deref(), &build_opts),
        Command::Ci {
            filter,
            binary,
            min_time,
            max_time,
            max_jobs,
            corpus_dir,
            crashes_dir,
            runs,
            junit,
            build_opts,
        } => cmd_ci(
            filter.as_deref(),
            binary,
            min_time,
            max_time,
            max_jobs,
            &corpus_dir,
            &crashes_dir,
            runs,
            junit.as_deref(),
            &build_opts,
        ),
    };
    std::process::exit(i32::from(code != ExitCode::SUCCESS));
}

// -- helpers -----------------------------------------------------------------

fn tests() -> &'static [Test] {
    TESTS.static_slice()
}

fn filter_tests(filter: Option<&str>) -> Vec<&'static Test> {
    match filter {
        Some(f) => tests().iter().filter(|t| t.name().contains(f)).collect(),
        None => tests().iter().collect(),
    }
}

fn resolve_one(filter: &str) -> Result<&'static Test, ExitCode> {
    let matched = filter_tests(Some(filter));
    if matched.is_empty() {
        eprintln!("no fuzz tests matching `{filter}`");
        return Err(ExitCode::FAILURE);
    }
    if matched.len() > 1 {
        eprintln!(
            "filter `{filter}` matched {} tests (need exactly 1):",
            matched.len()
        );
        for test in &matched {
            eprintln!("  {test}");
        }
        return Err(ExitCode::FAILURE);
    }
    Ok(matched[0])
}

fn resolve_sanitizer(test: &Test, explicit: Option<&str>) -> String {
    explicit.map_or_else(
        || {
            if test.sanitize().address {
                "address".to_string()
            } else if test.sanitize().thread {
                "thread".to_string()
            } else {
                "none".to_string()
            }
        },
        ToString::to_string,
    )
}

// -- list command -------------------------------------------------------------

fn cmd_list(filter: Option<&str>, json: bool) -> ExitCode {
    let matched = filter_tests(filter);

    if matched.is_empty() {
        if let Some(f) = filter {
            eprintln!("no fuzz tests matching `{f}`");
        } else {
            eprintln!("no fuzz tests registered");
        }
        return ExitCode::FAILURE;
    }

    for test in &matched {
        if json {
            let info = test.info();
            if let Ok(line) = serde_json::to_string(&info) {
                println!("{line}");
            }
        } else {
            println!("{test}");
        }
    }
    ExitCode::SUCCESS
}

// -- build command -----------------------------------------------------------

/// libfuzzer coverage instrumentation flags.
///
/// These match what `cargo-bolero` passes internally for the libfuzzer engine.
const LIBFUZZER_FLAGS: &[&str] = &[
    "--cfg fuzzing",
    "--cfg fuzzing_libfuzzer",
    "-Cpasses=sancov-module",
    "-Cllvm-args=-sanitizer-coverage-inline-8bit-counters",
    "-Cllvm-args=-sanitizer-coverage-level=4",
    "-Cllvm-args=-sanitizer-coverage-pc-table",
    "-Cllvm-args=-sanitizer-coverage-trace-compares",
    #[cfg(target_os = "linux")]
    "-Cllvm-args=-sanitizer-coverage-stack-depth",
];

/// Compose RUSTFLAGS the same way `cargo-bolero` does: instrumentation flags
/// first, then sanitizer flags, then whatever the caller already had in the
/// environment.
fn compose_rustflags(sanitizer: &str) -> String {
    let mut parts: Vec<String> = LIBFUZZER_FLAGS.iter().map(|s| (*s).to_string()).collect();

    if sanitizer != "none" {
        parts.push(format!("-Zsanitizer={sanitizer}"));
    }

    if let Ok(existing) = std::env::var("RUSTFLAGS") {
        parts.push(existing);
    }

    parts.join(" ")
}

/// Get the target triple this binary was compiled for.
///
/// cargo-bolero uses a build script to capture `TARGET`; we use
/// `rustc -vV` at runtime instead to avoid needing a build script.
fn default_target_triple() -> String {
    let Ok(output) = std::process::Command::new("rustc").args(["-vV"]).output() else {
        return "x86_64-unknown-linux-gnu".to_string();
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(triple) = line.strip_prefix("host: ") {
            return triple.to_string();
        }
    }
    "x86_64-unknown-linux-gnu".to_string()
}

/// Hash RUSTFLAGS to derive a target-dir suffix, matching cargo-bolero's convention.
fn fuzz_target_dir(rustflags: &str, explicit: Option<&str>) -> String {
    if let Some(dir) = explicit {
        return dir.to_string();
    }
    let mut hasher = DefaultHasher::new();
    rustflags.hash(&mut hasher);
    format!("target/fuzz/build_{:x}", hasher.finish())
}

/// Cargo JSON message for `--message-format=json`.
///
/// We only care about `compiler-artifact` messages that have an `executable` field.
#[derive(serde::Deserialize)]
struct CargoMessage {
    reason: String,
    executable: Option<String>,
    target: Option<CargoTarget>,
}

/// Target metadata within a cargo JSON artifact message.
#[derive(serde::Deserialize)]
struct CargoTarget {
    kind: Vec<String>,
    name: String,
}

/// Extract the unit test executable path from `cargo test --no-run --message-format=json` output.
///
/// We need the library's unit test binary (which contains the `#[test]` bolero functions),
/// NOT the `fuzz` integration test harness binary.  The library test artifact has
/// `target.kind = ["lib"]` while the harness has `target.kind = ["test"]` with
/// `target.name = "fuzz"`.
fn find_executable(cargo_json_output: &str) -> Option<String> {
    let mut exe = None;
    for line in cargo_json_output.lines() {
        let Ok(msg) = serde_json::from_str::<CargoMessage>(line) else {
            continue;
        };
        if msg.reason != "compiler-artifact" {
            continue;
        }
        // Skip the fuzz harness binary -- we want the lib's unit test binary.
        if let Some(ref target) = msg.target
            && target.name == "fuzz"
            && target.kind.iter().any(|k| k == "test")
        {
            continue;
        }
        if let Some(path) = msg.executable {
            exe = Some(path);
        }
    }
    exe
}

fn cmd_build(filter: Option<&str>, opts: &BuildOpts) -> ExitCode {
    let matched = filter_tests(filter);

    if matched.is_empty() {
        if let Some(f) = filter {
            eprintln!("no fuzz tests matching `{f}`");
        } else {
            eprintln!("no fuzz tests registered");
        }
        return ExitCode::FAILURE;
    }

    // Use the first matched test for package name
    let representative = matched[0];

    // Build defaults to no sanitizer -- it's a build-only step.
    // The user can opt in with --sanitizer.
    let sanitizer = opts.sanitizer.as_deref().unwrap_or("none");
    let rustflags = compose_rustflags(sanitizer);
    let target_dir = fuzz_target_dir(&rustflags, opts.target_dir.as_deref());

    let mut cmd = std::process::Command::new("cargo");
    cmd.arg("test");

    // If a specific test filter was given, pass it to cargo and require exactly one match
    if let Some(f) = filter {
        let test = match resolve_one(f) {
            Ok(t) => t,
            Err(code) => return code,
        };
        cmd.arg(test.name());
    }

    cmd.arg("--no-run");
    cmd.args(["--message-format", "json"]);
    cmd.args(["--package", &representative.package()]);
    cmd.args(["--profile", &opts.profile]);
    cmd.args(["--features", "bolero"]);
    cmd.arg("-Zbuild-std");
    cmd.args(["--target-dir", &target_dir]);

    // --target is required for -Zbuild-std to rebuild the stdlib with our RUSTFLAGS.
    // Without it, cargo may use the pre-compiled sysroot libraries (which lack sanitizer
    // instrumentation).  cargo-bolero always passes --target for the same reason.
    let default_target = default_target_triple();
    let target = opts.target.as_deref().unwrap_or(&default_target);
    cmd.args(["--target", target]);

    cmd.env("RUSTC_BOOTSTRAP", "1");
    cmd.env("RUSTFLAGS", &rustflags);
    cmd.env("BOLERO_FUZZER", "libfuzzer");

    // Capture stdout (JSON messages) but let stderr through for build progress.
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::inherit());

    eprintln!("build: {cmd:?}");
    eprintln!("RUSTFLAGS={rustflags}");

    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: failed to run cargo: {e}");
            return ExitCode::FAILURE;
        }
    };

    if !output.status.success() {
        let _ = std::io::Write::write_all(&mut std::io::stderr(), &output.stdout);
        return ExitCode::FAILURE;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let exe = find_executable(&stdout);

    if let Some(path) = exe {
        eprintln!("build complete");
        println!("{path}");
        ExitCode::SUCCESS
    } else {
        eprintln!("build succeeded but could not determine executable path");
        eprintln!("target-dir: {target_dir}");
        ExitCode::FAILURE
    }
}

// -- run command -------------------------------------------------------------

fn cmd_run(filter: &str, build_opts: &BuildOpts, run_opts: &RunOpts) -> ExitCode {
    let test = match resolve_one(filter) {
        Ok(t) => t,
        Err(code) => return code,
    };
    exec_bolero(test, build_opts, run_opts);
}

/// Build a `cargo-bolero test` command and exec it (replacing this process).
fn exec_bolero(test: &Test, build_opts: &BuildOpts, run_opts: &RunOpts) -> ! {
    use std::os::unix::process::CommandExt;

    let mut cmd = std::process::Command::new("cargo-bolero");
    cmd.arg("test");
    cmd.arg(test.name());
    cmd.args(["--package", &test.package()]);

    // Sanitizer
    let sanitizer = resolve_sanitizer(test, build_opts.sanitizer.as_deref());
    if sanitizer != "none" {
        cmd.args(["--sanitizer", &sanitizer]);
    }

    // Build options
    cmd.args(["--profile", &build_opts.profile]);
    if let Some(ref target) = build_opts.target {
        cmd.args(["--target", target]);
    }
    if let Some(ref target_dir) = build_opts.target_dir {
        cmd.args(["--target-dir", target_dir]);
    }

    // Run-specific options
    if let Some(ref timeout) = run_opts.timeout {
        cmd.args(["-T", timeout]);
    }
    if let Some(ref jobs) = run_opts.jobs {
        cmd.args(["--jobs", jobs]);
    }
    if let Some(ref runs) = run_opts.runs {
        cmd.args(["--runs", runs]);
    }
    if let Some(ref max_len) = run_opts.max_len {
        cmd.args(["--max-input-length", max_len]);
    }
    if let Some(ref corpus_dir) = run_opts.corpus_dir {
        cmd.args(["--corpus-dir", corpus_dir]);
    }
    if let Some(ref crashes_dir) = run_opts.crashes_dir {
        cmd.args(["--crashes-dir", crashes_dir]);
    }
    for engine_arg in &run_opts.engine_args {
        cmd.args(["--engine-args", engine_arg]);
    }

    // Common flags
    cmd.arg("--rustc-bootstrap");
    cmd.arg("--build-std");

    eprintln!("exec: {cmd:?}");
    let err = cmd.exec();
    eprintln!("error: failed to exec cargo-bolero: {err}");
    std::process::exit(1);
}

// -- ci command --------------------------------------------------------------

/// Result of running a single fuzz test.
#[derive(Debug, serde::Serialize)]
struct CiResult {
    name: String,
    package: String,
    jobs: u32,
    timeout: u32,
    status: CiStatus,
    /// Path to the stdout log file for this test.
    #[serde(skip)]
    stdout_log: std::path::PathBuf,
    /// Path to the stderr log file for this test.
    #[serde(skip)]
    stderr_log: std::path::PathBuf,
}

#[derive(Debug, Copy, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum CiStatus {
    /// Test completed within the timeout with exit code 0.
    Ok,
    /// Test was killed because it exceeded its timeout.  This is normal for
    /// fuzz tests -- it means the fuzzer ran for the full budget without finding
    /// a crash.
    Timeout,
    /// Test exited with a non-zero status (crash found or other error).
    Failed { exit_code: Option<i32> },
}

/// Resolve a user-provided path against `CARGO_MANIFEST_DIR` if relative.
///
/// `cargo test` sets cwd to the package directory, so relative paths from
/// the user's shell need to be resolved against the workspace root.
fn resolve_path(path: &str) -> std::path::PathBuf {
    let path = std::path::Path::new(path);
    if path.is_relative() {
        std::env::var("CARGO_MANIFEST_DIR").map_or_else(
            |_| path.to_path_buf(),
            |dir| std::path::PathBuf::from(dir).join(path),
        )
    } else {
        path.to_path_buf()
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn cmd_ci(
    filter: Option<&str>,
    binary: Option<String>,
    min_time: u32,
    max_time: u32,
    max_jobs: Option<u32>,
    corpus_dir: &str,
    crashes_dir: &str,
    runs: Option<u64>,
    junit_path: Option<&str>,
    build_opts: &BuildOpts,
) -> ExitCode {
    let matched = filter_tests(filter);
    if matched.is_empty() {
        if let Some(f) = filter {
            eprintln!("no fuzz tests matching `{f}`");
        } else {
            eprintln!("no fuzz tests registered");
        }
        return ExitCode::FAILURE;
    }

    // Resolve the binary path: use --binary if provided, otherwise build it.
    let binary = if let Some(path) = binary {
        path
    } else {
        eprintln!("ci: no --binary provided, building instrumented binary...");
        let Some(path) = build_and_get_binary(filter, build_opts) else {
            eprintln!("ci: build failed");
            return ExitCode::FAILURE;
        };
        path
    };

    let log_dir = resolve_path("./fuzz/logs");

    eprintln!("ci: binary = {binary}");
    eprintln!("ci: logs   = {}", log_dir.display());

    let max_jobs = max_jobs.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| u32::try_from(n.get()).unwrap_or(u32::MAX))
            .unwrap_or(4)
    });

    if min_time > max_time {
        eprintln!(
            "{} --min-time ({min_time}s) > --max-time ({max_time}s)",
            "error:".red().bold(),
        );
        return ExitCode::FAILURE;
    }

    eprintln!(
        "ci: {} tests, max {max_jobs} concurrent jobs, time {min_time}s..{max_time}s\n",
        matched.len()
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            eprintln!("error: failed to build tokio runtime: {e}");
            std::process::exit(1);
        });

    let results = rt.block_on(run_ci(
        &matched,
        &binary,
        min_time,
        max_time,
        max_jobs,
        corpus_dir,
        crashes_dir,
        runs,
        &log_dir,
    ));

    // Print final results
    eprintln!("\n{}", "--- Results ---".bold());
    let mut failures = 0u32;
    for result in &results {
        let status_str = match &result.status {
            CiStatus::Ok => "ok".green().bold().to_string(),
            CiStatus::Timeout => "timeout (ok)".green().to_string(),
            CiStatus::Failed { exit_code } => {
                failures += 1;
                format!(
                    "FAILED (exit {})",
                    exit_code.map_or("signal".to_string(), |c| c.to_string())
                )
                .red()
                .bold()
                .to_string()
            }
        };
        eprintln!(
            "  {} ({}s, {} jobs): {status_str}",
            result.name.bold(),
            result.timeout,
            result.jobs,
        );
        if matches!(result.status, CiStatus::Failed { .. }) {
            eprintln!(
                "    {} {}",
                "log:".dimmed(),
                result.stderr_log.display().to_string().dimmed(),
            );
        }
    }

    // Write JUnit report if requested.
    if let Some(path) = junit_path {
        let path = resolve_path(path);
        write_junit_report(&path, &results);
    }

    eprintln!();
    if failures > 0 {
        eprintln!("{}", format!("ci: {failures} test(s) FAILED").red().bold());
        if let Ok(json) = serde_json::to_string_pretty(&results) {
            println!("{json}");
        }
        ExitCode::FAILURE
    } else {
        eprintln!(
            "{}",
            format!("ci: all {} tests passed", results.len())
                .green()
                .bold()
        );
        ExitCode::SUCCESS
    }
}

fn write_junit_report(path: &std::path::Path, results: &[CiResult]) {
    use quick_junit::{NonSuccessKind, Report, TestCase, TestCaseStatus, TestSuite};

    let mut suite = TestSuite::new("fuzz-ci");

    for result in results {
        let status = match result.status {
            CiStatus::Ok | CiStatus::Timeout => TestCaseStatus::success(),
            CiStatus::Failed { exit_code } => {
                let mut status = TestCaseStatus::non_success(NonSuccessKind::Failure);
                status.set_message(exit_code.map_or("killed by signal".to_string(), |c| {
                    format!("exited with code {c}")
                }));
                status
            }
        };

        let mut tc = TestCase::new(result.name.clone(), status);
        tc.set_classname(result.package.clone());
        tc.set_time(std::time::Duration::from_secs(u64::from(result.timeout)));

        // Read log files for JUnit system-out / system-err
        if let Ok(stdout) = std::fs::read_to_string(&result.stdout_log)
            && !stdout.is_empty()
        {
            tc.set_system_out(stdout);
        }
        if let Ok(stderr) = std::fs::read_to_string(&result.stderr_log)
            && !stderr.is_empty()
        {
            tc.set_system_err(stderr);
        }

        suite.add_test_case(tc);
    }

    let mut report = Report::new("fuzz-ci");
    report.add_test_suite(suite);

    match std::fs::File::create(path) {
        Ok(file) => {
            if let Err(e) = report.serialize(std::io::BufWriter::new(file)) {
                eprintln!(
                    "warning: failed to write JUnit report to {}: {e}",
                    path.display()
                );
            } else {
                eprintln!("ci: JUnit report written to {}", path.display());
            }
        }
        Err(e) => {
            eprintln!(
                "warning: failed to create JUnit report file {}: {e}",
                path.display()
            );
        }
    }
}

/// Build the instrumented binary and return its path, reusing `cmd_build` logic.
fn build_and_get_binary(filter: Option<&str>, build_opts: &BuildOpts) -> Option<String> {
    let matched = filter_tests(filter);
    if matched.is_empty() {
        return None;
    }

    let representative = matched[0];
    let sanitizer = build_opts.sanitizer.as_deref().unwrap_or("none");
    let rustflags = compose_rustflags(sanitizer);
    let target_dir = fuzz_target_dir(&rustflags, build_opts.target_dir.as_deref());

    let mut cmd = std::process::Command::new("cargo");
    cmd.arg("test");
    cmd.arg("--no-run");
    cmd.args(["--message-format", "json"]);
    cmd.args(["--package", &representative.package()]);
    cmd.args(["--profile", &build_opts.profile]);
    cmd.args(["--features", "bolero"]);
    cmd.arg("-Zbuild-std");
    cmd.args(["--target-dir", &target_dir]);

    let default_target = default_target_triple();
    let target = build_opts.target.as_deref().unwrap_or(&default_target);
    cmd.args(["--target", target]);

    cmd.env("RUSTC_BOOTSTRAP", "1");
    cmd.env("RUSTFLAGS", &rustflags);
    cmd.env("BOLERO_FUZZER", "libfuzzer");
    // Capture stdout (JSON messages) but let stderr through for build progress.
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::inherit());

    eprintln!("ci build: {cmd:?}");

    let output = cmd.output().ok()?;
    if !output.status.success() {
        let _ = std::io::Write::write_all(&mut std::io::stderr(), &output.stdout);
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    find_executable(&stdout)
}

/// Events sent from test tasks to the status monitor.
enum CiEvent {
    Start {
        name: String,
        jobs: u32,
        started_at: std::time::Instant,
    },
    Finish {
        name: String,
        status: CiStatus,
    },
    /// Sentinel: all tests have been spawned and completed.
    Shutdown,
}

/// Format the current local wall-clock time as `HH:MM:SS`.
fn format_wall_clock() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}

/// Info tracked per active test.
struct ActiveTest {
    jobs: u32,
    started_at: std::time::Instant,
}

/// Status monitor that owns all mutable state.  Receives events via channel,
/// periodically prints a rich multi-line colored dashboard.
#[allow(clippy::too_many_lines)]
async fn status_monitor(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<CiEvent>,
    total: u32,
    cores_total: u32,
    queued: u32,
    color_map: std::collections::HashMap<String, colored::Color>,
) {
    let mut active: std::collections::BTreeMap<String, ActiveTest> =
        std::collections::BTreeMap::new();
    let mut cores_used: u32 = 0;
    let mut completed: u32 = 0;
    let mut remaining = queued;
    let mut failed: Vec<String> = Vec::new();
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3));
    // Track how many lines the last dashboard print used, so we can clear them.
    let mut last_lines: u16 = 0;

    let clear_dashboard = |last_lines: u16| {
        for _ in 0..last_lines {
            // Move up one line and clear it.
            eprint!("\x1b[A\x1b[2K");
        }
    };

    let print_dashboard =
        |active: &std::collections::BTreeMap<String, ActiveTest>,
         cores_used: u32,
         completed: u32,
         remaining: u32,
         failed: &[String],
         color_map: &std::collections::HashMap<String, colored::Color>|
         -> u16 {
            let now = format_wall_clock();
            let mut lines: u16 = 0;

            eprintln!(
                "{} {} {}/{} {} {}/{} {} {} {}",
                format!("--- fuzz-ci [{now}]").bold(),
                "---".bold(),
                completed.to_string().green().bold(),
                total,
                "done".dimmed(),
                cores_used.to_string().cyan().bold(),
                cores_total,
                "cores".dimmed(),
                remaining.to_string().yellow(),
                "queued".dimmed(),
            );
            lines += 1;

            if !active.is_empty() {
                eprintln!("  {}:", "Active".cyan().bold());
                lines += 1;
                for (name, info) in active {
                    let color = color_map
                        .get(name.as_str())
                        .copied()
                        .unwrap_or(colored::Color::White);
                    let elapsed = info.started_at.elapsed().as_secs();
                    eprintln!(
                        "    {} {}",
                        name.color(color),
                        format!("[{elapsed}s]").dimmed(),
                    );
                    lines += 1;
                }
            }

            if !failed.is_empty() {
                eprintln!("  {}:", "Failed".red().bold());
                lines += 1;
                for name in failed {
                    eprintln!("    {}", name.red());
                    lines += 1;
                }
            }

            lines
        };

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if completed < total {
                    clear_dashboard(last_lines);
                    last_lines = print_dashboard(&active, cores_used, completed, remaining, &failed, &color_map);
                }
            }
            event = rx.recv() => {
                match event {
                    Some(CiEvent::Start { name, jobs, started_at }) => {
                        active.insert(name, ActiveTest { jobs, started_at });
                        cores_used += jobs;
                        remaining = remaining.saturating_sub(1);
                    }
                    Some(CiEvent::Finish { name, status }) => {
                        if let Some(info) = active.remove(&name) {
                            cores_used -= info.jobs;
                        }
                        completed += 1;
                        if matches!(status, CiStatus::Failed { .. }) {
                            failed.push(name);
                        }
                        clear_dashboard(last_lines);
                        last_lines = print_dashboard(&active, cores_used, completed, remaining, &failed, &color_map);
                    }
                    Some(CiEvent::Shutdown) | None => {
                        break;
                    }
                }
            }
        }
    }

    clear_dashboard(last_lines);
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_ci(
    tests: &[&Test],
    binary: &str,
    min_time: u32,
    max_time: u32,
    max_jobs: u32,
    corpus_dir: &str,
    crashes_dir: &str,
    runs: Option<u64>,
    log_dir: &std::path::Path,
) -> Vec<CiResult> {
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(max_jobs as usize));
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

    let color_map: std::collections::HashMap<String, colored::Color> = tests
        .iter()
        .enumerate()
        .map(|(i, t)| (t.name().to_string(), test_color(i)))
        .collect();

    let total = u32::try_from(tests.len()).unwrap_or(u32::MAX);

    let monitor = tokio::spawn(status_monitor(
        rx,
        total,
        max_jobs,
        total,
        color_map,
    ));

    let mut handles = Vec::new();
    let binary = std::sync::Arc::<str>::from(binary);
    let log_dir = std::sync::Arc::<std::path::Path>::from(log_dir);

    for test in tests {
        let test_name = test.name().to_string();
        let package = test.package();
        let mut jobs = test.jobs();
        if jobs > max_jobs {
            eprintln!(
                "{} {} requested {} jobs but --max-jobs is {}; clamping",
                "warning:".yellow().bold(),
                test_name,
                jobs,
                max_jobs,
            );
            jobs = max_jobs;
        }
        let timeout = test.timeout().clamp(min_time, max_time);
        let sem = semaphore.clone();
        let bin = binary.clone();
        let tx = tx.clone();
        let ld = log_dir.clone();

        let test_corpus = format!("{corpus_dir}/{}", test_name.replace("::", "/"));
        let test_crashes = format!("{crashes_dir}/{}", test_name.replace("::", "/"));

        let handle = tokio::spawn(async move {
            // Per-test log directory
            let test_log_dir = ld.join(test_name.replace("::", "/"));
            let _ = tokio::fs::create_dir_all(&test_log_dir).await;
            let stdout_log = test_log_dir.join("stdout.log");
            let stderr_log = test_log_dir.join("stderr.log");

            // Acquire tokens equal to the number of jobs this test wants.
            let mut permits = Vec::new();
            for _ in 0..jobs {
                let Ok(permit) = sem.acquire().await else {
                    let status = CiStatus::Failed { exit_code: None };
                    let _ = tx.send(CiEvent::Finish {
                        name: test_name.clone(),
                        status,
                    });
                    return CiResult {
                        name: test_name,
                        package,
                        jobs,
                        timeout,
                        status,
                        stdout_log,
                        stderr_log,
                    };
                };
                permits.push(permit);
            }

            let _ = tx.send(CiEvent::Start {
                name: test_name.clone(),
                jobs,
                started_at: std::time::Instant::now(),
            });

            let status = run_one_test(&TestRun {
                binary: &bin,
                test_name: &test_name,
                timeout,
                jobs,
                corpus_dir: &test_corpus,
                crashes_dir: &test_crashes,
                runs,
                stdout_log: &stdout_log,
                stderr_log: &stderr_log,
            })
            .await;

            let _ = tx.send(CiEvent::Finish {
                name: test_name.clone(),
                status,
            });

            drop(permits);

            CiResult {
                name: test_name,
                package,
                jobs,
                timeout,
                status,
                stdout_log,
                stderr_log,
            }
        });

        handles.push(handle);
    }

    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }

    let _ = tx.send(CiEvent::Shutdown);
    drop(tx);
    let _ = monitor.await;

    results
}

/// Parameters for running a single fuzz test.
struct TestRun<'a> {
    binary: &'a str,
    test_name: &'a str,
    timeout: u32,
    jobs: u32,
    corpus_dir: &'a str,
    crashes_dir: &'a str,
    runs: Option<u64>,
    stdout_log: &'a std::path::Path,
    stderr_log: &'a std::path::Path,
}

async fn run_one_test(params: &TestRun<'_>) -> CiStatus {
    let TestRun {
        binary,
        test_name,
        timeout,
        jobs,
        corpus_dir,
        crashes_dir,
        runs,
        stdout_log,
        stderr_log,
    } = params;

    let _ = tokio::fs::create_dir_all(corpus_dir).await;
    let _ = tokio::fs::create_dir_all(crashes_dir).await;

    let per_input_timeout = 10;
    let mut libfuzzer_args = vec![
        corpus_dir.to_string(),
        crashes_dir.to_string(),
        format!("-artifact_prefix={crashes_dir}/"),
        format!("-max_total_time={timeout}"),
        format!("-timeout={per_input_timeout}"),
        format!("-jobs={jobs}"),
    ];
    if let Some(runs) = runs {
        libfuzzer_args.push(format!("-runs={runs}"));
    }

    let mut cmd = tokio::process::Command::new(binary);
    cmd.arg(test_name);
    cmd.args(["--exact", "--nocapture", "--quiet", "--test-threads", "1"]);
    cmd.env("BOLERO_TEST_NAME", test_name);
    cmd.env("BOLERO_LIBTEST_HARNESS", "1");
    cmd.env("BOLERO_LIBFUZZER_ARGS", libfuzzer_args.join(" "));

    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error spawning {test_name}: {e}");
            return CiStatus::Failed { exit_code: None };
        }
    };

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let relay_task = tokio::spawn(relay_output(
        stdout_log.to_path_buf(),
        stderr_log.to_path_buf(),
        stdout,
        stderr,
    ));

    let grace = 5;
    let duration = std::time::Duration::from_secs(u64::from(*timeout) + grace);

    let status = match tokio::time::timeout(duration, child.wait()).await {
        Ok(Ok(exit)) => {
            if exit.success() {
                CiStatus::Ok
            } else {
                CiStatus::Failed {
                    exit_code: exit.code(),
                }
            }
        }
        Ok(Err(e)) => {
            eprintln!("error waiting for {test_name}: {e}");
            CiStatus::Failed { exit_code: None }
        }
        Err(_) => {
            let _ = child.kill().await;
            CiStatus::Timeout
        }
    };

    let _ = relay_task.await;
    status
}

/// Stream child stdout/stderr to per-test log files (no terminal output).
async fn relay_output(
    stdout_path: std::path::PathBuf,
    stderr_path: std::path::PathBuf,
    stdout: Option<tokio::process::ChildStdout>,
    stderr: Option<tokio::process::ChildStderr>,
) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let out_task = async {
        if let Some(out) = stdout
            && let Ok(mut file) = tokio::fs::File::create(&stdout_path).await
        {
            let mut lines = BufReader::new(out).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = file.write_all(line.as_bytes()).await;
                let _ = file.write_all(b"\n").await;
            }
        }
    };

    let err_task = async {
        if let Some(err) = stderr
            && let Ok(mut file) = tokio::fs::File::create(&stderr_path).await
        {
            let mut lines = BufReader::new(err).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = file.write_all(line.as_bytes()).await;
                let _ = file.write_all(b"\n").await;
            }
        }
    };

    tokio::join!(out_task, err_task);
}
