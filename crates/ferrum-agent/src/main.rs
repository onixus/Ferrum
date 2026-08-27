//! Node agent. Last-known-good bundle, never fail-open if CP dies.

use ferrum_agent::{parse_trust_root, Agent, AgentConfig, AgentRole, RESPOND_NO_HOST_PIDNS};
use ferrum_common::FerrumError;
use ferrum_export::{EventSink, QueueSink, RotatingFileSink, SinkContext};
use ferrum_k8smeta::SharedCgroupIndex;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const DEFAULT_EXPORT_MAX_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_EXPORT_KEEP: usize = 5;
/// Events buffered between the decision path and the file writer. Full queue
/// drops telemetry (counted); it never blocks a decision.
const DEFAULT_EXPORT_QUEUE: usize = 8192;
/// Poll step of the shutdown watcher; only the exit path pays it.
const SHUTDOWN_TICK: Duration = Duration::from_millis(50);

/// One published cgroup set together with the moment it was resolved from a
/// successful scan. A set republished after a failed refresh keeps the OLD
/// stamp: the carrier must not read a retry of stale data as proof the map is
/// current.
#[cfg_attr(not(feature = "attach"), allow(dead_code))]
struct CgroupPublish {
    cgroups: BTreeSet<u64>,
    resolved_at: Instant,
}

/// Set from the SIGTERM/SIGINT handler, which may do nothing else.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flags = parse_flags(&args);
    let trust_hex = require_flag(&flags, "trust-root");
    let trust_root = match parse_trust_root(&trust_hex) {
        Ok(k) => k,
        Err(err) => {
            eprintln!("ferrum-agent: trust-root: {err}");
            exit(2);
        }
    };

    let role = match flags.map.get("role") {
        Some(s) if !s.is_empty() => match AgentRole::parse_name(s) {
            Ok(r) => r,
            Err(err) => {
                eprintln!("ferrum-agent: {err}");
                exit(2);
            }
        },
        _ => AgentRole::Observe,
    };
    // Respond needs identity, and identity comes from the apiserver watch.
    // Without it the cgroup index stays empty, `ferrum_cgroups` stays empty,
    // no event is ever flagged as a container and no kill can ever pass the
    // guards. A build like that must not pose as an enforcing agent.
    #[cfg(all(feature = "attach", not(feature = "apiserver")))]
    if role.respond_enabled() {
        die(
            "--role respond needs the apiserver feature: without pod metadata the cgroup index \
             and ferrum_cgroups stay empty, so no event is flagged as a container and no kill \
             can ever fire",
        );
    }

    let reload_ms: u64 = match flags.map.get("reload-ms") {
        Some(s) if !s.is_empty() => s.parse().unwrap_or_else(|_| die("invalid --reload-ms")),
        _ => 1000,
    };

    let bundle_path = flags
        .map
        .get("bundle")
        .cloned()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let lkg_dir = flags
        .map
        .get("lkg-dir")
        .cloned()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);

    let policy_name = flags.map.get("policy-name").cloned().unwrap_or_default();

    let export_dir = flags
        .map
        .get("export-dir")
        .cloned()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let export_max_bytes: u64 = match flags.map.get("export-max-bytes") {
        Some(s) if !s.is_empty() => s
            .parse()
            .unwrap_or_else(|_| die("invalid --export-max-bytes")),
        _ => DEFAULT_EXPORT_MAX_BYTES,
    };
    let export_keep: usize = match flags.map.get("export-keep") {
        Some(s) if !s.is_empty() => s.parse().unwrap_or_else(|_| die("invalid --export-keep")),
        _ => DEFAULT_EXPORT_KEEP,
    };
    let export_queue: usize = match flags.map.get("export-queue") {
        Some(s) if !s.is_empty() => s.parse().unwrap_or_else(|_| die("invalid --export-queue")),
        _ => DEFAULT_EXPORT_QUEUE,
    };
    let node = flags
        .map
        .get("node")
        .cloned()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "unknown-node".into());

    let mut agent = Agent::new(AgentConfig {
        role,
        lkg_dir,
        trust_root,
        bundle_path: bundle_path.clone(),
        exceptions: Vec::new(),
        policy_name,
    });
    if role.respond_enabled() {
        // The datapath reports tgids from the initial pid namespace. Without
        // hostPID they name other processes here, so respond is refused rather
        // than aimed at whatever happens to hold that pid in this namespace.
        if ferrum_agent::host_pid_namespace() {
            agent.set_responder(Box::new(ferrum_agent::SignalResponder));
        } else {
            eprintln!("ferrum-agent: {RESPOND_NO_HOST_PIDNS}");
            agent.disable_respond(RESPOND_NO_HOST_PIDNS);
        }
    }

    // Each message is the whole desired cgroup set, so a full channel drops an
    // update instead of queueing: the next refresh carries the current truth.
    let (cgroup_tx, cgroup_rx) = std::sync::mpsc::sync_channel::<CgroupPublish>(1);
    spawn_cgroup_refresh(agent.cgroup_index(), node.clone(), cgroup_tx);

    if let Err(err) = agent.restore_last_known_good() {
        eprintln!("ferrum-agent: {err}");
    }

    if let Some(path) = bundle_path.as_ref() {
        if let Err(err) = agent.apply_path(path) {
            eprintln!("ferrum-agent: {err}");
            if !agent.using_last_known_good() {
                exit(2);
            }
        }
        if let Err(err) = agent.reload_exceptions_path(path) {
            eprintln!("ferrum-agent: exceptions load failed, waivers dropped: {err}");
        }
    }

    match agent.attach_pins() {
        Ok(()) => {}
        Err(FerrumError::Degraded(reason)) => {
            eprintln!("ferrum-agent: {reason}");
        }
        Err(err) => {
            eprintln!("ferrum-agent: {err}");
        }
    }

    let role_name = if agent.role().respond_enabled() {
        "respond"
    } else {
        "observe"
    };
    let ctx = SinkContext::new(node, role_name);
    let inner: Box<dyn EventSink + Send + Sync> = match export_dir {
        Some(dir) => Box::new(RotatingFileSink::new(
            dir,
            export_max_bytes,
            export_keep,
            ctx.clone(),
        )),
        None => Box::new(ferrum_export::EnvelopeWriterSink::stdout(ctx.clone())),
    };
    ctx.set_bundle_digest(agent.last_good_digest().cloned());
    ctx.set_degraded(agent.is_degraded());
    let sink = std::sync::Arc::new(QueueSink::new(inner, export_queue));
    install_signal_handlers();
    spawn_shutdown_watcher(Arc::clone(&sink));

    run(agent, sink, ctx, bundle_path, reload_ms, &flags, cgroup_rx)
}

/// Fills the cgroup→pod index and publishes its key set to whoever owns the
/// `KernelHandle`. Until the index holds something, every namespaced policy
/// misses; until the kernel map holds it too, no event is flagged as a
/// container. Both are Degraded.
#[cfg(feature = "apiserver")]
fn spawn_cgroup_refresh(
    index: SharedCgroupIndex,
    node: String,
    sync_tx: std::sync::mpsc::SyncSender<CgroupPublish>,
) {
    use ferrum_agent::{CGROUP_CARRIER_GONE, CGROUP_REFRESH};
    use ferrum_k8smeta::watch::{ApiserverConfig, ApiserverWatcher};
    use ferrum_k8smeta::{CgroupResolver, StdCgroupFs, DEFAULT_CGROUP_ROOT};

    let config = match ApiserverConfig::from_service_account(node) {
        Ok(config) => config,
        Err(err) => {
            eprintln!(
                "ferrum-agent: no apiserver config ({err}); cgroup index stays empty and \
                 namespaced policies cannot match. Degraded."
            );
            return;
        }
    };
    let watcher = Arc::new(ApiserverWatcher::new(config));
    let cache = watcher.cache();
    let watch_thread = Arc::clone(&watcher);
    std::thread::spawn(move || watch_thread.run());
    std::thread::spawn(move || {
        let published = index.clone();
        let resolver = CgroupResolver::new(index);
        let source = ferrum_agent::SharedPodSource::new(cache);
        let fs = StdCgroupFs;
        let root = PathBuf::from(DEFAULT_CGROUP_ROOT);
        let mut resolved_at: Option<Instant> = None;
        loop {
            match resolver.refresh(&fs, &root, &source) {
                Ok(_) => resolved_at = Some(Instant::now()),
                Err(err) => {
                    eprintln!("ferrum-agent: cgroup refresh failed, keeping the last index: {err}")
                }
            }
            // Publish even after a failed refresh: the index is still the best
            // known truth, and the kernel map must not drift away from it. The
            // stamp stays at the last successful resolve, so a refresher stuck
            // on errors ages the container map out instead of renewing it.
            if let Some(resolved_at) = resolved_at {
                let cgroups: BTreeSet<u64> = published.snapshot().into_keys().collect();
                let update = CgroupPublish {
                    cgroups,
                    resolved_at,
                };
                if !ferrum_agent::publish_cgroups(&sync_tx, update) {
                    eprintln!("ferrum-agent: {CGROUP_CARRIER_GONE}");
                    return;
                }
            }
            std::thread::sleep(CGROUP_REFRESH);
        }
    });
}

#[cfg(not(feature = "apiserver"))]
fn spawn_cgroup_refresh(
    index: SharedCgroupIndex,
    _node: String,
    _sync_tx: std::sync::mpsc::SyncSender<CgroupPublish>,
) {
    let _ = index;
    eprintln!(
        "ferrum-agent: built without the apiserver feature: no pod metadata, the cgroup index \
         stays empty and namespaced policies cannot match. Degraded."
    );
}

extern "C" fn on_terminate(_signal: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

fn install_signal_handlers() {
    // Async-signal-safe by construction: the handler only sets a flag.
    #[allow(unsafe_code)]
    unsafe {
        libc::signal(libc::SIGTERM, on_terminate as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_terminate as libc::sighandler_t);
    }
}

/// SIGTERM must not throw away events the queue already accepted: they are
/// enforcement history, and the kubelet gives no second chance to write them.
fn spawn_shutdown_watcher(sink: Arc<QueueSink<Box<dyn EventSink + Send + Sync>>>) {
    std::thread::spawn(move || loop {
        if SHUTDOWN.load(Ordering::Relaxed) {
            sink.close();
            exit(0);
        }
        std::thread::sleep(SHUTDOWN_TICK);
    });
}

#[cfg(feature = "attach")]
fn run(
    agent: Agent,
    sink: std::sync::Arc<QueueSink<Box<dyn EventSink + Send + Sync>>>,
    ctx: SinkContext,
    bundle_path: Option<PathBuf>,
    reload_ms: u64,
    flags: &Flags,
    cgroup_rx: std::sync::mpsc::Receiver<CgroupPublish>,
) -> ! {
    use ferrum_ebpf::{plan_cgroup_sync, KernelHandle, SyscallArch};
    use std::sync::mpsc::sync_channel;
    use std::sync::RwLock;

    let elf_path = match flags.map.get("bpf-elf").filter(|s| !s.is_empty()) {
        Some(p) => PathBuf::from(p),
        None => die("--bpf-elf is required when built with the attach feature"),
    };
    let arch = match SyscallArch::host() {
        Some(arch) => arch,
        None => die("no syscall decode table for this host arch; refusing to attach"),
    };
    let elf = std::fs::read(&elf_path)
        .unwrap_or_else(|err| die(&format!("read {}: {err}", elf_path.display())));

    let agent = Arc::new(RwLock::new(agent));
    let mut handle = match KernelHandle::attach(&elf) {
        Ok(handle) => handle,
        Err(err) => {
            eprintln!("ferrum-agent: kernel attach failed, datapath is Degraded: {err}");
            ctx.set_degraded(true);
            park_degraded(&agent, ctx, bundle_path, reload_ms);
        }
    };
    if let Err(err) = handle.set_self_tgid(std::process::id() as u64) {
        // Without the self tgid the datapath cannot flag agent-self events,
        // and the agent could be told to kill itself. Refuse to run attached.
        eprintln!("ferrum-agent: {err}");
        exit(2);
    }
    let mut reader = match handle.take_ring_reader() {
        Ok(reader) => reader,
        Err(err) => {
            eprintln!("ferrum-agent: {err}");
            exit(2);
        }
    };
    agent
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .set_attached(true);

    // Bounded: a full channel backpressures the reader, and the kernel drops
    // (counted in events_dropped_total) instead of userspace growing without
    // bound.
    let (tx, rx) = sync_channel::<Vec<u8>>(16 * 1024);
    // The KernelHandle stays in this one thread: it owns the ring, the drop
    // counter and `ferrum_cgroups`, and none of them may be touched from two
    // places. The refresher only sends the desired cgroup set here.
    let drop_agent = Arc::clone(&agent);
    std::thread::spawn(move || {
        let mut handle = handle;
        let mut idle_ms = 1u64;
        let mut seen_drops = 0u64;
        let mut since_drop_check = Duration::ZERO;
        let mut publisher_alive = true;
        loop {
            if publisher_alive {
                let guard = drop_agent.read().unwrap_or_else(|e| e.into_inner());
                publisher_alive =
                    ferrum_agent::drain_cgroup_updates(&cgroup_rx, &guard, |agent, next| {
                        // The health stamp is the publisher's resolve time, not
                        // now: an unchanged set republished from a frozen index
                        // must not reaffirm the map.
                        match plan_cgroup_sync(handle.container_cgroups(), &next.cgroups) {
                            Ok(plan) if plan.is_empty() => agent.set_container_map_synced_at(
                                handle.container_map_entries() as u64,
                                next.resolved_at,
                            ),
                            Ok(plan) => match handle.sync_container_cgroups(&plan) {
                                Ok(stats) => agent.set_container_map_synced_at(
                                    stats.entries as u64,
                                    next.resolved_at,
                                ),
                                Err(err) => {
                                    eprintln!("ferrum-agent: {err}");
                                    agent.mark_container_map_error(err.to_string());
                                }
                            },
                            Err(err) => {
                                eprintln!("ferrum-agent: {err}");
                                agent.mark_container_map_error(err.to_string());
                            }
                        }
                    });
                if !publisher_alive {
                    eprintln!("ferrum-agent: {}", ferrum_agent::CGROUP_PUBLISHER_GONE);
                }
            }
            let n = reader.drain(|record| {
                let _ = tx.send(record.to_vec());
            });
            if n == 0 {
                std::thread::sleep(Duration::from_millis(idle_ms));
                since_drop_check += Duration::from_millis(idle_ms);
                idle_ms = (idle_ms * 2).min(10);
            } else {
                idle_ms = 1;
            }
            if since_drop_check >= Duration::from_millis(reload_ms) {
                since_drop_check = Duration::ZERO;
                if let Ok(total) = handle.events_dropped_total() {
                    let delta = total.saturating_sub(seen_drops);
                    if delta > 0 {
                        seen_drops = total;
                        drop_agent
                            .read()
                            .unwrap_or_else(|e| e.into_inner())
                            .record_drop(delta);
                    }
                }
            }
        }
    });

    let pump_agent = Arc::clone(&agent);
    let pump_sink = std::sync::Arc::clone(&sink);
    std::thread::spawn(move || {
        for record in rx {
            let guard = pump_agent.read().unwrap_or_else(|e| e.into_inner());
            ferrum_agent::pump_records(&guard, arch, [record], pump_sink.as_ref());
        }
    });

    match bundle_path {
        Some(path) => ferrum_agent::poll_bundle_shared(
            &agent,
            &path,
            Duration::from_millis(reload_ms),
            Some(&ctx),
        ),
        None => loop {
            std::thread::sleep(Duration::from_millis(reload_ms));
            let degraded = agent
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .is_degraded();
            ctx.set_degraded(degraded);
        },
    }
}

#[cfg(feature = "attach")]
fn park_degraded(
    agent: &std::sync::Arc<std::sync::RwLock<Agent>>,
    ctx: SinkContext,
    bundle_path: Option<PathBuf>,
    reload_ms: u64,
) -> ! {
    match bundle_path {
        Some(path) => ferrum_agent::poll_bundle_shared(
            agent,
            &path,
            Duration::from_millis(reload_ms),
            Some(&ctx),
        ),
        None => loop {
            std::thread::sleep(Duration::from_millis(reload_ms));
        },
    }
}

/// Without the `attach` feature there is no datapath: the userspace bundle is
/// verified and hot-reloaded, but nothing feeds `handle_event`. That is a
/// Degraded agent, and it says so instead of sleeping quietly.
#[cfg(not(feature = "attach"))]
fn run(
    mut agent: Agent,
    sink: std::sync::Arc<QueueSink<Box<dyn EventSink + Send + Sync>>>,
    ctx: SinkContext,
    bundle_path: Option<PathBuf>,
    reload_ms: u64,
    _flags: &Flags,
    _cgroup_rx: std::sync::mpsc::Receiver<CgroupPublish>,
) -> ! {
    let _ = sink;
    eprintln!(
        "ferrum-agent: built without the attach feature: no kernel datapath, \
         no syscall events, no reaction. Degraded."
    );
    ctx.set_degraded(true);
    match bundle_path {
        Some(path) => ferrum_agent::poll_bundle(
            &mut agent,
            &path,
            Duration::from_millis(reload_ms),
            Some(&ctx),
        ),
        None => loop {
            std::thread::sleep(Duration::from_millis(reload_ms));
        },
    }
}

struct Flags {
    map: BTreeMap<String, String>,
}

fn parse_flags(args: &[String]) -> Flags {
    let mut map = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(rest) = a.strip_prefix("--") {
            if let Some((k, v)) = rest.split_once('=') {
                map.insert(k.to_string(), v.to_string());
            } else if let Some(val) = args.get(i + 1) {
                if val.starts_with("--") {
                    map.insert(rest.to_string(), String::new());
                } else {
                    map.insert(rest.to_string(), val.clone());
                    i += 1;
                }
            } else {
                map.insert(rest.to_string(), String::new());
            }
        }
        i += 1;
    }
    Flags { map }
}

fn require_flag(flags: &Flags, name: &str) -> String {
    match flags.map.get(name) {
        Some(v) if !v.is_empty() => v.clone(),
        _ => die(
            "usage: ferrum-agent --trust-root <32-byte-hex> [--bundle <fsig|dir>] [--lkg-dir <dir>] [--role observe|respond] [--policy-name <name>] [--reload-ms 1000] [--node <name>] [--export-dir <dir>] [--export-max-bytes 67108864] [--export-keep 5] [--export-queue 8192] [--bpf-elf <path>]",
        ),
    }
}

fn die(msg: &str) -> ! {
    eprintln!("ferrum-agent: {msg}");
    exit(2);
}
