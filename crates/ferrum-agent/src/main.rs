//! Node agent. Last-known-good bundle, never fail-open if CP dies.

use ferrum_agent::{parse_trust_root, Agent, AgentConfig, AgentRole, RESPOND_NO_HOST_PIDNS};
use ferrum_common::FerrumError;
use ferrum_export::{EventSink, QueueSink, RotatingFileSink, SinkContext};
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
    // Parsed before anything is built, and every error here is exit(2): a
    // typo in `--siem-profile` that fell back to a default would put the node
    // on a wire format the receiver cannot parse, and the loss would happen
    // inside somebody else's parser where nothing in this tree can count it.
    let siem = siem_config(&flags);
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
    spawn_cgroup_refresh(&agent, node.clone(), cgroup_tx);

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
    let durable: Box<dyn EventSink + Send + Sync> = match export_dir.clone() {
        Some(dir) => Box::new(RotatingFileSink::new(
            dir,
            export_max_bytes,
            export_keep,
            ctx.clone(),
        )),
        None => Box::new(ferrum_export::EnvelopeWriterSink::stdout(ctx.clone())),
    };
    // The node-local record first, always, and the SIEM beside it — never
    // instead of it. A destination this node does not own must not be the only
    // copy of what it enforced: the file survives a SIEM outage, a rotated
    // credential and a firewall change, and it is what an investigation falls
    // back to when the export counters say records were lost.
    let mut destinations: Vec<Box<dyn EventSink + Send + Sync>> = vec![durable];
    if let Some(config) = siem {
        eprintln!(
            "ferrum-agent: exporting to {} over {} as {}",
            config.address,
            config.transport.name(),
            config.profile.name()
        );
        destinations.push(Box::new(ferrum_siem::SyslogSink::new(config)));
    }
    // Always a fan-out, even with one destination: one code path, and the
    // envelope is stamped once in one place.
    let inner: Box<dyn EventSink + Send + Sync> =
        Box::new(ferrum_export::FanoutSink::new(ctx.clone(), destinations));
    ctx.set_bundle_digest(agent.last_good_digest().cloned());
    ctx.set_degraded(agent.is_degraded());
    let sink = std::sync::Arc::new(QueueSink::new(inner, export_queue));
    install_signal_handlers();
    spawn_shutdown_watcher(Arc::clone(&sink));

    // Bound here, before anything claims to be running: a metrics port that
    // cannot be bound is a target that never comes up, and discovering that
    // from the scraper's side is discovering it hours later. Absent flag means
    // absent port — the endpoint is opt-in, because a listening socket on a
    // DaemonSet is a cost the operator has to choose.
    let metrics_listener = bind_metrics(&flags);

    run(
        agent,
        sink,
        ctx,
        bundle_path,
        export_dir,
        reload_ms,
        &flags,
        cgroup_rx,
        metrics_listener,
    )
}

/// `--siem-address host:port [--siem-transport udp|tcp] [--siem-profile ...]`,
/// or nothing.
///
/// Off unless an address is given, and that is not timidity: an export
/// destination is a site's own address, and a default would either be a name
/// that does not resolve — every event counted as an export failure on every
/// node, every node Degraded — or a guess about somebody's network.
///
/// The two other flags are only read when an address is present, and a value
/// this build does not know is exit(2) rather than a fallback. `--siem-profile
/// syslog` silently becoming CEF would put a fleet on a format the receiver's
/// parser drops, and that is the one loss no counter in this tree can see: the
/// records leave this node successfully and die inside somebody else's
/// pipeline.
fn siem_config(flags: &Flags) -> Option<ferrum_siem::SinkConfig> {
    let address = flags
        .map
        .get("siem-address")
        .filter(|s| !s.is_empty())?
        .clone();
    let transport = match flags.map.get("siem-transport").filter(|s| !s.is_empty()) {
        Some(name) => ferrum_siem::Transport::parse_name(name).unwrap_or_else(|err| die(&err)),
        // TCP by default. UDP loses records with nothing on either side to say
        // so, which is the failure mode this whole crate is written against;
        // it stays available for a receiver that only speaks it.
        None => ferrum_siem::Transport::Tcp,
    };
    let profile = match flags.map.get("siem-profile").filter(|s| !s.is_empty()) {
        Some(name) => ferrum_siem::Profile::parse_name(name).unwrap_or_else(|err| die(&err)),
        // The standard, not a vendor's dialect: a receiver nobody configured
        // for us still parses RFC 5424 structured data.
        None => ferrum_siem::Profile::Rfc5424,
    };
    Some(ferrum_siem::SinkConfig {
        address,
        transport,
        profile,
    })
}

/// `--metrics-listen host:port`, or nothing.
fn bind_metrics(flags: &Flags) -> Option<std::net::TcpListener> {
    let listen = flags.map.get("metrics-listen").filter(|s| !s.is_empty())?;
    match std::net::TcpListener::bind(listen.as_str()) {
        Ok(listener) => {
            eprintln!(
                "ferrum-agent: metrics on {listen}{}",
                ferrum_metrics::METRICS_PATH
            );
            Some(listener)
        }
        Err(err) => die(&format!("bind --metrics-listen {listen}: {err}")),
    }
}

/// Fills the cgroup→pod index and publishes its key set to whoever owns the
/// `KernelHandle`. Until the index holds something, every namespaced policy
/// misses; until the kernel map holds it too, no event is flagged as a
/// container. Both are Degraded.
#[cfg(feature = "apiserver")]
fn spawn_cgroup_refresh(
    agent: &Agent,
    node: String,
    sync_tx: std::sync::mpsc::SyncSender<CgroupPublish>,
) {
    use ferrum_agent::{CGROUP_CARRIER_GONE, CGROUP_REFRESH};
    use ferrum_k8smeta::watch::{ApiserverConfig, ApiserverWatcher};
    use ferrum_k8smeta::{detect_cgroup2_root, CgroupResolver, StdCgroupFs};

    let index = agent.cgroup_index();
    // Derived here, before the thread exists, so a failure is the agent's
    // reason rather than a line on stderr from a thread that then loops
    // forever over the wrong filesystem. The scan needs a root and there is
    // exactly one right answer for it; where that answer cannot be had, the
    // index is left empty and said so, not filled from a guess.
    let Some(root) = ferrum_agent::cgroup_scan_root(agent, detect_cgroup2_root()) else {
        eprintln!(
            "ferrum-agent: {}",
            agent.terminal_fault().unwrap_or_default()
        );
        return;
    };

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
    agent: &Agent,
    _node: String,
    _sync_tx: std::sync::mpsc::SyncSender<CgroupPublish>,
) {
    let _ = agent.cgroup_index();
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
        libc::signal(
            libc::SIGTERM,
            on_terminate as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            on_terminate as *const () as libc::sighandler_t,
        );
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
#[allow(clippy::too_many_arguments)]
fn run(
    agent: Agent,
    sink: std::sync::Arc<QueueSink<Box<dyn EventSink + Send + Sync>>>,
    ctx: SinkContext,
    bundle_path: Option<PathBuf>,
    export_dir: Option<PathBuf>,
    reload_ms: u64,
    flags: &Flags,
    cgroup_rx: std::sync::mpsc::Receiver<CgroupPublish>,
    metrics_listener: Option<std::net::TcpListener>,
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
    // The node's own state surface: envelopes, `status.json` beside them, and
    // the transition line. It reports and never acts — nothing here is a
    // probe, and no probe may be wired to it.
    let out = ferrum_agent::StatusOutput {
        ctx: Some(&ctx),
        sink: Some(sink.as_ref()),
        status_dir: export_dir.as_deref(),
    };
    if let Some(listener) = metrics_listener {
        ferrum_agent::spawn_metrics(
            listener,
            Arc::clone(&agent),
            ctx.clone(),
            std::sync::Arc::clone(&sink),
        );
    }
    let mut handle = match KernelHandle::attach_for_arch(&elf, arch) {
        Ok(handle) => {
            if !handle.unhooked_syscalls().is_empty() {
                // Not fatal: the remaining hooks are the datapath. But rules
                // naming these are dead on this node, and that must be said
                // out loud rather than looking like a clean attach. Covers
                // both absences the attach narrows the enforceable set for:
                // the syscall is not in this arch's ABI, or this kernel was
                // built without it (no CONFIG_MODULES, no init_module).
                eprintln!(
                    "ferrum-agent: no tracepoint on this node for {}; rules naming them cannot \
                     fire here",
                    handle.unhooked_syscalls().join(", ")
                );
            }
            handle
        }
        Err(err) => {
            eprintln!("ferrum-agent: kernel attach failed, datapath is Degraded: {err}");
            // The stderr line is on one node's console; status.json is what is
            // read from off the node, and until now it said only "no kernel
            // attach" with no cause anywhere in it. The container map is not
            // ready for exactly one reason here — there is no handle to sync
            // it through — so that reason is the attach failure itself,
            // RLIMIT_MEMLOCK state and all.
            agent
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .mark_container_map_error(format!("kernel attach failed: {err}"));
            ctx.set_degraded(true);
            park_degraded(&agent, &out, bundle_path, reload_ms);
        }
    };
    // The datapath writes `bpf_get_current_pid_tgid()`, an initial-pid-namespace
    // tgid. Without hostPID this process's pid names a different, arbitrary
    // process there — publishing it would leave EVENT_FLAG_AGENT_SELF unset for
    // the agent and set for whoever holds that number (typically init), so every
    // notAgentSelf rule would exempt the wrong process and apply to the agent.
    // Leave `ferrum_self` unconfigured instead, and say why.
    let self_tgid = ferrum_agent::self_tgid_to_publish(
        &agent.read().unwrap_or_else(|e| e.into_inner()),
        std::process::id() as u64,
    );
    match self_tgid {
        Some(tgid) => {
            if let Err(err) = handle.set_self_tgid(tgid) {
                // Without the self tgid the datapath cannot flag agent-self
                // events, and the agent could be told to kill itself. Refuse
                // to run attached.
                eprintln!("ferrum-agent: {err}");
                exit(2);
            }
        }
        None => eprintln!("ferrum-agent: {}", ferrum_agent::SELF_TGID_UNPUBLISHED),
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
        let mut ring =
            ferrum_agent::RingLoop::new(Duration::from_millis(reload_ms), Instant::now());
        let mut publisher_alive = true;
        let mut drop_check_broken = false;
        let mut records_alive = true;
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
            let tick = ring.tick(
                Instant::now(),
                || {
                    reader.drain(|record| {
                        if !records_alive {
                            return;
                        }
                        // No guard on the shared agent is taken here: `send`
                        // blocks while the channel is full, and a guard held
                        // across that block parks this thread, the poller and
                        // the pump forever. See `publish_record`.
                        if !ferrum_agent::publish_record(&drop_agent, &tx, record.to_vec()) {
                            // Keep draining so a full ring does not stall the
                            // kernel, but stop pretending these records reach
                            // a rule.
                            eprintln!("ferrum-agent: {}", ferrum_agent::RECORD_CHANNEL_GONE);
                            records_alive = false;
                        }
                    })
                },
                || handle.events_dropped_total(),
            );
            // Once: a counter that cannot be read stays unreadable, and this
            // runs every reload tick.
            if tick.drop_check_failed && !drop_check_broken {
                drop_check_broken = true;
                eprintln!("ferrum-agent: in-kernel drop counter unreadable; ring drops are blind");
            }
            if tick.drop_delta > 0 {
                drop_agent
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .record_drop(tick.drop_delta);
            }
            if let Some(sleep) = tick.sleep {
                std::thread::sleep(sleep);
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
        Some(path) => {
            ferrum_agent::poll_bundle_shared(&agent, &path, Duration::from_millis(reload_ms), &out)
        }
        None => ferrum_agent::poll_status(&agent, Duration::from_millis(reload_ms), &out),
    }
}

#[cfg(feature = "attach")]
fn park_degraded(
    agent: &std::sync::Arc<std::sync::RwLock<Agent>>,
    out: &ferrum_agent::StatusOutput<'_>,
    bundle_path: Option<PathBuf>,
    reload_ms: u64,
) -> ! {
    match bundle_path {
        // A parked agent still publishes: a node whose ELF will not attach is
        // exactly the node whose state has to be readable from outside it.
        Some(path) => {
            ferrum_agent::poll_bundle_shared(agent, &path, Duration::from_millis(reload_ms), out)
        }
        None => ferrum_agent::poll_status(agent, Duration::from_millis(reload_ms), out),
    }
}

/// Without the `attach` feature there is no datapath: the userspace bundle is
/// verified and hot-reloaded, but nothing feeds `handle_event`. That is a
/// Degraded agent, and it says so instead of sleeping quietly.
#[cfg(not(feature = "attach"))]
#[allow(clippy::too_many_arguments)]
fn run(
    agent: Agent,
    sink: std::sync::Arc<QueueSink<Box<dyn EventSink + Send + Sync>>>,
    ctx: SinkContext,
    bundle_path: Option<PathBuf>,
    export_dir: Option<PathBuf>,
    reload_ms: u64,
    _flags: &Flags,
    _cgroup_rx: std::sync::mpsc::Receiver<CgroupPublish>,
    metrics_listener: Option<std::net::TcpListener>,
) -> ! {
    eprintln!(
        "ferrum-agent: built without the attach feature: no kernel datapath, \
         no syscall events, no reaction. Degraded."
    );
    ctx.set_degraded(true);
    // Shared rather than owned, and in this build too: the metrics thread is a
    // second reader of the same agent, and a build whose only difference from
    // the shipped one is that its state is unreadable would be the harder of
    // the two to debug. The poll loops are the `_shared` forms for the same
    // reason the attach build uses them.
    let agent = std::sync::Arc::new(std::sync::RwLock::new(agent));
    let out = ferrum_agent::StatusOutput {
        ctx: Some(&ctx),
        sink: Some(sink.as_ref()),
        status_dir: export_dir.as_deref(),
    };
    if let Some(listener) = metrics_listener {
        ferrum_agent::spawn_metrics(
            listener,
            std::sync::Arc::clone(&agent),
            ctx.clone(),
            std::sync::Arc::clone(&sink),
        );
    }
    match bundle_path {
        Some(path) => {
            ferrum_agent::poll_bundle_shared(&agent, &path, Duration::from_millis(reload_ms), &out)
        }
        None => ferrum_agent::poll_status(&agent, Duration::from_millis(reload_ms), &out),
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
            "usage: ferrum-agent --trust-root <32-byte-hex> [--bundle <fsig|dir>] [--lkg-dir <dir>] [--role observe|respond] [--policy-name <name>] [--reload-ms 1000] [--node <name>] [--export-dir <dir>] [--export-max-bytes 67108864] [--export-keep 5] [--export-queue 8192] [--siem-address <host:port>] [--siem-transport tcp|udp] [--siem-profile rfc5424|cef|ecs] [--metrics-listen <host:port>] [--bpf-elf <path>]",
        ),
    }
}

fn die(msg: &str) -> ! {
    eprintln!("ferrum-agent: {msg}");
    exit(2);
}
