//! cgroup v2 tree walk: directory inode -> (podUID, containerID).
//!
//! `bpf_get_current_cgroup_id()` returns the inode of the task's cgroup
//! directory, so the key is computed locally from the node's own filesystem and
//! never taken from the workload. cgroup v1 has no single hierarchy to key on:
//! it is reported as degraded rather than guessed.

use ferrum_common::{FerrumError, Result};
use std::io;
use std::path::{Path, PathBuf};

pub const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Where the kernel publishes this process's mount table.
pub const SELF_MOUNTINFO: &str = "/proc/self/mountinfo";

/// The cgroup2 (unified) mount point of this node, read from the mount table
/// rather than assumed.
///
/// `DEFAULT_CGROUP_ROOT` is only right on a node where cgroup2 is mounted at
/// the top of `/sys/fs/cgroup`. On a hybrid node it is a tmpfs holding one
/// directory per v1 controller and cgroup2 sits below it (`unified`), so every
/// path built on the constant names a file that is not there. Both the index
/// (`scan`) and the agent's pre-signal target check are keyed on inodes of
/// this hierarchy, and they must be keyed on the *same* one: a derivation that
/// lives in one caller and not the other is two roots that can disagree.
///
/// `Degraded` rather than a fallback to the constant: a wrong root does not
/// fail loudly, it answers every question with the wrong number. The caller
/// has to be able to tell "no cgroup2 here" from "cgroup2 is at X".
pub fn detect_cgroup2_root() -> Result<PathBuf> {
    let raw = std::fs::read_to_string(SELF_MOUNTINFO)
        .map_err(|e| FerrumError::Degraded(format!("{SELF_MOUNTINFO} unreadable: {e}")))?;
    cgroup2_root_from_mountinfo(&raw)
}

/// The derivation itself, over mountinfo text.
///
/// A mountinfo line is `id parent major:minor root mountpoint opts... - fstype
/// source superopts`; the fields before the ` - ` separator are the ones this
/// needs. Only a mount whose *root* field is `/` is considered: a bind of a
/// subtree of the hierarchy is a real cgroup2 mount that is nonetheless the
/// wrong answer, because a path from `/proc/<pid>/cgroup` is relative to the
/// whole hierarchy and would resolve under it to something else or to nothing.
///
/// More than one such hierarchy on different superblocks is refused rather
/// than picked between. Several mount points of the *same* superblock are
/// views of one hierarchy — the inodes agree whichever is used — so the
/// shortest is taken and the answer is deterministic.
pub fn cgroup2_root_from_mountinfo(raw: &str) -> Result<PathBuf> {
    let mut whole: Vec<(String, PathBuf)> = Vec::new();
    let mut subtrees = 0usize;
    for line in raw.lines() {
        let Some((before, after)) = line.split_once(" - ") else {
            continue;
        };
        if after.split_whitespace().next() != Some("cgroup2") {
            continue;
        }
        let mut fields = before.split_whitespace().skip(2);
        let (Some(dev), Some(root), Some(point)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if root != "/" {
            subtrees += 1;
            continue;
        }
        whole.push((dev.to_string(), PathBuf::from(unescape_mount_point(point))));
    }

    whole.sort();
    whole.dedup();
    let devices: Vec<&String> = {
        let mut d: Vec<&String> = whole.iter().map(|(dev, _)| dev).collect();
        d.dedup();
        d
    };
    match devices.len() {
        0 if subtrees > 0 => Err(FerrumError::Degraded(format!(
            "no whole cgroup2 hierarchy in {SELF_MOUNTINFO}: {subtrees} cgroup2 mount(s) are \
             binds of a subtree, and a path from /proc/<pid>/cgroup does not resolve under one"
        ))),
        0 => Err(FerrumError::Degraded(format!(
            "no cgroup2 mount in {SELF_MOUNTINFO}: this node has no unified hierarchy, so no \
             cgroup inode can be computed for it"
        ))),
        1 => Ok(whole
            .iter()
            .map(|(_, point)| point)
            .min_by_key(|p| (p.as_os_str().len(), p.as_os_str().to_owned()))
            .cloned()
            .expect("one device means at least one mount point")),
        n => Err(FerrumError::Degraded(format!(
            "{n} distinct cgroup2 hierarchies in {SELF_MOUNTINFO} ({}): which one the datapath \
             keys on cannot be told from here, and picking wrong is indistinguishable from a \
             target that moved",
            whole
                .iter()
                .map(|(dev, p)| format!("{dev} at {}", p.display()))
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// mountinfo escapes space, tab, newline and backslash as three octal digits.
fn unescape_mount_point(raw: &str) -> String {
    if !raw.contains('\\') {
        return raw.to_string();
    }
    let bytes: Vec<char> = raw.chars().collect();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == '\\' && i + 3 < bytes.len() {
            let digits: String = bytes[i + 1..i + 4].iter().collect();
            if let Ok(code) = u8::from_str_radix(&digits, 8) {
                out.push(code as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// Marker file present only at the root of a cgroup v2 (unified) hierarchy.
const V2_MARKER: &str = "cgroup.controllers";

/// Depth below the root that still may hold a container cgroup. systemd nests
/// kubepods.slice/<qos>.slice/<pod>.slice/<container>.scope; nested containers
/// (kata, sysbox) add one more level.
const MAX_DEPTH: usize = 8;

/// Shortest accepted identifier: guards against matching `pod` or `cpu`.
const MIN_ID_LEN: usize = 8;

/// Container id prefix must be at least this long to be trusted for a
/// prefix-match against the runtime-reported id.
pub const MIN_ID_PREFIX_MATCH: usize = 12;

/// Injected stat: tests must not depend on the real inodes of a temp directory.
pub trait CgroupFs {
    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>>;
    fn inode(&self, path: &Path) -> io::Result<u64>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct StdCgroupFs;

impl CgroupFs for StdCgroupFs {
    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(path)? {
            out.push(entry?.path());
        }
        out.sort();
        Ok(out)
    }

    fn inode(&self, path: &Path) -> io::Result<u64> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(std::fs::metadata(path)?.ino())
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "cgroup inodes require unix",
            ))
        }
    }
}

/// One container cgroup directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupEntry {
    pub inode: u64,
    pub path: PathBuf,
    pub pod_uid: String,
    pub container_id: String,
}

/// Walk `root` and return every container cgroup directory found.
///
/// A missing v2 marker is `Degraded`, not an empty result: an empty index and
/// an unsupported hierarchy must not look the same to the caller.
pub fn scan(fs: &dyn CgroupFs, root: &Path) -> Result<Vec<CgroupEntry>> {
    let top = fs.read_dir(root).map_err(|e| {
        FerrumError::Degraded(format!("cgroup root {} unreadable: {e}", root.display()))
    })?;
    if !top.iter().any(|p| file_name(p) == V2_MARKER) {
        return Err(FerrumError::Degraded(format!(
            "cgroup v2 unified hierarchy not found at {}: no {V2_MARKER}; \
             cgroup v1 is not supported, pod identity would have to be guessed",
            root.display()
        )));
    }

    let mut out = Vec::new();
    let mut stack: Vec<(PathBuf, usize, bool)> = vec![(root.to_path_buf(), 0, false)];
    while let Some((dir, depth, seen_pod)) = stack.pop() {
        if depth >= MAX_DEPTH {
            continue;
        }
        // A regular file in the cgroup tree simply fails read_dir; skipping is
        // correct and keeps the trait to two calls.
        let Ok(children) = fs.read_dir(&dir) else {
            continue;
        };
        for child in children {
            let name = file_name(&child);
            if name.is_empty() {
                continue;
            }
            if seen_pod {
                if let Some(container_id) = parse_container_id(&name) {
                    match fs.inode(&child) {
                        Ok(inode) => {
                            out.push(CgroupEntry {
                                inode,
                                path: child.clone(),
                                pod_uid: current_pod_uid(&dir).unwrap_or_default(),
                                container_id,
                            });
                        }
                        Err(_) => continue,
                    }
                    continue;
                }
            }
            let child_seen_pod = seen_pod || parse_pod_uid(&name).is_some();
            stack.push((child, depth + 1, child_seen_pod));
        }
    }
    out.retain(|e| !e.pod_uid.is_empty());
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

/// Walk back up `dir` for the nearest component naming a pod.
fn current_pod_uid(dir: &Path) -> Option<String> {
    let mut cur = Some(dir);
    while let Some(p) = cur {
        if let Some(uid) = parse_pod_uid(&file_name(p)) {
            return Some(uid);
        }
        cur = p.parent();
    }
    None
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// `kubepods-burstable-pod<uid>.slice` (systemd, `-` escaped as `_`) or
/// `pod<uid>` (cgroupfs driver).
pub fn parse_pod_uid(component: &str) -> Option<String> {
    let name = component.strip_suffix(".slice").unwrap_or(component);
    if name.starts_with("kubepods") {
        let uid = name.rsplit_once("-pod").map(|(_, u)| u)?;
        return normalize_uid(uid);
    }
    if let Some(uid) = name.strip_prefix("pod") {
        return normalize_uid(uid);
    }
    None
}

fn normalize_uid(raw: &str) -> Option<String> {
    if raw.len() < MIN_ID_LEN || !raw.chars().all(is_uid_char) {
        return None;
    }
    // systemd escapes `-` to `_` inside unit names; the apiserver reports dashes.
    Some(raw.replace('_', "-").to_ascii_lowercase())
}

fn is_uid_char(c: char) -> bool {
    c.is_ascii_hexdigit() || c == '-' || c == '_'
}

/// `cri-containerd-<id>.scope`, `docker-<id>.scope`, `crio-<id>.scope`
/// (systemd) or a bare `<id>` directory (cgroupfs driver).
pub fn parse_container_id(component: &str) -> Option<String> {
    const PREFIXES: [&str; 5] = [
        "cri-containerd-",
        "containerd-",
        "cri-o-",
        "crio-",
        "docker-",
    ];
    if let Some(name) = component.strip_suffix(".scope") {
        for prefix in PREFIXES {
            if let Some(id) = name.strip_prefix(prefix) {
                return normalize_container_id(id);
            }
        }
        return None;
    }
    if component.contains('.') || component.starts_with("pod") {
        return None;
    }
    normalize_container_id(component)
}

fn normalize_container_id(raw: &str) -> Option<String> {
    // A bare cgroupfs directory is only a container when it is a full hash;
    // anything shorter is a QoS or slice directory.
    if raw.len() < 32 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(raw.to_ascii_lowercase())
}

/// Strip the CRI scheme (`containerd://`, `docker://`, `cri-o://`) the
/// apiserver reports in `status.containerStatuses[].containerID`.
pub fn strip_container_scheme(raw: &str) -> String {
    raw.rsplit_once("://")
        .map(|(_, id)| id)
        .unwrap_or(raw)
        .to_ascii_lowercase()
}

/// Runtime ids are full hashes; some drivers truncate the cgroup directory
/// name. Accept a prefix match only when it is long enough to be unambiguous.
pub fn container_id_matches(cgroup_id: &str, runtime_id: &str) -> bool {
    if cgroup_id.is_empty() || runtime_id.is_empty() {
        return false;
    }
    if cgroup_id == runtime_id {
        return true;
    }
    let (short, long) = if cgroup_id.len() < runtime_id.len() {
        (cgroup_id, runtime_id)
    } else {
        (runtime_id, cgroup_id)
    };
    short.len() >= MIN_ID_PREFIX_MATCH && long.starts_with(short)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The layout this defect was found on: `/sys/fs/cgroup` is a tmpfs of v1
    /// controller directories and cgroup2 is one level down. Every inode the
    /// datapath reports comes from `unified`; anything built on
    /// `DEFAULT_CGROUP_ROOT` here names a path that does not exist.
    #[test]
    fn hybrid_node_resolves_to_the_unified_mount_not_the_tmpfs() {
        let raw = "\
35 23 0:27 / /sys/fs/cgroup rw,relatime - tmpfs tmpfs rw
36 35 0:28 / /sys/fs/cgroup/cpu rw,relatime - cgroup cgroup rw,cpu
44 35 0:36 / /sys/fs/cgroup/systemd rw,relatime - cgroup cgroup rw,name=systemd
45 35 0:37 / /sys/fs/cgroup/unified rw,relatime - cgroup2 cgroup2 rw
";
        assert_eq!(
            cgroup2_root_from_mountinfo(raw).expect("hybrid node has one cgroup2 mount"),
            PathBuf::from("/sys/fs/cgroup/unified")
        );
    }

    #[test]
    fn unified_node_resolves_to_the_default_root() {
        let raw =
            "29 23 0:25 / /sys/fs/cgroup rw,nosuid,nodev,noexec - cgroup2 cgroup2 rw,nsdelegate\n";
        assert_eq!(
            cgroup2_root_from_mountinfo(raw).expect("unified node"),
            PathBuf::from(DEFAULT_CGROUP_ROOT)
        );
    }

    /// The rule the whole fix rests on: an answer the derivation cannot give
    /// must not come back as an answer. A silent fallback to
    /// `DEFAULT_CGROUP_ROOT` here is what turns "we do not know where cgroup2
    /// is" into "the target left its cgroup", which is a different claim
    /// entirely and the one that stops a node enforcing without saying so.
    #[test]
    fn an_ambiguous_or_absent_hierarchy_is_degraded_never_the_default() {
        // v1 only: no unified hierarchy at all.
        let v1 = "35 23 0:27 / /sys/fs/cgroup rw - tmpfs tmpfs rw\n\
36 35 0:28 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu\n";
        let err = cgroup2_root_from_mountinfo(v1).expect_err("no cgroup2");
        assert!(err.to_string().contains("no cgroup2 mount"), "{err}");

        // Two hierarchies on different superblocks: unknowable from here.
        let two = "29 23 0:25 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n\
45 35 0:37 / /run/other rw - cgroup2 cgroup2 rw\n";
        let err = cgroup2_root_from_mountinfo(two).expect_err("ambiguous");
        assert!(err.to_string().contains("2 distinct"), "{err}");

        // Only a bind of a subtree: a real cgroup2 mount and still the wrong
        // root, because /proc/<pid>/cgroup paths are whole-hierarchy paths.
        let sub = "45 35 0:37 /kubepods /run/kubepods rw - cgroup2 cgroup2 rw\n";
        let err = cgroup2_root_from_mountinfo(sub).expect_err("subtree bind");
        assert!(err.to_string().contains("binds of a subtree"), "{err}");

        // Nothing at all to read.
        assert!(cgroup2_root_from_mountinfo("").is_err());
    }

    /// Several mount points of one superblock are one hierarchy: the inodes
    /// agree whichever is used, so this is not ambiguity and must not degrade.
    #[test]
    fn several_views_of_one_hierarchy_pick_one_deterministically() {
        let raw = "29 23 0:25 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n\
88 23 0:25 / /run/host/sys/fs/cgroup rw - cgroup2 cgroup2 rw\n";
        assert_eq!(
            cgroup2_root_from_mountinfo(raw).expect("one hierarchy"),
            PathBuf::from("/sys/fs/cgroup")
        );
    }

    #[test]
    fn octal_escapes_in_the_mount_point_are_decoded() {
        let raw = "29 23 0:25 / /mnt/cgroup\\0402 rw - cgroup2 cgroup2 rw\n";
        assert_eq!(
            cgroup2_root_from_mountinfo(raw).expect("escaped point"),
            PathBuf::from("/mnt/cgroup 2")
        );
    }

    /// The node this ran on. Not an assertion about its layout — that is the
    /// host's business — but that the derivation answers the same question
    /// `scan` and the agent's target check ask, on whatever this node is.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_derivation_agrees_with_this_node_if_it_has_a_cgroup2_mount() {
        let Ok(root) = detect_cgroup2_root() else {
            // A node with no unified hierarchy is a legitimate answer here.
            return;
        };
        assert!(
            root.join(V2_MARKER).exists(),
            "derived cgroup2 root {} has no {V2_MARKER}: the derivation named a directory that \
             is not the root of a unified hierarchy",
            root.display()
        );
    }

    #[test]
    fn systemd_pod_slice_unescapes_uid() {
        assert_eq!(
            parse_pod_uid("kubepods-burstable-pod3f8a1b2c_4d5e_6f70_8192_a3b4c5d6e7f8.slice"),
            Some("3f8a1b2c-4d5e-6f70-8192-a3b4c5d6e7f8".into())
        );
        assert_eq!(
            parse_pod_uid("kubepods-pod3f8a1b2c_4d5e_6f70_8192_a3b4c5d6e7f8.slice"),
            Some("3f8a1b2c-4d5e-6f70-8192-a3b4c5d6e7f8".into())
        );
    }

    #[test]
    fn cgroupfs_pod_dir_and_non_pod_components() {
        assert_eq!(
            parse_pod_uid("pod3f8a1b2c-4d5e-6f70-8192-a3b4c5d6e7f8"),
            Some("3f8a1b2c-4d5e-6f70-8192-a3b4c5d6e7f8".into())
        );
        assert_eq!(parse_pod_uid("burstable"), None);
        assert_eq!(parse_pod_uid("kubepods.slice"), None);
        assert_eq!(parse_pod_uid("pod"), None);
    }

    #[test]
    fn container_scopes_and_bare_hashes() {
        let hash = "a".repeat(64);
        assert_eq!(
            parse_container_id(&format!("cri-containerd-{hash}.scope")),
            Some(hash.clone())
        );
        assert_eq!(
            parse_container_id(&format!("docker-{hash}.scope")),
            Some(hash.clone())
        );
        assert_eq!(parse_container_id(&hash), Some(hash.clone()));
        assert_eq!(parse_container_id("burstable"), None);
        assert_eq!(parse_container_id("cgroup.procs"), None);
    }

    #[test]
    fn scheme_stripped_and_prefix_match_bounded() {
        let hash = "b".repeat(64);
        assert_eq!(
            strip_container_scheme(&format!("containerd://{hash}")),
            hash
        );
        assert!(container_id_matches(&hash[..12], &hash));
        assert!(!container_id_matches(&hash[..8], &hash));
        assert!(!container_id_matches(&hash, &"c".repeat(64)));
    }
}
