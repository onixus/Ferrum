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
