//! Pins, in a real kernel.
//!
//! `tests/attach_live.rs` proves the datapath writes records this userspace can
//! read. This one proves the objects it writes them through can be made to
//! outlive the process that loaded them, which is the whole of what a pin is
//! for and the thing the rest of the Tampering row of RFC-02 §C is *about*:
//! there is nothing for an LSM to protect, and nothing for a watcher to find
//! missing, until something is pinned.
//!
//! The load-bearing assertion is the one that cannot be made by reading code:
//! after the `KernelHandle` is dropped, the pinned link and the pinned maps are
//! still there and still resolve to kernel objects. Everything else in this
//! file is about the refusals, and they are here for a specific reason — a pin
//! that fails must not cost a hook. Taking a link out of a program detaches it,
//! so `pin_at` is written to put it back, and "the handle still pins after a
//! refused pin" is the only way to show that it did.
//!
//! Needs CAP_BPF/root, tracefs, and a writable bpffs at `FERRUM_BPF_PIN_ROOT`.
//! `FERRUM_BPF_ELF_REQUIRED` turns every skip below into a failure, for the
//! reason spelled out at length in `attach_live.rs`: a gate that can decline to
//! run is a gate that reports green having measured nothing.

/// The gate, compiled out.
///
/// Same shape and same reason as `attach_live.rs`: without `--features attach`
/// every test below disappears and the binary exits 0 having run nothing, and
/// no assertion inside the `cfg` can say so.
#[cfg(not(feature = "attach"))]
#[test]
fn the_gate_must_not_be_compiled_out() {
    assert!(
        std::env::var_os("FERRUM_BPF_ELF_REQUIRED").is_none(),
        "FERRUM_BPF_ELF_REQUIRED is set, but this binary was built without \
         --features attach: every kernel test in attach_pins.rs is compiled out, \
         so this run pinned nothing and proves nothing about pins. Add --features attach."
    );
}

#[cfg(feature = "attach")]
mod gate {
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use aya::maps::MapData;
    use aya::programs::links::PinnedLink;
    use ferrum_ebpf::{KernelHandle, MAP_CGROUPS, MAP_EVENTS, MAP_SELF};

    /// One attach at a time. Two live handles would load the same programs
    /// twice and race on the same pin paths, and the failure would read as a
    /// pin defect rather than as two tests sharing a kernel.
    fn serialized() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|err| err.into_inner())
    }

    fn required() -> bool {
        std::env::var_os("FERRUM_BPF_ELF_REQUIRED").is_some()
    }

    fn elf_or_skip() -> Option<Vec<u8>> {
        let Ok(path) = std::env::var("FERRUM_BPF_ELF") else {
            if required() {
                panic!("FERRUM_BPF_ELF_REQUIRED is set but FERRUM_BPF_ELF is not");
            }
            println!("skipping: FERRUM_BPF_ELF not set (no compiled bpf ELF to pin)");
            return None;
        };
        Some(std::fs::read(&path).unwrap_or_else(|err| panic!("read {path}: {err}")))
    }

    /// A bpffs directory this test may create under.
    ///
    /// Read from the environment rather than hardcoded to `PIN_PATH`: the
    /// production path is where the *agent* pins, and a test that pinned there
    /// would be indistinguishable from an agent that had, which is exactly the
    /// confusion `pin_at` refuses to make on its own behalf.
    fn pin_root_or_skip(tag: &str) -> Option<PathBuf> {
        let Ok(root) = std::env::var("FERRUM_BPF_PIN_ROOT") else {
            if required() {
                panic!(
                    "FERRUM_BPF_ELF_REQUIRED is set but FERRUM_BPF_PIN_ROOT is not: there is no \
                     bpffs to pin on, so this run would prove nothing about pins"
                );
            }
            println!("skipping: FERRUM_BPF_PIN_ROOT not set (no bpffs to pin on)");
            return None;
        };
        Some(Path::new(&root).join(format!("ferrum-{}-{}", tag, std::process::id())))
    }

    fn attach_or_skip() -> Option<KernelHandle> {
        let elf = elf_or_skip()?;
        match KernelHandle::attach(&elf) {
            Ok(handle) => Some(handle),
            Err(err) => panic!("attach failed, so nothing here could pin: {err}"),
        }
    }

    /// Remove every pin under `root` and the directories themselves.
    ///
    /// Not tidiness: a pinned link keeps its program attached for as long as
    /// the pin exists, so a test that left one behind would leave this node
    /// running a datapath nobody owns for the rest of the build.
    fn unpin_all(root: &Path) {
        for dir in ["links", "maps"] {
            let dir = root.join(dir);
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
            let _ = std::fs::remove_dir(&dir);
        }
        let _ = std::fs::remove_dir(root);
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap_or_else(|err| panic!("read_dir {}: {err}", dir.display()))
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// The claim: pinned objects outlive the handle that made them.
    ///
    /// The drop is the point. Before it, every path could be explained by the
    /// live handle still holding the fds; after it, nothing in this process
    /// holds anything, and the objects are still there because bpffs is holding
    /// them. That is the difference between a datapath that survives the agent
    /// and one that dies with it — and until this test there was no pin in this
    /// tree at all, so the difference did not exist.
    #[test]
    fn pins_are_kernel_objects_that_outlive_the_handle() {
        let _serial = serialized();
        let Some(root) = pin_root_or_skip("outlive") else {
            return;
        };
        unpin_all(&root);
        let Some(mut handle) = attach_or_skip() else {
            return;
        };

        let pinned = handle
            .pin_at(&root)
            .unwrap_or_else(|err| panic!("pin at {}: {err}", root.display()));
        assert!(
            pinned.len() > 3,
            "pinned only {:?}: three maps and at least one link were expected",
            pinned
        );
        assert_eq!(
            entries(&root.join("maps")),
            {
                let mut want = vec![
                    MAP_CGROUPS.to_string(),
                    MAP_EVENTS.to_string(),
                    MAP_SELF.to_string(),
                ];
                want.sort();
                want
            },
            "the pinned maps are not the three this userspace binds against"
        );
        let links = entries(&root.join("links"));
        assert!(!links.is_empty(), "no link was pinned");

        // The handle goes away. Nothing in this process holds the programs,
        // the maps or the attachments any more.
        drop(handle);

        for name in entries(&root.join("maps")) {
            let path = root.join("maps").join(&name);
            MapData::from_pin(&path).unwrap_or_else(|err| {
                panic!(
                    "map pin {} does not resolve after the handle was dropped: {err}",
                    path.display()
                )
            });
        }
        for name in &links {
            let path = root.join("links").join(name);
            PinnedLink::from_pin(&path).unwrap_or_else(|err| {
                panic!(
                    "link pin {} does not resolve after the handle was dropped, so the \
                     attachment did not outlive the process: {err}",
                    path.display()
                )
            });
        }
        println!(
            "pins outlived the handle: {} maps, {} links under {}",
            3,
            links.len(),
            root.display()
        );

        unpin_all(&root);
        assert!(
            !root.exists(),
            "{} survived unpinning, so this node keeps a datapath nobody owns",
            root.display()
        );
    }

    /// A refused pin must cost nothing that was running.
    ///
    /// `pin_at` takes each link out of its program before handing it to bpffs,
    /// and a link that is out and not pinned is a hook that is off. The refusal
    /// path is therefore not a message but a repair, and the only way to show
    /// the repair happened is to pin successfully afterwards with the same
    /// handle: if the first refusal had eaten the links, this would find
    /// nothing left to pin.
    #[test]
    fn a_pin_root_that_is_not_bpffs_is_refused_and_leaves_no_tree() {
        let _serial = serialized();
        let Some(root) = pin_root_or_skip("refused") else {
            return;
        };
        unpin_all(&root);
        let Some(mut handle) = attach_or_skip() else {
            return;
        };

        let ordinary =
            std::env::temp_dir().join(format!("ferrum-not-bpffs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ordinary);
        let err = handle
            .pin_at(&ordinary)
            .expect_err("pinning onto an ordinary directory reported success");
        let err = err.to_string();
        assert!(
            err.contains("bpffs"),
            "the refusal does not say what is wrong with the path: {err}"
        );
        assert!(
            !ordinary.exists(),
            "{} was left behind: a tree that looks like a pin path and holds nothing",
            ordinary.display()
        );

        let pinned = handle.pin_at(&root).unwrap_or_else(|err| {
            panic!(
                "the refused pin cost this handle its links; the second pin found nothing to \
                 pin: {err}"
            )
        });
        assert!(pinned.len() > 3, "pinned only {pinned:?} after the refusal");
        unpin_all(&root);
    }

    /// An occupied pin path is refused, not adopted.
    ///
    /// From inside this process a pin left by a previous instance and a pin
    /// somebody else planted are the same file. Adopting it is how a tampered
    /// pin path becomes the one enforcement runs from, so `pin_at` refuses and
    /// names the path instead.
    #[test]
    fn a_pin_path_already_taken_is_refused_rather_than_adopted() {
        let _serial = serialized();
        let Some(root) = pin_root_or_skip("taken") else {
            return;
        };
        unpin_all(&root);
        let Some(mut handle) = attach_or_skip() else {
            return;
        };

        handle
            .pin_at(&root)
            .unwrap_or_else(|err| panic!("first pin: {err}"));
        let err = handle
            .pin_at(&root)
            .expect_err("pinning over an existing pin reported success")
            .to_string();
        assert!(
            err.contains("already pinned"),
            "the refusal does not name the collision: {err}"
        );
        unpin_all(&root);
    }
}
