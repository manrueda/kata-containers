// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{fs::File, os::unix::io::AsRawFd};

use anyhow::{Context, Result};
use nix::sched::{setns, CloneFlags};
use nix::unistd::{getpid, gettid};
use rand::rng as thread_rng;
use rand::RngExt;

use kata_types::sl;

pub struct NetnsGuard {
    old_netns: Option<File>,
}

impl NetnsGuard {
    pub fn new(new_netns_path: &str) -> Result<Self> {
        if new_netns_path.is_empty() {
            warn!(sl!(), "skip to set netns for empty netns path");
            return Ok(Self { old_netns: None });
        }

        let new_netns = File::open(new_netns_path)
            .with_context(|| format!("open new netns path {}", &new_netns_path))?;
        Self::from_file(&new_netns)
    }

    /// Enter a network namespace through an already-open file descriptor.
    ///
    /// The caller may retain this descriptor even after the procfs path used
    /// to open it disappears, for example when the namespace belongs to a
    /// thread that has exited.
    pub fn from_file(new_netns: &File) -> Result<Self> {
        let current_netns_path = format!("/proc/{}/task/{}/ns/{}", getpid(), gettid(), "net");
        let old_netns = File::open(&current_netns_path)
            .with_context(|| format!("open current netns path {}", &current_netns_path))?;

        setns(new_netns, CloneFlags::CLONE_NEWNET).context("set netns to new netns")?;
        info!(
            sl!(),
            "set netns from old {:?} to new {:?} tid {}",
            old_netns,
            new_netns,
            gettid().to_string()
        );

        Ok(Self {
            old_netns: Some(old_netns),
        })
    }
}

impl Drop for NetnsGuard {
    fn drop(&mut self) {
        if let Some(old_netns) = self.old_netns.as_ref() {
            setns(old_netns, CloneFlags::CLONE_NEWNET).unwrap();
            info!(sl!(), "set netns to old {:?}", old_netns.as_raw_fd());
        }
    }
}

// generate the network namespace name
pub fn generate_netns_name() -> String {
    let mut rng = thread_rng();
    let random_bytes: [u8; 16] = rng.random();
    format!(
        "cnitest-{}-{}-{}-{}-{}",
        hex::encode(&random_bytes[..4]),
        hex::encode(&random_bytes[4..6]),
        hex::encode(&random_bytes[6..8]),
        hex::encode(&random_bytes[8..10]),
        hex::encode(&random_bytes[10..])
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_utils::skip_if_not_root;

    #[test]
    fn test_new_netns_guard() {
        // test run under root
        skip_if_not_root!();

        let new_netns_path = "/proc/1/task/1/ns/net"; // systemd, always exists
        let netns_guard = NetnsGuard::new(new_netns_path).unwrap();
        drop(netns_guard);

        let empty_path = "";
        assert!(NetnsGuard::new(empty_path).unwrap().old_netns.is_none());
    }

    #[test]
    fn test_netns_guard_from_file_after_thread_exit() {
        // setns requires root even when entering the current namespace.
        skip_if_not_root!();

        let (sender, receiver) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let tid = gettid();
            let path = format!("/proc/{}/task/{}/ns/net", getpid(), tid);
            let netns = File::open(&path).unwrap();
            sender.send((netns, path)).unwrap();
        });

        let (netns, path) = receiver.recv().unwrap();
        thread.join().unwrap();
        assert!(
            !std::path::Path::new(&path).exists(),
            "thread namespace path should disappear after thread exit"
        );

        let netns_guard = NetnsGuard::from_file(&netns).unwrap();
        drop(netns_guard);
    }

    #[test]
    fn test_generate_netns_name() {
        let name1 = generate_netns_name();
        let name2 = generate_netns_name();
        let name3 = generate_netns_name();
        assert_ne!(name1, name2);
        assert_ne!(name2, name3);
        assert_ne!(name1, name3);
    }
}
