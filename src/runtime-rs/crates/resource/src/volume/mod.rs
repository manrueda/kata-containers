// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

pub(crate) mod block_emptydir_volume;
mod block_volume;
mod default_volume;
mod ephemeral_volume;
pub mod hugepage;
mod local_volume;
mod share_fs_volume;
mod shm_volume;
pub mod utils;

pub mod direct_volume;
use crate::volume::{direct_volume::is_direct_volume, share_fs_volume::VolumeManager};
pub mod direct_volumes;

use std::{
    collections::HashMap,
    hash::Hash,
    sync::{Arc, Mutex},
    vec::Vec,
};

use self::hugepage::{get_huge_page_limits_map, get_huge_page_option};
use crate::{share_fs::ShareFs, volume::block_volume::is_block_volume};
use agent::Agent;
use anyhow::{Context, Result};
use async_trait::async_trait;
use hypervisor::device::device_manager::DeviceManager;
use kata_sys_util::{k8s::is_disk_empty_dir, mount::get_mount_options};
use oci_spec::runtime as oci;
use tokio::sync::{Notify, RwLock};

const BIND: &str = "bind";

type HandledVolume = (
    Arc<dyn Volume>,
    Option<block_emptydir_volume::EphemeralDiskInfo>,
);
type RollbackVolume = (
    Arc<dyn Volume>,
    Option<Arc<block_emptydir_volume::BlockEmptyDirVolume>>,
);

pub struct VolumeContext<'a> {
    pub share_fs: &'a Option<Arc<dyn ShareFs>>,
    pub d: &'a RwLock<DeviceManager>,
    pub sid: &'a str,
    pub agent: Arc<dyn Agent>,
    pub emptydir_mode: &'a str,
    pub fs_sharing_supported: bool,
    pub block_device_discard_supported: bool,
}

#[async_trait]
pub trait Volume: Send + Sync {
    fn get_volume_mount(&self) -> Result<Vec<oci::Mount>>;
    fn get_storage(&self) -> Result<Vec<agent::Storage>>;
    fn get_device_id(&self) -> Result<Option<String>>;
    async fn cleanup(&self, device_manager: &RwLock<DeviceManager>) -> Result<()>;
    async fn cleanup_after_vm_stop(&self, device_manager: &RwLock<DeviceManager>) -> Result<()> {
        let Some(device_id) = self.get_device_id()? else {
            return Err(anyhow::anyhow!(
                "non-device host cleanup remains pending after VM stop"
            ));
        };
        if device_manager.read().await.contains_device(&device_id) {
            device_manager
                .write()
                .await
                .release_block_device_after_vm_stop(&device_id)
                .await
                .with_context(|| {
                    format!("release volume device {device_id} after confirmed VM stop")
                })?;
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct VolumeResourceInner {
    volumes: Vec<Arc<dyn Volume>>,
    pending_rollback_volumes: Vec<Arc<dyn Volume>>,
}

#[derive(Default)]
struct EphemeralDiskStoreState {
    // Runtime acceptance is bounded at eight attached EmptyDirs, so a compact
    // Vec avoids a second allocation and hashing for this small ownership set.
    disks: Vec<block_emptydir_volume::EphemeralDiskInfo>,
    sealed: bool,
    active_setups: usize,
    next_tracking_id: u64,
    tracking_ids_exhausted: bool,
}

#[derive(Clone, Default)]
pub(crate) struct EphemeralDiskStore {
    state: Arc<Mutex<EphemeralDiskStoreState>>,
    setup_finished: Arc<Notify>,
}

#[derive(Clone)]
pub(crate) struct EphemeralDiskSetup {
    store: EphemeralDiskStore,
    _lease: Arc<EphemeralDiskSetupLease>,
}

struct EphemeralDiskSetupLease {
    store: EphemeralDiskStore,
}

impl EphemeralDiskStore {
    fn with_state<R>(&self, operation: impl FnOnce(&mut EphemeralDiskStoreState) -> R) -> R {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        operation(&mut state)
    }

    fn with_disks<R>(
        &self,
        operation: impl FnOnce(&mut Vec<block_emptydir_volume::EphemeralDiskInfo>) -> R,
    ) -> R {
        self.with_state(|state| operation(&mut state.disks))
    }

    pub(crate) fn begin_setup(&self) -> Result<EphemeralDiskSetup> {
        self.with_state(|state| {
            if state.sealed {
                return Err(anyhow::anyhow!(
                    "block EmptyDir ownership store is sealed for post-stop finalization"
                ));
            }
            state.active_setups += 1;
            Ok(EphemeralDiskSetup {
                store: self.clone(),
                _lease: Arc::new(EphemeralDiskSetupLease {
                    store: self.clone(),
                }),
            })
        })
    }

    async fn seal_and_wait(&self) {
        loop {
            let setup_finished = self.setup_finished.notified();
            let active_setups = self.with_state(|state| {
                state.sealed = true;
                state.active_setups
            });
            if active_setups == 0 {
                return;
            }
            setup_finished.await;
        }
    }

    #[cfg(test)]
    fn is_sealed(&self) -> bool {
        self.with_state(|state| state.sealed)
    }

    fn snapshot(&self) -> Vec<block_emptydir_volume::EphemeralDiskInfo> {
        self.with_disks(|disks| disks.clone())
    }

    fn update_discovered_device_id(&self, tracking_id: u64, device_id: String) {
        self.with_disks(|disks| {
            if let Some(disk) = disks
                .iter_mut()
                .find(|disk| disk.tracking_id == tracking_id)
            {
                disk.device_id = Some(device_id);
            }
        });
    }

    fn reconcile(
        &self,
        attempted: &[block_emptydir_volume::EphemeralDiskInfo],
        remaining: &[block_emptydir_volume::EphemeralDiskInfo],
    ) {
        self.with_disks(|disks| {
            reconcile_snapshot_occurrences(disks, attempted, remaining, |disk| disk.tracking_id)
        });
    }
}

impl EphemeralDiskSetup {
    pub(crate) fn allocate_tracking_id(&self) -> Result<u64> {
        self.store.with_state(|state| {
            if state.tracking_ids_exhausted {
                return Err(anyhow::anyhow!(
                    "block EmptyDir ownership tracking IDs exhausted"
                ));
            }
            let tracking_id = state.next_tracking_id;
            match tracking_id.checked_add(1) {
                Some(next_tracking_id) => state.next_tracking_id = next_tracking_id,
                None => state.tracking_ids_exhausted = true,
            }
            Ok(tracking_id)
        })
    }

    #[cfg(test)]
    fn set_next_tracking_id(&self, next_tracking_id: u64) {
        self.store.with_state(|state| {
            state.next_tracking_id = next_tracking_id;
            state.tracking_ids_exhausted = false;
        });
    }

    pub(crate) fn register(&self, disk: block_emptydir_volume::EphemeralDiskInfo) -> Result<()> {
        self.store.with_state(|state| {
            if state.sealed {
                return Err(anyhow::anyhow!(
                    "block EmptyDir ownership store was sealed before registration"
                ));
            }
            upsert_ephemeral_disk(&mut state.disks, disk);
            Ok(())
        })
    }

    pub(crate) fn preserve_for_cleanup(&self, disk: block_emptydir_volume::EphemeralDiskInfo) {
        self.store
            .with_disks(|disks| upsert_ephemeral_disk(disks, disk));
    }

    pub(crate) fn update_device_id(&self, tracking_id: u64, device_id: String) {
        self.store.with_disks(|disks| {
            let disk = disks
                .iter_mut()
                .find(|disk| disk.tracking_id == tracking_id)
                .expect("active block EmptyDir setup lost its ownership record");
            disk.device_id = Some(device_id);
        });
    }

    pub(crate) fn update_guest_stats_path(&self, tracking_id: u64, guest_stats_path: String) {
        self.store.with_disks(|disks| {
            let disk = disks
                .iter_mut()
                .find(|disk| disk.tracking_id == tracking_id)
                .expect("active block EmptyDir setup lost its ownership record");
            disk.guest_stats_path = guest_stats_path;
        });
    }

    pub(crate) fn refresh(&self, disk: block_emptydir_volume::EphemeralDiskInfo) {
        self.store.with_disks(|disks| {
            let existing = disks
                .iter_mut()
                .find(|existing| existing.tracking_id == disk.tracking_id)
                .expect("active block EmptyDir setup lost its ownership record");
            *existing = disk;
        });
    }

    pub(crate) fn remove(&self, tracking_id: u64) {
        self.store
            .with_disks(|disks| disks.retain(|disk| disk.tracking_id != tracking_id));
    }
}

impl Drop for EphemeralDiskSetupLease {
    fn drop(&mut self) {
        let remaining = self.store.with_state(|state| {
            state.active_setups = state
                .active_setups
                .checked_sub(1)
                .expect("block EmptyDir setup count underflow");
            state.active_setups
        });
        if remaining == 0 {
            self.store.setup_finished.notify_waiters();
        }
    }
}

fn upsert_ephemeral_disk(
    disks: &mut Vec<block_emptydir_volume::EphemeralDiskInfo>,
    disk: block_emptydir_volume::EphemeralDiskInfo,
) {
    if let Some(existing) = disks
        .iter_mut()
        .find(|existing| existing.tracking_id == disk.tracking_id)
    {
        *existing = disk;
    } else {
        disks.push(disk);
    }
}

#[derive(Default)]
pub struct VolumeResource {
    inner: Arc<RwLock<VolumeResourceInner>>,
    ephemeral_disks: EphemeralDiskStore,
    // The core purpose of introducing `volume_manager` to `VolumeResource` is to centralize the management of shared file system volumes.
    // By creating a single VolumeManager instance within VolumeResource, all shared file volumes are managed by one central entity.
    // This single volume_manager can accurately track the references of all ShareFsVolume instances to the shared volumes,
    // ensuring correct reference counting, proper volume lifecycle management, and preventing issues like volumes being overwritten.
    volume_manager: Arc<VolumeManager>,
}

impl VolumeResource {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(VolumeResourceInner::default())),
            ephemeral_disks: EphemeralDiskStore::default(),
            volume_manager: Arc::new(VolumeManager::new()),
        }
    }

    pub async fn handler_volumes(
        &self,
        ctx: &VolumeContext<'_>,
        cid: &str,
        spec: &oci::Spec,
    ) -> Result<Vec<Arc<dyn Volume>>> {
        let share_fs = ctx.share_fs;
        let d = ctx.d;
        let sid = ctx.sid;
        let emptydir_mode = ctx.emptydir_mode;
        let fs_sharing_supported = ctx.fs_sharing_supported;
        let mut volumes: Vec<Arc<dyn Volume>> = vec![];
        let mut block_emptydir_volumes: Vec<Arc<block_emptydir_volume::BlockEmptyDirVolume>> =
            Vec::new();
        let mut rollback_volumes: Vec<RollbackVolume> = Vec::new();
        let oci_mounts = &spec.mounts().clone().unwrap_or_default();
        let ownership_setup = oci_mounts
            .iter()
            .any(|mount| block_emptydir_volume::is_block_emptydir_volume(mount, emptydir_mode))
            .then(|| self.ephemeral_disks.begin_setup())
            .transpose()?;
        info!(sl!(), " oci mount is : {:?}", oci_mounts.clone());
        // handle mounts
        for (ordinal, m) in oci_mounts.iter().enumerate() {
            let read_only = get_mount_options(m.options()).iter().any(|opt| opt == "ro");
            let volume_result: Result<Option<HandledVolume>> = async {
                let result = if shm_volume::is_shm_volume(m) {
                    Some((
                        Arc::new(
                            shm_volume::ShmVolume::new(m)
                                .with_context(|| format!("new shm volume {m:?}"))?,
                        ) as Arc<dyn Volume>,
                        None,
                    ))
                } else if ephemeral_volume::is_ephemeral_volume(m) {
                    Some((
                        Arc::new(
                            ephemeral_volume::EphemeralVolume::new(m)
                                .with_context(|| format!("new ephemeral volume {m:?}"))?,
                        ) as Arc<dyn Volume>,
                        None,
                    ))
                } else if block_emptydir_volume::is_block_emptydir_volume(m, emptydir_mode) {
                    let volume = match block_emptydir_volume::BlockEmptyDirVolume::new(
                        d,
                        m,
                        sid,
                        emptydir_mode,
                        ctx.block_device_discard_supported,
                        ownership_setup
                            .as_ref()
                            .expect("block EmptyDir setup lease was not acquired"),
                    )
                    .await
                    {
                        Ok(volume) => volume,
                        Err(error) => {
                            return Err(error)
                                .with_context(|| format!("new block emptydir volume {m:?}"));
                        }
                    };
                    let disk_info = volume.disk_info.clone();
                    let volume = Arc::new(volume);
                    block_emptydir_volumes.push(volume.clone());
                    Some((volume as Arc<dyn Volume>, Some(disk_info)))
                } else if need_local_volume(m, fs_sharing_supported, emptydir_mode) {
                    // This branch comes after is_block_emptydir_volume() so
                    // block-encrypted and block-plain emptyDirs are handled as
                    // block devices before falling back to guest-local storage.
                    warn!(
                        sl!(),
                        "handling emptyDir as guest-local volume because fs sharing is unsupported; Kubelet cannot enforce sizeLimit-based eviction",
                    );
                    Some((
                        Arc::new(
                            local_volume::LocalStorage::new(m, sid, cid)
                                .with_context(|| format!("new local volume {m:?}"))?,
                        ) as Arc<dyn Volume>,
                        None,
                    ))
                } else if is_block_volume(m) {
                    Some((
                        Arc::new(
                            block_volume::BlockVolume::new(d, m, read_only, sid)
                                .await
                                .with_context(|| format!("new block volume {m:?}"))?,
                        ) as Arc<dyn Volume>,
                        None,
                    ))
                } else if is_direct_volume(m)? {
                    direct_volume::handle_direct_volume(d, m, read_only, sid)
                        .await
                        .context("handle direct volume")?
                        .map(|volume| (volume, None))
                } else if let Some(options) =
                    get_huge_page_option(m).context("failed to check huge page")?
                {
                    let hugepage_limits =
                        get_huge_page_limits_map(spec).context("get huge page option")?;
                    Some((
                        Arc::new(
                            hugepage::Hugepage::new(m, hugepage_limits, options)
                                .with_context(|| format!("handle hugepages {m:?}"))?,
                        ) as Arc<dyn Volume>,
                        None,
                    ))
                } else if share_fs_volume::is_share_fs_volume(m) {
                    Some((
                        Arc::new(
                            share_fs_volume::ShareFsVolume::new(
                                share_fs,
                                m,
                                cid,
                                read_only,
                                ctx.agent.clone(),
                                self.volume_manager.clone(),
                            )
                            .await
                            .with_context(|| format!("new share fs volume {m:?}"))?,
                        ) as Arc<dyn Volume>,
                        None,
                    ))
                } else if is_skip_volume(m) {
                    info!(sl!(), "skip volume {:?}", m);
                    None
                } else {
                    Some((
                        Arc::new(
                            default_volume::DefaultVolume::new(m)
                                .with_context(|| format!("new default volume {m:?}"))?,
                        ) as Arc<dyn Volume>,
                        None,
                    ))
                };

                Ok(result)
            }
            .await;

            match volume_result {
                Ok(Some((volume, disk_info))) => {
                    let rollback_block = disk_info
                        .as_ref()
                        .and_then(|_| block_emptydir_volumes.last().cloned());
                    rollback_volumes.push((volume.clone(), rollback_block));
                    volumes.push(volume);
                }
                Ok(None) => {}
                Err(error) => {
                    let error = error.context(format!(
                        "failed to attach volume {} of {}",
                        ordinal + 1,
                        oci_mounts.len()
                    ));
                    let attempted_disks = rollback_volumes
                        .iter()
                        .filter_map(|(_, volume)| {
                            volume.as_ref().map(|volume| volume.disk_info.clone())
                        })
                        .collect::<Vec<_>>();
                    let (error, unresolved_disks, failed_rollback_volumes) =
                        rollback_volume_sequence(error, &rollback_volumes, d).await;
                    for disk in &unresolved_disks {
                        ownership_setup
                            .as_ref()
                            .expect("block EmptyDir rollback lost its setup lease")
                            .refresh(disk.clone());
                    }
                    self.ephemeral_disks
                        .reconcile(&attempted_disks, &unresolved_disks);
                    if !failed_rollback_volumes.is_empty() {
                        let mut inner = self.inner.write().await;
                        inner
                            .pending_rollback_volumes
                            .extend(failed_rollback_volumes);
                    }
                    return Err(error);
                }
            }
        }

        let mut inner = self.inner.write().await;
        inner.volumes.extend(volumes.iter().cloned());

        Ok(volumes)
    }

    pub async fn detach_ephemeral_disks(
        &self,
        device_manager: &RwLock<DeviceManager>,
    ) -> Result<()> {
        let disks = self.ephemeral_disks.snapshot();
        let mut detach_errors = Vec::new();
        for disk in &disks {
            debug!(
                sl!(),
                "detaching block emptyDir device {:?}", disk.device_id
            );

            let device_id = match disk.device_id.clone() {
                Some(device_id) => Some(device_id),
                None => {
                    hypervisor::device::device_manager::find_device_id(
                        device_manager,
                        &disk.disk_path.display().to_string(),
                    )
                    .await
                }
            };
            if let Some(device_id) = device_id {
                self.ephemeral_disks
                    .update_discovered_device_id(disk.tracking_id, device_id.clone());
                let registered = device_manager.read().await.contains_device(&device_id);
                if registered {
                    if let Err(error) = device_manager
                        .write()
                        .await
                        .try_remove_device_with_outcome(&device_id)
                        .await
                    {
                        detach_errors.push(format!(
                            "detach block emptyDir device {device_id}: {error:#}"
                        ));
                    }
                }
            }
        }

        if detach_errors.is_empty() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(detach_errors.join("; ")))
        }
    }

    pub async fn finalize_ephemeral_disks(
        &self,
        device_manager: &RwLock<DeviceManager>,
    ) -> Result<()> {
        self.ephemeral_disks.seal_and_wait().await;
        loop {
            let disks = self.ephemeral_disks.snapshot();
            if disks.is_empty() {
                return Ok(());
            }

            let mut remaining = Vec::new();
            let mut cleanup_errors = Vec::new();
            for disk in &disks {
                let device_id = match disk.device_id.clone() {
                    Some(device_id) => Some(device_id),
                    None => {
                        hypervisor::device::device_manager::find_device_id(
                            device_manager,
                            &disk.disk_path.display().to_string(),
                        )
                        .await
                    }
                };
                if let Some(device_id) = device_id {
                    let registered = device_manager.read().await.contains_device(&device_id);
                    if registered {
                        if let Err(error) = device_manager
                            .write()
                            .await
                            .release_block_device_after_vm_stop(&device_id)
                            .await
                        {
                            cleanup_errors.push(format!(
                                "finalize block EmptyDir device {device_id}: {error:#}"
                            ));
                            remaining.push(disk.clone());
                            continue;
                        }
                    }
                }

                if let Err(error) = block_emptydir_volume::cleanup_owned_emptydir_artifacts(disk) {
                    cleanup_errors.push(format!(
                        "clean block EmptyDir artifacts for {}: {error:#}",
                        disk.source_path
                    ));
                    remaining.push(disk.clone());
                }
            }
            self.ephemeral_disks.reconcile(&disks, &remaining);

            if !cleanup_errors.is_empty() {
                return Err(anyhow::anyhow!(cleanup_errors.join("; ")));
            }
        }
    }

    pub async fn guest_volume_stats_path(&self, host_volume_path: &str) -> Option<String> {
        self.ephemeral_disks.with_disks(|disks| {
            disks.iter().rev().find_map(|disk| {
                (host_volume_path == disk.source_path
                    || host_volume_path == disk.disk_path.display().to_string())
                .then_some(disk.guest_stats_path.as_str())
                .filter(|guest_path| !guest_path.is_empty())
                .map(|guest_path| guest_path.to_string())
            })
        })
    }

    pub async fn retry_failed_rollbacks(
        &self,
        device_manager: &RwLock<DeviceManager>,
    ) -> Result<()> {
        let volumes = self.inner.read().await.pending_rollback_volumes.clone();
        let mut remaining = Vec::new();
        let mut errors = Vec::new();
        for volume in &volumes {
            if let Err(error) = volume.cleanup(device_manager).await {
                errors.push(format!("retry volume rollback cleanup: {error:#}"));
                remaining.push(volume.clone());
            }
        }
        reconcile_pending_rollbacks(
            &mut self.inner.write().await.pending_rollback_volumes,
            &volumes,
            &remaining,
        );
        if errors.is_empty() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(errors.join("; ")))
        }
    }

    pub async fn finalize_failed_rollbacks_after_vm_stop(
        &self,
        device_manager: &RwLock<DeviceManager>,
    ) -> Result<()> {
        let volumes = self.inner.read().await.pending_rollback_volumes.clone();
        let mut remaining = Vec::new();
        let mut errors = Vec::new();
        for volume in &volumes {
            if let Err(error) = volume.cleanup_after_vm_stop(device_manager).await {
                errors.push(format!("finalize failed volume rollback: {error:#}"));
                remaining.push(volume.clone());
            }
        }
        reconcile_pending_rollbacks(
            &mut self.inner.write().await.pending_rollback_volumes,
            &volumes,
            &remaining,
        );
        if errors.is_empty() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(errors.join("; ")))
        }
    }

    pub async fn guest_volume_stats_path(&self, host_volume_path: &str) -> Option<String> {
        let inner = self.inner.read().await;
        for disk in &inner.ephemeral_disks {
            if host_volume_path == disk.source_path
                || host_volume_path == disk.disk_path.display().to_string()
            {
                return Some(disk.guest_stats_path.clone());
            }
        }
        None
    }

    pub async fn dump(&self) {
        let inner = self.inner.read().await;
        for v in &inner.volumes {
            info!(
                sl!(),
                "volume mount {:?}: count {}",
                v.get_volume_mount(),
                Arc::strong_count(v)
            );
        }
    }
}

fn reconcile_pending_rollbacks(
    current: &mut Vec<Arc<dyn Volume>>,
    attempted: &[Arc<dyn Volume>],
    remaining: &[Arc<dyn Volume>],
) {
    reconcile_snapshot_occurrences(current, attempted, remaining, |volume| {
        Arc::as_ptr(volume) as *const ()
    });
}

fn reconcile_snapshot_occurrences<T, K, F>(
    current: &mut Vec<T>,
    attempted: &[T],
    remaining: &[T],
    identity: F,
) where
    K: Eq + Hash,
    F: Fn(&T) -> K,
{
    let mut successful = HashMap::<K, usize>::new();
    for item in attempted {
        *successful.entry(identity(item)).or_default() += 1;
    }
    for item in remaining {
        if let Some(count) = successful.get_mut(&identity(item)) {
            *count = count.saturating_sub(1);
        }
    }
    current.retain(|item| {
        let Some(count) = successful.get_mut(&identity(item)) else {
            return true;
        };
        if *count == 0 {
            true
        } else {
            *count -= 1;
            false
        }
    });
}

async fn rollback_volume_sequence(
    attach_error: anyhow::Error,
    volumes: &[RollbackVolume],
    device_manager: &RwLock<DeviceManager>,
) -> (
    anyhow::Error,
    Vec<block_emptydir_volume::EphemeralDiskInfo>,
    Vec<Arc<dyn Volume>>,
) {
    let mut rollback_errors = Vec::new();
    let mut unresolved_disks = Vec::new();
    let mut failed_rollback_volumes = Vec::new();

    for (volume, block_emptydir) in volumes.iter().rev() {
        let Some(block_emptydir) = block_emptydir else {
            if let Err(error) = volume.cleanup(device_manager).await {
                rollback_errors.push(format!("clean previously constructed volume: {error:#}"));
                failed_rollback_volumes.push(volume.clone());
            }
            continue;
        };
        let disk_info = block_emptydir.disk_info.clone();
        let device_id = disk_info
            .device_id
            .as_deref()
            .unwrap_or(&block_emptydir.device_id)
            .to_string();
        let removal = block_emptydir.cleanup_with_outcome(device_manager).await;
        let artifact_cleanup =
            block_emptydir_volume::cleanup_artifacts_after_device_removal(&disk_info, &removal);
        match removal {
            Ok(hypervisor::device::device_manager::DeviceRemoval::Detached) => {
                if let Err(error) = artifact_cleanup {
                    rollback_errors.push(format!(
                        "clean artifacts for {}: {error:#}",
                        disk_info.source_path
                    ));
                    unresolved_disks.push(disk_info);
                }
            }
            Ok(hypervisor::device::device_manager::DeviceRemoval::ReferenceReleased) => {
                if disk_info.disk_created || disk_info.metadata_created {
                    rollback_errors.push(format!(
                        "device {} still has active references; preserved artifacts for {}",
                        device_id, disk_info.source_path
                    ));
                    unresolved_disks.push(disk_info);
                }
            }
            Err(error) => {
                rollback_errors.push(format!(
                    "detach block emptyDir device {}: {error:#}",
                    device_id
                ));
                unresolved_disks.push(disk_info);
            }
        }
    }

    let error = if rollback_errors.is_empty() {
        attach_error.context(format!(
            "rolled back {} previously constructed volumes",
            volumes.len()
        ))
    } else {
        anyhow::anyhow!(
            "{attach_error:#}; volume rollback incomplete: {}",
            rollback_errors.join("; ")
        )
    };
    (error, unresolved_disks, failed_rollback_volumes)
}

/// Indicates whether a mount needs to be a local volume, i.e. created
/// inside the guest instead of being shared from the host.
///
/// This returns true when the hypervisor doesn't support fs sharing
/// (e.g. peer pods) and the mount is a non-block-based disk-backed
/// emptyDir.
///
/// Limitation: Local volumes cannot be managed by Kubelet and hence may
/// starve the host storage.
fn need_local_volume(m: &oci::Mount, fs_sharing_supported: bool, emptydir_mode: &str) -> bool {
    !fs_sharing_supported
        && !block_emptydir_volume::is_block_emptydir_mode(emptydir_mode)
        && m.source()
            .as_ref()
            .is_some_and(|src| is_disk_empty_dir(&src.display().to_string()))
}

fn is_skip_volume(_m: &oci::Mount) -> bool {
    // TODO: support volume check
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use hypervisor::{
        device::{device_manager::do_handle_device, DeviceConfig, DeviceType},
        BlockConfigModern, VIRTIO_BLOCK_PCI,
    };

    struct RetryVolume {
        name: &'static str,
        order: Arc<std::sync::Mutex<Vec<&'static str>>>,
        failures: std::sync::atomic::AtomicUsize,
    }

    struct LiveHypervisorCleanupVolume {
        vm_live: Arc<std::sync::atomic::AtomicBool>,
        failures: std::sync::atomic::AtomicUsize,
        device_id: Option<String>,
        post_stop_host_cleanup_pending: bool,
    }

    struct BlockingCleanupVolume {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        fail: bool,
    }

    #[async_trait]
    impl Volume for BlockingCleanupVolume {
        fn get_volume_mount(&self) -> Result<Vec<oci::Mount>> {
            Ok(Vec::new())
        }

        fn get_storage(&self) -> Result<Vec<agent::Storage>> {
            Ok(Vec::new())
        }

        fn get_device_id(&self) -> Result<Option<String>> {
            Ok(None)
        }

        async fn cleanup(&self, _device_manager: &RwLock<DeviceManager>) -> Result<()> {
            self.entered.notify_one();
            self.release.notified().await;
            if self.fail {
                Err(anyhow!("injected blocked cleanup failure"))
            } else {
                Ok(())
            }
        }

        async fn cleanup_after_vm_stop(
            &self,
            _device_manager: &RwLock<DeviceManager>,
        ) -> Result<()> {
            self.entered.notify_one();
            self.release.notified().await;
            if self.fail {
                Err(anyhow!("injected blocked cleanup failure"))
            } else {
                Ok(())
            }
        }
    }

    #[async_trait]
    impl Volume for LiveHypervisorCleanupVolume {
        fn get_volume_mount(&self) -> Result<Vec<oci::Mount>> {
            Ok(Vec::new())
        }

        fn get_storage(&self) -> Result<Vec<agent::Storage>> {
            Ok(Vec::new())
        }

        fn get_device_id(&self) -> Result<Option<String>> {
            Ok(self.device_id.clone())
        }

        async fn cleanup(&self, _device_manager: &RwLock<DeviceManager>) -> Result<()> {
            if !self.vm_live.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(anyhow!("normal cleanup called after hypervisor teardown"));
            }
            if self
                .failures
                .fetch_update(
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                    |failures| failures.checked_sub(1),
                )
                .is_ok()
            {
                return Err(anyhow!("injected live-hypervisor cleanup failure"));
            }
            Ok(())
        }

        async fn cleanup_after_vm_stop(
            &self,
            device_manager: &RwLock<DeviceManager>,
        ) -> Result<()> {
            if let Some(device_id) = self.device_id.as_deref() {
                if device_manager.read().await.contains_device(device_id) {
                    device_manager
                        .write()
                        .await
                        .release_block_device_after_vm_stop(device_id)
                        .await?;
                }
            }
            if self.post_stop_host_cleanup_pending {
                Err(anyhow!(
                    "non-device host cleanup remains pending after VM stop"
                ))
            } else {
                Ok(())
            }
        }
    }

    #[async_trait]
    impl Volume for RetryVolume {
        fn get_volume_mount(&self) -> Result<Vec<oci::Mount>> {
            Ok(Vec::new())
        }

        fn get_storage(&self) -> Result<Vec<agent::Storage>> {
            Ok(Vec::new())
        }

        fn get_device_id(&self) -> Result<Option<String>> {
            Ok(Some(format!("{}-device", self.name)))
        }

        async fn cleanup(&self, _device_manager: &RwLock<DeviceManager>) -> Result<()> {
            self.order.lock().unwrap().push(self.name);
            if self
                .failures
                .fetch_update(
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                    |failures| failures.checked_sub(1),
                )
                .is_ok()
            {
                Err(anyhow!("{} cleanup failed", self.name))
            } else {
                Ok(())
            }
        }
    }

    fn retry_volume(
        name: &'static str,
        order: &Arc<std::sync::Mutex<Vec<&'static str>>>,
        failures: usize,
    ) -> Arc<dyn Volume> {
        Arc::new(RetryVolume {
            name,
            order: order.clone(),
            failures: std::sync::atomic::AtomicUsize::new(failures),
        })
    }

    async fn assert_concurrent_same_arc_survives_snapshot(post_stop: bool) {
        let device_manager = Arc::new(RwLock::new(
            DeviceManager::new(Arc::new(hypervisor::firecracker::Firecracker::new()), None)
                .await
                .unwrap(),
        ));
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let volume: Arc<dyn Volume> = Arc::new(BlockingCleanupVolume {
            entered: entered.clone(),
            release: release.clone(),
            fail: false,
        });
        let resource = Arc::new(VolumeResource::new());
        resource
            .inner
            .write()
            .await
            .pending_rollback_volumes
            .push(volume.clone());

        let cleanup_resource = resource.clone();
        let cleanup_manager = device_manager.clone();
        let cleanup = tokio::spawn(async move {
            if post_stop {
                cleanup_resource
                    .finalize_failed_rollbacks_after_vm_stop(cleanup_manager.as_ref())
                    .await
            } else {
                cleanup_resource
                    .retry_failed_rollbacks(cleanup_manager.as_ref())
                    .await
            }
        });
        entered.notified().await;
        resource
            .inner
            .write()
            .await
            .pending_rollback_volumes
            .push(volume.clone());
        release.notify_one();
        cleanup.await.unwrap().unwrap();

        let pending = &resource.inner.read().await.pending_rollback_volumes;
        assert_eq!(pending.len(), 1);
        assert!(Arc::ptr_eq(&pending[0], &volume));
    }

    #[tokio::test]
    async fn mixed_volume_rollback_retries_failed_cleanup_in_reverse_order() {
        let device_manager = RwLock::new(
            DeviceManager::new(Arc::new(hypervisor::firecracker::Firecracker::new()), None)
                .await
                .unwrap(),
        );
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let direct = retry_volume("direct", &order, 0);
        let shared = retry_volume("shared", &order, 1);
        let default = retry_volume("default", &order, 0);
        let rollback = vec![(direct, None), (shared, None), (default, None)];

        let (error, unresolved, failed) =
            rollback_volume_sequence(anyhow!("later mount failed"), &rollback, &device_manager)
                .await;
        assert_eq!(
            order.lock().unwrap().as_slice(),
            ["default", "shared", "direct"]
        );
        assert!(format!("{error:#}").contains("shared cleanup failed"));
        assert!(unresolved.is_empty());
        assert_eq!(failed.len(), 1);
        assert_eq!(
            failed[0].get_device_id().unwrap().as_deref(),
            Some("shared-device")
        );

        let resource = VolumeResource::new();
        resource.inner.write().await.pending_rollback_volumes = failed;
        resource
            .retry_failed_rollbacks(&device_manager)
            .await
            .unwrap();
        assert_eq!(
            order.lock().unwrap().as_slice(),
            ["default", "shared", "direct", "shared"]
        );
        assert!(resource
            .inner
            .read()
            .await
            .pending_rollback_volumes
            .is_empty());
    }

    #[tokio::test]
    async fn failed_rollback_retries_while_hypervisor_is_live() {
        let device_manager = RwLock::new(
            DeviceManager::new(Arc::new(hypervisor::firecracker::Firecracker::new()), None)
                .await
                .unwrap(),
        );
        let vm_live = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let volume: Arc<dyn Volume> = Arc::new(LiveHypervisorCleanupVolume {
            vm_live: vm_live.clone(),
            failures: std::sync::atomic::AtomicUsize::new(1),
            device_id: None,
            post_stop_host_cleanup_pending: false,
        });
        let (_, _, failed) = rollback_volume_sequence(
            anyhow!("later mount failed"),
            &[(volume, None)],
            &device_manager,
        )
        .await;
        assert_eq!(failed.len(), 1);
        let resource = VolumeResource::new();
        resource.inner.write().await.pending_rollback_volumes = failed;

        resource
            .retry_failed_rollbacks(&device_manager)
            .await
            .unwrap();
        assert!(vm_live.load(std::sync::atomic::Ordering::SeqCst));
        assert!(resource
            .inner
            .read()
            .await
            .pending_rollback_volumes
            .is_empty());
    }

    #[tokio::test]
    async fn post_stop_finalization_releases_device_and_retains_host_cleanup() {
        let device_manager = RwLock::new(
            DeviceManager::new(Arc::new(hypervisor::firecracker::Firecracker::new()), None)
                .await
                .unwrap(),
        );
        let device = do_handle_device(
            &device_manager,
            &DeviceConfig::BlockCfgModern(BlockConfigModern {
                path_on_host: "/tmp/post-stop-retry.img".to_string(),
                driver_option: VIRTIO_BLOCK_PCI.to_string(),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        let device_id = match device {
            DeviceType::BlockModern(device) => device.lock().await.device_id.clone(),
            unexpected => panic!("expected BlockModern, got {:?}", unexpected),
        };
        let vm_live = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let volume: Arc<dyn Volume> = Arc::new(LiveHypervisorCleanupVolume {
            vm_live: vm_live.clone(),
            failures: std::sync::atomic::AtomicUsize::new(2),
            device_id: Some(device_id.clone()),
            post_stop_host_cleanup_pending: true,
        });
        let (_, _, failed) = rollback_volume_sequence(
            anyhow!("later mount failed"),
            &[(volume, None)],
            &device_manager,
        )
        .await;
        let resource = VolumeResource::new();
        resource.inner.write().await.pending_rollback_volumes = failed;

        assert!(resource
            .retry_failed_rollbacks(&device_manager)
            .await
            .is_err());
        vm_live.store(false, std::sync::atomic::Ordering::SeqCst);
        let error = resource
            .finalize_failed_rollbacks_after_vm_stop(&device_manager)
            .await
            .unwrap_err();

        assert!(format!("{error:#}").contains("host cleanup remains pending"));
        assert!(!device_manager.read().await.contains_device(&device_id));
        assert_eq!(
            resource.inner.read().await.pending_rollback_volumes.len(),
            1
        );
    }

    #[tokio::test]
    async fn block_emptydir_stats_prefer_newest_nonempty_mapping() {
        let volumes = VolumeResource::new();
        let make_disk = |guest_path: &str| block_emptydir_volume::EphemeralDiskInfo {
            tracking_id: 0,
            disk_path: std::path::PathBuf::from("/host/emptydir/disk.img"),
            source_path: "/host/emptydir".to_string(),
            guest_stats_path: guest_path.to_string(),
            disk_created: false,
            metadata_created: false,
            device_id: None,
        };
        volumes.ephemeral_disks.with_disks(|disks| {
            disks.extend([
                make_disk("/run/kata/older"),
                make_disk(""),
                make_disk("/run/kata/newest"),
            ])
        });

        assert_eq!(
            volumes
                .guest_volume_stats_path("/host/emptydir")
                .await
                .as_deref(),
            Some("/run/kata/newest")
        );
    }

    #[test]
    fn ephemeral_disk_store_updates_one_tracking_record() {
        let store = EphemeralDiskStore::default();
        let setup = store.begin_setup().unwrap();
        let mut disk = block_emptydir_volume::EphemeralDiskInfo {
            tracking_id: 7,
            disk_path: std::path::PathBuf::from("/host/emptydir/disk.img"),
            source_path: "/host/emptydir".to_string(),
            guest_stats_path: String::new(),
            disk_created: true,
            metadata_created: true,
            device_id: None,
        };
        setup.register(disk.clone()).unwrap();
        setup.update_device_id(disk.tracking_id, "device-id".to_string());
        disk.device_id = Some("device-id".to_string());
        disk.guest_stats_path = "/run/kata/emptydir".to_string();
        setup.register(disk.clone()).unwrap();

        assert_eq!(store.snapshot().len(), 1);
        assert_eq!(store.snapshot()[0].guest_stats_path, disk.guest_stats_path);
    }

    #[tokio::test]
    async fn retry_failed_rollbacks_preserves_concurrent_addition() {
        let device_manager = Arc::new(RwLock::new(
            DeviceManager::new(Arc::new(hypervisor::firecracker::Firecracker::new()), None)
                .await
                .unwrap(),
        ));
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let original: Arc<dyn Volume> = Arc::new(BlockingCleanupVolume {
            entered: entered.clone(),
            release: release.clone(),
            fail: true,
        });
        let concurrent = retry_volume(
            "concurrent",
            &Arc::new(std::sync::Mutex::new(Vec::new())),
            0,
        );
        let resource = Arc::new(VolumeResource::new());
        resource
            .inner
            .write()
            .await
            .pending_rollback_volumes
            .push(original.clone());

        let cleanup_resource = resource.clone();
        let cleanup_manager = device_manager.clone();
        let cleanup = tokio::spawn(async move {
            cleanup_resource
                .retry_failed_rollbacks(cleanup_manager.as_ref())
                .await
        });
        entered.notified().await;
        resource
            .inner
            .write()
            .await
            .pending_rollback_volumes
            .push(concurrent.clone());
        release.notify_one();
        cleanup.await.unwrap().unwrap_err();

        let pending = &resource.inner.read().await.pending_rollback_volumes;
        assert_eq!(pending.len(), 2);
        assert!(pending.iter().any(|volume| Arc::ptr_eq(volume, &original)));
        assert!(pending
            .iter()
            .any(|volume| Arc::ptr_eq(volume, &concurrent)));
    }

    #[tokio::test]
    async fn retry_failed_rollbacks_preserves_concurrent_same_arc() {
        assert_concurrent_same_arc_survives_snapshot(false).await;
    }

    #[tokio::test]
    async fn post_stop_rollbacks_preserve_concurrent_same_arc() {
        assert_concurrent_same_arc_survives_snapshot(true).await;
    }

    #[tokio::test]
    async fn retry_failed_rollbacks_reconciles_duplicate_multiplicity() {
        let device_manager = RwLock::new(
            DeviceManager::new(Arc::new(hypervisor::firecracker::Firecracker::new()), None)
                .await
                .unwrap(),
        );
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let volume = retry_volume("duplicate", &order, 1);
        let resource = VolumeResource::new();
        resource
            .inner
            .write()
            .await
            .pending_rollback_volumes
            .extend([volume.clone(), volume.clone()]);

        assert!(resource
            .retry_failed_rollbacks(&device_manager)
            .await
            .is_err());
        assert_eq!(
            resource.inner.read().await.pending_rollback_volumes.len(),
            1
        );

        resource
            .retry_failed_rollbacks(&device_manager)
            .await
            .unwrap();
        assert!(resource
            .inner
            .read()
            .await
            .pending_rollback_volumes
            .is_empty());
    }

    #[tokio::test]
    async fn post_stop_rollbacks_preserve_concurrent_addition() {
        let device_manager = Arc::new(RwLock::new(
            DeviceManager::new(Arc::new(hypervisor::firecracker::Firecracker::new()), None)
                .await
                .unwrap(),
        ));
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let original: Arc<dyn Volume> = Arc::new(BlockingCleanupVolume {
            entered: entered.clone(),
            release: release.clone(),
            fail: true,
        });
        let concurrent = retry_volume(
            "concurrent",
            &Arc::new(std::sync::Mutex::new(Vec::new())),
            0,
        );
        let resource = Arc::new(VolumeResource::new());
        resource
            .inner
            .write()
            .await
            .pending_rollback_volumes
            .push(original.clone());

        let cleanup_resource = resource.clone();
        let cleanup_manager = device_manager.clone();
        let cleanup = tokio::spawn(async move {
            cleanup_resource
                .finalize_failed_rollbacks_after_vm_stop(cleanup_manager.as_ref())
                .await
        });
        entered.notified().await;
        resource
            .inner
            .write()
            .await
            .pending_rollback_volumes
            .push(concurrent.clone());
        release.notify_one();
        cleanup.await.unwrap().unwrap_err();

        let pending = &resource.inner.read().await.pending_rollback_volumes;
        assert_eq!(pending.len(), 2);
        assert!(pending.iter().any(|volume| Arc::ptr_eq(volume, &original)));
        assert!(pending
            .iter()
            .any(|volume| Arc::ptr_eq(volume, &concurrent)));
    }

    #[tokio::test]
    async fn registered_setup_blocks_finalization_and_late_registration() {
        let device_manager = Arc::new(RwLock::new(
            DeviceManager::new(Arc::new(hypervisor::firecracker::Firecracker::new()), None)
                .await
                .unwrap(),
        ));
        let device = do_handle_device(
            device_manager.as_ref(),
            &DeviceConfig::BlockCfgModern(BlockConfigModern {
                path_on_host: "/tmp/blocked-finalization.img".to_string(),
                driver_option: VIRTIO_BLOCK_PCI.to_string(),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        let DeviceType::BlockModern(block) = device else {
            panic!("expected BlockModern device");
        };
        let device_id = block.lock().await.device_id.clone();
        let original = block_emptydir_volume::EphemeralDiskInfo {
            tracking_id: 1,
            disk_path: std::path::PathBuf::from("/tmp/blocked-finalization.img"),
            source_path: "/tmp/original".to_string(),
            guest_stats_path: String::new(),
            disk_created: false,
            metadata_created: false,
            device_id: Some(device_id),
        };
        let concurrent = block_emptydir_volume::EphemeralDiskInfo {
            tracking_id: 2,
            disk_path: std::path::PathBuf::from("/tmp/concurrent-finalization.img"),
            source_path: "/tmp/concurrent".to_string(),
            guest_stats_path: String::new(),
            disk_created: false,
            metadata_created: false,
            device_id: None,
        };
        let resource = Arc::new(VolumeResource::new());
        let registered = resource.ephemeral_disks.begin_setup().unwrap();
        registered.register(original).unwrap();
        let racing = resource.ephemeral_disks.begin_setup().unwrap();

        let block_guard = block.lock().await;
        let cleanup_resource = resource.clone();
        let cleanup_manager = device_manager.clone();
        let cleanup = tokio::spawn(async move {
            cleanup_resource
                .finalize_ephemeral_disks(cleanup_manager.as_ref())
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !resource.ephemeral_disks.is_sealed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("finalization never sealed ownership");
        assert!(racing.register(concurrent).is_err());
        assert!(resource.ephemeral_disks.begin_setup().is_err());
        registered.update_device_id(1, block_guard.device_id.clone());
        drop(racing);
        drop(registered);
        drop(block_guard);
        cleanup.await.unwrap().unwrap();

        assert!(resource.ephemeral_disks.snapshot().is_empty());
    }

    #[tokio::test]
    async fn finalization_drains_duplicate_records() {
        let temp_dir = tempfile::tempdir().unwrap();
        let disk_path = temp_dir.path().join("duplicate.img");
        std::fs::write(&disk_path, b"owned").unwrap();
        let resource = VolumeResource::new();
        for tracking_id in [1, 2] {
            let setup = resource.ephemeral_disks.begin_setup().unwrap();
            setup
                .register(block_emptydir_volume::EphemeralDiskInfo {
                    tracking_id,
                    disk_path: disk_path.clone(),
                    source_path: temp_dir.path().display().to_string(),
                    guest_stats_path: String::new(),
                    disk_created: true,
                    metadata_created: false,
                    device_id: None,
                })
                .unwrap();
        }
        let device_manager = RwLock::new(
            DeviceManager::new(Arc::new(hypervisor::firecracker::Firecracker::new()), None)
                .await
                .unwrap(),
        );

        resource
            .finalize_ephemeral_disks(&device_manager)
            .await
            .unwrap();

        assert!(!disk_path.exists());
        assert!(resource.ephemeral_disks.snapshot().is_empty());
    }

    #[tokio::test]
    async fn failed_finalization_retains_ownership_for_second_retry() {
        let temp_dir = tempfile::tempdir().unwrap();
        let disk_path = temp_dir.path().join("disk.img");
        std::fs::create_dir(&disk_path).unwrap();
        let resource = VolumeResource::new();
        let setup = resource.ephemeral_disks.begin_setup().unwrap();
        setup
            .register(block_emptydir_volume::EphemeralDiskInfo {
                tracking_id: 1,
                disk_path: disk_path.clone(),
                source_path: temp_dir.path().display().to_string(),
                guest_stats_path: String::new(),
                disk_created: true,
                metadata_created: false,
                device_id: None,
            })
            .unwrap();
        drop(setup);
        let device_manager = RwLock::new(
            DeviceManager::new(Arc::new(hypervisor::firecracker::Firecracker::new()), None)
                .await
                .unwrap(),
        );

        assert!(resource
            .finalize_ephemeral_disks(&device_manager)
            .await
            .is_err());
        assert_eq!(resource.ephemeral_disks.snapshot().len(), 1);

        std::fs::remove_dir(&disk_path).unwrap();
        std::fs::write(&disk_path, b"owned").unwrap();
        resource
            .finalize_ephemeral_disks(&device_manager)
            .await
            .unwrap();
        assert!(!disk_path.exists());
        assert!(resource.ephemeral_disks.snapshot().is_empty());
    }
}
