// Copyright (c) 2026 NVIDIA Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Weak};

use super::{EphemeralDiskSetup, Volume};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
#[cfg(test)]
use hypervisor::device::device_manager::do_handle_device;
use hypervisor::{
    device::{
        device_manager::{
            find_device_id, get_block_device_info, get_machine_type, DeviceManager, DeviceRemoval,
        },
        device_state_in_doubt,
        topology::PCIeTopology,
        DeviceConfig, DeviceType,
    },
    qemu::supports_pcie_root_ports,
    BlockConfigModern, BlockDeviceAio, HYPERVISOR_QEMU,
};
use kata_sys_util::k8s::is_disk_empty_dir;
use kata_types::config::hypervisor::VIRTIO_BLK_PCI;
use kata_types::config::{EMPTYDIR_MODE_BLOCK_ENCRYPTED, EMPTYDIR_MODE_BLOCK_PLAIN};
use kata_types::mount::{
    add_volume_mount_info, is_volume_mounted, join_path, kata_direct_volume_root_path,
    DirectVolumeMountInfo, DEFAULT_KATA_GUEST_SANDBOX_DIR, KATA_BLOCK_VOLUME_CREATE_FS,
};
use nix::fcntl::{Flock, FlockArg};
use nix::sys::statfs::statfs;
use oci_spec::runtime as oci;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard, RwLock};

use crate::volume::utils::KATA_MOUNT_BIND_TYPE;

const DISK_IMG: &str = "disk.img";
const ENCRYPTION_KEY_DRIVER_OPTION: &str = "encryption_key";
const ENCRYPTION_KEY_VALUE: &str = "ephemeral";
const METADATA_CREATE_FILESYSTEM: &str = "createFilesystem";
const METADATA_ENCRYPTION_KEY: &str = "encryptionKey";
const METADATA_FS_GROUP: &str = "fsGroup";
const DISCARD_MOUNT_OPTION: &str = "discard";
const SETUP_LOCK_FILE: &str = ".kata-block-emptydir.lock";
static ACTIVE_SETUP_TRANSACTIONS: LazyLock<
    std::sync::Mutex<HashMap<String, Weak<AsyncMutex<()>>>>,
> = LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));
#[cfg(test)]
static ARTIFACT_PREPARATION_GATES: LazyLock<
    std::sync::Mutex<HashMap<String, Arc<ArtifactPreparationGate>>>,
> = LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

#[cfg(test)]
#[derive(Default)]
struct ArtifactPreparationGate {
    state: std::sync::Mutex<ArtifactPreparationGateState>,
    changed: std::sync::Condvar,
}

#[cfg(test)]
#[derive(Default)]
struct ArtifactPreparationGateState {
    entered: bool,
    released: bool,
    fail_cleanup: bool,
}

#[cfg(test)]
impl ArtifactPreparationGate {
    fn wait_until_entered(&self) {
        let mut state = self.state.lock().unwrap();
        while !state.entered {
            state = self.changed.wait(state).unwrap();
        }
    }

    fn release(&self) {
        let mut state = self.state.lock().unwrap();
        state.released = true;
        self.changed.notify_all();
    }

    fn set_fail_cleanup(&self, fail_cleanup: bool) {
        self.state.lock().unwrap().fail_cleanup = fail_cleanup;
    }

    fn fail_cleanup(&self) -> bool {
        self.state.lock().unwrap().fail_cleanup
    }
}

/// Information about an ephemeral disk created on the host, needed for
/// sandbox-level cleanup and volume statistics mapping.
#[derive(Debug, Clone)]
pub(crate) struct EphemeralDiskInfo {
    pub tracking_id: u64,
    pub disk_path: PathBuf,
    pub source_path: String,
    /// Guest path passed to the agent for volume statistics queries.
    pub guest_stats_path: String,
    pub disk_created: bool,
    pub metadata_created: bool,
    pub device_id: Option<String>,
}

impl EphemeralDiskInfo {
    fn owns_artifacts(&self) -> bool {
        self.disk_created || self.metadata_created
    }
}

#[derive(Debug)]
struct PendingBlockEmptyDirCleanup {
    disk: EphemeralDiskInfo,
    message: String,
}

impl std::fmt::Display for PendingBlockEmptyDirCleanup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PendingBlockEmptyDirCleanup {}

pub(crate) fn pending_ephemeral_disk(error: &anyhow::Error) -> Option<EphemeralDiskInfo> {
    error.chain().find_map(|cause| {
        cause
            .downcast_ref::<PendingBlockEmptyDirCleanup>()
            .map(|pending| pending.disk.clone())
    })
}

fn pending_cleanup_error(disk: EphemeralDiskInfo, message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(PendingBlockEmptyDirCleanup {
        disk,
        message: message.into(),
    })
}

#[derive(Clone)]
pub(crate) struct BlockEmptyDirVolume {
    storage: Option<agent::Storage>,
    mount: oci::Mount,
    pub(crate) device_id: String,
    pub(crate) disk_info: EphemeralDiskInfo,
}

impl BlockEmptyDirVolume {
    pub(crate) async fn new(
        d: &RwLock<DeviceManager>,
        m: &oci::Mount,
        sid: &str,
        emptydir_mode: &str,
        block_device_discard_supported: bool,
        ownership: &EphemeralDiskSetup,
    ) -> Result<Self> {
        let encrypted = emptydir_mode == EMPTYDIR_MODE_BLOCK_ENCRYPTED;
        let discard_unmap =
            emptydir_mode == EMPTYDIR_MODE_BLOCK_PLAIN && block_device_discard_supported;
        let source = m
            .source()
            .as_ref()
            .ok_or_else(|| anyhow!("block emptyDir mount has no source"))?
            .display()
            .to_string();
        let _transaction_guard = lock_emptydir_transaction(&source).await?;

        let emptydir_path = Path::new(&source);
        let disk_path = emptydir_path.join(DISK_IMG);

        // Stat the emptyDir now; kubelet sets its GID to the pod's fsGroup so
        // we need the value both for mountInfo.json metadata and for the agent
        // storage's fs_group field (which genpolicy validates exactly).
        let dir_gid = std::fs::metadata(emptydir_path)
            .with_context(|| format!("stat emptyDir {:?}", emptydir_path))?
            .gid();

        let mut disk_info = match prepare_emptydir_artifacts_async(
            source.clone(),
            encrypted,
            discard_unmap,
            dir_gid,
            ownership.clone(),
        )
        .await
        {
            Ok(disk_info) => disk_info,
            Err(error) => {
                if let Some(disk_info) = pending_ephemeral_disk(&error) {
                    if let Err(registration_error) = ownership.register(disk_info.clone()) {
                        return Err(cleanup_rejected_registration(
                            error.context(registration_error),
                            disk_info,
                            ownership,
                        ));
                    }
                }
                return Err(error);
            }
        };
        if let Err(error) = ownership.register(disk_info.clone()) {
            return Err(cleanup_rejected_registration(error, disk_info, ownership));
        }

        let blkdev_info = get_block_device_info(d).await;
        let machine_type = get_machine_type(d).await;
        let topology = d.read().await.get_pcie_topology();
        let block_driver = block_emptydir_driver(discard_unmap, &blkdev_info.block_device_driver);
        let use_pcie_root_port =
            use_qemu_pcie_root_port(block_driver, &machine_type, topology.as_ref());
        let block_config = BlockConfigModern {
            path_on_host: disk_path.display().to_string(),
            use_pcie_root_port,
            driver_option: block_driver.to_string(),
            blkdev_aio: BlockDeviceAio::new(&blkdev_info.block_device_aio),
            num_queues: blkdev_info.num_queues,
            queue_size: blkdev_info.queue_size,
            logical_sector_size: blkdev_info.block_device_logical_sector_size,
            physical_sector_size: blkdev_info.block_device_physical_sector_size,
            discard_unmap,
            retain_on_unclassified_attach_error: true,
            ..Default::default()
        };

        let tracking_id = disk_info.tracking_id;
        let device_info = match hypervisor::device::device_manager::do_handle_device_with_id(
            d,
            &DeviceConfig::BlockCfgModern(block_config),
            |device_id| ownership.update_device_id(tracking_id, device_id.to_string()),
        )
        .await
        {
            Ok(device_info) => device_info,
            Err(error) => {
                let error = error.context("plug block emptyDir block device");
                let device_id = find_device_id(d, &disk_path.display().to_string())
                    .await
                    .or_else(|| {
                        device_state_in_doubt(&error).map(|pending| pending.device_id().to_string())
                    });
                disk_info.device_id = device_id;
                return Err(pending_cleanup_error(
                    disk_info,
                    format!("{error:#}; preserved block emptyDir artifacts for post-stop cleanup"),
                ));
            }
        };

        let attached_device_id = match &device_info {
            DeviceType::BlockModern(device) => device.lock().await.device_id.clone(),
            unexpected => {
                let error = anyhow!(
                    "block emptyDir attach returned unexpected device type: {unexpected:?}"
                );
                if let Some(device_id) = find_device_id(d, &disk_path.display().to_string()).await {
                    disk_info.device_id = Some(device_id.clone());
                    let error =
                        rollback_failed_emptydir_device(d, &device_id, error, disk_info).await;
                    reconcile_constructor_error(ownership, tracking_id, &error);
                    return Err(error);
                }
                let error = cleanup_owned_emptydir_after_error(error, &disk_info);
                reconcile_constructor_error(ownership, tracking_id, &error);
                return Err(error);
            }
        };
        disk_info.device_id = Some(attached_device_id.clone());

        let (storage, mut mount, device_id) = match crate::volume::utils::handle_block_volume(
            device_info,
            m,
            false,
            sid,
            "ext4",
            Some(&[]),
        )
        .await
        {
            Ok(volume) => volume,
            Err(error) => {
                let error =
                    rollback_failed_emptydir_device(d, &attached_device_id, error, disk_info).await;
                reconcile_constructor_error(ownership, tracking_id, &error);
                return Err(error);
            }
        };

        // genpolicy generates a "bind" type mount for emptyDir volumes; keep
        // the OCI mount type as "bind" so the agent policy allows the request.
        mount.set_typ(Some("bind".to_string()));

        let mut storage = storage;
        configure_block_emptydir_storage(&mut storage, encrypted, discard_unmap);

        // Mirror the Go runtime's handleBlkOCIMounts: the agent mounts the
        // block device at $(spath)/$(b64_device_id) which genpolicy expands to
        // kataGuestSandboxStorageDir + "/" + base64url(source).  That constant
        // is "/run/kata-containers/sandbox/storage" (== genpolicy's "spath"),
        // which is distinct from kata_guest_share_dir.  Using the passthrough
        // path would always fail the policy check.
        let b64_source = URL_SAFE.encode(storage.source.as_bytes());
        let agent_mount_point =
            format!("{}/storage/{}", DEFAULT_KATA_GUEST_SANDBOX_DIR, b64_source);
        storage.mount_point = agent_mount_point.clone();
        mount.set_source(Some(PathBuf::from(&agent_mount_point)));
        disk_info.guest_stats_path = agent_mount_point.clone();
        ownership.update_guest_stats_path(tracking_id, agent_mount_point);

        // Propagate the emptyDir directory GID as fs_group so that the agent
        // policy check (strict equality on fs_group) matches what genpolicy
        // generated from the pod's securityContext.fsGroup.
        if dir_gid != 0 {
            storage.fs_group = Some(agent::FSGroup {
                group_id: dir_gid,
                group_change_policy: agent::FSGroupChangePolicy::Always,
            });
        }

        Ok(Self {
            storage: Some(storage),
            mount,
            device_id,
            disk_info,
        })
    }

    pub(crate) async fn cleanup_with_outcome(
        &self,
        device_manager: &RwLock<DeviceManager>,
    ) -> Result<DeviceRemoval> {
        device_manager
            .write()
            .await
            .try_remove_device_with_outcome(&self.device_id)
            .await
            .with_context(|| format!("detach block emptyDir device {}", self.device_id))
    }
}

async fn lock_emptydir_transaction(source: &str) -> Result<OwnedMutexGuard<()>> {
    let transaction = {
        let mut transactions = ACTIVE_SETUP_TRANSACTIONS
            .lock()
            .map_err(|_| anyhow!("block EmptyDir transaction registry is poisoned"))?;
        if let Some(transaction) = transactions.get(source).and_then(Weak::upgrade) {
            transaction
        } else {
            let transaction = Arc::new(AsyncMutex::new(()));
            transactions.insert(source.to_string(), Arc::downgrade(&transaction));
            transaction
        }
    };
    Ok(transaction.lock_owned().await)
}

async fn rollback_failed_emptydir_device(
    device_manager: &RwLock<DeviceManager>,
    device_id: &str,
    setup_error: anyhow::Error,
    disk_info: EphemeralDiskInfo,
) -> anyhow::Error {
    let removal = device_manager
        .write()
        .await
        .try_remove_device_with_outcome(device_id)
        .await;
    let artifact_cleanup = cleanup_artifacts_after_device_removal(&disk_info, &removal);

    match removal {
        Ok(DeviceRemoval::Detached) => match artifact_cleanup {
            Ok(_) => setup_error.context(format!(
                "rolled back block emptyDir device {device_id} after setup failed"
            )),
            Err(cleanup_error) => {
                pending_cleanup_error(
                    disk_info,
                    format!(
                        "{setup_error:#}; device {device_id} detached but artifact cleanup remains pending: {cleanup_error:#}"
                    ),
                )
            }
        },
        Ok(DeviceRemoval::ReferenceReleased) => {
            if disk_info.owns_artifacts() {
                pending_cleanup_error(
                    disk_info,
                    format!(
                        "{setup_error:#}; released shared block emptyDir device reference {device_id}; artifacts remain owned by another reference"
                    ),
                )
            } else {
                setup_error.context(format!(
                    "released shared block emptyDir device reference {device_id} after setup failed"
                ))
            }
        }
        Err(rollback_error) => {
            pending_cleanup_error(
                disk_info,
                format!(
                    "{setup_error:#}; device {device_id} and its artifacts remain pending cleanup: {rollback_error:#}"
                ),
            )
        }
    }
}

fn reconcile_constructor_error(
    ownership: &EphemeralDiskSetup,
    tracking_id: u64,
    error: &anyhow::Error,
) {
    if pending_ephemeral_disk(error).is_none() {
        ownership.remove(tracking_id);
    }
}

fn cleanup_rejected_registration(
    registration_error: anyhow::Error,
    disk: EphemeralDiskInfo,
    ownership: &EphemeralDiskSetup,
) -> anyhow::Error {
    match cleanup_owned_emptydir_artifacts(&disk) {
        Ok(()) => registration_error.context(
            "removed block EmptyDir artifacts because post-stop finalization had already sealed ownership",
        ),
        Err(cleanup_error) => {
            ownership.preserve_for_cleanup(disk.clone());
            pending_cleanup_error(
                disk,
                format!(
                    "{registration_error:#}; registration was rejected before device attachment, but artifact cleanup remains pending: {cleanup_error:#}"
                ),
            )
        }
    }
}

fn block_emptydir_metadata(encrypted: bool, dir_gid: u32) -> HashMap<String, String> {
    let mut metadata = HashMap::new();
    metadata.insert(METADATA_CREATE_FILESYSTEM.to_string(), true.to_string());
    if encrypted {
        metadata.insert(
            METADATA_ENCRYPTION_KEY.to_string(),
            ENCRYPTION_KEY_VALUE.to_string(),
        );
    }
    if dir_gid != 0 {
        metadata.insert(METADATA_FS_GROUP.to_string(), dir_gid.to_string());
    }
    metadata
}

fn block_emptydir_mount_options(discard_unmap: bool) -> Vec<String> {
    if discard_unmap {
        vec![DISCARD_MOUNT_OPTION.to_string()]
    } else {
        vec![]
    }
}

fn configure_block_emptydir_storage(
    storage: &mut agent::Storage,
    encrypted: bool,
    discard_unmap: bool,
) {
    if encrypted {
        storage.driver_options.push(format!(
            "{}={}",
            ENCRYPTION_KEY_DRIVER_OPTION, ENCRYPTION_KEY_VALUE
        ));
    }
    storage
        .driver_options
        .push(KATA_BLOCK_VOLUME_CREATE_FS.to_string());
    if discard_unmap {
        storage.options.push(DISCARD_MOUNT_OPTION.to_string());
    }
    storage.shared = true;
}

#[async_trait]
impl Volume for BlockEmptyDirVolume {
    fn get_volume_mount(&self) -> Result<Vec<oci::Mount>> {
        Ok(vec![self.mount.clone()])
    }

    fn get_storage(&self) -> Result<Vec<agent::Storage>> {
        let s = if let Some(s) = self.storage.as_ref() {
            vec![s.clone()]
        } else {
            vec![]
        };
        Ok(s)
    }

    async fn cleanup(&self, device_manager: &RwLock<DeviceManager>) -> Result<()> {
        self.cleanup_with_outcome(device_manager).await.map(|_| ())
    }

    fn get_device_id(&self) -> Result<Option<String>> {
        Ok(Some(self.device_id.clone()))
    }
}

#[derive(Debug)]
struct PreparedEmptyDirArtifacts {
    disk_info: Option<EphemeralDiskInfo>,
    _setup_lock: Flock<std::fs::File>,
}

impl PreparedEmptyDirArtifacts {
    fn commit(mut self) -> EphemeralDiskInfo {
        self.disk_info.take().unwrap()
    }
}

struct PreparedEmptyDirOperation {
    prepared: Option<PreparedEmptyDirArtifacts>,
    ownership: EphemeralDiskSetup,
}

impl PreparedEmptyDirOperation {
    fn commit(mut self) -> EphemeralDiskInfo {
        self.prepared.take().unwrap().commit()
    }
}

impl Drop for PreparedEmptyDirOperation {
    fn drop(&mut self) {
        let Some(prepared) = self.prepared.take() else {
            return;
        };
        let mut prepared = prepared;
        let disk_info = prepared.disk_info.take().unwrap();
        if let Err(cleanup_error) = cleanup_owned_emptydir_artifacts(&disk_info) {
            error!(
                sl!(),
                "failed to clean canceled block EmptyDir artifact setup: {cleanup_error:#}"
            );
            self.ownership.preserve_for_cleanup(disk_info);
        }
    }
}

async fn prepare_emptydir_artifacts_async(
    source: String,
    encrypted: bool,
    discard_unmap: bool,
    dir_gid: u32,
    ownership: EphemeralDiskSetup,
) -> Result<EphemeralDiskInfo> {
    let prepared = tokio::task::spawn_blocking(move || -> Result<PreparedEmptyDirOperation> {
        let tracking_id = ownership.allocate_tracking_id()?;
        match prepare_emptydir_artifacts_with_tracking_id(
            &source,
            encrypted,
            discard_unmap,
            dir_gid,
            tracking_id,
        ) {
            Ok(prepared) => Ok(PreparedEmptyDirOperation {
                prepared: Some(prepared),
                ownership,
            }),
            Err(error) => {
                if let Some(disk_info) = pending_ephemeral_disk(&error) {
                    ownership.preserve_for_cleanup(disk_info);
                }
                Err(error)
            }
        }
    })
    .await
    .context("join block emptyDir artifact setup")??;
    Ok(prepared.commit())
}

#[cfg(test)]
fn prepare_emptydir_artifacts(
    source: &str,
    encrypted: bool,
    discard_unmap: bool,
    dir_gid: u32,
) -> Result<PreparedEmptyDirArtifacts> {
    prepare_emptydir_artifacts_with_tracking_id(source, encrypted, discard_unmap, dir_gid, 0)
}

fn prepare_emptydir_artifacts_with_tracking_id(
    source: &str,
    encrypted: bool,
    discard_unmap: bool,
    dir_gid: u32,
    tracking_id: u64,
) -> Result<PreparedEmptyDirArtifacts> {
    let setup_lock = lock_emptydir_source(source)?;
    let disk_path = Path::new(source).join(DISK_IMG);
    let mut disk_info = EphemeralDiskInfo {
        tracking_id,
        disk_path: disk_path.clone(),
        source_path: source.to_string(),
        guest_stats_path: String::new(),
        disk_created: false,
        metadata_created: false,
        device_id: None,
    };
    if is_volume_mounted(source) {
        return Ok(PreparedEmptyDirArtifacts {
            disk_info: Some(disk_info),
            _setup_lock: setup_lock,
        });
    }

    let metadata_root = kata_direct_volume_root_path();
    std::fs::create_dir_all(&metadata_root)
        .with_context(|| format!("create direct-volume root {metadata_root}"))?;
    let metadata_path = join_path(&metadata_root, source)?;
    if metadata_path.exists() {
        return Err(anyhow!(
            "block emptyDir {source} has unowned partial metadata; refusing to remove it"
        ));
    }

    let file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&disk_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if is_volume_mounted(source) {
                return Ok(PreparedEmptyDirArtifacts {
                    disk_info: Some(disk_info),
                    _setup_lock: setup_lock,
                });
            }
            return Err(anyhow!(
                "block emptyDir {source} has an unowned or in-progress disk {}; refusing to truncate or remove it",
                disk_path.display()
            ));
        }
        Err(error) => {
            return Err(error).with_context(|| format!("create sparse disk {:?}", disk_path));
        }
    };
    disk_info.disk_created = true;

    let create_result = (|| -> Result<()> {
        let capacity = get_filesystem_capacity(Path::new(source))?;
        file.set_len(capacity)
            .with_context(|| format!("truncate sparse disk to {capacity} bytes"))?;
        inject_emptydir_setup_failure()?;

        let mount_info = DirectVolumeMountInfo {
            volume_type: "blk".to_string(),
            device: disk_path.display().to_string(),
            fs_type: "ext4".to_string(),
            metadata: block_emptydir_metadata(encrypted, dir_gid),
            options: block_emptydir_mount_options(discard_unmap),
        };
        disk_info.metadata_created = true;
        if let Err(error) = add_volume_mount_info(source, &mount_info) {
            return Err(error).context("write direct-volume mountInfo.json");
        }
        pause_emptydir_setup_after_ownership(source)?;
        Ok(())
    })();

    match create_result {
        Ok(()) => Ok(PreparedEmptyDirArtifacts {
            disk_info: Some(disk_info),
            _setup_lock: setup_lock,
        }),
        Err(error) => Err(cleanup_owned_emptydir_after_error(error, &disk_info)),
    }
}

fn lock_emptydir_source(source: &str) -> Result<Flock<std::fs::File>> {
    let lock_path = Path::new(source).join(SETUP_LOCK_FILE);
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("open block emptyDir setup lock {lock_path:?}"))?;
    Flock::lock(lock_file, FlockArg::LockExclusive)
        .map_err(|(_, error)| anyhow!(error))
        .with_context(|| format!("lock block emptyDir setup {lock_path:?}"))
}

#[cfg(not(test))]
fn inject_emptydir_setup_failure() -> Result<()> {
    Ok(())
}

#[cfg(test)]
fn inject_emptydir_setup_failure() -> Result<()> {
    let Some(marker) = std::env::var_os("KATA_TEST_BLOCK_EMPTYDIR_FAIL_MARKER") else {
        return Ok(());
    };
    std::fs::write(marker, b"owned")?;
    std::thread::sleep(std::time::Duration::from_millis(200));
    Err(anyhow!("injected metadata registration failure"))
}

#[cfg(not(test))]
fn pause_emptydir_setup_after_ownership(_source: &str) -> Result<()> {
    Ok(())
}

#[cfg(test)]
fn pause_emptydir_setup_after_ownership(source: &str) -> Result<()> {
    let gate = ARTIFACT_PREPARATION_GATES
        .lock()
        .unwrap()
        .get(source)
        .cloned();
    if let Some(gate) = gate {
        let mut state = gate.state.lock().unwrap();
        state.entered = true;
        gate.changed.notify_all();
        while !state.released {
            state = gate.changed.wait(state).unwrap();
        }
        return Ok(());
    }

    let Some(marker) = std::env::var_os("KATA_TEST_BLOCK_EMPTYDIR_PAUSE_MARKER") else {
        return Ok(());
    };
    std::fs::write(marker, b"owned")?;
    std::thread::sleep(std::time::Duration::from_millis(300));
    Ok(())
}

pub(crate) fn cleanup_owned_emptydir_artifacts(disk: &EphemeralDiskInfo) -> Result<()> {
    #[cfg(test)]
    if ARTIFACT_PREPARATION_GATES
        .lock()
        .unwrap()
        .get(&disk.source_path)
        .is_some_and(|gate| gate.fail_cleanup())
    {
        return Err(anyhow!("injected owned-artifact cleanup failure"));
    }

    let mut cleanup_errors = Vec::new();
    if disk.disk_created {
        if let Err(error) = std::fs::remove_file(&disk.disk_path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                cleanup_errors.push(format!("remove {}: {error}", disk.disk_path.display()));
            }
        }
    }
    if disk.metadata_created {
        if let Err(error) = kata_types::mount::remove_volume_path(&disk.source_path) {
            let not_found = error
                .chain()
                .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
                .any(|error| error.kind() == std::io::ErrorKind::NotFound);
            if !not_found {
                cleanup_errors.push(format!(
                    "remove direct-volume metadata for {}: {error}",
                    disk.source_path
                ));
            }
        }
    }

    if cleanup_errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(cleanup_errors.join("; ")))
    }
}

pub(crate) fn cleanup_artifacts_after_device_removal(
    disk: &EphemeralDiskInfo,
    removal: &Result<DeviceRemoval>,
) -> Result<bool> {
    if !disk.owns_artifacts() || !matches!(removal, Ok(DeviceRemoval::Detached)) {
        return Ok(false);
    }
    cleanup_owned_emptydir_artifacts(disk)?;
    Ok(true)
}

fn cleanup_owned_emptydir_after_error(
    setup_error: anyhow::Error,
    disk: &EphemeralDiskInfo,
) -> anyhow::Error {
    match cleanup_owned_emptydir_artifacts(disk) {
        Ok(()) => setup_error,
        Err(cleanup_error) => pending_cleanup_error(
            disk.clone(),
            format!("{setup_error:#}; failed to clean block emptyDir setup: {cleanup_error:#}"),
        ),
    }
}

pub(crate) fn is_block_emptydir_volume(m: &oci::Mount, emptydir_mode: &str) -> bool {
    if !is_block_emptydir_mode(emptydir_mode) {
        return false;
    }
    // Kubelet always presents emptyDir mounts as "bind" type in the OCI spec.
    // Any other type means this is not a plain host-backed emptyDir, so skip it.
    let typ = match m.typ() {
        Some(t) => t,
        None => return false,
    };
    if typ != KATA_MOUNT_BIND_TYPE {
        return false;
    }
    match m.source() {
        Some(src) => is_disk_empty_dir(&src.display().to_string()),
        None => false,
    }
}

pub(crate) fn is_block_emptydir_mode(emptydir_mode: &str) -> bool {
    emptydir_mode == EMPTYDIR_MODE_BLOCK_ENCRYPTED || emptydir_mode == EMPTYDIR_MODE_BLOCK_PLAIN
}

/// Keep block-backed EmptyDirs on the configured hypervisor transport.
/// Discard remains a separate backend and guest mount option instead of
/// overriding the transport selected by the operator.
fn block_emptydir_driver(_discard_unmap: bool, default_driver: &str) -> &str {
    default_driver
}

fn use_qemu_pcie_root_port(
    block_driver: &str,
    machine_type: &str,
    topology: Option<&PCIeTopology>,
) -> bool {
    block_driver == VIRTIO_BLK_PCI
        && supports_pcie_root_ports(machine_type)
        && topology.is_some_and(|topology| {
            topology.hypervisor_name == HYPERVISOR_QEMU && topology.pcie_root_ports > 0
        })
}

fn get_filesystem_capacity(path: &Path) -> Result<u64> {
    let stat = statfs(path).with_context(|| format!("statfs {:?}", path))?;
    let total = stat.blocks() as u64 * stat.block_size() as u64;
    if total == 0 {
        return Err(anyhow!("filesystem at {:?} reports zero capacity", path));
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::volume::EphemeralDiskStore;
    use kata_types::config::hypervisor::{VIRTIO_BLK_CCW, VIRTIO_BLK_MMIO, VIRTIO_SCSI};
    use std::sync::Arc;

    const ARTIFACT_FAILURE_TEST_ENV: &str = "KATA_TEST_BLOCK_EMPTYDIR_ARTIFACT_FAILURE";
    const CONCURRENT_SETUP_TEST_ENV: &str = "KATA_TEST_BLOCK_EMPTYDIR_CONCURRENT_SETUP";
    const SAME_PROCESS_SETUP_TEST_ENV: &str = "KATA_TEST_BLOCK_EMPTYDIR_SAME_PROCESS_SETUP";
    const CANCELED_SETUP_TEST_ENV: &str = "KATA_TEST_BLOCK_EMPTYDIR_CANCELED_SETUP";
    const CANCELED_FINALIZATION_TEST_ENV: &str = "KATA_TEST_BLOCK_EMPTYDIR_CANCELED_FINALIZATION";
    const TRACKING_ID_EXHAUSTION_TEST_ENV: &str = "KATA_TEST_BLOCK_EMPTYDIR_TRACKING_ID_EXHAUSTION";

    #[test]
    fn block_emptydir_preserves_configured_transport_and_selects_root_port() {
        let qemu = PCIeTopology {
            hypervisor_name: HYPERVISOR_QEMU.to_string(),
            pcie_root_ports: 8,
            ..Default::default()
        };
        let qemu_without_root_ports = PCIeTopology {
            hypervisor_name: HYPERVISOR_QEMU.to_string(),
            ..Default::default()
        };
        let cloud_hypervisor = PCIeTopology {
            hypervisor_name: "cloud-hypervisor".to_string(),
            pcie_root_ports: 8,
            ..Default::default()
        };

        assert_eq!(block_emptydir_driver(true, VIRTIO_SCSI), VIRTIO_SCSI);
        assert_eq!(block_emptydir_driver(false, VIRTIO_SCSI), VIRTIO_SCSI);
        assert_eq!(block_emptydir_driver(true, VIRTIO_BLK_PCI), VIRTIO_BLK_PCI);
        assert_eq!(block_emptydir_driver(true, VIRTIO_BLK_CCW), VIRTIO_BLK_CCW);

        assert!(use_qemu_pcie_root_port(VIRTIO_BLK_PCI, "q35", Some(&qemu)));
        assert!(use_qemu_pcie_root_port(VIRTIO_BLK_PCI, "virt", Some(&qemu)));
        assert!(!use_qemu_pcie_root_port(
            VIRTIO_BLK_PCI,
            "pseries",
            Some(&qemu)
        ));
        assert!(!use_qemu_pcie_root_port(VIRTIO_SCSI, "q35", Some(&qemu)));
        assert!(!use_qemu_pcie_root_port(
            VIRTIO_BLK_CCW,
            "s390-ccw-virtio",
            Some(&qemu)
        ));
        assert!(!use_qemu_pcie_root_port(
            VIRTIO_BLK_MMIO,
            "virt",
            Some(&qemu)
        ));
        assert!(!use_qemu_pcie_root_port(
            VIRTIO_BLK_PCI,
            "q35",
            Some(&cloud_hypervisor)
        ));
        assert!(!use_qemu_pcie_root_port(
            VIRTIO_BLK_PCI,
            "q35",
            Some(&qemu_without_root_ports)
        ));
        assert!(!use_qemu_pcie_root_port(VIRTIO_BLK_PCI, "q35", None));
    }

    #[test]
    fn block_plain_emptydir_requests_filesystem_creation_and_discard() {
        let metadata = block_emptydir_metadata(false, 0);

        assert_eq!(
            metadata.get(METADATA_CREATE_FILESYSTEM).map(String::as_str),
            Some("true")
        );
        assert!(!metadata.contains_key(METADATA_ENCRYPTION_KEY));
        assert!(!metadata.contains_key(METADATA_FS_GROUP));
        assert_eq!(
            block_emptydir_mount_options(true),
            vec![DISCARD_MOUNT_OPTION.to_string()]
        );

        let mut storage = agent::Storage::default();

        configure_block_emptydir_storage(&mut storage, false, true);

        assert_eq!(
            storage.driver_options,
            vec![KATA_BLOCK_VOLUME_CREATE_FS.to_string()]
        );
        assert_eq!(storage.options, vec![DISCARD_MOUNT_OPTION.to_string()]);
        assert!(storage.shared);
    }

    #[test]
    fn block_plain_emptydir_skips_discard_when_hypervisor_cannot_expose_it() {
        assert!(block_emptydir_mount_options(false).is_empty());

        let mut storage = agent::Storage::default();

        configure_block_emptydir_storage(&mut storage, false, false);

        assert_eq!(
            storage.driver_options,
            vec![KATA_BLOCK_VOLUME_CREATE_FS.to_string()]
        );
        assert!(storage.options.is_empty());
        assert!(storage.shared);
    }

    #[test]
    fn block_encrypted_emptydir_requests_encryption_and_filesystem_creation() {
        let metadata = block_emptydir_metadata(true, 0);

        assert_eq!(
            metadata.get(METADATA_CREATE_FILESYSTEM).map(String::as_str),
            Some("true")
        );
        assert_eq!(
            metadata.get(METADATA_ENCRYPTION_KEY).map(String::as_str),
            Some(ENCRYPTION_KEY_VALUE)
        );
        assert!(!metadata.contains_key(METADATA_FS_GROUP));
        assert!(block_emptydir_mount_options(false).is_empty());

        let mut storage = agent::Storage::default();

        configure_block_emptydir_storage(&mut storage, true, false);

        assert_eq!(
            storage.driver_options,
            vec![
                format!("{}={}", ENCRYPTION_KEY_DRIVER_OPTION, ENCRYPTION_KEY_VALUE),
                KATA_BLOCK_VOLUME_CREATE_FS.to_string(),
            ]
        );
        assert!(storage.options.is_empty());
        assert!(storage.shared);
    }

    #[tokio::test]
    async fn sealed_registration_cleans_artifacts_created_before_registration() {
        let temp_dir = tempfile::tempdir().unwrap();
        let disk_path = temp_dir.path().join(DISK_IMG);
        std::fs::write(&disk_path, b"owned").unwrap();
        let store = EphemeralDiskStore::default();
        let setup = store.begin_setup().unwrap();
        let sealing_store = store.clone();
        let sealing = tokio::spawn(async move { sealing_store.seal_and_wait().await });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !store.is_sealed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("finalization never sealed ownership");
        let disk = EphemeralDiskInfo {
            tracking_id: 1,
            disk_path: disk_path.clone(),
            source_path: temp_dir.path().display().to_string(),
            guest_stats_path: String::new(),
            disk_created: true,
            metadata_created: false,
            device_id: None,
        };

        let registration_error = setup.register(disk.clone()).unwrap_err();
        let error = cleanup_rejected_registration(registration_error, disk, &setup);

        assert!(format!("{error:#}").contains("sealed before registration"));
        assert!(!disk_path.exists());
        assert!(store.snapshot().is_empty());
        drop(setup);
        sealing.await.unwrap();
    }

    #[test]
    fn concurrent_processes_use_production_artifact_ownership() {
        if let Some(role) = std::env::var_os(CONCURRENT_SETUP_TEST_ENV) {
            kata_types::rootless::set_rootless(true);
            let source = std::env::var_os("KATA_TEST_BLOCK_EMPTYDIR_SOURCE").unwrap();
            let source = PathBuf::from(source);
            std::fs::create_dir_all(&source).unwrap();
            let result = prepare_emptydir_artifacts(&source.display().to_string(), false, false, 0);
            if role == "fail" {
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains("injected metadata registration failure"));
                assert!(!source.join(DISK_IMG).exists());
            } else {
                let disk = result.unwrap().commit();
                assert!(disk.disk_created);
                assert!(disk.disk_path.exists());
                assert!(is_volume_mounted(&disk.source_path));
            }
            return;
        }

        let temp_dir = tempfile::tempdir().unwrap();
        let source = temp_dir.path().join("source");
        let runtime_dir = temp_dir.path().join("runtime");
        let marker = temp_dir.path().join("owner-ready");
        let test_binary = std::env::current_exe().unwrap();
        let mut failing = std::process::Command::new(&test_binary)
            .arg("concurrent_processes_use_production_artifact_ownership")
            .arg("--test-threads=1")
            .env(CONCURRENT_SETUP_TEST_ENV, "fail")
            .env("KATA_TEST_BLOCK_EMPTYDIR_SOURCE", &source)
            .env("KATA_TEST_BLOCK_EMPTYDIR_FAIL_MARKER", &marker)
            .env("XDG_RUNTIME_DIR", &runtime_dir)
            .spawn()
            .unwrap();
        for _ in 0..100 {
            if marker.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(marker.exists(), "failing process never acquired ownership");
        let successful = std::process::Command::new(test_binary)
            .arg("concurrent_processes_use_production_artifact_ownership")
            .arg("--test-threads=1")
            .env(CONCURRENT_SETUP_TEST_ENV, "success")
            .env("KATA_TEST_BLOCK_EMPTYDIR_SOURCE", &source)
            .env("XDG_RUNTIME_DIR", &runtime_dir)
            .output()
            .unwrap();
        assert!(failing.wait().unwrap().success());
        assert!(
            successful.status.success(),
            "successful participant failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&successful.stdout),
            String::from_utf8_lossy(&successful.stderr)
        );
        assert!(source.join(DISK_IMG).exists());
    }

    #[test]
    fn concurrent_same_process_setup_serializes_and_reuses_artifacts() {
        if std::env::var_os(SAME_PROCESS_SETUP_TEST_ENV).is_some() {
            kata_types::rootless::set_rootless(true);
            let source =
                PathBuf::from(std::env::var_os("KATA_TEST_BLOCK_EMPTYDIR_SOURCE").unwrap());
            let marker =
                PathBuf::from(std::env::var_os("KATA_TEST_BLOCK_EMPTYDIR_PAUSE_MARKER").unwrap());
            std::fs::create_dir_all(&source).unwrap();
            let source_string = source.display().to_string();
            let first_source = source_string.clone();
            let first = std::thread::spawn(move || {
                prepare_emptydir_artifacts(&first_source, false, false, 0)
                    .unwrap()
                    .commit()
            });
            for _ in 0..100 {
                if marker.exists() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(marker.exists(), "first setup never acquired ownership");
            let second = std::thread::spawn(move || {
                prepare_emptydir_artifacts(&source_string, false, false, 0)
                    .unwrap()
                    .commit()
            });

            let first = first.join().unwrap();
            let second = second.join().unwrap();
            assert!(first.disk_created);
            assert!(first.metadata_created);
            assert!(!second.disk_created);
            assert!(!second.metadata_created);
            return;
        }

        let temp_dir = tempfile::tempdir().unwrap();
        let source = temp_dir.path().join("source");
        let runtime_dir = temp_dir.path().join("runtime");
        let marker = temp_dir.path().join("first-owned");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("concurrent_same_process_setup_serializes_and_reuses_artifacts")
            .arg("--test-threads=1")
            .env(SAME_PROCESS_SETUP_TEST_ENV, "1")
            .env("KATA_TEST_BLOCK_EMPTYDIR_SOURCE", &source)
            .env("KATA_TEST_BLOCK_EMPTYDIR_PAUSE_MARKER", &marker)
            .env("XDG_RUNTIME_DIR", runtime_dir)
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "same-process setup test failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test]
    async fn canceled_setup_cleans_worker_owned_artifacts() {
        if let Some(source) = std::env::var_os(CANCELED_SETUP_TEST_ENV) {
            kata_types::rootless::set_rootless(true);
            let source = PathBuf::from(source);
            std::fs::create_dir_all(&source).unwrap();
            let marker =
                PathBuf::from(std::env::var_os("KATA_TEST_BLOCK_EMPTYDIR_MARKER").unwrap());
            let source_string = source.display().to_string();
            let ownership = EphemeralDiskStore::default().begin_setup().unwrap();
            let setup = tokio::spawn(prepare_emptydir_artifacts_async(
                source_string.clone(),
                false,
                false,
                0,
                ownership,
            ));
            for _ in 0..100 {
                if marker.exists() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert!(marker.exists(), "setup worker never acquired ownership");
            setup.abort();
            assert!(setup.await.unwrap_err().is_cancelled());
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            assert!(!source.join(DISK_IMG).exists());
            assert!(!is_volume_mounted(&source_string));
            return;
        }

        let temp_dir = tempfile::tempdir().unwrap();
        let source = temp_dir.path().join("source");
        let runtime_dir = temp_dir.path().join("runtime");
        let marker = temp_dir.path().join("owned");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("canceled_setup_cleans_worker_owned_artifacts")
            .arg("--test-threads=1")
            .env(CANCELED_SETUP_TEST_ENV, &source)
            .env("KATA_TEST_BLOCK_EMPTYDIR_PAUSE_MARKER", &marker)
            .env("KATA_TEST_BLOCK_EMPTYDIR_MARKER", &marker)
            .env("XDG_RUNTIME_DIR", runtime_dir)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated cancellation test failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test]
    async fn canceled_artifact_worker_blocks_finalization_and_preserves_cleanup_failure() {
        if let Some(mode) = std::env::var_os(CANCELED_FINALIZATION_TEST_ENV) {
            kata_types::rootless::set_rootless(true);
            let source =
                PathBuf::from(std::env::var_os("KATA_TEST_BLOCK_EMPTYDIR_SOURCE").unwrap());
            std::fs::create_dir_all(&source).unwrap();
            let source_string = source.display().to_string();
            let gate = Arc::new(ArtifactPreparationGate::default());
            ARTIFACT_PREPARATION_GATES
                .lock()
                .unwrap()
                .insert(source_string.clone(), gate.clone());

            let resource = Arc::new(crate::volume::VolumeResource::new());
            let ownership = resource.ephemeral_disks.begin_setup().unwrap();
            let setup_source = source_string.clone();
            let setup = tokio::spawn(prepare_emptydir_artifacts_async(
                setup_source,
                false,
                false,
                0,
                ownership,
            ));
            let entered_gate = gate.clone();
            tokio::task::spawn_blocking(move || entered_gate.wait_until_entered())
                .await
                .unwrap();
            setup.abort();
            assert!(setup.await.unwrap_err().is_cancelled());

            let device_manager = Arc::new(RwLock::new(
                DeviceManager::new(Arc::new(hypervisor::firecracker::Firecracker::new()), None)
                    .await
                    .unwrap(),
            ));
            let finalize_resource = resource.clone();
            let finalize_manager = device_manager.clone();
            let finalize = tokio::spawn(async move {
                finalize_resource
                    .finalize_ephemeral_disks(finalize_manager.as_ref())
                    .await
            });
            while !resource.ephemeral_disks.is_sealed() {
                tokio::task::yield_now().await;
            }

            let finalized_before_worker_exit = finalize.is_finished();
            let inject_cleanup_failure = mode == "cleanup-failure";
            gate.set_fail_cleanup(inject_cleanup_failure);
            gate.release();
            let finalize_result = finalize.await.unwrap();
            assert!(
                !finalized_before_worker_exit,
                "finalization completed while artifact preparation was still blocked"
            );

            if inject_cleanup_failure {
                let error = finalize_result.unwrap_err();
                assert!(format!("{error:#}").contains("injected owned-artifact cleanup failure"));
                assert_eq!(resource.ephemeral_disks.snapshot().len(), 1);
                gate.set_fail_cleanup(false);
                resource
                    .finalize_ephemeral_disks(device_manager.as_ref())
                    .await
                    .unwrap();
            } else {
                finalize_result.unwrap();
            }
            assert!(resource.ephemeral_disks.snapshot().is_empty());
            assert!(!source.join(DISK_IMG).exists());
            assert!(!is_volume_mounted(&source_string));
            return;
        }

        for mode in ["cleanup-success", "cleanup-failure"] {
            let temp_dir = tempfile::tempdir().unwrap();
            let source = temp_dir.path().join("source");
            let runtime_dir = temp_dir.path().join("runtime");
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .arg(
                    "volume::block_emptydir_volume::tests::canceled_artifact_worker_blocks_finalization_and_preserves_cleanup_failure",
                )
                .arg("--exact")
                .arg("--test-threads=1")
                .env(CANCELED_FINALIZATION_TEST_ENV, mode)
                .env("KATA_TEST_BLOCK_EMPTYDIR_SOURCE", source)
                .env("XDG_RUNTIME_DIR", runtime_dir)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{mode} participant failed:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn tracking_id_exhaustion_never_wraps_or_replaces_ownership() {
        if let Some(root) = std::env::var_os(TRACKING_ID_EXHAUSTION_TEST_ENV) {
            kata_types::rootless::set_rootless(true);
            let root = PathBuf::from(root);
            let first_source = root.join("first");
            std::fs::create_dir_all(&first_source).unwrap();
            let store = EphemeralDiskStore::default();
            let setup = store.begin_setup().unwrap();
            setup.set_next_tracking_id(u64::MAX);

            let first_tracking_id = setup.allocate_tracking_id().unwrap();
            let first = prepare_emptydir_artifacts_with_tracking_id(
                &first_source.display().to_string(),
                false,
                false,
                0,
                first_tracking_id,
            )
            .unwrap()
            .commit();
            assert_eq!(first.tracking_id, u64::MAX);
            setup.register(first.clone()).unwrap();
            let error = setup.allocate_tracking_id().unwrap_err();
            assert!(format!("{error:#}").contains("tracking IDs exhausted"));
            assert_eq!(store.snapshot().len(), 1);
            assert_eq!(store.snapshot()[0].tracking_id, u64::MAX);
            cleanup_owned_emptydir_artifacts(&first).unwrap();
            return;
        }

        let temp_dir = tempfile::tempdir().unwrap();
        let runtime_dir = temp_dir.path().join("runtime");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg(
                "volume::block_emptydir_volume::tests::tracking_id_exhaustion_never_wraps_or_replaces_ownership",
            )
            .arg("--exact")
            .arg("--test-threads=1")
            .env(TRACKING_ID_EXHAUSTION_TEST_ENV, temp_dir.path())
            .env("XDG_RUNTIME_DIR", runtime_dir)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "tracking-ID exhaustion participant failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test]
    async fn failing_current_volume_preserves_artifacts_when_detach_fails() {
        let temp_dir = tempfile::tempdir().unwrap();
        let disk_path = temp_dir.path().join(DISK_IMG);
        std::fs::write(&disk_path, b"attached data").unwrap();
        let device_manager = RwLock::new(
            DeviceManager::new(Arc::new(hypervisor::firecracker::Firecracker::new()), None)
                .await
                .unwrap(),
        );
        let device = do_handle_device(
            &device_manager,
            &DeviceConfig::BlockCfgModern(BlockConfigModern {
                path_on_host: disk_path.display().to_string(),
                driver_option: hypervisor::VIRTIO_BLOCK_PCI.to_string(),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        let device_id = match device {
            DeviceType::BlockModern(device) => device.lock().await.device_id.clone(),
            unexpected => panic!("expected BlockModern, got {:?}", unexpected),
        };
        let disk_info = EphemeralDiskInfo {
            tracking_id: 0,
            disk_path: disk_path.clone(),
            source_path: temp_dir.path().display().to_string(),
            guest_stats_path: String::new(),
            disk_created: true,
            metadata_created: true,
            device_id: Some(device_id.clone()),
        };
        let error = rollback_failed_emptydir_device(
            &device_manager,
            &device_id,
            anyhow!("injected mount discovery failure"),
            disk_info,
        )
        .await;

        assert!(error
            .to_string()
            .contains("artifacts remain pending cleanup"));
        assert!(disk_path.exists());
        assert_eq!(
            pending_ephemeral_disk(&error).unwrap().device_id.as_deref(),
            Some(device_id.as_str())
        );
        assert_eq!(
            find_device_id(&device_manager, &disk_path.display().to_string()).await,
            Some(device_id)
        );
    }

    #[test]
    fn failed_removal_and_unowned_setup_preserve_artifacts() {
        if let Some(source) = std::env::var_os(ARTIFACT_FAILURE_TEST_ENV) {
            kata_types::rootless::set_rootless(true);
            let source = PathBuf::from(source);
            std::fs::create_dir_all(&source).unwrap();
            let disk_path = source.join(DISK_IMG);
            std::fs::write(&disk_path, b"attached data").unwrap();
            let source_string = source.display().to_string();
            add_volume_mount_info(
                &source_string,
                &DirectVolumeMountInfo {
                    volume_type: "blk".to_string(),
                    device: disk_path.display().to_string(),
                    fs_type: "ext4".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            let disk = EphemeralDiskInfo {
                tracking_id: 0,
                disk_path: disk_path.clone(),
                source_path: source_string.clone(),
                guest_stats_path: String::new(),
                disk_created: true,
                metadata_created: true,
                device_id: Some("pending-device".to_string()),
            };
            let failed_removal = Err(anyhow!("injected detach failure"));

            assert!(!cleanup_artifacts_after_device_removal(&disk, &failed_removal).unwrap());
            assert!(disk_path.exists());
            assert!(is_volume_mounted(&source_string));

            assert!(
                cleanup_artifacts_after_device_removal(&disk, &Ok(DeviceRemoval::Detached))
                    .unwrap()
            );
            assert!(!disk_path.exists());
            assert!(!is_volume_mounted(&source_string));

            let reused_disk = source.join("reused.img");
            std::fs::write(&reused_disk, b"reused data").unwrap();
            let reused = EphemeralDiskInfo {
                tracking_id: 1,
                disk_path: reused_disk.clone(),
                source_path: source_string.clone(),
                guest_stats_path: String::new(),
                disk_created: false,
                metadata_created: false,
                device_id: Some("shared-device".to_string()),
            };
            assert!(
                !cleanup_artifacts_after_device_removal(&reused, &Ok(DeviceRemoval::Detached))
                    .unwrap()
            );
            assert_eq!(std::fs::read(reused_disk).unwrap(), b"reused data");

            let unowned = source.join("unowned");
            std::fs::create_dir_all(&unowned).unwrap();
            let unowned_disk = unowned.join(DISK_IMG);
            std::fs::write(&unowned_disk, b"must remain").unwrap();
            let error = prepare_emptydir_artifacts(&unowned.display().to_string(), false, false, 0)
                .unwrap_err();
            assert!(error.to_string().contains("unowned or in-progress disk"));
            assert_eq!(std::fs::read(unowned_disk).unwrap(), b"must remain");
            return;
        }

        let temp_dir = tempfile::tempdir().unwrap();
        let source = temp_dir.path().join("source");
        let runtime_dir = temp_dir.path().join("runtime");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("failed_removal_and_unowned_setup_preserve_artifacts")
            .arg("--test-threads=1")
            .env(ARTIFACT_FAILURE_TEST_ENV, &source)
            .env("XDG_RUNTIME_DIR", runtime_dir)
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "isolated artifact test failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn artifact_cleanup_is_gated_by_each_device_detach_outcome() {
        let temp_dir = tempfile::tempdir().unwrap();
        let detached_path = temp_dir.path().join("detached.img");
        let failed_path = temp_dir.path().join("failed.img");
        std::fs::write(&detached_path, b"detached").unwrap();
        std::fs::write(&failed_path, b"still attached").unwrap();
        let disk = |path: PathBuf, device_id: &str| EphemeralDiskInfo {
            tracking_id: 0,
            disk_path: path,
            source_path: temp_dir.path().display().to_string(),
            guest_stats_path: String::new(),
            disk_created: true,
            metadata_created: false,
            device_id: Some(device_id.to_string()),
        };
        let detached = disk(detached_path.clone(), "detached-device");
        let failed = disk(failed_path.clone(), "failed-device");

        assert!(
            cleanup_artifacts_after_device_removal(&detached, &Ok(DeviceRemoval::Detached))
                .unwrap()
        );
        assert!(!cleanup_artifacts_after_device_removal(
            &failed,
            &Err(anyhow!("injected detach failure"))
        )
        .unwrap());

        assert!(!detached_path.exists());
        assert!(failed_path.exists());
    }
}
