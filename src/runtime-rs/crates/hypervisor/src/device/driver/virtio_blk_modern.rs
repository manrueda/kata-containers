// Copyright (c) 2026 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::device::pci_path::PciPath;
use crate::device::topology::PCIeTopology;
use crate::device::util::do_decrease_count;
use crate::device::util::do_increase_count;
use crate::device::Device;
use crate::device::DeviceType;
use crate::device::{device_state_in_doubt, DeviceStateInDoubt};
use crate::Hypervisor as hypervisor;
use crate::HYPERVISOR_QEMU;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;

/// VIRTIO_BLOCK_PCI indicates block driver is virtio-pci based
pub const VIRTIO_BLOCK_PCI: &str = "virtio-blk-pci";
pub const VIRTIO_BLOCK_MMIO: &str = "virtio-blk-mmio";
pub const VIRTIO_BLOCK_CCW: &str = "virtio-blk-ccw";
pub const VIRTIO_PMEM: &str = "virtio-pmem";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockCleanupState {
    pub frontend: bool,
    pub backend: bool,
    pub fdsets: bool,
}

impl BlockCleanupState {
    pub fn attached(fdsets: bool) -> Self {
        Self {
            frontend: true,
            backend: true,
            fdsets,
        }
    }

    pub fn is_complete(self) -> bool {
        !self.frontend && !self.backend && !self.fdsets
    }
}

#[derive(Debug, thiserror::Error)]
#[error("QEMU block device {node_name} cleanup remains incomplete: {details}")]
pub struct BlockDeviceCleanupPending {
    node_name: String,
    details: String,
    state: BlockCleanupState,
}

impl BlockDeviceCleanupPending {
    pub fn with_state(
        node_name: impl Into<String>,
        details: impl Into<String>,
        state: BlockCleanupState,
    ) -> Self {
        Self {
            node_name: node_name.into(),
            details: details.into(),
            state,
        }
    }

    pub fn state(&self) -> BlockCleanupState {
        self.state
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BlockDeviceAio {
    // IoUring is the Linux io_uring I/O implementation.
    #[default]
    IoUring,

    // Native is the native Linux AIO implementation.
    Native,

    // Threads is the pthread asynchronous I/O implementation.
    Threads,
}

impl BlockDeviceAio {
    pub fn new(aio: &str) -> Self {
        match aio {
            "native" => BlockDeviceAio::Native,
            "threads" => BlockDeviceAio::Threads,
            _ => BlockDeviceAio::IoUring,
        }
    }
}

impl std::fmt::Display for BlockDeviceAio {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let to_string = match *self {
            BlockDeviceAio::Native => "native".to_string(),
            BlockDeviceAio::Threads => "threads".to_string(),
            _ => "iouring".to_string(),
        };
        write!(f, "{to_string}")
    }
}

const MAX_VMDK_EXTENT_SECTORS: u64 = 0x8000_0000 >> 9;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmdkExtent {
    pub path_on_host: String,
    pub sectors: u64,
    pub file_offset: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VmdkConfig {
    pub extents: Vec<VmdkExtent>,
}

impl VmdkConfig {
    pub fn push_extent(&mut self, path_on_host: &str, sectors: u64, file_offset: u64) {
        self.extents.push(VmdkExtent {
            path_on_host: path_on_host.to_string(),
            sectors,
            file_offset,
        });
    }

    pub fn push_extent_chunked(&mut self, path_on_host: &str, total_sectors: u64) {
        let mut remaining = total_sectors;
        let mut file_offset = 0;
        while remaining > 0 {
            let sectors = remaining.min(MAX_VMDK_EXTENT_SECTORS);
            self.push_extent(path_on_host, sectors, file_offset);
            file_offset += sectors;
            remaining -= sectors;
        }
    }

    pub fn total_sectors(&self) -> Option<u64> {
        self.extents
            .iter()
            .try_fold(0_u64, |total, extent| total.checked_add(extent.sectors))
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct BlockConfigModern {
    /// Actual host path for a raw block source; every backend consumes this
    /// value according to its block transport. When `vmdk` is present, QEMU is
    /// currently the only backend that consumes the structured layout. In that
    /// case, this is a reserved descriptor path used as the block-device key and
    /// for logging; QEMU neither creates nor opens a file at this path. A future
    /// backend may instead materialize and open its descriptor here. If
    /// structured layouts gain more consumers, replace this field and `vmdk`
    /// with explicit source variants distinguishing a raw host path from a
    /// VMDK descriptor path and layout.
    pub path_on_host: String,

    /// If set to true, the drive is opened in read-only mode. Otherwise, the
    /// drive is opened as read-write.
    pub is_readonly: bool,

    /// Enables discard/unmap support for this block device.
    pub discard_unmap: bool,

    /// Retains the device identity when the backend returns an unclassified
    /// attach error that might represent a completed operation.
    pub retain_on_unclassified_attach_error: bool,

    /// Don't close `path_on_host` file when dropping the device.
    pub no_drop: bool,

    /// Structured VMDK layout, currently consumed only by QEMU. When present,
    /// the QEMU backend opens the backing extents in the shim, renders an
    /// anonymous descriptor containing fdset paths, and passes it to QEMU by
    /// file descriptor. No descriptor file is created at `path_on_host`.
    /// Without a structured layout, the block source is raw.
    pub vmdk: Option<VmdkConfig>,

    /// Specifies cache-related options for block devices.
    /// Denotes whether use of O_DIRECT (bypass the host page cache) is enabled.
    /// If not set, use configurarion block_device_cache_direct.
    pub is_direct: Option<bool>,

    /// device index
    pub index: u64,

    /// blkdev_aio defines the type of asynchronous I/O the block device should use.
    pub blkdev_aio: BlockDeviceAio,

    /// driver type for block device
    pub driver_option: String,

    /// device path in guest
    pub virt_path: String,

    /// pci path is the slot at which the drive is attached
    pub pci_path: Option<PciPath>,

    /// Preconfigured PCIe root-port bus used for QEMU hot-plug.
    pub pcie_root_port: Option<String>,

    /// Requires QEMU to hot-plug this device through a PCIe root port.
    pub use_pcie_root_port: bool,

    /// Tracks exact QEMU residue after an incomplete attach rollback.
    pub cleanup_state: Option<BlockCleanupState>,

    /// scsi_addr of the block device, in case the device is attached using SCSI driver
    /// scsi_addr is of the format SCSI-Id:LUN
    pub scsi_addr: Option<String>,

    /// CCW device address for virtio-blk-ccw on s390x (e.g., "0.0.0005")
    pub ccw_addr: Option<String>,

    /// device attach count
    pub attach_count: u64,

    /// device major number
    pub major: i64,

    /// device minor number
    pub minor: i64,

    /// virtio queue size. size: byte
    pub queue_size: u32,

    /// block device multi-queue
    pub num_queues: usize,

    /// Logical sector size in bytes reported to the guest. 0 means use hypervisor default.
    pub logical_sector_size: u32,

    /// Physical sector size in bytes reported to the guest. 0 means use hypervisor default.
    pub physical_sector_size: u32,

    /// Override the QEMU virtio serial for this device.
    /// When set, the device is discoverable in the guest via
    /// `/dev/disk/by-id/virtio-<serial>`.
    /// If empty, the default `image-{device_id}` serial is used.
    pub serial_override: String,
}

#[derive(Debug, Clone, Default)]
pub struct BlockDeviceModern {
    pub device_id: String,
    pub attach_count: u64,
    pub config: BlockConfigModern,
}

#[derive(Debug, Clone)]
pub struct BlockDeviceModernHandle {
    inner: Arc<Mutex<BlockDeviceModern>>,
    attach_pending: bool,
}

impl BlockDeviceModernHandle {
    pub fn new(device_id: String, config: BlockConfigModern) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BlockDeviceModern {
                device_id,
                attach_count: 0,
                config,
            })),
            attach_pending: false,
        }
    }

    pub fn arc(&self) -> Arc<Mutex<BlockDeviceModern>> {
        self.inner.clone()
    }

    pub async fn snapshot_config(&self) -> BlockConfigModern {
        self.inner.lock().await.config.clone()
    }

    pub async fn device_id(&self) -> String {
        self.inner.lock().await.device_id.clone()
    }

    pub async fn attach_count(&self) -> u64 {
        self.inner.lock().await.attach_count
    }
}

fn uses_qemu_pcie_root_port(
    config: &BlockConfigModern,
    topology: Option<&PCIeTopology>,
) -> Result<bool> {
    if !config.use_pcie_root_port {
        return Ok(false);
    }

    let topology = topology
        .ok_or_else(|| anyhow!("required PCIe topology is unavailable for block device"))?;
    Ok(topology.hypervisor_name == HYPERVISOR_QEMU)
}

fn pending_cleanup_state(error: &anyhow::Error) -> Option<BlockCleanupState> {
    error.chain().find_map(|cause| {
        cause
            .downcast_ref::<BlockDeviceCleanupPending>()
            .map(BlockDeviceCleanupPending::state)
    })
}

fn cleanup_state_in_doubt(device_id: impl Into<String>, error: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(DeviceStateInDoubt::new(device_id, error.to_string()))
}

#[async_trait]
impl Device for BlockDeviceModernHandle {
    async fn attach(
        &mut self,
        pcie_topo: &mut Option<&mut PCIeTopology>,
        h: &dyn hypervisor,
    ) -> Result<()> {
        if let Some(state) = self.inner.lock().await.config.cleanup_state {
            let device_id = self.device_id().await;
            return Err(anyhow::Error::new(DeviceStateInDoubt::new(
                device_id,
                format!("QEMU cleanup remains pending: {state:?}"),
            )));
        }

        if !self.attach_pending {
            // Increase the attach count and skip the hypervisor operation if
            // another owner already attached this device.
            if self
                .increase_attach_count()
                .await
                .context("failed to increase attach count")?
            {
                return Ok(());
            }
        }

        // An independently owned backend completes this operation even if
        // this future is canceled. Mark it pending before the cancellation
        // point so a same-device retry joins that operation instead of
        // treating the reference count as proof of attachment.
        if h.block_device_add_is_independently_owned() {
            self.attach_pending = true;
        }

        let root_port_result = {
            let inner = self.inner.lock().await;
            uses_qemu_pcie_root_port(&inner.config, pcie_topo.as_deref())
        };
        let use_pcie_root_port = match root_port_result {
            Ok(use_root_port) => use_root_port,
            Err(error) => {
                self.decrease_attach_count().await?;
                return Err(error);
            }
        };
        if use_pcie_root_port {
            let device_id = self.device_id().await;
            let bus = pcie_topo
                .as_deref_mut()
                .ok_or_else(|| {
                    anyhow!("block device {device_id} requires a preconfigured PCIe root port")
                })?
                .reserve_existing_root_port_for_device(&device_id);
            match bus {
                Ok(bus) => self.inner.lock().await.config.pcie_root_port = Some(bus),
                Err(error) => {
                    self.decrease_attach_count().await?;
                    return Err(error);
                }
            }
        }

        match h.add_device(DeviceType::BlockModern(self.arc())).await {
            Ok(_) => {
                self.attach_pending = false;
                Ok(())
            }
            Err(error) if pending_cleanup_state(&error).is_some() => {
                let state = pending_cleanup_state(&error).expect("checked pending cleanup state");
                let device_id = self.device_id().await;
                self.inner.lock().await.config.cleanup_state = Some(state);
                self.attach_pending = true;
                Err(cleanup_state_in_doubt(device_id, error))
            }
            Err(error) if device_state_in_doubt(&error).is_some() => {
                self.attach_pending = true;
                Err(error)
            }
            Err(error)
                if self
                    .inner
                    .lock()
                    .await
                    .config
                    .retain_on_unclassified_attach_error =>
            {
                self.attach_pending = true;
                let device_id = self.device_id().await;
                Err(error.context(DeviceStateInDoubt::new(
                    device_id,
                    "unclassified block-device attach failure retained for reconciliation",
                )))
            }
            Err(error) => {
                self.attach_pending = false;
                error!(sl!(), "failed to attach block device: {:?}", error);
                self.decrease_attach_count().await?;
                if use_pcie_root_port {
                    let device_id = self.device_id().await;
                    if let Some(topology) = pcie_topo.as_deref_mut() {
                        topology.release_bus_for_device(&device_id)?;
                    }
                    self.inner.lock().await.config.pcie_root_port = None;
                }

                Err(error)
            }
        }
    }

    async fn detach(
        &mut self,
        pcie_topo: &mut Option<&mut PCIeTopology>,
        h: &dyn hypervisor,
    ) -> Result<Option<u64>> {
        // get the count of device detached, skip detach once it reaches the 0
        if self
            .decrease_attach_count()
            .await
            .context("failed to decrease attach count")?
        {
            return Ok(None);
        }
        if let Err(error) = h.remove_device(DeviceType::BlockModern(self.arc())).await {
            self.increase_attach_count().await?;
            if let Some(state) = pending_cleanup_state(&error) {
                let device_id = self.device_id().await;
                self.inner.lock().await.config.cleanup_state = Some(state);
                return Err(cleanup_state_in_doubt(device_id, error));
            }
            return Err(error);
        }
        self.inner.lock().await.config.cleanup_state = None;
        if self.inner.lock().await.config.pcie_root_port.is_some() {
            let device_id = self.device_id().await;
            let topology = pcie_topo.as_deref_mut().ok_or_else(|| {
                anyhow!("missing PCIe topology while detaching block device {device_id}")
            })?;
            topology.release_bus_for_device(&device_id)?;
            self.inner.lock().await.config.pcie_root_port = None;
        }
        Ok(Some(self.snapshot_config().await.index))
    }

    async fn update(&mut self, _h: &dyn hypervisor) -> Result<()> {
        // There's no need to do update for virtio-blk
        Ok(())
    }

    async fn get_device_info(&self) -> DeviceType {
        DeviceType::BlockModern(self.inner.clone())
    }

    async fn increase_attach_count(&mut self) -> Result<bool> {
        let mut guard = self.inner.lock().await;
        do_increase_count(&mut guard.attach_count)
    }

    async fn decrease_attach_count(&mut self) -> Result<bool> {
        let mut guard = self.inner.lock().await;
        do_decrease_count(&mut guard.attach_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_port_requirement_is_qemu_specific() {
        let config = BlockConfigModern {
            use_pcie_root_port: true,
            ..Default::default()
        };
        let qemu_topology = PCIeTopology {
            hypervisor_name: HYPERVISOR_QEMU.to_string(),
            ..Default::default()
        };
        let cloud_hypervisor_topology = PCIeTopology {
            hypervisor_name: "cloud-hypervisor".to_string(),
            ..Default::default()
        };

        assert!(uses_qemu_pcie_root_port(&config, Some(&qemu_topology)).unwrap());
        assert!(!uses_qemu_pcie_root_port(&config, Some(&cloud_hypervisor_topology)).unwrap());
        assert!(uses_qemu_pcie_root_port(&config, None).is_err());

        let unrelated_config = BlockConfigModern::default();
        assert!(!uses_qemu_pcie_root_port(&unrelated_config, None).unwrap());
    }

    #[test]
    fn incomplete_cleanup_uses_foundation_in_doubt_marker() {
        let state = BlockCleanupState {
            frontend: false,
            backend: true,
            fdsets: true,
        };
        let cleanup_error =
            BlockDeviceCleanupPending::with_state("drive-3", "injected incomplete cleanup", state);
        let error = cleanup_state_in_doubt("drive-3", cleanup_error.into());

        assert!(device_state_in_doubt(&error).is_some());
    }
}
