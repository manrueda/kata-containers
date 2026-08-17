// Copyright (c) 2024 Red Hat
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::device::pci_path::PciPath;
use crate::qemu::cmdline_generator::{CcwSubChannel, DeviceVirtioNet, Netdev, QMP_SOCKET_FILE};
use crate::utils::get_jailer_root;
use crate::BlockDeviceFormat;
use crate::VcpuThreadIds;

use anyhow::{anyhow, Context, Result};
use kata_types::config::hypervisor::{VIRTIO_BLK_CCW, VIRTIO_SCSI};
use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
use qapi_qmp::{
    self as qmp, BlockdevAioOptions, BlockdevDiscardOptions, BlockdevOptions, BlockdevOptionsBase,
    BlockdevOptionsGenericCOWFormat, BlockdevOptionsGenericFormat, BlockdevOptionsRaw, BlockdevRef,
    MigrationInfo, PciDeviceInfo,
};
use qapi_qmp::{migrate, migrate_incoming, migrate_set_capabilities};
use qapi_qmp::{MigrationCapability, MigrationCapabilityStatus};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::{Debug, Error, Formatter};
use std::io::{BufRead, BufReader, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use qapi_spec::Dictionary;
use std::thread;
use std::time::Instant;

/// QMP read timeout (milliseconds).
///
/// Historically this was 250ms and was re-applied after VFIO / DEVICE_DELETED
/// paths. Under concurrent boot pressure that short timeout surfaces as
/// `EAGAIN` / "Resource temporarily unavailable"; reusing the stream after a
/// partial read can then lose qapi framing.
const DEFAULT_QMP_READ_TIMEOUT: u64 = 5000;
/// Default overall deadline for QMP bring-up when the caller does not pass one.
pub const DEFAULT_QMP_CONNECT_DEADLINE_MS: u64 = 50000;

const DEVICE_DELETED_TIMEOUT: Duration = Duration::from_secs(10);
const QMP_RECONNECT_TIMEOUT: Duration = Duration::from_secs(5);

type QmpClient = qapi::Qmp<qapi::Stream<BufReader<UnixStream>, UnixStream>>;

fn is_transport_error(error: &qapi::ExecuteError) -> bool {
    matches!(error, qapi::ExecuteError::Io(_))
}

pub struct Qmp {
    qmp: QmpClient,
    socket_path: PathBuf,
    transport_poisoned: bool,

    // This is basically the output of
    // `cat /sys/devices/system/memory/block_size_bytes`
    // on the guest.  Note a slightly peculiar behaviour with relation to
    // the size of hotplugged memory blocks: if an amount of memory is being
    // hotplugged whose size is not an integral multiple of page size
    // (4k usually) hotplugging fails immediately.  However, if the amount
    // is fine wrt the page size *but* isn't wrt this "guest memory block size"
    // hotplugging apparently succeeds, even though none of the hotplugged
    // blocks seem ever to be onlined in the guest by kata-agent.
    // Store as u64 to keep up the convention of bytes being represented as u64.
    guest_memory_block_size: u64,

    // CCW subchannel for s390x device address management.
    // Transferred from QemuCmdLine after boot so that hotplug allocations
    // continue from where boot-time allocations left off.
    ccw_subchannel: Option<CcwSubChannel>,

    // Hot-plug slot tracking for cold-plugged pci-bridge-N devices. Mirrors
    // virtcontainers/types/bridges.go Bridge.Devices (slots 1..30).
    pci_bridge_devices: HashMap<String, HashMap<i64, String>>,
}

// We have to implement Debug since the Hypervisor trait requires it and Qmp
// is ultimately stored in one of Hypervisor's implementations (Qemu).
// We can't do it automatically since the type of Qmp::qmp isn't Debug.
impl Debug for Qmp {
    fn fmt(&self, _f: &mut Formatter<'_>) -> Result<(), Error> {
        Ok(())
    }
}

impl Qmp {
    /// Complete QMP bring-up on an already-dialed stream.
    ///
    /// Mirrors the transport setup used by the Go runtime's
    /// `setupEarlyQmpConnection`: dial once against the runtime-owned listener
    /// before QEMU is spawned, then complete startup on that same connection.
    /// This avoids creating and abandoning additional connections while QEMU
    /// is still initializing.
    pub fn from_stream(
        stream: UnixStream,
        socket_path: PathBuf,
        overall_timeout: Duration,
    ) -> Result<Self> {
        let (qmp_client, info) = initialize_qmp_stream(stream, overall_timeout)?;
        let qmp = Qmp {
            qmp: qmp_client,
            socket_path,
            transport_poisoned: false,
            guest_memory_block_size: 0,
            ccw_subchannel: None,
            pci_bridge_devices: HashMap::new(),
        };

        info!(sl!(), "QMP initialized: {:#?}", info);

        Ok(qmp)
    }

    fn reconnect(&mut self) -> Result<()> {
        if let Err(error) = self
            .qmp
            .inner_mut()
            .get_mut_write()
            .shutdown(Shutdown::Both)
        {
            debug!(sl!(), "failed to close poisoned QMP transport: {}", error);
        }

        let stream = UnixStream::connect(&self.socket_path)
            .with_context(|| format!("reconnect QMP socket {}", self.socket_path.display()))?;
        let (mut qmp, info) = initialize_qmp_stream(stream, QMP_RECONNECT_TIMEOUT)
            .context("reinitialize QMP transport")?;
        let pci = qmp
            .execute(&qapi_qmp::query_pci {})
            .context("query PCI state after QMP reconnect")?;

        self.pci_bridge_devices = collect_pci_bridge_devices(&pci);
        if self.ccw_subchannel.is_some() {
            warn!(sl!(), "disabling CCW hotplug after QMP transport recovery");
            self.ccw_subchannel = None;
        }

        self.qmp = qmp;
        self.transport_poisoned = false;
        info!(sl!(), "QMP reconnected: {:#?}", info);
        Ok(())
    }

    fn recover_transport(&mut self) {
        self.transport_poisoned = true;
        if let Err(error) = self.reconnect() {
            warn!(sl!(), "QMP reconnect failed: {:#}", error);
        }
    }

    fn ensure_transport(&mut self) -> Result<()> {
        if self.transport_poisoned {
            self.reconnect()?;
        }
        Ok(())
    }

    fn execute<C: qapi::Command>(&mut self, command: &C) -> qapi::ExecuteResult<C> {
        self.ensure_transport().map_err(|error| {
            qapi::ExecuteError::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                format!("QMP transport is unavailable: {error:#}"),
            ))
        })?;

        let result = self.qmp.execute(command);
        if matches!(&result, Err(qapi::ExecuteError::Io(_))) {
            // The command may have reached QEMU. Recover only for future
            // operations and return the original error without replaying it.
            self.recover_transport();
        }
        result
    }

    pub fn set_ccw_subchannel(&mut self, subchannel: CcwSubChannel) {
        self.ccw_subchannel = Some(subchannel);
    }

    /// Initialise PCI bridge slot maps for cold-plugged `pci-bridge-N` devices.
    pub fn init_pci_bridges(&mut self, count: u32) {
        for idx in 0..count {
            self.pci_bridge_devices
                .insert(format!("pci-bridge-{idx}"), HashMap::new());
        }
    }

    pub fn set_ignore_shared_memory_capability(&mut self) -> Result<()> {
        self.execute(&migrate_set_capabilities {
            capabilities: vec![MigrationCapabilityStatus {
                capability: MigrationCapability::x_ignore_shared,
                state: true,
            }],
        })
        .map(|_| ())
        .context("set ignore shared memory capability")
    }

    pub fn execute_migration(&mut self, uri: &str) -> Result<()> {
        self.execute(&migrate {
            channels: None,
            detach: None,
            resume: None,
            uri: Some(uri.to_string()),
        })
        .map(|_| ())
        .context("execute migration")
    }

    pub async fn execute_query_migrate(&mut self) -> Result<MigrationInfo> {
        let migrate_info = self.execute(&qmp::query_migrate {})?;

        Ok(migrate_info)
    }

    pub fn execute_migration_incoming(&mut self, uri: &str) -> Result<()> {
        self.execute(&migrate_incoming {
            channels: None,
            exit_on_error: None,
            uri: Some(uri.to_string()),
        })
        .map(|_| ())
        .context("execute migration incoming")
    }

    pub fn hotplug_vcpus(&mut self, vcpu_cnt: u32) -> Result<u32> {
        let hotpluggable_cpus = self.execute(&qmp::query_hotpluggable_cpus {})?;
        //info!(sl!(), "hotpluggable CPUs: {:#?}", hotpluggable_cpus);

        let mut hotplugged = 0;
        for vcpu in &hotpluggable_cpus {
            if hotplugged >= vcpu_cnt {
                break;
            }
            let core_id = match vcpu.props.core_id {
                Some(id) => id,
                None => {
                    warn!(sl!(), "hotpluggable vcpu has no core_id, skipping");
                    continue;
                }
            };
            if vcpu.qom_path.is_some() {
                info!(sl!(), "hotpluggable vcpu {} hotplugged already", core_id);
                continue;
            }
            let driver = &vcpu.type_;
            let mut cpu_args = Dictionary::new();
            cpu_args.insert("core-id".to_owned(), core_id.into());
            if !is_flat_cpu_topology(driver) {
                match (vcpu.props.socket_id, vcpu.props.thread_id) {
                    (Some(socket_id), Some(thread_id)) => {
                        cpu_args.insert("socket-id".to_owned(), socket_id.into());
                        cpu_args.insert("thread-id".to_owned(), thread_id.into());
                    }
                    (None, None) => {
                        warn!(sl!(), "hotpluggable vcpu {} has no socket_id and thread_id for driver {}, skipping", core_id, driver);
                        continue;
                    }
                    (None, _) => {
                        warn!(
                            sl!(),
                            "hotpluggable vcpu {} has no socket_id for driver {}, skipping",
                            core_id,
                            driver
                        );
                        continue;
                    }
                    (_, None) => {
                        warn!(
                            sl!(),
                            "hotpluggable vcpu {} has no thread_id for driver {}, skipping",
                            core_id,
                            driver
                        );
                        continue;
                    }
                }
            }
            self.execute(&qmp::device_add {
                bus: None,
                id: Some(vcpu_id_from_core_id(core_id)),
                driver: driver.clone(),
                arguments: cpu_args,
            })?;

            hotplugged += 1;
        }

        info!(
            sl!(),
            "Qmp::hotplug_vcpus(): hotplugged {}/{} vcpus", hotplugged, vcpu_cnt
        );

        Ok(hotplugged)
    }

    pub fn hotunplug_vcpus(&mut self, vcpu_cnt: u32) -> Result<u32> {
        let hotpluggable_cpus = self.execute(&qmp::query_hotpluggable_cpus {})?;

        let mut hotunplugged = 0;
        for vcpu in &hotpluggable_cpus {
            if hotunplugged >= vcpu_cnt {
                break;
            }
            let core_id = match vcpu.props.core_id {
                Some(id) => id,
                None => continue,
            };
            if vcpu.qom_path.is_none() {
                info!(sl!(), "hotpluggable vcpu {} not hotplugged yet", core_id);
                continue;
            }
            self.execute(&qmp::device_del {
                id: vcpu_id_from_core_id(core_id),
            })?;
            hotunplugged += 1;
        }

        info!(
            sl!(),
            "Qmp::hotunplug_vcpus(): hotunplugged {}/{} vcpus", hotunplugged, vcpu_cnt
        );

        Ok(hotunplugged)
    }

    pub fn set_guest_memory_block_size(&mut self, size: u64) {
        self.guest_memory_block_size = size;
    }

    pub fn guest_memory_block_size(&self) -> u64 {
        self.guest_memory_block_size
    }

    pub fn hotplugged_memory_size(&mut self) -> Result<u64> {
        let memory_frontends = self.execute(&qapi_qmp::query_memory_devices {})?;

        let mut hotplugged_mem_size = 0_u64;

        info!(
            sl!(),
            "hotplugged_memory_size(): iterating over memory devices"
        );
        for mem_frontend in &memory_frontends {
            match mem_frontend {
                qapi_qmp::MemoryDeviceInfo::dimm(dimm_info) => {
                    let id = match dimm_info.data.id {
                        Some(ref id) => id.clone(),
                        None => "".to_owned(),
                    };

                    info!(
                        sl!(),
                        "dimm id: {} size={}, hotplugged: {}",
                        id,
                        dimm_info.data.size,
                        dimm_info.data.hotplugged
                    );

                    if dimm_info.data.hotpluggable && dimm_info.data.hotplugged {
                        hotplugged_mem_size += dimm_info.data.size as u64;
                    }
                }
                qapi_qmp::MemoryDeviceInfo::virtio_mem(vm_info) => {
                    // For virtio-mem, the 'size' field is the requested-size
                    info!(
                        sl!(),
                        "virtio-mem device: requested-size={} bytes ({} MB)",
                        vm_info.data.size,
                        vm_info.data.size / (1024 * 1024)
                    );
                    hotplugged_mem_size += vm_info.data.size;
                }
                _ => {}
            }
        }

        info!(
            sl!(),
            "Total hotplugged memory: {} bytes ({} MB)",
            hotplugged_mem_size,
            hotplugged_mem_size / (1024 * 1024)
        );

        Ok(hotplugged_mem_size)
    }

    /// Hotplug memory into the VM.
    /// Automatically detects if virtio-mem is available and uses it; otherwise falls back to pc-dimm.
    pub fn hotplug_memory(&mut self, size: u64) -> Result<()> {
        // Query existing memory devices to detect virtio-mem
        let memory_devices = self.execute(&qapi_qmp::query_memory_devices {})?;

        // Check if virtio-mem device exists
        let has_virtio_mem = memory_devices
            .iter()
            .any(|memdev| matches!(memdev, qapi_qmp::MemoryDeviceInfo::virtio_mem(_)));

        if has_virtio_mem {
            self.hotplug_virtio_mem(size, memory_devices)
        } else {
            self.hotplug_pc_dimm(size, memory_devices)
        }
    }

    /// Hotplug memory using virtio-mem resize method.
    fn hotplug_virtio_mem(
        &mut self,
        size: u64,
        memory_devices: Vec<qapi_qmp::MemoryDeviceInfo>,
    ) -> Result<()> {
        info!(sl!(), "Detected virtio-mem device, using resize method");

        // Calculate current hotplugged memory from virtio-mem device
        let current_hotplugged_mb = memory_devices
            .iter()
            .filter_map(|memdev| {
                if let qapi_qmp::MemoryDeviceInfo::virtio_mem(vm_info) = memdev {
                    Some(vm_info.data.size / (1024 * 1024))
                } else {
                    None
                }
            })
            .sum::<u64>();

        let size_mb = size / (1024 * 1024);
        let new_total_mb = (current_hotplugged_mb + size_mb) as i64;

        info!(
            sl!(),
            "Hotplugging {} MB using virtio-mem (current: {} MB, new total: {} MB)",
            size_mb,
            current_hotplugged_mb,
            new_total_mb
        );

        self.resize_virtio_mem(new_total_mb)
    }

    /// Hotplug memory using pc-dimm device.
    fn hotplug_pc_dimm(
        &mut self,
        size: u64,
        memory_devices: Vec<qapi_qmp::MemoryDeviceInfo>,
    ) -> Result<()> {
        info!(sl!(), "No virtio-mem detected, using pc-dimm hotplug");

        let memdev_idx = memory_devices
            .into_iter()
            .filter(|memdev| {
                if let qapi_qmp::MemoryDeviceInfo::dimm(dimm_info) = memdev {
                    return dimm_info.data.hotpluggable && dimm_info.data.hotplugged;
                }
                false
            })
            .count();

        let memory_backend_id = format!("hotplugged-{memdev_idx}");

        let memory_backend = qmp::object_add(qapi_qmp::ObjectOptions::memory_backend_file {
            id: memory_backend_id.clone(),
            memory_backend_file: qapi_qmp::MemoryBackendFileProperties {
                base: qapi_qmp::MemoryBackendProperties {
                    dump: None,
                    host_nodes: None,
                    merge: None,
                    policy: None,
                    prealloc: None,
                    prealloc_context: None,
                    prealloc_threads: None,
                    reserve: None,
                    share: Some(true),
                    x_use_canonical_path_for_ramblock_id: None,
                    size,
                },
                align: None,
                discard_data: None,
                offset: None,
                pmem: None,
                readonly: None,
                mem_path: "/dev/shm".to_owned(),
                rom: None,
            },
        });
        self.execute(&memory_backend)?;

        let memory_frontend_id = format!("frontend-to-{memory_backend_id}");

        let mut mem_frontend_args = Dictionary::new();
        mem_frontend_args.insert("memdev".to_owned(), memory_backend_id.into());
        self.execute(&qmp::device_add {
            bus: None,
            id: Some(memory_frontend_id),
            driver: "pc-dimm".to_owned(),
            arguments: mem_frontend_args,
        })?;

        Ok(())
    }

    /// Cleanup virtio-mem resources on setup failure
    fn cleanup_virtio_mem_setup(&mut self, device_id: &str) {
        // Remove memory backend object
        let _ = self.execute(&qmp::object_del {
            id: "virtiomem".to_owned(),
        });

        // Remove CCW device slot
        if let Some(ccw) = self.ccw_subchannel.as_mut() {
            ccw.remove_device(device_id).ok();
        }
    }

    pub fn setup_virtio_mem(
        &mut self,
        default_memory: u32,
        default_maxmemory: u32,
        machine_type: &str,
        shared_fs: Option<&str>,
    ) -> Result<()> {
        // Calculate virtio-mem size: (default_maxmemory - default_memory) aligned to 4MB
        // default_maxmemory is already validated during sandbox initialization
        let diff_mb = default_maxmemory
            .checked_sub(default_memory)
            .ok_or_else(|| {
                anyhow!(
                    "default_maxmemory ({}) must be >= default_memory ({}) for virtio-mem setup",
                    default_maxmemory,
                    default_memory
                )
            })?;
        let size_mb = u64::from(diff_mb & !3u32);

        if size_mb == 0 {
            info!(sl!(), "virtio-mem size is 0, skipping setup");
            return Ok(());
        }

        // Validate machine type for virtio-mem support
        // TODO: support more architectures
        if machine_type != "s390-ccw-virtio" {
            return Err(anyhow!(
                "virtio-mem supports multiple architectures, the current implementation is only for s390x (s390-ccw-virtio). Current machine type: {}",
                machine_type
            ));
        }

        // Determine memory backend based on shared filesystem
        let uses_virtio_fs = shared_fs
            .map(|fs| fs == "virtio-fs" || fs == "virtio-fs-nydus")
            .unwrap_or(false);

        let (qomtype, mempath, share) = if uses_virtio_fs {
            ("memory-backend-file", "/dev/shm", true)
        } else {
            ("memory-backend-ram", "", false)
        };

        let size_bytes = size_mb * 1024 * 1024;

        // Allocate CCW slot and format address
        // Use same ID for both CCW subchannel tracking and QMP device
        let device_id = "virtiomem0";
        let ccw = self
            .ccw_subchannel
            .as_mut()
            .ok_or_else(|| anyhow!("CCW subchannel not initialized for s390x"))?;
        let slot = ccw
            .add_device(device_id)
            .map_err(|e| anyhow!("Failed to add CCW device: {:?}", e))?;
        let devno = ccw.address_format_ccw(slot);

        info!(
            sl!(),
            "Setting up virtio-mem-ccw: backend={}, path={}, share={}, devno={}",
            qomtype,
            if mempath.is_empty() { "none" } else { mempath },
            share,
            devno
        );

        // Helper to create common MemoryBackendProperties
        let create_backend_props = || qapi_qmp::MemoryBackendProperties {
            dump: None,
            host_nodes: None,
            merge: None,
            policy: None,
            prealloc: None,
            prealloc_context: None,
            prealloc_threads: None,
            reserve: None,
            share: Some(share),
            x_use_canonical_path_for_ramblock_id: None,
            size: size_bytes,
        };

        // STEP 1: Create memory backend
        let memory_backend = if mempath.is_empty() {
            qmp::object_add(qapi_qmp::ObjectOptions::memory_backend_ram {
                id: "virtiomem".to_owned(),
                memory_backend_ram: create_backend_props(),
            })
        } else {
            qmp::object_add(qapi_qmp::ObjectOptions::memory_backend_file {
                id: "virtiomem".to_owned(),
                memory_backend_file: qapi_qmp::MemoryBackendFileProperties {
                    base: create_backend_props(),
                    align: None,
                    discard_data: None,
                    offset: None,
                    pmem: None,
                    readonly: None,
                    rom: None,
                    mem_path: mempath.to_owned(),
                },
            })
        };

        // Execute backend creation with cleanup on error
        if let Err(e) = self.execute(&memory_backend) {
            if !is_transport_error(&e) {
                self.cleanup_virtio_mem_setup(device_id);
            }
            return if e.to_string().contains("Cannot allocate memory") {
                Err(anyhow!("Failed to allocate {} MB for virtio-mem: {}. \
                            Please use command 'echo 1 > /proc/sys/vm/overcommit_memory' to handle it.",
                            size_mb, e))
            } else {
                Err(e.into())
            };
        }

        // STEP 2: Create virtio-mem-ccw device
        let mut device_args = Dictionary::new();
        device_args.insert("memdev".to_owned(), "virtiomem".into());
        device_args.insert("devno".to_owned(), devno.into());

        if let Err(e) = self.execute(&qmp::device_add {
            bus: None,
            id: Some(device_id.to_owned()),
            driver: "virtio-mem-ccw".to_owned(),
            arguments: device_args,
        }) {
            if !is_transport_error(&e) {
                self.cleanup_virtio_mem_setup(device_id);
            }
            return Err(anyhow!("Failed to add virtio-mem-ccw device: {}", e));
        }

        info!(
            sl!(),
            "Successfully set up virtio-mem-ccw with max capacity {} MB", size_mb
        );
        Ok(())
    }

    /// Resize virtio-mem device to the specified size in MB.
    /// This uses QMP qom-set to change the requested-size property.
    ///
    /// # Arguments
    /// * `new_size_mb` - New size in MB for the virtio-mem device
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err` if resize fails or size is negative
    pub fn resize_virtio_mem(&mut self, new_size_mb: i64) -> Result<()> {
        // Validate and convert size from MB to bytes
        if new_size_mb < 0 {
            return Err(anyhow!(
                "cannot resize virtio-mem device to negative size ({}) memory",
                new_size_mb
            ));
        }
        let size_bytes = (new_size_mb as u64) * 1024 * 1024;

        info!(
            sl!(),
            "Resizing virtio-mem device to {} MB ({} bytes)", new_size_mb, size_bytes
        );

        // Use qom-set to change the requested-size property of virtiomem0
        self.execute(&qmp::qom_set {
            path: "virtiomem0".to_owned(),
            property: "requested-size".to_owned(),
            value: serde_json::json!(size_bytes),
        })?;

        info!(
            sl!(),
            "Successfully resized virtio-mem to {} MB", new_size_mb
        );
        Ok(())
    }

    pub fn hotunplug_memory(&mut self, size: i64) -> Result<()> {
        // Query existing memory devices to detect virtio-mem
        let memory_devices = self.execute(&qapi_qmp::query_memory_devices {})?;

        // Check if virtio-mem device exists
        let has_virtio_mem = memory_devices
            .iter()
            .any(|memdev| matches!(memdev, qapi_qmp::MemoryDeviceInfo::virtio_mem(_)));

        if has_virtio_mem {
            self.hotunplug_virtio_mem(size, memory_devices)
        } else {
            self.hotunplug_pc_dimm(size, memory_devices)
        }
    }

    /// Hotunplug memory using virtio-mem resize method.
    fn hotunplug_virtio_mem(
        &mut self,
        size: i64,
        memory_devices: Vec<qapi_qmp::MemoryDeviceInfo>,
    ) -> Result<()> {
        // Validate size is non-negative before casting
        if size < 0 {
            return Err(anyhow!(
                "cannot hotunplug negative memory size: {} bytes",
                size
            ));
        }

        // Get current size from virtio-mem device (this is the requested-size, not actual size)
        let current_size_bytes = memory_devices
            .iter()
            .filter_map(|memdev| {
                if let qapi_qmp::MemoryDeviceInfo::virtio_mem(vm_info) = memdev {
                    Some(vm_info.data.size)
                } else {
                    None
                }
            })
            .sum::<u64>();

        // size parameter is the amount to REMOVE (in bytes)
        let new_size_bytes = current_size_bytes.saturating_sub(size as u64);
        let new_size_mb = (new_size_bytes / (1024 * 1024)) as i64;

        info!(
            sl!(),
            "Decreasing virtio-mem by {} bytes (current: {} bytes, new: {} bytes = {} MB)",
            size,
            current_size_bytes,
            new_size_bytes,
            new_size_mb
        );

        self.resize_virtio_mem(new_size_mb)
    }

    /// Hotunplug memory using pc-dimm device removal.
    fn hotunplug_pc_dimm(
        &mut self,
        size: i64,
        memory_devices: Vec<qapi_qmp::MemoryDeviceInfo>,
    ) -> Result<()> {
        info!(sl!(), "No virtio-mem detected, using pc-dimm hotunplug");

        let frontend = memory_devices.into_iter().find(|memdev| {
            if let qapi_qmp::MemoryDeviceInfo::dimm(dimm_info) = memdev {
                let dimm_id = match dimm_info.data.id {
                    Some(ref id) => id,
                    None => return false,
                };
                if dimm_info.data.hotpluggable
                    && dimm_info.data.hotplugged
                    && dimm_info.data.size == size
                    && dimm_id.starts_with("frontend-to-hotplugged-")
                {
                    return true;
                }
            }
            false
        });

        if let Some(frontend) = frontend {
            if let qapi_qmp::MemoryDeviceInfo::dimm(frontend) = frontend {
                info!(sl!(), "found frontend to hotunplug: {:#?}", frontend);

                let frontend_id = match frontend.data.id {
                    Some(id) => id,
                    // This shouldn't happen as it was checked by find() above already.
                    None => return Err(anyhow!("memory frontend to hotunplug has empty id")),
                };

                let backend_id = match frontend_id.strip_prefix("frontend-to-") {
                    Some(id) => id.to_owned(),
                    // This shouldn't happen as it was checked by find() above already.
                    None => {
                        return Err(anyhow!(
                        "memory backend to hotunplug has id that doesn't have the expected prefix"
                    ))
                    }
                };

                self.execute(&qmp::device_del { id: frontend_id })?;
                self.execute(&qmp::object_del { id: backend_id })?;
            } else {
                // This shouldn't happen as it was checked by find() above already.
                return Err(anyhow!("memory device to hotunplug is not a dimm"));
            }
        } else {
            return Err(anyhow!(
                "couldn't find a suitable memory device to hotunplug"
            ));
        }
        Ok(())
    }

    fn find_free_slot(&mut self) -> Result<(String, i64)> {
        // Prefer in-memory bridge state (matches Go virtcontainers/types/bridges.go).
        let mut bridge_ids: Vec<&str> =
            self.pci_bridge_devices.keys().map(String::as_str).collect();
        bridge_ids.sort_by(|a, b| {
            let parse_idx = |id: &str| {
                id.strip_prefix("pci-bridge-")
                    .and_then(|n| n.parse::<u32>().ok())
            };
            match (parse_idx(a), parse_idx(b)) {
                (Some(ai), Some(bi)) => ai.cmp(&bi),
                _ => a.cmp(b),
            }
        });

        for bridge_id in bridge_ids {
            let occupied = self.pci_bridge_devices.get(bridge_id).unwrap();
            for slot in PCI_BRIDGE_FIRST_HOTPLUG_SLOT..=PCI_BRIDGE_MAX_CAPACITY {
                if !occupied.contains_key(&slot) {
                    info!(sl!(), "found free slot on bridge {}: {}", bridge_id, slot);
                    return Ok((bridge_id.to_string(), slot));
                }
            }
        }

        // Fallback: walk query-pci tree. Under OVMF, pcie-pci-bridge (pci-bridge-N)
        // is nested under rp-pci-bridge-N, not at the root of the PCI tree.
        let pci = self.execute(&qapi_qmp::query_pci {})?;
        for pci_info in &pci {
            if let Some((bus, slot)) = find_free_slot_in_pci_devices(&pci_info.devices) {
                info!(
                    sl!(),
                    "found free slot on bridge {} via query-pci: {}", bus, slot
                );
                return Ok((bus, slot));
            }
        }

        Err(anyhow!("no free slots on PCI bridges"))
    }

    fn record_pci_bridge_slot(&mut self, bridge_id: &str, slot: i64, device_id: &str) {
        if let Some(devices) = self.pci_bridge_devices.get_mut(bridge_id) {
            devices.insert(slot, device_id.to_owned());
        } else {
            warn!(
                sl!(),
                "record_pci_bridge_slot: bridge {} not in pci_bridge_devices, slot {} for device {} not tracked",
                bridge_id,
                slot,
                device_id
            );
        }
    }

    fn pass_fd(&mut self, fd: RawFd, fdname: &str) -> Result<()> {
        info!(sl!(), "passing fd {:?} as {}", fd, fdname);
        self.ensure_transport()
            .context("prepare QMP transport for FD passing")?;

        // Put the QMP 'getfd' command itself into the message payload.
        let getfd_cmd = format!(
            "{{ \"execute\": \"getfd\", \"arguments\": {{ \"fdname\": \"{fdname}\" }} }}\r\n"
        );
        let buf = getfd_cmd.as_bytes();
        let bufs = &mut [std::io::IoSlice::new(buf)][..];

        debug!(sl!(), "bufs: {:?}", bufs);

        let fds = [fd];
        let cmsg = [ControlMessage::ScmRights(&fds)];

        let sent = match sendmsg::<()>(
            self.qmp.inner_mut().get_mut_write().as_raw_fd(),
            bufs,
            &cmsg,
            MsgFlags::empty(),
            None,
        ) {
            Ok(0) => {
                self.recover_transport();
                return Err(anyhow!(
                    "failed to send QMP file descriptor {} ({}): zero-byte write",
                    fdname,
                    fd
                ));
            }
            Ok(sent) => sent,
            Err(error) => {
                self.recover_transport();
                return Err(anyhow!(
                    "failed to send QMP file descriptor {} ({}): {}",
                    fdname,
                    fd,
                    error
                ));
            }
        };
        if sent < buf.len() {
            if let Err(error) = self.qmp.inner_mut().get_mut_write().write_all(&buf[sent..]) {
                self.recover_transport();
                return Err(anyhow!(
                    "failed to finish QMP getfd command {} ({}): {}",
                    fdname,
                    fd,
                    error
                ));
            }
        }

        let result = self.qmp.read_response::<&qmp::getfd>();
        if matches!(&result, Err(qapi::ExecuteError::Io(_))) {
            self.recover_transport();
        }

        match result {
            Ok(_) => {
                info!(sl!(), "successfully passed {} ({})", fdname, fd);
                Ok(())
            }
            Err(err) => Err(anyhow!("failed to pass {} ({}): {}", fdname, fd, err)),
        }
    }

    pub fn hotplug_network_device(
        &mut self,
        netdev: &Netdev,
        virtio_net_device: &DeviceVirtioNet,
    ) -> Result<()> {
        let use_ccw_bus = crate::utils::uses_native_ccw_bus();
        let netdev_id = netdev.get_id().clone();

        let mut netdev_frontend_args = Dictionary::new();
        netdev_frontend_args.insert(
            "netdev".to_owned(),
            virtio_net_device.get_netdev_id().clone().into(),
        );
        netdev_frontend_args.insert("mac".to_owned(), virtio_net_device.get_mac_addr().into());
        netdev_frontend_args.insert("mq".to_owned(), true.into());

        let frontend_id = format!("frontend-{}", virtio_net_device.get_netdev_id());

        let pci_hotplug = if use_ccw_bus {
            let subchannel = self.ccw_subchannel.as_mut().ok_or_else(|| {
                anyhow!("CCW subchannel not available for virtio-net-ccw hotplug")
            })?;
            let slot = subchannel
                .add_device(&frontend_id)
                .map_err(|e| anyhow!("CCW subchannel add_device failed: {:?}", e))?;
            let devno = subchannel.address_format_ccw(slot);
            netdev_frontend_args.insert("devno".to_owned(), devno.into());
            None
        } else {
            let (bus, slot) = self.find_free_slot()?;
            netdev_frontend_args.insert("addr".to_owned(), format!("{slot:02}").into());
            // As the golang runtime documents the vectors computation, it's
            // 2N+2 vectors, N for tx queues, N for rx queues, 1 for config,
            // and one for possible control vq.  PCI-specific (MSI-X).
            netdev_frontend_args.insert(
                "vectors".to_owned(),
                (2 * virtio_net_device.get_num_queues() + 2).into(),
            );
            // Never force legacy (disable-modern) virtio on a hot-plugged PCI
            // NIC.  A legacy-only virtio device needs an I/O BAR, but the NIC is
            // hot-plugged behind a pcie-pci-bridge whose I/O window can be
            // exhausted (e.g. by the GPU root-port pool), making the I/O BAR
            // unassignable and the guest virtio-pci probe fail with -EIO.  The
            // Go runtime hot-plugs NICs with disable-modern=false for the same
            // reason; modern/transitional virtio uses MMIO and has no such
            // dependency.  disable-modern is only meaningful for cold-plug.
            Some((bus, slot))
        };

        let bus = pci_hotplug.as_ref().map(|(bus, _)| bus.clone());

        let mut fd_names = vec![];
        for (idx, fd) in netdev.get_fds().iter().enumerate() {
            let fdname = format!("fd{idx}");
            self.pass_fd(fd.as_raw_fd(), fdname.as_ref())?;
            fd_names.push(fdname);
        }

        let mut vhostfd_names = vec![];
        for (idx, fd) in netdev.get_vhostfds().iter().enumerate() {
            let vhostfdname = format!("vhostfd{idx}");
            self.pass_fd(fd.as_raw_fd(), vhostfdname.as_ref())?;
            vhostfd_names.push(vhostfdname);
        }

        self.execute(&qapi_qmp::netdev_add(qapi_qmp::Netdev::tap {
            id: netdev_id.clone(),
            tap: qapi_qmp::NetdevTapOptions {
                br: None,
                downscript: None,
                fd: None,
                // Logic in cmdline_generator::Netdev::new() seems to
                // guarantee that there will always be at least one fd.
                fds: Some(fd_names.join(",")),
                helper: None,
                ifname: None,
                poll_us: None,
                queues: None,
                script: None,
                sndbuf: None,
                vhost: if vhostfd_names.is_empty() {
                    None
                } else {
                    Some(true)
                },
                vhostfd: None,
                vhostfds: if vhostfd_names.is_empty() {
                    None
                } else {
                    Some(vhostfd_names.join(","))
                },
                vhostforce: None,
                vnet_hdr: None,
            },
        }))
        .map_err(|e| {
            if use_ccw_bus {
                if let Some(subchannel) = self.ccw_subchannel.as_mut() {
                    let _ = subchannel.remove_device(&frontend_id);
                }
            }

            anyhow!(e)
        })?;

        let device_add_result = self.execute(&qmp::device_add {
            bus,
            id: Some(frontend_id.clone()),
            driver: virtio_net_device.get_device_driver().clone(),
            arguments: netdev_frontend_args,
        });
        if let Err(e) = device_add_result {
            if is_transport_error(&e) {
                return Err(e.into());
            }

            if use_ccw_bus {
                if let Some(subchannel) = self.ccw_subchannel.as_mut() {
                    let _ = subchannel.remove_device(&frontend_id);
                }
            }

            if let Err(del_err) = self.execute(&qmp::netdev_del {
                id: netdev_id.clone(),
            }) {
                warn!(
                    sl!(),
                    "hotplug_network_device(): netdev_del failed for {} after device_add error {:?}: {:?}",
                    netdev_id,
                    e,
                    del_err
                );
            }

            return Err(e.into());
        }

        debug!(
            sl!(),
            "hotplug_network_device(): successfully added {}", frontend_id
        );

        if let Some((bridge_id, slot)) = pci_hotplug {
            self.record_pci_bridge_slot(&bridge_id, slot, &frontend_id);
        }

        Ok(())
    }

    pub fn get_device_by_qdev_id(&mut self, qdev_id: &str) -> Result<PciPath> {
        let format_str = |vec: &Vec<i64>| -> String {
            vec.iter()
                .map(|num| format!("{num:02x}"))
                .collect::<Vec<String>>()
                .join("/")
        };

        let mut path = vec![];
        let pci = self.execute(&qapi_qmp::query_pci {})?;
        for pci_info in pci.iter() {
            if let Some(_device) = get_pci_path_by_qdev_id(&pci_info.devices, qdev_id, &mut path) {
                let pci_path = format_str(&path);
                return PciPath::try_from(pci_path.as_str());
            }
        }

        Err(anyhow!("no target device found"))
    }

    /// Execute device_add for a block device. On failure, automatically
    /// rolls back the blockdev node added earlier to avoid orphaned resources.
    fn device_add_with_rollback(
        &mut self,
        node_name: &str,
        bus: Option<String>,
        driver: &str,
        arguments: Dictionary,
    ) -> Result<()> {
        if let Err(e) = self.execute(&qmp::device_add {
            bus,
            id: Some(node_name.to_owned()),
            driver: driver.to_owned(),
            arguments,
        }) {
            if is_transport_error(&e) {
                return Err(anyhow!("device_add {:?}", e));
            }

            if let Err(e) = self.execute(&qapi_qmp::blockdev_del {
                node_name: node_name.to_owned(),
            }) {
                warn!(
                    sl!(),
                    "device_add_with_rollback(): blockdev_del failed for {}: {:?}", node_name, e
                );
            }
            return Err(anyhow!("device_add {:?}", e));
        }
        Ok(())
    }

    fn wait_for_device_deleted(&mut self, device_id: &str, timeout: Duration) -> Result<()> {
        const POLL_INTERVAL: Duration = Duration::from_millis(100);
        let deadline = Instant::now() + timeout;

        self.qmp
            .inner_mut()
            .get_mut_write()
            .set_read_timeout(Some(timeout))?;

        let result = loop {
            if let Err(e) = self.execute(&qmp::query_version {}) {
                break Err(anyhow!(
                    "QMP transport failed while waiting for DEVICE_DELETED for {}: {}; device state is uncertain",
                    device_id,
                    e
                ));
            }

            let found = self.qmp.events().any(|event| {
                matches!(event, qapi_qmp::Event::DEVICE_DELETED { ref data, .. }
                    if data.device.as_deref() == Some(device_id))
            });
            if found {
                info!(
                    sl!(),
                    "The QMP received DEVICE_DELETED event for {}", device_id
                );
                break Ok(());
            }

            let now = Instant::now();
            if now >= deadline {
                break Err(anyhow!(
                    "timed out ({:?}) waiting for DEVICE_DELETED event for {}",
                    timeout,
                    device_id
                ));
            }
            thread::sleep(POLL_INTERVAL.min(deadline - now));
        };

        // Reset the default read timeout for subsequent QMP operations.
        // Failure here is non-fatal — a stale timeout only affects the next
        // QMP read, not the already-completed device removal.
        if let Err(e) = self
            .qmp
            .inner_mut()
            .get_mut_write()
            .set_read_timeout(Some(Duration::from_millis(DEFAULT_QMP_READ_TIMEOUT)))
        {
            warn!(sl!(), "Failed to reset read timeout: {:?}", e);
        }

        result
    }

    /// Hotplug block device:
    /// {
    ///     "execute": "blockdev-add",
    ///     "arguments": {
    ///         "node-name": "drive-0",
    ///         "file": {"driver": "file", "filename": "/path/to/block"},
    ///         "cache": {"direct": true},
    ///         "read-only": false
    ///     }
    /// }
    ///
    /// {
    ///     "execute": "device_add",
    ///     "arguments": {
    ///         "id": "drive-0",
    ///         "driver": "virtio-blk-pci",
    ///         "drive": "drive-0",
    ///         "addr":"0x0",
    ///         "bus": "pcie.1"
    ///     }
    /// }
    /// Hotplug SCSI block device
    /// # virtio-scsi0
    /// {"execute":"device_add","arguments":{"driver":"virtio-scsi-pci","id":"virtio-scsi0","bus":"bus1"}}
    /// {"return": {}}
    ///
    /// {"execute":"blockdev_add", "arguments": {"file":"/path/to/block.image","format":"qcow2","id":"virtio-scsi0"}}
    /// {"return": {}}
    /// {"execute":"device_add","arguments":{"driver":"scsi-hd","drive":"virtio-scsi0","id":"scsi_device_0","bus":"virtio-scsi1.0"}}
    /// {"return": {}}
    ///
    /// Hotplug virtio-blk-ccw block device on s390x
    /// # virtio-blk-ccw0
    /// {"execute":"blockdev_add", "arguments": {"file":"/path/to/block.image","format":"qcow2","id":"virtio-blk-ccw0"}}
    /// {"return": {}}
    /// {"execute":"device_add","arguments":{"driver":"virtio-blk-ccw","id":"virtio-blk-ccw0","drive":"virtio-blk-ccw0","devno":"fe.0.0005","share-rw":true}}
    /// {"return": {}}
    ///
    #[allow(clippy::too_many_arguments)]
    pub fn hotplug_block_device(
        &mut self,
        block_driver: &str,
        index: u64,
        path_on_host: &str,
        blkdev_aio: &str,
        is_direct: Option<bool>,
        is_readonly: bool,
        no_drop: bool,
        discard_unmap: bool,
        logical_block_size: u32,
        physical_block_size: u32,
        format: &BlockDeviceFormat,
        iothread: Option<&str>,
    ) -> Result<(Option<PciPath>, Option<String>)> {
        // `blockdev-add`
        let node_name = block_node_name(index);
        let discard_option = || discard_unmap.then_some(BlockdevDiscardOptions::unmap);

        let create_base_options = || qapi_qmp::BlockdevOptionsBase {
            auto_read_only: None,
            cache: if is_direct.is_none() {
                None
            } else {
                Some(qapi_qmp::BlockdevCacheOptions {
                    direct: is_direct,
                    no_flush: None,
                })
            },
            detect_zeroes: None,
            discard: discard_option(),
            force_share: None,
            node_name: None,
            read_only: Some(is_readonly),
        };

        let create_backend_options = || qapi_qmp::BlockdevOptionsFile {
            aio: Some(
                BlockdevAioOptions::from_str(blkdev_aio).unwrap_or(BlockdevAioOptions::io_uring),
            ),
            aio_max_batch: None,
            drop_cache: if !no_drop { None } else { Some(no_drop) },
            locking: None,
            pr_manager: None,
            x_check_cache_dropped: None,
            filename: path_on_host.to_owned(),
        };

        // Add block device backend and check if the file is a regular file or device
        let blockdev_file = if std::fs::metadata(path_on_host)?.is_file() {
            // Regular file
            qmp::BlockdevOptions::file {
                base: create_base_options(),
                file: create_backend_options(),
            }
        } else {
            // Host device (e.g., /dev/sdx, /dev/loopX)
            qmp::BlockdevOptions::host_device {
                base: create_base_options(),
                host_device: create_backend_options(),
            }
        };

        let blockdev_options = match format {
            BlockDeviceFormat::Raw => BlockdevOptions::raw {
                base: BlockdevOptionsBase {
                    detect_zeroes: None,
                    cache: None,
                    discard: discard_option(),
                    force_share: if is_readonly { Some(true) } else { None },
                    auto_read_only: None,
                    node_name: Some(node_name.clone()),
                    read_only: Some(is_readonly),
                },
                raw: BlockdevOptionsRaw {
                    base: BlockdevOptionsGenericFormat {
                        file: BlockdevRef::definition(Box::new(blockdev_file)),
                    },
                    offset: None,
                    size: None,
                },
            },
            BlockDeviceFormat::Vmdk => {
                info!(
                    sl!(),
                    "hotplug_block_device: using VMDK format driver for {} (read_only={}, force_share=true)",
                    path_on_host,
                    is_readonly
                );
                BlockdevOptions::vmdk {
                    base: BlockdevOptionsBase {
                        detect_zeroes: None,
                        cache: None,
                        discard: discard_option(),
                        force_share: Some(true),
                        auto_read_only: None,
                        node_name: Some(node_name.clone()),
                        read_only: Some(is_readonly),
                    },
                    vmdk: BlockdevOptionsGenericCOWFormat {
                        base: BlockdevOptionsGenericFormat {
                            file: BlockdevRef::definition(Box::new(blockdev_file)),
                        },
                        backing: None,
                    },
                }
            }
        };

        self.execute(&qapi_qmp::blockdev_add(blockdev_options))
            .map_err(|e| anyhow!("blockdev-add backend {:?}", e))
            .map(|_| ())?;

        // block device
        // `device_add`
        let mut blkdev_add_args = Dictionary::new();
        blkdev_add_args.insert("drive".to_owned(), node_name.clone().into());
        if discard_unmap && block_driver != VIRTIO_SCSI {
            blkdev_add_args.insert("discard".to_owned(), true.into());
        }

        if logical_block_size > 0 {
            blkdev_add_args.insert("logical_block_size".to_owned(), logical_block_size.into());
        }
        if physical_block_size > 0 {
            blkdev_add_args.insert("physical_block_size".to_owned(), physical_block_size.into());
        }

        if block_driver == VIRTIO_SCSI {
            // Helper closure to decode a flattened u16 SCSI index into an (ID, LUN) pair.
            let get_scsi_id_lun = |index_u16: u16| -> Result<(u8, u8)> {
                // Uses bitwise operations for efficient and clear conversion.
                let scsi_id = (index_u16 >> 8) as u8; // Equivalent to index_u16 / 256
                let lun = (index_u16 & 0xFF) as u8; // Equivalent to index_u16 % 256

                Ok((scsi_id, lun))
            };

            // Safely convert the u64 index to u16, ensuring it does not exceed `u16::MAX` (65535).
            let (scsi_id, lun) = get_scsi_id_lun(u16::try_from(index)?)?;
            let scsi_addr = format!("{scsi_id}:{lun}");

            // add SCSI frontend device
            blkdev_add_args.insert("scsi-id".to_string(), scsi_id.into());
            blkdev_add_args.insert("lun".to_string(), lun.into());
            if !is_readonly {
                blkdev_add_args.insert("share-rw".to_string(), true.into());
            }

            info!(
                sl!(),
                "hotplug_block_device(): device_add arguments: bus: {}, id: {}, driver: {}, blkdev_add_args: {:#?}",
                "scsi0.0",
                node_name,
                "scsi-hd",
                blkdev_add_args
            );
            self.device_add_with_rollback(
                &node_name,
                Some("scsi0.0".to_string()),
                "scsi-hd",
                blkdev_add_args,
            )?;

            info!(
                sl!(),
                "hotplug scsi block device return scsi address: {:?}", &scsi_addr
            );

            Ok((None, Some(scsi_addr)))
        } else if block_driver == VIRTIO_BLK_CCW {
            let subchannel = match self.ccw_subchannel.as_mut() {
                Some(sub) => sub,
                None => {
                    self.execute(&qapi_qmp::blockdev_del {
                        node_name: node_name.to_owned(),
                    })?;

                    return Err(anyhow!(
                        "CCW subchannel not available for virtio-blk-ccw hotplug"
                    ));
                }
            };

            let slot = match subchannel.add_device(&node_name) {
                Ok(s) => s,
                Err(e) => {
                    self.execute(&qapi_qmp::blockdev_del {
                        node_name: node_name.to_owned(),
                    })?;

                    return Err(anyhow!("CCW subchannel add_device failed: {:?}", e));
                }
            };
            let devno = subchannel.address_format_ccw(slot);
            let ccw_addr = subchannel.address_format_ccw_for_virt_server(slot);

            blkdev_add_args.insert("devno".to_owned(), devno.clone().into());
            if !is_readonly {
                blkdev_add_args.insert("share-rw".to_string(), true.into());
            }

            info!(
                sl!(),
                "hotplug_block_device(): CCW device_add: id: {}, driver: {}, blkdev_add_args: {:#?}, ccw_addr: {}",
                node_name,
                block_driver,
                blkdev_add_args,
                ccw_addr
            );
            if let Err(e) =
                self.device_add_with_rollback(&node_name, None, block_driver, blkdev_add_args)
            {
                if let Some(ref mut sub) = self.ccw_subchannel {
                    // Roll back CCW subchannel state if QMP device_add fails
                    let _ = sub.remove_device(&node_name);
                }
                return Err(e);
            }

            info!(
                sl!(),
                "hotplug CCW block device return ccw address: {:?}", &ccw_addr
            );

            Ok((None, Some(ccw_addr)))
        } else {
            let (bus, slot) = self.find_free_slot()?;
            blkdev_add_args.insert("addr".to_owned(), format!("{slot:02}").into());
            if !is_readonly {
                blkdev_add_args.insert("share-rw".to_string(), true.into());
            }

            // Add iothread parameter for virtio-blk devices if specified
            if let Some(iothread_id) = iothread {
                info!(
                    sl!(),
                    "hotplug_block_device(): attaching to iothread: {}", iothread_id
                );
                blkdev_add_args.insert("iothread".to_owned(), iothread_id.to_string().into());
            }

            info!(
                sl!(),
                "hotplug_block_device(): device_add arguments: bus: {}, id: {}, driver: {}, blkdev_add_args: {:#?}",
                bus,
                node_name,
                block_driver,
                blkdev_add_args
            );

            self.device_add_with_rollback(
                &node_name,
                Some(bus.clone()),
                block_driver,
                blkdev_add_args,
            )?;

            let pci_path = self
                .get_device_by_qdev_id(&node_name)
                .context("get device by qdev_id failed")?;
            self.record_pci_bridge_slot(&bus, slot, &node_name);
            info!(
                sl!(),
                "hotplug block device return pci path: {:?}", &pci_path
            );

            Ok((Some(pci_path), None))
        }
    }

    /// Hotunplug block device.
    pub fn hotunplug_block_device(&mut self, block_driver: &str, index: u64) -> Result<()> {
        let node_name = block_node_name(index);
        let mut frontend_deleted = false;

        let result = (|| -> Result<()> {
            // Remove the frontend device (virtio-blk-pci / scsi-hd / virtio-blk-ccw).
            self.execute(&qmp::device_del {
                id: node_name.clone(),
            })
            .map_err(|e| anyhow!("device_del for block device {}: {:?}", node_name, e))?;

            // device_del is asynchronous — wait for the guest to acknowledge removal
            // before tearing down the backend, otherwise blockdev_del may fail with
            // "Node is still in use".
            self.wait_for_device_deleted(&node_name, DEVICE_DELETED_TIMEOUT)
                .context("hotunplug_block_device(): waiting for DEVICE_DELETED")?;
            frontend_deleted = true;

            // Remove the blockdev backend node.
            self.execute(&qapi_qmp::blockdev_del {
                node_name: node_name.clone(),
            })
            .map_err(|e| anyhow!("blockdev_del for block device {}: {:?}", node_name, e))?;

            Ok(())
        })();

        if let Err(ref e) = result {
            warn!(
                sl!(),
                "hotunplug_block_device(): failed for {}, cleaning up CCW state: {:?}",
                node_name,
                e
            );
        }

        // Reuse a CCW subchannel only after frontend deletion was confirmed.
        // On timeout the QEMU state is ambiguous, so retaining the allocation
        // is the safe failure mode.
        if block_driver == VIRTIO_BLK_CCW && frontend_deleted {
            if let Some(ref mut subchannel) = self.ccw_subchannel {
                let _ = subchannel.remove_device(&node_name);
            }
        }

        result?;

        info!(
            sl!(),
            "hotunplug_block_device(): successfully removed {}", node_name
        );

        Ok(())
    }

    pub fn hotplug_vfio_device(
        &mut self,
        hostdev_id: &str,
        sysfs_path: &str,
        bus_slot_func: &str,
        driver: &str,
        bus: &str,
    ) -> Result<Option<PciPath>> {
        let mut vfio_args = Dictionary::new();

        let (vfio_device_add, early_return) = match driver {
            "vfio-ap" => {
                vfio_args.insert("sysfsdev".to_owned(), sysfs_path.to_string().into());
                let device_add = qmp::device_add {
                    driver: driver.to_string(),
                    bus: None,
                    id: Some(hostdev_id.to_string()),
                    arguments: vfio_args,
                };
                (device_add, Some(Ok(None)))
            }
            _ => {
                let bdf = if !bus_slot_func.starts_with("0000") {
                    format!("0000:{bus_slot_func}")
                } else {
                    bus_slot_func.to_owned()
                };
                vfio_args.insert("addr".to_owned(), "0x0".into());
                vfio_args.insert("host".to_owned(), bdf.into());
                vfio_args.insert("multifunction".to_owned(), "off".into());
                let device_add = qmp::device_add {
                    driver: driver.to_string(),
                    bus: Some(bus.to_string()),
                    id: Some(hostdev_id.to_string()),
                    arguments: vfio_args,
                };
                (device_add, None)
            }
        };
        info!(sl!(), "vfio_device_add: {:?}", vfio_device_add.clone());

        self.execute(&vfio_device_add)
            .map_err(|e| anyhow!("device_add vfio device failed {:?}", e))?;

        // For AP devices, we don't need to get the PCI path as it's not available.
        if let Some(result) = early_return {
            return result;
        }

        let pci_path = self
            .get_device_by_qdev_id(hostdev_id)
            .context("get device by qdev_id failed")?;

        Ok(Some(pci_path))
    }

    pub fn qmp_stop(&mut self) -> Result<()> {
        self.execute(&qmp::stop {})
            .map(|_| ())
            .context("execute qmp stop")
    }

    pub fn qmp_cont(&mut self) -> Result<()> {
        self.execute(&qmp::cont {})
            .map(|_| ())
            .context("execute qmp cont")
    }

    /// Get vCPU thread IDs through QMP query_cpus_fast.
    pub fn get_vcpu_thread_ids(&mut self) -> Result<VcpuThreadIds> {
        let vcpu_info = self
            .execute(&qmp::query_cpus_fast {})
            .map_err(|e| anyhow!("query_cpus_fast failed: {:?}", e))?;

        let vcpus: HashMap<u32, u32> = vcpu_info
            .iter()
            .map(|info| match info {
                qmp::CpuInfoFast::aarch64(cpu_info)
                | qmp::CpuInfoFast::alpha(cpu_info)
                | qmp::CpuInfoFast::arm(cpu_info)
                | qmp::CpuInfoFast::avr(cpu_info)
                | qmp::CpuInfoFast::cris(cpu_info)
                | qmp::CpuInfoFast::hppa(cpu_info)
                | qmp::CpuInfoFast::i386(cpu_info)
                | qmp::CpuInfoFast::loongarch64(cpu_info)
                | qmp::CpuInfoFast::m68k(cpu_info)
                | qmp::CpuInfoFast::microblaze(cpu_info)
                | qmp::CpuInfoFast::microblazeel(cpu_info)
                | qmp::CpuInfoFast::mips(cpu_info)
                | qmp::CpuInfoFast::mips64(cpu_info)
                | qmp::CpuInfoFast::mips64el(cpu_info)
                | qmp::CpuInfoFast::mipsel(cpu_info)
                | qmp::CpuInfoFast::or1k(cpu_info)
                | qmp::CpuInfoFast::ppc(cpu_info)
                | qmp::CpuInfoFast::ppc64(cpu_info)
                | qmp::CpuInfoFast::riscv32(cpu_info)
                | qmp::CpuInfoFast::riscv64(cpu_info)
                | qmp::CpuInfoFast::rx(cpu_info)
                | qmp::CpuInfoFast::sh4(cpu_info)
                | qmp::CpuInfoFast::sh4eb(cpu_info)
                | qmp::CpuInfoFast::sparc(cpu_info)
                | qmp::CpuInfoFast::sparc64(cpu_info)
                | qmp::CpuInfoFast::tricore(cpu_info)
                | qmp::CpuInfoFast::x86_64(cpu_info)
                | qmp::CpuInfoFast::xtensa(cpu_info)
                | qmp::CpuInfoFast::xtensaeb(cpu_info) => {
                    let vcpu_id = cpu_info.cpu_index as u32;
                    let thread_id = cpu_info.thread_id as u32;
                    (vcpu_id, thread_id)
                }
                qmp::CpuInfoFast::s390x { base, .. } => {
                    let vcpu_id = base.cpu_index as u32;
                    let thread_id = base.thread_id as u32;
                    (vcpu_id, thread_id)
                }
            })
            .collect();

        Ok(VcpuThreadIds { vcpus })
    }
}

fn vcpu_id_from_core_id(core_id: i64) -> String {
    format!("cpu-{core_id}")
}

/// Returns whether the CPU driver uses a flat topology.
/// s390x and ppc64le use a flat CPU topology.
fn is_flat_cpu_topology(driver: &str) -> bool {
    matches!(driver, "host-s390x-cpu" | "host-powerpc64-cpu")
}

const PCI_BRIDGE_MAX_CAPACITY: i64 = 30;
const PCI_BRIDGE_FIRST_HOTPLUG_SLOT: i64 = 1;

fn collect_pci_bridge_devices(pci: &[qapi_qmp::PciInfo]) -> HashMap<String, HashMap<i64, String>> {
    fn collect(devices: &[PciDeviceInfo], bridges: &mut HashMap<String, HashMap<i64, String>>) {
        for device in devices {
            if let Some(bridge) = &device.pci_bridge {
                if let Some(children) = &bridge.devices {
                    if device.qdev_id.starts_with("pci-bridge-") {
                        bridges.insert(
                            device.qdev_id.clone(),
                            children
                                .iter()
                                .map(|child| (child.slot, child.qdev_id.clone()))
                                .collect(),
                        );
                    }
                    collect(children, bridges);
                } else if device.qdev_id.starts_with("pci-bridge-") {
                    bridges.insert(device.qdev_id.clone(), HashMap::new());
                }
            }
        }
    }

    let mut bridges = HashMap::new();
    for bus in pci {
        collect(&bus.devices, &mut bridges);
    }
    bridges
}

fn free_slot_on_pci_bridge(pci_dev: &PciDeviceInfo) -> Option<i64> {
    if !pci_dev.qdev_id.starts_with("pci-bridge-") {
        return None;
    }

    let occupied_slots: Vec<i64> = pci_dev
        .pci_bridge
        .as_ref()
        .and_then(|bridge| bridge.devices.as_ref())
        .map(|devices| devices.iter().map(|dev| dev.slot).collect())
        .unwrap_or_default();

    (PCI_BRIDGE_FIRST_HOTPLUG_SLOT..=PCI_BRIDGE_MAX_CAPACITY)
        .find(|slot| !occupied_slots.contains(slot))
}

fn find_free_slot_in_pci_devices(devices: &[PciDeviceInfo]) -> Option<(String, i64)> {
    for pci_dev in devices {
        if let Some(slot) = free_slot_on_pci_bridge(pci_dev) {
            return Some((pci_dev.qdev_id.clone(), slot));
        }

        if let Some(ref bridge) = pci_dev.pci_bridge {
            if let Some(ref children) = bridge.devices {
                if let Some(found) = find_free_slot_in_pci_devices(children) {
                    return Some(found);
                }
            }
        }
    }

    None
}

// The get_pci_path_by_qdev_id function searches a device list for a device matching a given qdev_id,
// tracking the device's path. It recursively explores bridge devices and returns the found device along
// with its updated path.
pub fn get_pci_path_by_qdev_id(
    devices: &[PciDeviceInfo],
    qdev_id: &str,
    path: &mut Vec<i64>,
) -> Option<PciDeviceInfo> {
    for device in devices {
        path.push(device.slot);
        if device.qdev_id == qdev_id {
            return Some(device.clone());
        }

        if let Some(ref bridge) = device.pci_bridge {
            if let Some(ref bridge_devices) = bridge.devices {
                if let Some(found_device) = get_pci_path_by_qdev_id(bridge_devices, qdev_id, path) {
                    return Some(found_device);
                }
            }
        }

        // If the device not found, pop the current slot before moving to next device
        path.pop();
    }
    None
}

pub fn get_qmp_socket_path(sid: &str) -> String {
    [get_jailer_root(sid).as_str(), QMP_SOCKET_FILE].join("/")
}

/// Generate a blockdev node name based on the given index.
fn block_node_name(index: u64) -> String {
    format!("drive-{index}")
}

fn initialize_qmp_stream(
    stream: UnixStream,
    overall_timeout: Duration,
) -> Result<(QmpClient, qapi_qmp::QMP)> {
    if overall_timeout.is_zero() {
        return Err(anyhow!("invalid QMP timeout of 0"));
    }

    let deadline = Instant::now() + overall_timeout;
    stream
        .set_nonblocking(false)
        .context("set qmp stream blocking")?;

    let mut reader = BufReader::new(stream.try_clone().context("clone qmp stream")?);
    let info = read_qmp_greeting(&mut reader, deadline).context("read QMP greeting")?;
    negotiate_qmp_capabilities(&mut reader, &stream, deadline)
        .context("enable QMP capabilities")?;

    let mut qmp = qapi::Qmp::new(qapi::Stream::new(reader, stream));
    qmp.inner_mut()
        .get_mut_write()
        .set_read_timeout(Some(Duration::from_millis(DEFAULT_QMP_READ_TIMEOUT)))
        .context("set steady-state qmp read timeout")?;

    Ok((qmp, info))
}

/// Read the QMP greeting while tolerating asynchronous events emitted before
/// it. QEMU can emit events such as `RESUME` before the greeting when the
/// client is connected to the inherited listener before QEMU starts.
fn read_qmp_greeting(
    reader: &mut BufReader<UnixStream>,
    deadline: Instant,
) -> Result<qapi_qmp::QMP> {
    let mut line = Vec::new();
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| anyhow!("timed out waiting for QMP greeting"))?;
        reader
            .get_mut()
            .set_read_timeout(Some(
                remaining.min(Duration::from_millis(DEFAULT_QMP_READ_TIMEOUT)),
            ))
            .context("set QMP greeting read timeout")?;

        match reader.read_until(b'\n', &mut line) {
            Ok(0) => return Err(anyhow!("QMP peer closed before sending a greeting")),
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => return Err(e).context("read QMP greeting line"),
        }

        let value: serde_json::Value =
            serde_json::from_slice(&line).context("parse QMP greeting line")?;
        if value.get("QMP").is_some() {
            let capabilities: qapi_qmp::QapiCapabilities =
                serde_json::from_value(value).context("decode QMP greeting")?;
            return Ok(capabilities.QMP);
        }

        if let Some(event) = value.get("event") {
            debug!(
                sl!(),
                "ignoring QMP event before greeting: {}",
                event.as_str().unwrap_or("unknown")
            );
            line.clear();
            continue;
        }

        return Err(anyhow!("unexpected message before QMP greeting: {}", value));
    }
}

/// Enable QMP capabilities while tolerating startup events and a repeated
/// greeting. These messages have been observed with an early client under
/// concurrent QEMU startup and are not accepted by `qapi::Qmp::handshake()`.
fn negotiate_qmp_capabilities(
    reader: &mut BufReader<UnixStream>,
    mut writer: &UnixStream,
    deadline: Instant,
) -> Result<()> {
    writer
        .write_all(b"{\"execute\":\"qmp_capabilities\"}\n")
        .context("write qmp_capabilities command")?;
    writer.flush().context("flush qmp_capabilities command")?;

    let mut line = Vec::new();
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| anyhow!("QMP init timed out during capabilities negotiation"))?;
        reader
            .get_mut()
            .set_read_timeout(Some(
                remaining.min(Duration::from_millis(DEFAULT_QMP_READ_TIMEOUT)),
            ))
            .context("set QMP capabilities read timeout")?;

        match reader.read_until(b'\n', &mut line) {
            Ok(0) => return Err(anyhow!("QMP peer closed during capabilities negotiation")),
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => return Err(e).context("read qmp_capabilities response"),
        }

        let value: serde_json::Value =
            serde_json::from_slice(&line).context("parse qmp_capabilities response")?;
        if value.get("return").is_some() {
            return Ok(());
        }
        if let Some(error) = value.get("error") {
            return Err(anyhow!("qmp_capabilities failed: {}", error));
        }
        if value.get("event").is_some() || value.get("QMP").is_some() {
            debug!(
                sl!(),
                "ignoring asynchronous QMP startup message: {}", value
            );
            line.clear();
            continue;
        }

        return Err(anyhow!("unexpected qmp_capabilities response: {}", value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn qmp_socket_paths_are_absolute_and_sandbox_scoped() {
        let first = PathBuf::from(get_qmp_socket_path("sandbox-one"));
        let second = PathBuf::from(get_qmp_socket_path("sandbox-two"));

        assert!(first.is_absolute());
        assert!(second.is_absolute());
        assert_ne!(first, second);
        assert_eq!(first.file_name().unwrap(), QMP_SOCKET_FILE);
        assert_eq!(second.file_name().unwrap(), QMP_SOCKET_FILE);
    }

    fn complete_mock_handshake(conn: &mut UnixStream) {
        conn.write_all(
            br#"{"QMP":{"version":{"qemu":{"major":8,"minor":2,"micro":2},"package":"mock"},"capabilities":[]}}"#,
        )
        .unwrap();
        conn.write_all(b"\r\n").unwrap();

        let mut command = String::new();
        BufReader::new(conn.try_clone().unwrap())
            .read_line(&mut command)
            .unwrap();
        assert!(command.contains("qmp_capabilities"), "{}", command);
        conn.write_all(b"{\"return\":{}}\r\n").unwrap();
    }

    #[test]
    fn transport_failure_reconnects_without_replaying_command() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join(QMP_SOCKET_FILE);
        let listener = UnixListener::bind(&socket_path).unwrap();
        let client = UnixStream::connect(&socket_path).unwrap();

        let server = thread::spawn(move || {
            let mut commands = Vec::new();

            let (mut first, _) = listener.accept().unwrap();
            complete_mock_handshake(&mut first);
            let mut command = String::new();
            BufReader::new(first.try_clone().unwrap())
                .read_line(&mut command)
                .unwrap();
            commands.push(command);
            drop(first);

            let (mut second, _) = listener.accept().unwrap();
            complete_mock_handshake(&mut second);
            let mut reader = BufReader::new(second.try_clone().unwrap());

            let mut query_pci = String::new();
            reader.read_line(&mut query_pci).unwrap();
            commands.push(query_pci);
            second
                .write_all(
                    br#"{"return":[{"bus":0,"devices":[{"bus":0,"slot":1,"function":0,"class_info":{"class":1536},"id":{"device":1,"vendor":1},"irq_pin":0,"qdev_id":"pci-bridge-0","pci_bridge":{"bus":{"number":0,"secondary":1,"subordinate":1,"io_range":{"base":0,"limit":0},"memory_range":{"base":0,"limit":0},"prefetchable_range":{"base":0,"limit":0}},"devices":[{"bus":1,"slot":5,"function":0,"class_info":{"class":256},"id":{"device":2,"vendor":2},"irq_pin":0,"qdev_id":"drive-1","regions":[]}]},"regions":[]}]}]}"#,
                )
                .unwrap();
            second.write_all(b"\r\n").unwrap();

            let mut query_cpus = String::new();
            reader.read_line(&mut query_cpus).unwrap();
            commands.push(query_cpus);
            second.write_all(b"{\"return\":[]}\r\n").unwrap();

            commands
        });

        let mut qmp = Qmp::from_stream(client, socket_path, Duration::from_secs(3)).unwrap();
        qmp.qmp_stop()
            .expect_err("failed command must return its original transport error");

        assert!(!qmp.transport_poisoned);
        assert_eq!(qmp.pci_bridge_devices["pci-bridge-0"][&5], "drive-1");
        assert!(qmp.get_vcpu_thread_ids().unwrap().vcpus.is_empty());

        let commands = server.join().unwrap();
        assert_eq!(
            commands
                .iter()
                .filter(|command| command.contains("\"stop\""))
                .count(),
            1
        );
        assert_eq!(
            commands
                .iter()
                .filter(|command| command.contains("query-pci"))
                .count(),
            1
        );
        assert_eq!(
            commands
                .iter()
                .filter(|command| command.contains("query-cpus-fast"))
                .count(),
            1
        );
    }

    #[test]
    fn failed_reconnect_keeps_transport_poisoned() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join(QMP_SOCKET_FILE);
        let listener = UnixListener::bind(&socket_path).unwrap();
        let client = UnixStream::connect(&socket_path).unwrap();

        let server = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            complete_mock_handshake(&mut conn);
            let mut command = String::new();
            BufReader::new(conn.try_clone().unwrap())
                .read_line(&mut command)
                .unwrap();
            assert!(command.contains("\"stop\""), "{}", command);
        });

        let mut qmp = Qmp::from_stream(client, socket_path, Duration::from_secs(3)).unwrap();
        qmp.qmp_stop().expect_err("closed transport must fail");
        server.join().unwrap();
        assert!(qmp.transport_poisoned);

        let error = qmp
            .get_vcpu_thread_ids()
            .expect_err("poisoned transport must reconnect before any new command");
        assert!(
            format!("{error:#}").contains("QMP transport is unavailable"),
            "{:#}",
            error
        );
        assert!(qmp.transport_poisoned);
    }

    #[test]
    fn fd_passing_failure_reconnects_without_resending_fd() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join(QMP_SOCKET_FILE);
        let listener = UnixListener::bind(&socket_path).unwrap();
        let client = UnixStream::connect(&socket_path).unwrap();

        let server = thread::spawn(move || {
            let (mut first, _) = listener.accept().unwrap();
            complete_mock_handshake(&mut first);
            let mut getfd = [0_u8; 256];
            let getfd_len = first.read(&mut getfd).unwrap();
            let getfd = String::from_utf8_lossy(&getfd[..getfd_len]).into_owned();
            drop(first);

            let (mut second, _) = listener.accept().unwrap();
            complete_mock_handshake(&mut second);
            let mut query_pci = String::new();
            BufReader::new(second.try_clone().unwrap())
                .read_line(&mut query_pci)
                .unwrap();
            assert!(query_pci.contains("query-pci"), "{}", query_pci);
            second.write_all(b"{\"return\":[]}\r\n").unwrap();
            second
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();

            let mut unexpected = [0_u8; 256];
            let unexpected_len = match second.read(&mut unexpected) {
                Ok(length) => length,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    0
                }
                Err(error) => panic!("unexpected read error: {}", error),
            };
            (
                getfd,
                String::from_utf8_lossy(&unexpected[..unexpected_len]).into_owned(),
            )
        });

        let mut qmp = Qmp::from_stream(client, socket_path, Duration::from_secs(3)).unwrap();
        let (fd, _peer) = UnixStream::pair().unwrap();
        qmp.pass_fd(fd.as_raw_fd(), "network-fd")
            .expect_err("ambiguous getfd must not be replayed");

        let (first_command, reconnect_commands) = server.join().unwrap();
        assert!(first_command.contains("\"getfd\""), "{}", first_command);
        assert!(
            !reconnect_commands.contains("\"getfd\""),
            "{}",
            reconnect_commands
        );
    }

    fn mock_qmp_handshake(
        greeting_delay: Duration,
        fragment_delay: Option<Duration>,
        event_before_greeting: bool,
        repeat_greeting_before_response: bool,
    ) {
        let temp_dir = tempdir().unwrap();
        let sock_path = temp_dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let client = UnixStream::connect(&sock_path).unwrap();

        let server = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            thread::sleep(greeting_delay);

            if event_before_greeting {
                conn.write_all(br#"{"timestamp":{"seconds":1,"microseconds":0},"event":"RESUME"}"#)
                    .unwrap();
                conn.write_all(b"\r\n").unwrap();
            }

            let greeting = br#"{"QMP":{"version":{"qemu":{"major":8,"minor":2,"micro":2},"package":"mock"},"capabilities":[]}}"#;
            if let Some(delay) = fragment_delay {
                for chunk in greeting.chunks(7) {
                    conn.write_all(chunk).unwrap();
                    thread::sleep(delay);
                }
                conn.write_all(b"\r\n").unwrap();
            } else {
                conn.write_all(greeting).unwrap();
                conn.write_all(b"\r\n").unwrap();
            }

            let mut command = String::new();
            BufReader::new(conn.try_clone().unwrap())
                .read_line(&mut command)
                .unwrap();
            assert!(
                command.contains("qmp_capabilities"),
                "unexpected QMP command: {}",
                command
            );
            if repeat_greeting_before_response {
                conn.write_all(greeting).unwrap();
                conn.write_all(b"\r\n").unwrap();
            }
            conn.write_all(b"{\"return\":{}}\r\n").unwrap();
        });

        let qmp = Qmp::from_stream(client, sock_path, Duration::from_secs(3))
            .expect("QMP handshake should complete on the early-dialed connection");
        drop(qmp);
        server.join().unwrap();
    }

    #[test]
    fn early_dial_completes_delayed_qmp_handshake() {
        mock_qmp_handshake(Duration::from_millis(200), None, false, false);
    }

    #[test]
    fn early_dial_completes_fragmented_qmp_handshake() {
        mock_qmp_handshake(
            Duration::from_millis(50),
            Some(Duration::from_millis(10)),
            false,
            false,
        );
    }

    #[test]
    fn early_dial_accepts_event_before_qmp_greeting() {
        mock_qmp_handshake(Duration::from_millis(50), None, true, false);
    }

    #[test]
    fn early_dial_accepts_repeated_greeting_during_negotiation() {
        mock_qmp_handshake(Duration::from_millis(50), None, false, true);
    }

    #[test]
    fn early_dial_times_out_when_no_greeting() {
        let temp_dir = tempdir().unwrap();
        let sock_path = temp_dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let client = UnixStream::connect(&sock_path).unwrap();

        // Accept but never write a greeting.
        let server = thread::spawn(move || {
            let (conn, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(500));
            conn
        });

        let err = Qmp::from_stream(client, sock_path, Duration::from_millis(150))
            .expect_err("must time out");
        let err_msg = format!("{err:#}");
        assert!(
            err_msg.contains("timed out"),
            "unexpected error: {}",
            err_msg
        );

        drop(server.join().unwrap());
    }

    #[test]
    fn early_dial_fails_fast_when_listener_disappears() {
        let temp_dir = tempdir().unwrap();
        let sock_path = temp_dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let client = UnixStream::connect(&sock_path).unwrap();

        // Model QEMU exiting before accept after the runtime has closed its
        // listener copy. The queued client must be reset without waiting for
        // the full startup deadline.
        drop(listener);
        let started = Instant::now();
        Qmp::from_stream(client, sock_path, Duration::from_secs(3))
            .expect_err("closed listener must fail QMP startup");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "listener closure was not detected promptly"
        );
    }

    #[test]
    fn early_dial_survives_concurrent_handshakes() {
        const CONNECTIONS: usize = 64;

        let clients: Vec<_> = (0..CONNECTIONS)
            .map(|index| {
                thread::spawn(move || {
                    let greeting_delay = Duration::from_millis((index % 8) as u64 * 5);
                    let fragment_delay = (index % 3 == 0).then_some(Duration::from_millis(1));
                    mock_qmp_handshake(
                        greeting_delay,
                        fragment_delay,
                        index % 4 == 0,
                        index % 7 == 0,
                    );
                })
            })
            .collect();

        for client in clients {
            client.join().unwrap();
        }
    }
}
