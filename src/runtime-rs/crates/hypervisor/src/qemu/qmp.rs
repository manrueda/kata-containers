// Copyright (c) 2024 Red Hat
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::device::pci_path::PciPath;
use crate::qemu::block_source::{block_fd_node_name, block_fd_opaque, prepare_block_source};
use crate::qemu::cmdline_generator::{CcwSubChannel, DeviceVirtioNet, Netdev, QMP_SOCKET_FILE};
use crate::utils::get_jailer_root;
use crate::VcpuThreadIds;
use crate::VmdkConfig;
use crate::{BlockCleanupState, BlockDeviceCleanupPending};

use anyhow::{anyhow, Context, Result};
use kata_types::config::hypervisor::{VIRTIO_BLK_CCW, VIRTIO_SCSI};
use kata_types::rootless::is_rootless;
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
use std::io::BufReader;
use std::net::Shutdown;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::str::FromStr;
use std::time::Duration;

use qapi_spec::{Dictionary, ErrorClass};
use std::thread;
use std::time::Instant;

type QmpConnection = qapi::Qmp<qapi::Stream<BufReader<UnixStream>, UnixStream>>;

#[derive(serde::Serialize)]
struct QueryNamedBlockNodes {
    flat: bool,
}

impl qapi_spec::Command for QueryNamedBlockNodes {
    const NAME: &'static str = "query-named-block-nodes";
    const ALLOW_OOB: bool = false;
    type Ok = Vec<serde_json::Value>;
}

enum QmpResidue {
    Frontend,
    Backend,
}

enum ReconciledAdd {
    Applied,
    Absent(anyhow::Error),
}

/// default qmp connection read timeout
const DEFAULT_QMP_READ_TIMEOUT: u64 = 250;
const DEFAULT_QMP_INIT_READ_TIMEOUT: u64 = 5000;
const DEFAULT_QMP_CONNECT_DEADLINE_MS: u64 = 50000;
const DEFAULT_QMP_RETRY_SLEEP_MS: u64 = 50;

const DEVICE_DELETED_TIMEOUT: Duration = Duration::from_secs(10);

fn incomplete_block_cleanup(
    node_name: &str,
    primary_error: impl std::fmt::Display,
    cleanup_error: impl std::fmt::Display,
    state: BlockCleanupState,
) -> anyhow::Error {
    BlockDeviceCleanupPending::with_state(
        node_name,
        format!("{primary_error}; rollback failed: {cleanup_error}"),
        state,
    )
    .into()
}

fn cleanup_state_error(
    node_name: &str,
    error: impl std::fmt::Display,
    state: BlockCleanupState,
) -> anyhow::Error {
    BlockDeviceCleanupPending::with_state(node_name, error.to_string(), state).into()
}

fn find_fd_by_opaque(fdsets: &[qmp::FdsetInfo], opaque: &str) -> Option<qmp::AddfdInfo> {
    fdsets.iter().find_map(|fdset| {
        fdset.fds.iter().find_map(|fd| {
            (fd.opaque.as_deref() == Some(opaque)).then_some(qmp::AddfdInfo {
                fd: fd.fd,
                fdset_id: fdset.fdset_id,
            })
        })
    })
}

fn collect_block_fdsets(fdsets: Vec<qmp::FdsetInfo>) -> HashMap<String, Vec<i64>> {
    let mut block_fdsets: HashMap<String, Vec<i64>> = HashMap::new();
    for fdset in fdsets {
        for fd in fdset.fds {
            let Some(node_name) = fd.opaque.as_deref().and_then(block_fd_node_name) else {
                continue;
            };
            let ids = block_fdsets.entry(node_name.to_string()).or_default();
            if !ids.contains(&fdset.fdset_id) {
                ids.push(fdset.fdset_id);
            }
        }
    }
    block_fdsets
}

pub struct Qmp {
    qmp: QmpConnection,
    qmp_sock_path: Option<String>,

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

    // QMP fdsets backing hot-plugged block devices. Keep them until the
    // backend is removed because format drivers such as VMDK may reopen an
    // extent after blockdev-add completes.
    block_fdsets: HashMap<String, Vec<i64>>,
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
    pub fn new(qmp_sock_path: &str) -> Result<Self> {
        let try_new_once_fn = || -> Result<Qmp> {
            let mut qmp = Qmp {
                qmp: Self::connect(qmp_sock_path)?,
                qmp_sock_path: Some(qmp_sock_path.to_string()),
                guest_memory_block_size: 0,
                ccw_subchannel: None,
                pci_bridge_devices: HashMap::new(),
                block_fdsets: HashMap::new(),
            };
            qmp.refresh_block_fdsets()?;

            Ok(qmp)
        };

        let deadline = Instant::now() + Duration::from_millis(DEFAULT_QMP_CONNECT_DEADLINE_MS);
        let mut last_err: Option<anyhow::Error> = None;

        while Instant::now() < deadline {
            match try_new_once_fn() {
                Ok(qmp) => return Ok(qmp),
                Err(e) => {
                    debug!(sl!(), "QMP not ready yet: {}", e);
                    last_err = Some(e);
                    thread::sleep(Duration::from_millis(DEFAULT_QMP_RETRY_SLEEP_MS));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("QMP init timed out")))
            .with_context(|| format!("timed out waiting for QMP ready: {}", qmp_sock_path))
    }

    fn connect(qmp_sock_path: &str) -> Result<QmpConnection> {
        let stream = UnixStream::connect(qmp_sock_path)?;
        stream
            .set_read_timeout(Some(Duration::from_millis(DEFAULT_QMP_INIT_READ_TIMEOUT)))
            .context("set qmp read timeout")?;
        let mut qmp = qapi::Qmp::new(qapi::Stream::new(
            BufReader::new(stream.try_clone()?),
            stream,
        ));
        let info = qmp.handshake().context("qmp handshake failed")?;
        info!(sl!(), "QMP initialized: {:#?}", info);
        Ok(qmp)
    }

    fn reconnect(&mut self) -> Result<()> {
        let qmp_sock_path = self
            .qmp_sock_path
            .clone()
            .ok_or_else(|| anyhow!("QMP socket path is unavailable for reconnection"))?;
        let _ = self
            .qmp
            .inner_mut()
            .get_mut_write()
            .shutdown(Shutdown::Both);
        self.qmp = Self::connect(&qmp_sock_path)?;
        self.refresh_block_fdsets()
    }

    fn refresh_block_fdsets(&mut self) -> Result<()> {
        let fdsets = self
            .qmp
            .execute(&qmp::query_fdsets {})
            .context("query QEMU fdsets")?;
        self.block_fdsets = collect_block_fdsets(fdsets);
        Ok(())
    }

    fn refresh_block_fdsets_recovering(&mut self) -> Result<()> {
        match self.qmp.execute(&qmp::query_fdsets {}) {
            Ok(fdsets) => {
                self.block_fdsets = collect_block_fdsets(fdsets);
                Ok(())
            }
            Err(qapi::ExecuteError::Qapi(error)) => {
                Err(anyhow!("QEMU rejected query-fdsets: {error}"))
            }
            Err(qapi::ExecuteError::Io(_)) => self.reconnect(),
        }
    }

    pub fn verify_block_fdsets(&self, mut expected: HashMap<String, Vec<i64>>) -> Result<()> {
        let mut actual = self.block_fdsets.clone();
        for ids in expected.values_mut() {
            ids.sort_unstable();
        }
        for ids in actual.values_mut() {
            ids.sort_unstable();
        }
        if actual != expected {
            return Err(anyhow!(
                "QEMU startup block fdsets do not match the descriptors passed by the shim"
            ));
        }
        Ok(())
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
        self.qmp
            .execute(&migrate_set_capabilities {
                capabilities: vec![MigrationCapabilityStatus {
                    capability: MigrationCapability::x_ignore_shared,
                    state: true,
                }],
            })
            .map(|_| ())
            .context("set ignore shared memory capability")
    }

    pub fn execute_migration(&mut self, uri: &str) -> Result<()> {
        self.qmp
            .execute(&migrate {
                channels: None,
                detach: None,
                resume: None,
                uri: Some(uri.to_string()),
            })
            .map(|_| ())
            .context("execute migration")
    }

    pub async fn execute_query_migrate(&mut self) -> Result<MigrationInfo> {
        let migrate_info = self.qmp.execute(&qmp::query_migrate {})?;

        Ok(migrate_info)
    }

    pub fn execute_migration_incoming(&mut self, uri: &str) -> Result<()> {
        self.qmp
            .execute(&migrate_incoming {
                channels: None,
                exit_on_error: None,
                uri: Some(uri.to_string()),
            })
            .map(|_| ())
            .context("execute migration incoming")
    }

    pub fn hotplug_vcpus(&mut self, vcpu_cnt: u32) -> Result<u32> {
        let hotpluggable_cpus = self.qmp.execute(&qmp::query_hotpluggable_cpus {})?;
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
            self.qmp.execute(&qmp::device_add {
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
        let hotpluggable_cpus = self.qmp.execute(&qmp::query_hotpluggable_cpus {})?;

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
            self.qmp.execute(&qmp::device_del {
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
        let memory_frontends = self.qmp.execute(&qapi_qmp::query_memory_devices {})?;

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
        let memory_devices = self.qmp.execute(&qapi_qmp::query_memory_devices {})?;

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
        self.qmp.execute(&memory_backend)?;

        let memory_frontend_id = format!("frontend-to-{memory_backend_id}");

        let mut mem_frontend_args = Dictionary::new();
        mem_frontend_args.insert("memdev".to_owned(), memory_backend_id.into());
        self.qmp.execute(&qmp::device_add {
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
        let _ = self.qmp.execute(&qmp::object_del {
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
        if let Err(e) = self.qmp.execute(&memory_backend) {
            self.cleanup_virtio_mem_setup(device_id);
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

        if let Err(e) = self.qmp.execute(&qmp::device_add {
            bus: None,
            id: Some(device_id.to_owned()),
            driver: "virtio-mem-ccw".to_owned(),
            arguments: device_args,
        }) {
            self.cleanup_virtio_mem_setup(device_id);
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
        self.qmp.execute(&qmp::qom_set {
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
        let memory_devices = self.qmp.execute(&qapi_qmp::query_memory_devices {})?;

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

                self.qmp.execute(&qmp::device_del { id: frontend_id })?;
                self.qmp.execute(&qmp::object_del { id: backend_id })?;
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
        let pci = self.qmp.execute(&qapi_qmp::query_pci {})?;
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

        // Put the QMP 'getfd' command itself into the message payload.
        let getfd_cmd =
            format!("{{ \"execute\": \"getfd\", \"arguments\": {{ \"fdname\": \"{fdname}\" }} }}");
        let buf = getfd_cmd.as_bytes();
        let bufs = &mut [std::io::IoSlice::new(buf)][..];

        debug!(sl!(), "bufs: {:?}", bufs);

        let fds = [fd];
        let cmsg = [ControlMessage::ScmRights(&fds)];

        let result = sendmsg::<()>(
            self.qmp.inner_mut().get_mut_write().as_raw_fd(),
            bufs,
            &cmsg,
            MsgFlags::empty(),
            None,
        );
        info!(sl!(), "sendmsg() result: {:#?}", result);

        let result = self.qmp.read_response::<&qmp::getfd>();

        match result {
            Ok(_) => {
                info!(sl!(), "successfully passed {} ({})", fdname, fd);
                Ok(())
            }
            Err(err) => Err(anyhow!("failed to pass {} ({}): {}", fdname, fd, err)),
        }
    }

    fn pass_block_fd(&mut self, fd: RawFd, opaque: &str) -> Result<qmp::AddfdInfo> {
        let mut command = serde_json::json!({
            "execute": "add-fd",
            "arguments": { "opaque": opaque },
        })
        .to_string();
        command.push('\n');
        let bufs = &mut [std::io::IoSlice::new(command.as_bytes())][..];
        let fds = [fd];
        let cmsg = [ControlMessage::ScmRights(&fds)];

        sendmsg::<()>(
            self.qmp.inner_mut().get_mut_write().as_raw_fd(),
            bufs,
            &cmsg,
            MsgFlags::empty(),
            None,
        )
        .with_context(|| format!("send QEMU block fd for {opaque}"))?;

        match self.qmp.read_response::<&qmp::add_fd>() {
            Ok(info) => Ok(info),
            Err(qapi::ExecuteError::Qapi(error)) => {
                Err(anyhow!("QEMU rejected add-fd for {opaque}: {error}"))
            }
            Err(qapi::ExecuteError::Io(error)) => {
                let node_name = block_fd_node_name(opaque).unwrap_or("unknown-block-device");
                let state = BlockCleanupState {
                    frontend: false,
                    backend: false,
                    fdsets: true,
                };
                self.reconnect().map_err(|reconnect_error| {
                    cleanup_state_error(
                        node_name,
                        format!(
                            "add-fd response was lost: {error}; QMP reconnection failed: {reconnect_error}"
                        ),
                        state,
                    )
                })?;
                let fdsets = self.qmp.execute(&qmp::query_fdsets {}).map_err(|query_error| {
                    cleanup_state_error(
                        node_name,
                        format!(
                            "add-fd response was lost: {error}; fdset discovery failed: {query_error}"
                        ),
                        state,
                    )
                })?;
                self.block_fdsets = collect_block_fdsets(fdsets.clone());
                find_fd_by_opaque(&fdsets, opaque).ok_or_else(|| {
                    anyhow!(
                        "add-fd response was lost for {opaque}, and QEMU confirms the fd is absent"
                    )
                })
            }
        }
    }

    fn remove_block_fdsets(&mut self, node_name: &str) -> Result<()> {
        let Some(fdset_ids) = self.block_fdsets.remove(node_name) else {
            return Ok(());
        };

        self.remove_fdset_ids(node_name, fdset_ids)
    }

    fn remove_fdset_ids(&mut self, node_name: &str, fdset_ids: Vec<i64>) -> Result<()> {
        let mut failed = Vec::new();
        for fdset_id in fdset_ids {
            let result = self.qmp.execute(&qmp::remove_fd { fd: None, fdset_id });
            if matches!(&result, Err(qapi::ExecuteError::Io(_))) && self.reconnect().is_err() {
                failed.push(fdset_id);
                continue;
            }
            let fdsets = match self.qmp.execute(&qmp::query_fdsets {}) {
                Ok(fdsets) => fdsets,
                Err(error) => {
                    warn!(
                        sl!(),
                        "failed to verify QEMU fdset {} removal for {}: {:?}",
                        fdset_id,
                        node_name,
                        error
                    );
                    failed.push(fdset_id);
                    continue;
                }
            };
            let remains = fdsets.iter().any(|fdset| fdset.fdset_id == fdset_id);
            self.block_fdsets = collect_block_fdsets(fdsets);
            if remains {
                warn!(
                    sl!(),
                    "QEMU block fdset {} for {} remains after remove-fd: {:?}",
                    fdset_id,
                    node_name,
                    result
                );
                failed.push(fdset_id);
            }
        }
        if !failed.is_empty() {
            let ids = self.block_fdsets.entry(node_name.to_string()).or_default();
            ids.extend(failed.iter().copied());
            ids.sort_unstable();
            ids.dedup();
            return Err(anyhow!(
                "failed to remove QEMU fdsets {:?} for {}",
                failed,
                node_name
            ));
        }

        Ok(())
    }

    fn cleanup_block_backend(&mut self, node_name: &str) -> Result<()> {
        self.cleanup_pending_block_device(
            node_name,
            BlockCleanupState {
                frontend: false,
                backend: true,
                fdsets: self.block_fdsets.contains_key(node_name),
            },
        )
    }

    fn frontend_exists(&mut self, node_name: &str) -> Result<bool> {
        let devices = self.qmp.execute(&qapi_qmp::qom_list {
            path: "/machine/peripheral".to_string(),
        })?;
        Ok(devices.iter().any(|device| device.name == node_name))
    }

    fn block_backend_exists(&mut self, node_name: &str) -> Result<bool> {
        let nodes = self.qmp.execute(&QueryNamedBlockNodes { flat: true })?;
        Ok(nodes
            .iter()
            .any(|node| node.get("node-name").and_then(|name| name.as_str()) == Some(node_name)))
    }

    fn reconcile_ambiguous_add(
        &mut self,
        node_name: &str,
        operation: &str,
        error: std::io::Error,
        state: BlockCleanupState,
        residue: QmpResidue,
    ) -> Result<bool> {
        self.reconnect().map_err(|reconnect_error| {
            cleanup_state_error(
                node_name,
                format!(
                    "{operation} response was lost: {error}; QMP reconnection failed: {reconnect_error}"
                ),
                state,
            )
        })?;
        let discovered = match residue {
            QmpResidue::Frontend => self.frontend_exists(node_name),
            QmpResidue::Backend => self.block_backend_exists(node_name),
        };
        discovered.map_err(|query_error| {
            cleanup_state_error(
                node_name,
                format!(
                    "{operation} response was lost: {error}; state discovery failed: {query_error}"
                ),
                state,
            )
        })
    }

    fn reconcile_add_result(
        &mut self,
        node_name: &str,
        operation: &str,
        result: std::result::Result<qapi_spec::Empty, qapi::ExecuteError>,
        state: BlockCleanupState,
        residue: QmpResidue,
    ) -> Result<ReconciledAdd> {
        match result {
            Ok(_) => Ok(ReconciledAdd::Applied),
            Err(qapi::ExecuteError::Qapi(error)) => Ok(ReconciledAdd::Absent(anyhow!(
                "QEMU rejected {operation} for {node_name}: {error}"
            ))),
            Err(qapi::ExecuteError::Io(error)) => {
                if self.reconcile_ambiguous_add(node_name, operation, error, state, residue)? {
                    Ok(ReconciledAdd::Applied)
                } else {
                    Ok(ReconciledAdd::Absent(anyhow!(
                        "{operation} response was lost for {node_name}, and QEMU confirms the resource is absent"
                    )))
                }
            }
        }
    }

    fn cleanup_pending_block_device(
        &mut self,
        node_name: &str,
        state: BlockCleanupState,
    ) -> Result<()> {
        self.cleanup_pending_block_device_with_timeout(node_name, state, DEVICE_DELETED_TIMEOUT)
    }

    fn cleanup_pending_block_device_with_timeout(
        &mut self,
        node_name: &str,
        mut state: BlockCleanupState,
        device_deleted_timeout: Duration,
    ) -> Result<()> {
        state.fdsets |= self.block_fdsets.contains_key(node_name);

        if state.frontend {
            match self.qmp.execute(&qmp::device_del {
                id: node_name.to_string(),
            }) {
                Ok(_) => {
                    if let Err(wait_err) =
                        self.wait_for_device_deleted(node_name, device_deleted_timeout)
                    {
                        if let Err(reconnect_error) = self.reconnect() {
                            return Err(cleanup_state_error(
                                node_name,
                                format!(
                                    "{wait_err}; QMP reconnection before frontend discovery failed: {reconnect_error}"
                                ),
                                state,
                            ));
                        }
                        match self.frontend_exists(node_name) {
                            Ok(false) => state.frontend = false,
                            Ok(true) => {
                                return Err(cleanup_state_error(node_name, wait_err, state));
                            }
                            Err(query_err) => {
                                return Err(cleanup_state_error(
                                    node_name,
                                    format!(
                                    "{wait_err}; failed to verify frontend removal: {query_err}"
                                ),
                                    state,
                                ));
                            }
                        }
                    } else {
                        state.frontend = false;
                    }
                }
                Err(device_del_err) => {
                    if matches!(
                        &device_del_err,
                        qapi::ExecuteError::Qapi(qapi_error)
                            if qapi_error.class == ErrorClass::DeviceNotFound
                    ) {
                        state.frontend = false;
                    } else {
                        if matches!(&device_del_err, qapi::ExecuteError::Io(_)) {
                            self.reconnect().map_err(|reconnect_error| {
                                cleanup_state_error(
                                    node_name,
                                    format!(
                                        "{device_del_err}; QMP reconnection before frontend discovery failed: {reconnect_error}"
                                    ),
                                    state,
                                )
                            })?;
                        }
                        match self.frontend_exists(node_name) {
                            Ok(false) => state.frontend = false,
                            Ok(true) => {
                                return Err(cleanup_state_error(node_name, device_del_err, state));
                            }
                            Err(query_err) => {
                                return Err(cleanup_state_error(
                                    node_name,
                                    format!(
                                        "{device_del_err}; failed to verify frontend state: {query_err}"
                                    ),
                                    state,
                                ));
                            }
                        }
                    }
                }
            }
        }

        if state.backend {
            if let Err(blockdev_del_err) = self.qmp.execute(&qapi_qmp::blockdev_del {
                node_name: node_name.to_string(),
            }) {
                if matches!(
                    &blockdev_del_err,
                    qapi::ExecuteError::Qapi(qapi_error)
                        if qapi_error.class == ErrorClass::DeviceNotFound
                ) {
                    state.backend = false;
                } else {
                    if matches!(&blockdev_del_err, qapi::ExecuteError::Io(_)) {
                        self.reconnect().map_err(|reconnect_error| {
                            cleanup_state_error(
                                node_name,
                                format!(
                                    "{blockdev_del_err}; QMP reconnection before backend discovery failed: {reconnect_error}"
                                ),
                                state,
                            )
                        })?;
                    }
                    match self.block_backend_exists(node_name) {
                        Ok(false) => {}
                        Ok(true) => {
                            return Err(cleanup_state_error(node_name, blockdev_del_err, state));
                        }
                        Err(query_err) => {
                            return Err(cleanup_state_error(
                                node_name,
                                format!(
                                    "{blockdev_del_err}; failed to verify backend state: {query_err}"
                                ),
                                state,
                            ));
                        }
                    }
                }
            }
            state.backend = false;
        }

        if state.fdsets {
            self.refresh_block_fdsets_recovering()
                .map_err(|error| cleanup_state_error(node_name, error, state))?;
            if !self.block_fdsets.contains_key(node_name) {
                state.fdsets = false;
            }
            if let Err(err) = self.remove_block_fdsets(node_name) {
                state.fdsets = self.block_fdsets.contains_key(node_name);
                return Err(cleanup_state_error(node_name, err, state));
            }
            state.fdsets = false;
        }

        if !state.is_complete() {
            return Err(cleanup_state_error(
                node_name,
                "cleanup state remains incomplete",
                state,
            ));
        }

        Ok(())
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

        self.qmp
            .execute(&qapi_qmp::netdev_add(qapi_qmp::Netdev::tap {
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

        let device_add_result = self.qmp.execute(&qmp::device_add {
            bus,
            id: Some(frontend_id.clone()),
            driver: virtio_net_device.get_device_driver().clone(),
            arguments: netdev_frontend_args,
        });
        if let Err(e) = device_add_result {
            if use_ccw_bus {
                if let Some(subchannel) = self.ccw_subchannel.as_mut() {
                    let _ = subchannel.remove_device(&frontend_id);
                }
            }

            if let Err(del_err) = self.qmp.execute(&qmp::netdev_del {
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
        let pci = self.qmp.execute(&qapi_qmp::query_pci {})?;
        for pci_info in pci.iter() {
            if let Some(_device) = get_pci_path_by_qdev_id(&pci_info.devices, qdev_id, &mut path) {
                let pci_path = format_str(&path);
                return PciPath::try_from(pci_path.as_str());
            }
        }

        Err(anyhow!("no target device found"))
    }

    fn get_root_port_device_path(&mut self, qdev_id: &str, root_port: &str) -> Result<PciPath> {
        let device_path = format!("/machine/peripheral/{qdev_id}");
        let parent_bus = self
            .qmp
            .execute(&qapi_qmp::qom_get {
                path: device_path.clone(),
                property: "parent_bus".to_string(),
            })?
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow!("QEMU returned a non-string parent bus for {qdev_id}"))?;
        let expected_parent = format!("/machine/peripheral/{root_port}/{root_port}");
        if parent_bus != expected_parent {
            return Err(anyhow!(
                "QEMU attached {qdev_id} to {parent_bus}, expected {expected_parent}"
            ));
        }

        let device_addr = self
            .qmp
            .execute(&qapi_qmp::qom_get {
                path: device_path,
                property: "addr".to_string(),
            })?
            .as_i64()
            .ok_or_else(|| anyhow!("QEMU returned a non-integer PCI address for {qdev_id}"))?;
        let root_addr = self
            .qmp
            .execute(&qapi_qmp::qom_get {
                path: format!("/machine/peripheral/{root_port}"),
                property: "addr".to_string(),
            })?
            .as_i64()
            .ok_or_else(|| anyhow!("QEMU returned a non-integer PCI address for {root_port}"))?;
        if device_addr < 0 || root_addr < 0 {
            return Err(anyhow!(
                "QEMU returned a negative PCI address for {qdev_id} or {root_port}"
            ));
        }

        PciPath::try_from(format!("{:02x}/{:02x}", root_addr >> 3, device_addr >> 3).as_str())
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
        let result = self.qmp.execute(&qmp::device_add {
            bus,
            id: Some(node_name.to_owned()),
            driver: driver.to_owned(),
            arguments,
        });
        let state = BlockCleanupState::attached(self.block_fdsets.contains_key(node_name));
        let error = match self.reconcile_add_result(
            node_name,
            "device_add",
            result,
            state,
            QmpResidue::Frontend,
        )? {
            ReconciledAdd::Applied => return Ok(()),
            ReconciledAdd::Absent(error) => error,
        };
        if let Err(cleanup_error) = self.cleanup_block_backend(node_name) {
            return Err(cleanup_error.context(error.to_string()));
        }
        Err(error)
    }

    fn wait_for_device_deleted(&mut self, device_id: &str, timeout: Duration) -> Result<()> {
        const POLL_INTERVAL: Duration = Duration::from_millis(100);
        let deadline = Instant::now() + timeout;

        let result = loop {
            let now = Instant::now();
            if now >= deadline {
                break Err(anyhow!(
                    "timed out ({:?}) waiting for DEVICE_DELETED event for {}",
                    timeout,
                    device_id
                ));
            }
            if let Err(error) = self
                .qmp
                .inner_mut()
                .get_mut_write()
                .set_read_timeout(Some(POLL_INTERVAL.min(deadline - now)))
            {
                break Err(error.into());
            }

            if let Err(poll_error) = self.qmp.nop() {
                warn!(
                    sl!(),
                    "The QMP nop() failed for {}: {:?}", device_id, poll_error
                );
                if let Err(reconnect_error) = self.reconnect() {
                    break Err(anyhow!(
                        "QMP deletion poll failed for {device_id}: {poll_error}; QMP reconnection failed: {reconnect_error}"
                    ));
                }

                let now = Instant::now();
                if now >= deadline {
                    break Err(anyhow!(
                        "timed out ({:?}) waiting for DEVICE_DELETED event for {}",
                        timeout,
                        device_id
                    ));
                }
                if let Err(error) = self
                    .qmp
                    .inner_mut()
                    .get_mut_write()
                    .set_read_timeout(Some(deadline - now))
                {
                    break Err(error.into());
                }
                match self.frontend_exists(device_id) {
                    Ok(false) => break Ok(()),
                    Ok(true) => continue,
                    Err(query_error) => {
                        break Err(anyhow!(
                            "QMP deletion poll failed for {device_id}: {poll_error}; failed to verify frontend state after reconnection: {query_error}"
                        ));
                    }
                }
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
        vmdk: Option<&VmdkConfig>,
        iothread: Option<&str>,
        pcie_root_port: Option<&str>,
    ) -> Result<(Option<PciPath>, Option<String>)> {
        // `blockdev-add`
        let node_name = block_node_name(index);
        if self.block_fdsets.contains_key(&node_name) {
            return Err(anyhow!("duplicate QEMU block device ID {node_name}"));
        }
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

        let mut fdset_ids = Vec::new();
        let prepared_source = match prepare_block_source(
            path_on_host,
            vmdk,
            is_readonly,
            is_direct.unwrap_or(false),
            |file, label| {
                let opaque = block_fd_opaque(&node_name, label);
                let info = self.pass_block_fd(file.as_raw_fd(), &opaque)?;
                fdset_ids.push(info.fdset_id);
                Ok(format!("/dev/fdset/{}", info.fdset_id))
            },
        ) {
            Ok(source) => source,
            Err(err) => {
                if err.downcast_ref::<BlockDeviceCleanupPending>().is_some() {
                    return Err(err);
                }
                if let Err(cleanup_err) = self.remove_fdset_ids(&node_name, fdset_ids) {
                    return Err(incomplete_block_cleanup(
                        &node_name,
                        err,
                        cleanup_err,
                        BlockCleanupState {
                            frontend: false,
                            backend: false,
                            fdsets: true,
                        },
                    ));
                }
                return Err(err);
            }
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
            filename: prepared_source.filename.clone(),
        };

        // Add block device backend and check if the file is a regular file or device
        let blockdev_file = if prepared_source.is_regular_file {
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

        let blockdev_options = if vmdk.is_none() {
            BlockdevOptions::raw {
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
            }
        } else {
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
        };

        if !fdset_ids.is_empty() {
            self.block_fdsets.insert(node_name.clone(), fdset_ids);
        }

        let blockdev_result = self.qmp.execute(&qapi_qmp::blockdev_add(blockdev_options));
        let state = BlockCleanupState {
            frontend: false,
            backend: true,
            fdsets: self.block_fdsets.contains_key(&node_name),
        };
        let blockdev_error = match self.reconcile_add_result(
            &node_name,
            "blockdev-add",
            blockdev_result,
            state,
            QmpResidue::Backend,
        )? {
            ReconciledAdd::Applied => None,
            ReconciledAdd::Absent(error) => Some(error),
        };
        if let Some(err) = blockdev_error {
            if let Err(cleanup_err) = self.remove_block_fdsets(&node_name) {
                return Err(incomplete_block_cleanup(
                    &node_name,
                    err,
                    cleanup_err,
                    BlockCleanupState {
                        frontend: false,
                        backend: false,
                        fdsets: true,
                    },
                ));
            }
            return Err(anyhow!("blockdev-add backend {:?}", err));
        }

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
                    let error = anyhow!("CCW subchannel not available for virtio-blk-ccw hotplug");
                    if let Err(cleanup_err) = self.cleanup_block_backend(&node_name) {
                        return Err(cleanup_err.context(error.to_string()));
                    }
                    return Err(error);
                }
            };

            let slot = match subchannel.add_device(&node_name) {
                Ok(s) => s,
                Err(e) => {
                    let error = anyhow!("CCW subchannel add_device failed: {:?}", e);
                    if let Err(cleanup_err) = self.cleanup_block_backend(&node_name) {
                        return Err(cleanup_err.context(error.to_string()));
                    }
                    return Err(error);
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
            let (bus, slot, track_bridge_slot) =
                match select_block_pci_target(pcie_root_port, || self.find_free_slot()) {
                    Ok(value) => value,
                    Err(err) => {
                        if let Err(cleanup_err) = self.cleanup_block_backend(&node_name) {
                            return Err(cleanup_err.context(err.to_string()));
                        }
                        return Err(err);
                    }
                };
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

            let pci_path = if let Some(root_port) = pcie_root_port {
                self.get_root_port_device_path(&node_name, root_port)
            } else {
                self.get_device_by_qdev_id(&node_name)
            }
            .context("get device by qdev_id failed");
            let cleanup_state =
                BlockCleanupState::attached(self.block_fdsets.contains_key(&node_name));
            let pci_path = complete_pci_path_lookup(&node_name, pci_path, cleanup_state, || {
                self.hotunplug_block_device(block_driver, index, Some(cleanup_state))
            })?;
            if track_bridge_slot {
                self.record_pci_bridge_slot(&bus, slot, &node_name);
            }
            info!(
                sl!(),
                "hotplug block device return pci path: {:?}", &pci_path
            );

            Ok((Some(pci_path), None))
        }
    }

    /// Hotunplug block device.
    pub fn hotunplug_block_device(
        &mut self,
        block_driver: &str,
        index: u64,
        cleanup_state: Option<BlockCleanupState>,
    ) -> Result<()> {
        let node_name = block_node_name(index);

        let state = cleanup_state.unwrap_or_else(|| {
            BlockCleanupState::attached(self.block_fdsets.contains_key(&node_name))
        });
        let result = self.cleanup_pending_block_device(&node_name, state);
        if result.is_ok() && block_driver == VIRTIO_BLK_CCW {
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

        // We've chosen to set a 5-second read timeout on Unix sockets for QMP operations. We consider set_read_timeout()
        // a lightweight operation that shouldn't significantly impact performance, even with multiple VFIO devices.
        // However, we also need to ensure its debuggability.
        // As it could obscure the root cause of connection failures as set an excessively long QMP timeout.
        // For example, if QEMU fails to launch, a 5-second QMP timeout will immediately provide a "QMP connection failed" log message,
        // clearly pinpointing the issue. Conversely, a prolonged timeout might only result in vague error messages, making debugging
        // difficult as it won't explicitly indicate where the problem lies.

        // Given our current inability to comprehensively test across a wide range of hardware and configurations, we've made a pragmatic
        // decision: we'll maintain the 5-second timeout for now. A configurable timeout option will be introduced if future use cases
        // clearly demonstrate a justified need.
        {
            // set read timeout with 5000
            self.qmp
                .inner_mut()
                .get_mut_write()
                .set_read_timeout(Some(Duration::from_millis(5000)))?;
            // send the VFIO hotplug request
            self.qmp
                .execute(&vfio_device_add)
                .map_err(|e| anyhow!("device_add vfio device failed {:?}", e))?;
            // reset read timeout with 250
            self.qmp
                .inner_mut()
                .get_mut_write()
                .set_read_timeout(Some(Duration::from_millis(DEFAULT_QMP_READ_TIMEOUT)))?;
        }

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
        self.qmp
            .execute(&qmp::stop {})
            .map(|_| ())
            .context("execute qmp stop")
    }

    pub fn qmp_cont(&mut self) -> Result<()> {
        self.qmp
            .execute(&qmp::cont {})
            .map(|_| ())
            .context("execute qmp cont")
    }

    /// Get vCPU thread IDs through QMP query_cpus_fast.
    pub fn get_vcpu_thread_ids(&mut self) -> Result<VcpuThreadIds> {
        let vcpu_info = self
            .qmp
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

fn complete_pci_path_lookup<Cleanup>(
    node_name: &str,
    lookup: Result<PciPath>,
    cleanup_state: BlockCleanupState,
    cleanup: Cleanup,
) -> Result<PciPath>
where
    Cleanup: FnOnce() -> Result<()>,
{
    match lookup {
        Ok(path) => Ok(path),
        Err(lookup_err) => match cleanup() {
            Ok(()) => Err(lookup_err),
            Err(cleanup_err) => {
                if cleanup_err
                    .downcast_ref::<BlockDeviceCleanupPending>()
                    .is_some()
                {
                    Err(cleanup_err.context(lookup_err.to_string()))
                } else {
                    Err(incomplete_block_cleanup(
                        node_name,
                        lookup_err,
                        cleanup_err,
                        cleanup_state,
                    ))
                }
            }
        },
    }
}

fn select_block_pci_target<FindBridge>(
    pcie_root_port: Option<&str>,
    find_bridge: FindBridge,
) -> Result<(String, i64, bool)>
where
    FindBridge: FnOnce() -> Result<(String, i64)>,
{
    if let Some(root_port) = pcie_root_port {
        let valid_root_port = root_port
            .strip_prefix("rp")
            .is_some_and(|index| !index.is_empty() && index.parse::<u32>().is_ok());
        if !valid_root_port {
            return Err(anyhow!("invalid PCIe root-port bus {root_port}"));
        }
        return Ok((root_port.to_string(), 0, false));
    }

    let (bus, slot) = find_bridge()?;
    Ok((bus, slot, true))
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
    if is_rootless() {
        [get_jailer_root(sid).as_str(), QMP_SOCKET_FILE].join("/")
    } else {
        QMP_SOCKET_FILE.to_string()
    }
}

/// Generate a blockdev node name based on the given index.
fn block_node_name(index: u64) -> String {
    format!("drive-{index}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::{BufRead, Write};
    use std::os::unix::net::UnixListener;
    use std::path::Path;

    const QMP_GREETING: &str = r#"{"QMP":{"version":{"qemu":{"major":8,"minor":2,"micro":0},"package":""},"capabilities":[]}}"#;
    const TEST_BLOCK_FDSETS: &str =
        r#"{"return":[{"fdset-id":7,"fds":[{"fd":9,"opaque":"kata-block:drive-0:source"}]}]}"#;

    struct TestQemuProcess {
        child: std::process::Child,
    }

    impl TestQemuProcess {
        fn start(socket_path: &Path) -> Self {
            let kernel_path = socket_path.parent().unwrap().join("Image");
            let kernel = std::fs::File::create(&kernel_path).unwrap();
            let status = std::process::Command::new("sudo")
                .args(["-n", "gzip", "-dc", "/boot/vmlinuz"])
                .stdout(std::process::Stdio::from(kernel))
                .status()
                .unwrap();
            assert!(status.success(), "extract the Lima kernel");

            let mut command = std::process::Command::new("qemu-system-aarch64");
            command
                .args([
                    "-machine",
                    "virt",
                    "-accel",
                    "tcg",
                    "-cpu",
                    "max",
                    "-S",
                    "-display",
                    "none",
                    "-nodefaults",
                    "-m",
                    "512M",
                    "-kernel",
                ])
                .arg(&kernel_path)
                .args([
                    "-initrd",
                    "/boot/initrd.img",
                    "-append",
                    "console=ttyAMA0 root=/dev/doesnotexist panic=-1",
                    "-serial",
                    "null",
                ])
                .arg("-qmp")
                .arg(format!("unix:{},server=on,wait=off", socket_path.display()));
            for index in 0..8 {
                command.arg("-device").arg(format!(
                    "pcie-root-port,id=rp{index},bus=pcie.0,chassis=0,slot={index}"
                ));
            }
            command
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::inherit());
            let child = command.spawn().expect("launch qemu-system-aarch64");
            let mut process = Self { child };
            for _ in 0..100 {
                if socket_path.exists() {
                    return process;
                }
                if let Some(status) = process.child.try_wait().unwrap() {
                    panic!("QEMU exited before creating its QMP socket: {}", status);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            panic!("QEMU did not create its QMP socket");
        }
    }

    impl Drop for TestQemuProcess {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[derive(serde::Serialize)]
    struct TestBlockdevAdd {}

    impl qapi_spec::Command for TestBlockdevAdd {
        const NAME: &'static str = "blockdev-add";
        const ALLOW_OOB: bool = false;
        type Ok = qapi_spec::Empty;
    }

    fn write_qmp_response(writer: &mut UnixStream, response: &str) {
        writer.write_all(response.as_bytes()).unwrap();
        writer.write_all(b"\n").unwrap();
        writer.flush().unwrap();
    }

    fn read_qmp_command(reader: &mut BufReader<UnixStream>) -> serde_json::Value {
        let mut request = String::new();
        reader.read_line(&mut request).unwrap();
        serde_json::from_str(&request).unwrap()
    }

    fn accept_initialized_qmp(
        listener: &UnixListener,
        fdsets: &str,
        commands: &mut Vec<serde_json::Value>,
    ) -> (BufReader<UnixStream>, UnixStream) {
        let (stream, _) = listener.accept().unwrap();
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);
        write_qmp_response(&mut writer, QMP_GREETING);
        commands.push(read_qmp_command(&mut reader));
        write_qmp_response(&mut writer, r#"{"return":{}}"#);
        commands.push(read_qmp_command(&mut reader));
        write_qmp_response(&mut writer, fdsets);
        (reader, writer)
    }

    fn qmp_with_responses(
        responses: Vec<&'static str>,
    ) -> (Qmp, std::thread::JoinHandle<Vec<serde_json::Value>>) {
        let (client, server) = UnixStream::pair().unwrap();
        let qmp = Qmp {
            qmp: qapi::Qmp::new(qapi::Stream::new(
                BufReader::new(client.try_clone().unwrap()),
                client,
            )),
            qmp_sock_path: None,
            guest_memory_block_size: 0,
            ccw_subchannel: None,
            pci_bridge_devices: HashMap::new(),
            block_fdsets: HashMap::new(),
        };
        let server_thread = std::thread::spawn(move || {
            let mut reader = BufReader::new(server.try_clone().unwrap());
            let mut writer = server;
            let mut commands = Vec::new();
            for response in responses {
                let mut request = String::new();
                reader.read_line(&mut request).unwrap();
                commands.push(serde_json::from_str(&request).unwrap());
                writer.write_all(response.as_bytes()).unwrap();
                writer.write_all(b"\n").unwrap();
                writer.flush().unwrap();
            }
            commands
        });
        (qmp, server_thread)
    }

    #[test]
    #[ignore = "requires KATA_TEST_QEMU_TCG=1 and qemu-system-aarch64"]
    fn real_qemu_tcg_block_lifecycle() {
        if std::env::var("KATA_TEST_QEMU_TCG").as_deref() != Ok("1") {
            return;
        }

        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("qmp.sock");
        let _process = TestQemuProcess::start(&socket_path);
        let disk_path = temp_dir.path().join("disk.img");
        let disk = std::fs::File::create(&disk_path).unwrap();
        disk.set_len(64 * 1024 * 1024).unwrap();
        drop(disk);

        let mut qmp = Qmp::new(socket_path.to_str().unwrap()).unwrap();
        qmp.qmp_cont().unwrap();
        let aio = crate::device::driver::BlockDeviceAio::Threads.to_string();
        let opaque = block_fd_opaque("drive-0", "block-source");
        let (pci_path, address) = qmp
            .hotplug_block_device(
                "virtio-blk-pci",
                0,
                disk_path.to_str().unwrap(),
                &aio,
                Some(false),
                false,
                false,
                true,
                0,
                0,
                None,
                None,
                Some("rp3"),
            )
            .unwrap();

        assert_eq!(pci_path.unwrap().to_string(), "04/00");
        assert!(address.is_none());
        assert!(qmp.frontend_exists("drive-0").unwrap());
        assert!(qmp.block_backend_exists("drive-0").unwrap());
        let fdsets = qmp.qmp.execute(&qmp::query_fdsets {}).unwrap();
        assert!(find_fd_by_opaque(&fdsets, &opaque).is_some());

        if let Err(mut last_error) = qmp.hotunplug_block_device("virtio-blk-pci", 0, None) {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let pending = last_error
                    .downcast_ref::<BlockDeviceCleanupPending>()
                    .unwrap_or_else(|| {
                        panic!("unexpected QEMU hot-unplug error: {:#}", last_error)
                    });
                let state = pending.state();
                assert_eq!(
                    state,
                    BlockCleanupState {
                        frontend: false,
                        backend: false,
                        fdsets: true,
                    },
                    "QEMU hot-unplug reported inaccurate cleanup state: {last_error:#}"
                );
                eprintln!("QEMU block cleanup pending with state {state:?}: {last_error:#}");

                if Instant::now() >= deadline {
                    panic!(
                        "QEMU block cleanup retry deadline expired: {:#}",
                        last_error
                    );
                }
                std::thread::sleep(Duration::from_millis(10));
                match qmp.hotunplug_block_device("virtio-blk-pci", 0, Some(state)) {
                    Ok(()) => break,
                    Err(error) => last_error = error,
                }
            }
        }

        assert!(!qmp.frontend_exists("drive-0").unwrap());
        assert!(!qmp.block_backend_exists("drive-0").unwrap());
        let fdsets = qmp.qmp.execute(&qmp::query_fdsets {}).unwrap();
        assert!(find_fd_by_opaque(&fdsets, &opaque).is_none());
    }

    #[test]
    fn add_fd_lost_response_discovers_accepted_fd() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let opaque = block_fd_opaque("drive-0", "source");
        let expected_opaque = opaque.clone();
        let server = std::thread::spawn(move || {
            let mut commands = Vec::new();
            let (mut reader, writer) =
                accept_initialized_qmp(&listener, r#"{"return":[]}"#, &mut commands);
            commands.push(read_qmp_command(&mut reader));
            drop(reader);
            drop(writer);

            let fdsets = serde_json::json!({
                "return": [{
                    "fdset-id": 7,
                    "fds": [{"fd": 9, "opaque": expected_opaque}]
                }]
            })
            .to_string();
            let (mut reader, mut writer) =
                accept_initialized_qmp(&listener, &fdsets, &mut commands);
            commands.push(read_qmp_command(&mut reader));
            write_qmp_response(&mut writer, &fdsets);
            commands
        });

        let mut qmp = Qmp::new(socket_path.to_str().unwrap()).unwrap();
        let file = tempfile::tempfile().unwrap();
        let info = qmp.pass_block_fd(file.as_raw_fd(), &opaque).unwrap();

        assert_eq!(info.fdset_id, 7);
        assert_eq!(qmp.block_fdsets.get("drive-0"), Some(&vec![7]));
        let commands = server.join().unwrap();
        assert_eq!(commands[2]["execute"], "add-fd");
        assert_eq!(commands[5]["execute"], "query-fdsets");
    }

    #[test]
    fn blockdev_add_lost_response_discovers_accepted_backend() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let server = std::thread::spawn(move || {
            let mut commands = Vec::new();
            let (mut reader, writer) =
                accept_initialized_qmp(&listener, r#"{"return":[]}"#, &mut commands);
            commands.push(read_qmp_command(&mut reader));
            drop(reader);
            drop(writer);

            let (mut reader, mut writer) =
                accept_initialized_qmp(&listener, r#"{"return":[]}"#, &mut commands);
            commands.push(read_qmp_command(&mut reader));
            write_qmp_response(&mut writer, r#"{"return":[{"node-name":"drive-0"}]}"#);
            commands
        });

        let mut qmp = Qmp::new(socket_path.to_str().unwrap()).unwrap();
        let result = qmp.qmp.execute(&TestBlockdevAdd {});
        let outcome = qmp
            .reconcile_add_result(
                "drive-0",
                "blockdev-add",
                result,
                BlockCleanupState {
                    frontend: false,
                    backend: true,
                    fdsets: false,
                },
                QmpResidue::Backend,
            )
            .unwrap();

        assert!(matches!(outcome, ReconciledAdd::Applied));
        let commands = server.join().unwrap();
        assert_eq!(commands[2]["execute"], "blockdev-add");
        assert_eq!(commands[5]["execute"], "query-named-block-nodes");
    }

    #[test]
    fn device_add_lost_response_discovers_accepted_frontend() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let server = std::thread::spawn(move || {
            let mut commands = Vec::new();
            let (mut reader, writer) =
                accept_initialized_qmp(&listener, r#"{"return":[]}"#, &mut commands);
            commands.push(read_qmp_command(&mut reader));
            drop(reader);
            drop(writer);

            let (mut reader, mut writer) =
                accept_initialized_qmp(&listener, r#"{"return":[]}"#, &mut commands);
            commands.push(read_qmp_command(&mut reader));
            write_qmp_response(
                &mut writer,
                r#"{"return":[{"name":"drive-0","type":"child<virtio-blk-pci>"}]}"#,
            );
            commands
        });

        let mut qmp = Qmp::new(socket_path.to_str().unwrap()).unwrap();
        qmp.device_add_with_rollback(
            "drive-0",
            Some("rp0".to_string()),
            "virtio-blk-pci",
            Dictionary::new(),
        )
        .unwrap();
        let commands = server.join().unwrap();
        assert_eq!(commands[2]["execute"], "device_add");
        assert_eq!(commands[5]["execute"], "qom-list");
    }

    #[test]
    fn remove_fd_lost_response_discovers_absent_fdset() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let opaque = block_fd_opaque("drive-0", "source");
        let server = std::thread::spawn(move || {
            let mut commands = Vec::new();
            let fdsets = serde_json::json!({
                "return": [{
                    "fdset-id": 7,
                    "fds": [{"fd": 9, "opaque": opaque}]
                }]
            })
            .to_string();
            let (mut reader, writer) = accept_initialized_qmp(&listener, &fdsets, &mut commands);
            commands.push(read_qmp_command(&mut reader));
            drop(reader);
            drop(writer);

            let (mut reader, mut writer) =
                accept_initialized_qmp(&listener, r#"{"return":[]}"#, &mut commands);
            commands.push(read_qmp_command(&mut reader));
            write_qmp_response(&mut writer, r#"{"return":[]}"#);
            commands
        });

        let mut qmp = Qmp::new(socket_path.to_str().unwrap()).unwrap();
        qmp.remove_fdset_ids("drive-0", vec![7]).unwrap();

        assert!(!qmp.block_fdsets.contains_key("drive-0"));
        let commands = server.join().unwrap();
        assert_eq!(commands[2]["execute"], "remove-fd");
        assert_eq!(commands[4]["execute"], "query-fdsets");
    }

    fn assert_block_removal_reconciles_lost_response(block_driver: &str) {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let server = std::thread::spawn(move || {
            let mut commands = Vec::new();
            let (mut reader, writer) =
                accept_initialized_qmp(&listener, r#"{"return":[]}"#, &mut commands);
            commands.push(read_qmp_command(&mut reader));
            drop(reader);
            drop(writer);

            let (mut reader, mut writer) =
                accept_initialized_qmp(&listener, r#"{"return":[]}"#, &mut commands);
            commands.push(read_qmp_command(&mut reader));
            write_qmp_response(&mut writer, r#"{"return":[]}"#);
            commands.push(read_qmp_command(&mut reader));
            write_qmp_response(
                &mut writer,
                r#"{"error":{"class":"DeviceNotFound","desc":"backend already absent"}}"#,
            );
            commands.push(read_qmp_command(&mut reader));
            write_qmp_response(&mut writer, r#"{"return":[]}"#);

            commands.push(read_qmp_command(&mut reader));
            write_qmp_response(
                &mut writer,
                r#"{"error":{"class":"DeviceNotFound","desc":"frontend already absent"}}"#,
            );
            commands.push(read_qmp_command(&mut reader));
            write_qmp_response(
                &mut writer,
                r#"{"error":{"class":"DeviceNotFound","desc":"backend already absent"}}"#,
            );
            commands
        });

        let mut qmp = Qmp::new(socket_path.to_str().unwrap()).unwrap();
        qmp.block_fdsets.insert("drive-0".to_string(), vec![7]);

        qmp.hotunplug_block_device(block_driver, 0, None).unwrap();
        qmp.hotunplug_block_device(block_driver, 0, None).unwrap();
        assert!(!qmp.block_fdsets.contains_key("drive-0"));

        let commands = server.join().unwrap();
        assert_eq!(
            commands
                .iter()
                .map(|command| command["execute"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "qmp_capabilities",
                "query-fdsets",
                "device_del",
                "qmp_capabilities",
                "query-fdsets",
                "qom-list",
                "blockdev-del",
                "query-fdsets",
                "device_del",
                "blockdev-del",
            ]
        );
    }

    #[test]
    fn scsi_removal_reconciles_lost_response_and_absent_residue() {
        assert_block_removal_reconciles_lost_response(VIRTIO_SCSI);
    }

    #[test]
    fn ccw_removal_reconciles_lost_response_and_absent_residue() {
        assert_block_removal_reconciles_lost_response(VIRTIO_BLK_CCW);
    }

    #[test]
    fn ccw_removal_preserves_subchannel_until_frontend_is_absent() {
        let (mut qmp, server) = qmp_with_responses(vec![
            r#"{"error":{"class":"GenericError","desc":"injected device delete failure"}}"#,
            r#"{"return":[{"name":"drive-0","type":"child<virtio-blk-ccw>"}]}"#,
            r#"{"error":{"class":"DeviceNotFound","desc":"frontend already absent"}}"#,
            r#"{"error":{"class":"DeviceNotFound","desc":"backend already absent"}}"#,
        ]);
        let mut subchannel = CcwSubChannel::new();
        subchannel.add_device("drive-0").unwrap();
        qmp.set_ccw_subchannel(subchannel);

        let error = qmp
            .hotunplug_block_device(VIRTIO_BLK_CCW, 0, None)
            .unwrap_err();
        let state = error
            .downcast_ref::<BlockDeviceCleanupPending>()
            .unwrap()
            .state();
        assert!(qmp
            .ccw_subchannel
            .as_mut()
            .unwrap()
            .add_device("drive-0")
            .is_err());

        qmp.hotunplug_block_device(VIRTIO_BLK_CCW, 0, Some(state))
            .unwrap();
        assert!(qmp
            .ccw_subchannel
            .as_mut()
            .unwrap()
            .add_device("drive-0")
            .is_ok());

        let commands = server.join().unwrap();
        assert_eq!(commands[0]["execute"], "device_del");
        assert_eq!(commands[1]["execute"], "qom-list");
        assert_eq!(commands[2]["execute"], "device_del");
        assert_eq!(commands[3]["execute"], "blockdev-del");
    }

    #[test]
    fn successful_remove_fd_preserves_residue_until_retry_confirms_absence() {
        let (mut qmp, server) = qmp_with_responses(vec![
            TEST_BLOCK_FDSETS,
            r#"{"return":{}}"#,
            TEST_BLOCK_FDSETS,
            TEST_BLOCK_FDSETS,
            r#"{"return":{}}"#,
            r#"{"return":[]}"#,
        ]);
        qmp.block_fdsets.insert("drive-0".to_string(), vec![7]);
        let state = BlockCleanupState {
            frontend: false,
            backend: false,
            fdsets: true,
        };

        let error = qmp
            .cleanup_pending_block_device("drive-0", state)
            .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<BlockDeviceCleanupPending>()
                .unwrap()
                .state(),
            state
        );
        assert_eq!(qmp.block_fdsets.get("drive-0"), Some(&vec![7]));
        qmp.cleanup_pending_block_device("drive-0", state).unwrap();
        assert!(!qmp.block_fdsets.contains_key("drive-0"));

        let commands = server.join().unwrap();
        assert_eq!(commands[0]["execute"], "query-fdsets");
        assert_eq!(commands[1]["execute"], "remove-fd");
        assert_eq!(commands[2]["execute"], "query-fdsets");
        assert_eq!(commands[3]["execute"], "query-fdsets");
        assert_eq!(commands[4]["execute"], "remove-fd");
        assert_eq!(commands[5]["execute"], "query-fdsets");
    }

    #[test]
    fn device_deleted_timeout_discovers_absent_frontend() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let server = std::thread::spawn(move || {
            let mut commands = Vec::new();
            let (mut reader, mut writer) =
                accept_initialized_qmp(&listener, r#"{"return":[]}"#, &mut commands);
            commands.push(read_qmp_command(&mut reader));
            write_qmp_response(&mut writer, r#"{"return":{}}"#);
            commands.push(read_qmp_command(&mut reader));
            write_qmp_response(
                &mut writer,
                r#"{"return":{"qemu":{"major":8,"minor":2,"micro":0},"package":""}}"#,
            );
            drop(reader);
            drop(writer);

            let (mut reader, mut writer) =
                accept_initialized_qmp(&listener, r#"{"return":[]}"#, &mut commands);
            commands.push(read_qmp_command(&mut reader));
            write_qmp_response(&mut writer, r#"{"return":[]}"#);
            commands
        });

        let mut qmp = Qmp::new(socket_path.to_str().unwrap()).unwrap();
        qmp.cleanup_pending_block_device_with_timeout(
            "drive-0",
            BlockCleanupState {
                frontend: true,
                backend: false,
                fdsets: false,
            },
            Duration::from_millis(1),
        )
        .unwrap();

        let commands = server.join().unwrap();
        assert_eq!(commands[2]["execute"], "device_del");
        assert_eq!(commands[3]["execute"], "query-version");
        assert_eq!(commands[6]["execute"], "qom-list");
    }

    #[test]
    fn failed_device_deleted_poll_reconnects_before_queued_event() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let server = std::thread::spawn(move || {
            let mut first_commands = Vec::new();
            let (mut first_reader, mut first_writer) =
                accept_initialized_qmp(&listener, r#"{"return":[]}"#, &mut first_commands);
            first_commands.push(read_qmp_command(&mut first_reader));
            write_qmp_response(&mut first_writer, r#"{"return":{}}"#);
            first_commands.push(read_qmp_command(&mut first_reader));
            write_qmp_response(
                &mut first_writer,
                r#"{"event":"DEVICE_DELETED","data":{"device":"drive-0","path":"/machine/peripheral/drive-0"},"timestamp":{"seconds":1,"microseconds":0}}"#,
            );

            let mut second_commands = Vec::new();
            let (mut second_reader, mut second_writer) =
                accept_initialized_qmp(&listener, r#"{"return":[]}"#, &mut second_commands);
            second_commands.push(read_qmp_command(&mut second_reader));
            write_qmp_response(&mut second_writer, r#"{"return":[]}"#);
            second_commands.push(read_qmp_command(&mut second_reader));
            write_qmp_response(
                &mut second_writer,
                r#"{"return":{"qemu":{"major":8,"minor":2,"micro":0},"package":""}}"#,
            );

            (first_commands, second_commands)
        });

        let mut qmp = Qmp::new(socket_path.to_str().unwrap()).unwrap();
        qmp.cleanup_pending_block_device_with_timeout(
            "drive-0",
            BlockCleanupState {
                frontend: true,
                backend: false,
                fdsets: false,
            },
            Duration::from_millis(250),
        )
        .unwrap();
        assert_eq!(
            qmp.qmp.inner_mut().get_mut_write().read_timeout().unwrap(),
            Some(Duration::from_millis(DEFAULT_QMP_READ_TIMEOUT))
        );
        qmp.qmp.nop().unwrap();

        let (first_commands, second_commands) = server.join().unwrap();
        assert_eq!(
            first_commands
                .iter()
                .map(|command| command["execute"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "qmp_capabilities",
                "query-fdsets",
                "device_del",
                "query-version"
            ]
        );
        assert_eq!(
            second_commands
                .iter()
                .map(|command| command["execute"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "qmp_capabilities",
                "query-fdsets",
                "qom-list",
                "query-version"
            ]
        );
    }

    #[test]
    fn block_pci_target_prefers_preallocated_root_port() {
        let bridge_lookup_called = Cell::new(false);
        let target = select_block_pci_target(Some("rp3"), || {
            bridge_lookup_called.set(true);
            Ok(("pci-bridge-0".to_string(), 1))
        })
        .unwrap();

        assert_eq!(target, ("rp3".to_string(), 0, false));
        assert!(!bridge_lookup_called.get());
        assert!(select_block_pci_target(Some("pci-bridge-0"), || unreachable!()).is_err());
    }

    #[test]
    fn root_port_path_uses_structured_qom_properties() {
        let (mut qmp, server) = qmp_with_responses(vec![
            r#"{"return":"/machine/peripheral/rp3/rp3"}"#,
            r#"{"return":0}"#,
            r#"{"return":32}"#,
        ]);

        assert_eq!(
            qmp.get_root_port_device_path("drive-0", "rp3")
                .unwrap()
                .to_string(),
            "04/00"
        );

        let commands = server.join().unwrap();
        assert!(commands
            .iter()
            .all(|command| command["execute"] == "qom-get"));
    }

    #[test]
    fn path_lookup_failure_returns_after_successful_rollback() {
        let error = complete_pci_path_lookup(
            "drive-0",
            Err(anyhow!("lookup failed")),
            BlockCleanupState::attached(false),
            || Ok(()),
        )
        .unwrap_err();

        assert_eq!(error.to_string(), "lookup failed");
        assert!(error.downcast_ref::<BlockDeviceCleanupPending>().is_none());
    }

    #[test]
    fn path_lookup_failure_preserves_state_after_rollback_failure() {
        let error = complete_pci_path_lookup(
            "drive-0",
            Err(anyhow!("lookup failed")),
            BlockCleanupState::attached(false),
            || Err(anyhow!("device_del failed")),
        )
        .unwrap_err();

        let pending = error
            .downcast_ref::<BlockDeviceCleanupPending>()
            .expect("cleanup failure must preserve ownership");
        assert!(pending.to_string().contains("lookup failed"));
        assert!(pending.to_string().contains("device_del failed"));
    }

    #[test]
    fn device_add_failure_removes_block_backend() {
        let (mut qmp, server) = qmp_with_responses(vec![
            r#"{"error":{"class":"GenericError","desc":"injected device failure"}}"#,
            r#"{"return":{}}"#,
            TEST_BLOCK_FDSETS,
            r#"{"return":{}}"#,
            r#"{"return":[]}"#,
        ]);
        qmp.block_fdsets.insert("drive-0".to_string(), vec![7]);
        let mut arguments = Dictionary::new();
        arguments.insert("drive".to_string(), "drive-0".into());

        let error = qmp
            .device_add_with_rollback(
                "drive-0",
                Some("rp0".to_string()),
                "virtio-blk-pci",
                arguments,
            )
            .unwrap_err();
        assert!(error.to_string().contains("device_add"));

        let commands = server.join().unwrap();
        assert_eq!(commands[0]["execute"], "device_add");
        assert_eq!(commands[0]["arguments"]["bus"], "rp0");
        assert_eq!(commands[1]["execute"], "blockdev-del");
        assert_eq!(commands[1]["arguments"]["node-name"], "drive-0");
        assert_eq!(commands[2]["execute"], "query-fdsets");
        assert_eq!(commands[3]["execute"], "remove-fd");
        assert_eq!(commands[3]["arguments"]["fdset-id"], 7);
        assert!(!qmp.block_fdsets.contains_key("drive-0"));
    }

    #[test]
    fn device_add_rollback_failure_preserves_fdset_state() {
        let (mut qmp, server) = qmp_with_responses(vec![
            r#"{"error":{"class":"GenericError","desc":"injected device failure"}}"#,
            r#"{"error":{"class":"GenericError","desc":"injected backend failure"}}"#,
            r#"{"return":[{"node-name":"drive-0"}]}"#,
            r#"{"return":{}}"#,
            TEST_BLOCK_FDSETS,
            r#"{"return":{}}"#,
            r#"{"return":[]}"#,
        ]);
        qmp.block_fdsets.insert("drive-0".to_string(), vec![7]);
        let mut arguments = Dictionary::new();
        arguments.insert("drive".to_string(), "drive-0".into());

        let error = qmp
            .device_add_with_rollback(
                "drive-0",
                Some("rp0".to_string()),
                "virtio-blk-pci",
                arguments,
            )
            .unwrap_err();

        let cleanup_state = error
            .downcast_ref::<BlockDeviceCleanupPending>()
            .unwrap()
            .state();
        assert_eq!(
            cleanup_state,
            BlockCleanupState {
                frontend: false,
                backend: true,
                fdsets: true,
            }
        );
        assert_eq!(qmp.block_fdsets.get("drive-0"), Some(&vec![7]));

        qmp.cleanup_pending_block_device("drive-0", cleanup_state)
            .unwrap();
        assert!(!qmp.block_fdsets.contains_key("drive-0"));

        let commands = server.join().unwrap();
        assert_eq!(commands[0]["execute"], "device_add");
        assert_eq!(commands[1]["execute"], "blockdev-del");
        assert_eq!(commands[2]["execute"], "query-named-block-nodes");
        assert_eq!(commands[3]["execute"], "blockdev-del");
        assert_eq!(commands[4]["execute"], "query-fdsets");
        assert_eq!(commands[5]["execute"], "remove-fd");
    }

    #[test]
    fn pending_frontend_cleanup_retries_all_residue_stages() {
        let (mut qmp, server) = qmp_with_responses(vec![
            r#"{"error":{"class":"GenericError","desc":"injected device delete failure"}}"#,
            r#"{"error":{"class":"GenericError","desc":"injected query failure"}}"#,
            r#"{"error":{"class":"DeviceNotFound","desc":"frontend already absent"}}"#,
            r#"{"return":{}}"#,
            TEST_BLOCK_FDSETS,
            r#"{"return":{}}"#,
            r#"{"return":[]}"#,
        ]);
        qmp.block_fdsets.insert("drive-0".to_string(), vec![7]);
        let attached = BlockCleanupState::attached(true);

        let error = qmp
            .cleanup_pending_block_device("drive-0", attached)
            .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<BlockDeviceCleanupPending>()
                .unwrap()
                .state(),
            attached
        );

        qmp.cleanup_pending_block_device("drive-0", attached)
            .unwrap();
        assert!(!qmp.block_fdsets.contains_key("drive-0"));

        let commands = server.join().unwrap();
        assert_eq!(commands[0]["execute"], "device_del");
        assert_eq!(commands[1]["execute"], "qom-list");
        assert_eq!(commands[2]["execute"], "device_del");
        assert_eq!(commands[3]["execute"], "blockdev-del");
        assert_eq!(commands[4]["execute"], "query-fdsets");
        assert_eq!(commands[5]["execute"], "remove-fd");
    }

    #[test]
    fn pending_fdset_only_cleanup_is_idempotent() {
        let (mut qmp, server) = qmp_with_responses(vec![
            TEST_BLOCK_FDSETS,
            r#"{"error":{"class":"GenericError","desc":"injected fdset failure"}}"#,
            TEST_BLOCK_FDSETS,
            TEST_BLOCK_FDSETS,
            r#"{"return":{}}"#,
            r#"{"return":[]}"#,
        ]);
        qmp.block_fdsets.insert("drive-0".to_string(), vec![7]);
        let fdset_only = BlockCleanupState {
            frontend: false,
            backend: false,
            fdsets: true,
        };

        let error = qmp
            .cleanup_pending_block_device("drive-0", fdset_only)
            .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<BlockDeviceCleanupPending>()
                .unwrap()
                .state(),
            fdset_only
        );
        qmp.cleanup_pending_block_device("drive-0", fdset_only)
            .unwrap();
        qmp.cleanup_pending_block_device("drive-0", BlockCleanupState::default())
            .unwrap();

        assert!(!qmp.block_fdsets.contains_key("drive-0"));
        let commands = server.join().unwrap();
        assert_eq!(commands.len(), 6);
        assert_eq!(commands[0]["execute"], "query-fdsets");
        assert_eq!(commands[1]["execute"], "remove-fd");
        assert_eq!(commands[2]["execute"], "query-fdsets");
        assert_eq!(commands[3]["execute"], "query-fdsets");
        assert_eq!(commands[4]["execute"], "remove-fd");
        assert_eq!(commands[5]["execute"], "query-fdsets");
    }

    #[test]
    fn pending_backend_cleanup_verifies_already_absent_node() {
        let (mut qmp, server) = qmp_with_responses(vec![
            r#"{"error":{"class":"DeviceNotFound","desc":"backend already absent"}}"#,
        ]);
        let backend_only = BlockCleanupState {
            frontend: false,
            backend: true,
            fdsets: false,
        };

        qmp.cleanup_pending_block_device("drive-0", backend_only)
            .unwrap();

        let commands = server.join().unwrap();
        assert_eq!(commands[0]["execute"], "blockdev-del");
        assert_eq!(commands.len(), 1);
    }

    #[test]
    fn reconstructs_kata_block_fdsets_from_qmp() {
        let fdsets = vec![
            qmp::FdsetInfo {
                fdset_id: 7,
                fds: vec![
                    qmp::FdsetFdInfo {
                        fd: 21,
                        opaque: Some(block_fd_opaque("drive-2", "vmdk-extent-0")),
                    },
                    qmp::FdsetFdInfo {
                        fd: 22,
                        opaque: Some(block_fd_opaque("drive-2", "vmdk-extent-1")),
                    },
                ],
            },
            qmp::FdsetInfo {
                fdset_id: 8,
                fds: vec![qmp::FdsetFdInfo {
                    fd: 23,
                    opaque: Some(block_fd_opaque("drive-2", "vmdk-descriptor")),
                }],
            },
            qmp::FdsetInfo {
                fdset_id: 9,
                fds: vec![qmp::FdsetFdInfo {
                    fd: 24,
                    opaque: Some("unrelated".to_string()),
                }],
            },
        ];

        assert_eq!(
            collect_block_fdsets(fdsets),
            HashMap::from([("drive-2".to_string(), vec![7, 8])])
        );
    }
}
