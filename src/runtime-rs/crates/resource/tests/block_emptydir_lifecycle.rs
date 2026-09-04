// Copyright (c) 2026 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    convert::TryFrom,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex},
    time::Duration,
};

use agent::{kata::KataAgent, Agent};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use hypervisor::{
    device::{
        device_manager::{find_device_id, DeviceManager},
        pci_path::PciPath,
        DeviceStateInDoubt, DeviceType,
    },
    hypervisor_persist::HypervisorState,
    Hypervisor, MemoryConfig, VcpuThreadIds, KATA_BLK_DEV_TYPE, VIRTIO_BLOCK_MMIO,
    VIRTIO_BLOCK_PCI,
};
use kata_types::{
    capabilities::{Capabilities, CapabilityBits},
    config::{
        hypervisor::{Hypervisor as HypervisorConfig, TopologyConfigInfo, VIRTIO_SCSI},
        Agent as AgentConfig, EMPTYDIR_MODE_BLOCK_PLAIN,
    },
    mount::{join_path, kata_direct_volume_root_path, KATA_MOUNT_INFO_FILE_NAME},
};
use oci_spec::runtime as oci;
use resource::volume::{VolumeContext, VolumeResource};
use tempfile::TempDir;
use tokio::{
    sync::{Barrier, Notify, RwLock},
    time::timeout,
};

const ASYNC_ASSERTION_TIMEOUT: Duration = Duration::from_secs(5);
const PENDING_ASSERTION_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Default)]
struct FakeState {
    attempted_devices: Vec<(String, String)>,
    attempted_indexes: Vec<u64>,
    added_devices: Vec<(String, String)>,
    block_adds: Vec<BlockAdd>,
    removed_paths: Vec<String>,
    add_events: Vec<AddEvent>,
    running: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BlockAdd {
    device_id: String,
    driver_option: String,
    discard_unmap: bool,
    pcie_root_port: Option<String>,
    use_pcie_root_port: bool,
    index: u64,
    path_on_host: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AddEvent {
    Attempt(usize),
    FirstReleased,
}

#[derive(Debug, Default)]
struct FirstAddGate {
    entered: Notify,
    release: Notify,
}

#[derive(Debug)]
struct FakeHypervisor {
    state: Mutex<FakeState>,
    fail_add_at: Option<usize>,
    ambiguous_add_at: Option<usize>,
    first_add_gate: Option<Arc<FirstAddGate>>,
    successful_add_gate: Option<Arc<FirstAddGate>>,
    config_gate: Option<Arc<FirstAddGate>>,
    hot_unplug_supported: bool,
    config: HypervisorConfig,
}

impl FakeHypervisor {
    fn new(fail_add_at: Option<usize>, hot_unplug_supported: bool) -> Self {
        Self::with_first_add_gate(fail_add_at, hot_unplug_supported, None)
    }

    fn with_first_add_gate(
        fail_add_at: Option<usize>,
        hot_unplug_supported: bool,
        first_add_gate: Option<Arc<FirstAddGate>>,
    ) -> Self {
        Self::with_failure_modes(fail_add_at, None, hot_unplug_supported, first_add_gate)
    }

    fn with_failure_modes(
        fail_add_at: Option<usize>,
        ambiguous_add_at: Option<usize>,
        hot_unplug_supported: bool,
        first_add_gate: Option<Arc<FirstAddGate>>,
    ) -> Self {
        let mut config = HypervisorConfig::default();
        config.blockdev_info.block_device_driver = VIRTIO_BLOCK_MMIO.to_string();
        Self {
            state: Mutex::new(FakeState {
                running: true,
                ..Default::default()
            }),
            fail_add_at,
            ambiguous_add_at,
            first_add_gate,
            successful_add_gate: None,
            config_gate: None,
            hot_unplug_supported,
            config,
        }
    }

    fn with_successful_add_gate(gate: Arc<FirstAddGate>) -> Self {
        let mut hypervisor = Self::new(None, true);
        hypervisor.successful_add_gate = Some(gate);
        hypervisor
    }

    fn with_config_gate(gate: Arc<FirstAddGate>) -> Self {
        let mut hypervisor = Self::new(None, true);
        hypervisor.config_gate = Some(gate);
        hypervisor
    }

    fn stop(&self) {
        self.state.lock().unwrap().running = false;
    }

    fn snapshot(&self) -> FakeSnapshot {
        let state = self.state.lock().unwrap();
        FakeSnapshot {
            attempted_devices: state.attempted_devices.clone(),
            attempted_indexes: state.attempted_indexes.clone(),
            added_devices: state.added_devices.clone(),
            block_adds: state.block_adds.clone(),
            removed_paths: state.removed_paths.clone(),
            add_events: state.add_events.clone(),
        }
    }
}

#[derive(Debug)]
struct FakeSnapshot {
    attempted_devices: Vec<(String, String)>,
    attempted_indexes: Vec<u64>,
    added_devices: Vec<(String, String)>,
    block_adds: Vec<BlockAdd>,
    removed_paths: Vec<String>,
    add_events: Vec<AddEvent>,
}

async fn block_add(device: &DeviceType) -> Option<BlockAdd> {
    match device {
        DeviceType::BlockModern(block) => {
            let block = block.lock().await;
            Some(BlockAdd {
                device_id: block.device_id.clone(),
                driver_option: block.config.driver_option.clone(),
                discard_unmap: block.config.discard_unmap,
                pcie_root_port: block.config.pcie_root_port.clone(),
                use_pcie_root_port: block.config.use_pcie_root_port,
                index: block.config.index,
                path_on_host: block.config.path_on_host.clone(),
            })
        }
        _ => None,
    }
}

async fn block_identity(device: &DeviceType) -> Option<(String, String)> {
    match device {
        DeviceType::BlockModern(block) => {
            let block = block.lock().await;
            Some((block.device_id.clone(), block.config.path_on_host.clone()))
        }
        _ => None,
    }
}

#[async_trait]
impl Hypervisor for FakeHypervisor {
    async fn prepare_vm(
        &self,
        _id: &str,
        _netns: Option<String>,
        _annotations: &HashMap<String, String>,
        _selinux_label: Option<String>,
    ) -> Result<()> {
        Ok(())
    }

    async fn start_vm(&self, _timeout: i32) -> Result<()> {
        self.state.lock().unwrap().running = true;
        Ok(())
    }

    async fn stop_vm(&self) -> Result<()> {
        self.stop();
        Ok(())
    }

    async fn wait_vm(&self) -> Result<i32> {
        Ok(0)
    }

    async fn pause_vm(&self) -> Result<()> {
        Ok(())
    }

    async fn save_vm(&self) -> Result<()> {
        Ok(())
    }

    async fn resume_vm(&self) -> Result<()> {
        Ok(())
    }

    async fn resize_vcpu(&self, old_vcpus: u32, new_vcpus: u32) -> Result<(u32, u32)> {
        Ok((old_vcpus, new_vcpus))
    }

    async fn resize_memory(&self, new_mem_mb: u32) -> Result<(u32, MemoryConfig)> {
        Ok((
            new_mem_mb,
            MemoryConfig {
                size_mb: new_mem_mb,
                ..Default::default()
            },
        ))
    }

    async fn add_device(&self, device: DeviceType) -> Result<DeviceType> {
        let block_add = block_add(&device)
            .await
            .ok_or_else(|| anyhow!("expected BlockModern device"))?;
        let device_id = block_add.device_id.clone();
        let path = block_add.path_on_host.clone();
        let index = block_add.index;
        let ordinal = {
            let mut state = self.state.lock().unwrap();
            state
                .attempted_devices
                .push((device_id.clone(), path.clone()));
            state.attempted_indexes.push(index);
            state.block_adds.push(block_add.clone());
            let ordinal = state.attempted_devices.len();
            state.add_events.push(AddEvent::Attempt(ordinal));
            ordinal
        };
        if ordinal == 1 {
            if let Some(gate) = &self.first_add_gate {
                gate.entered.notify_one();
                gate.release.notified().await;
                self.state
                    .lock()
                    .unwrap()
                    .add_events
                    .push(AddEvent::FirstReleased);
            }
        }
        if self.fail_add_at == Some(ordinal) {
            return Err(anyhow!("injected add_device failure"));
        }
        if self.ambiguous_add_at == Some(ordinal) {
            self.state
                .lock()
                .unwrap()
                .added_devices
                .push((device_id.clone(), path.clone()));
            let DeviceType::BlockModern(block) = device else {
                unreachable!("block identity requires a BlockModern device");
            };
            block.lock().await.config.path_on_host = format!("{path}.hidden-from-manager-lookup");
            return Err(anyhow::Error::new(DeviceStateInDoubt::new(
                device_id,
                "injected ambiguous add_device failure",
            )));
        }
        if block_add.driver_option == KATA_BLK_DEV_TYPE {
            let pci_path = PciPath::try_from(format!("{:02x}/00", block_add.index + 2).as_str())?;
            if let DeviceType::BlockModern(block) = &device {
                block.lock().await.config.pci_path = Some(pci_path);
            }
        }
        self.state
            .lock()
            .unwrap()
            .added_devices
            .push((device_id, path));
        if ordinal == 1 {
            if let Some(gate) = &self.successful_add_gate {
                gate.entered.notify_one();
                gate.release.notified().await;
            }
        }
        Ok(device)
    }

    async fn remove_device(&self, device: DeviceType) -> Result<()> {
        let (_, path) = block_identity(&device)
            .await
            .ok_or_else(|| anyhow!("expected BlockModern device"))?;
        let mut state = self.state.lock().unwrap();
        if !state.running {
            return Err(anyhow!("remove_device called after VM stop"));
        }
        if !self.hot_unplug_supported {
            return Err(anyhow!("hot unplug unsupported"));
        }
        state.removed_paths.push(path);
        Ok(())
    }

    async fn update_device(&self, _device: DeviceType) -> Result<()> {
        Ok(())
    }

    async fn get_agent_socket(&self) -> Result<String> {
        Ok(String::new())
    }

    async fn disconnect(&self) {}

    async fn hypervisor_config(&self) -> HypervisorConfig {
        if let Some(gate) = &self.config_gate {
            gate.entered.notify_one();
            gate.release.notified().await;
        }
        self.config.clone()
    }

    async fn get_thread_ids(&self) -> Result<VcpuThreadIds> {
        Ok(VcpuThreadIds::default())
    }

    async fn get_pids(&self) -> Result<Vec<u32>> {
        Ok(Vec::new())
    }

    async fn get_vmm_master_tid(&self) -> Result<u32> {
        Ok(0)
    }

    async fn get_ns_path(&self) -> Result<String> {
        Ok(String::new())
    }

    async fn cleanup(&self) -> Result<()> {
        Ok(())
    }

    async fn check(&self) -> Result<()> {
        Ok(())
    }

    async fn get_jailer_root(&self) -> Result<String> {
        Ok(String::new())
    }

    async fn save_state(&self) -> Result<HypervisorState> {
        Ok(HypervisorState::default())
    }

    async fn capabilities(&self) -> Result<Capabilities> {
        Ok(Capabilities::default())
    }

    async fn get_hypervisor_metrics(&self) -> Result<String> {
        Ok(String::new())
    }

    async fn set_capabilities(&self, _flag: CapabilityBits) {}

    async fn set_guest_memory_block_size(&self, _size: u32) {}

    async fn guest_memory_block_size(&self) -> u32 {
        0
    }

    async fn get_passfd_listener_addr(&self) -> Result<(String, u32)> {
        Ok((String::new(), 0))
    }
}

struct Harness {
    volume_resource: VolumeResource,
    device_manager: RwLock<DeviceManager>,
    hypervisor: Arc<FakeHypervisor>,
    share_fs: Option<Arc<dyn resource::share_fs::ShareFs>>,
    agent: Arc<dyn Agent>,
}

impl Harness {
    async fn new(fail_add_at: Option<usize>, hot_unplug_supported: bool) -> Self {
        Self::with_hypervisor(FakeHypervisor::new(fail_add_at, hot_unplug_supported)).await
    }

    async fn with_first_add_gate(gate: Arc<FirstAddGate>) -> Self {
        Self::with_hypervisor(FakeHypervisor::with_first_add_gate(
            Some(1),
            true,
            Some(gate),
        ))
        .await
    }

    async fn with_successful_add_gate(gate: Arc<FirstAddGate>) -> Self {
        Self::with_hypervisor(FakeHypervisor::with_successful_add_gate(gate)).await
    }

    async fn with_config_gate(gate: Arc<FirstAddGate>) -> Self {
        Self::with_hypervisor(FakeHypervisor::with_config_gate(gate)).await
    }

    async fn with_ambiguous_add() -> Self {
        Self::with_hypervisor(FakeHypervisor::with_failure_modes(
            None,
            Some(1),
            false,
            None,
        ))
        .await
    }

    async fn with_hypervisor(hypervisor: FakeHypervisor) -> Self {
        Self::with_hypervisor_and_topology(hypervisor, None).await
    }

    async fn qemu(block_driver: &str) -> Self {
        let mut hypervisor = FakeHypervisor::new(None, true);
        hypervisor.config.machine_info.machine_type = "virt".to_string();
        hypervisor.config.blockdev_info.block_device_driver = block_driver.to_string();
        hypervisor.config.device_info.pcie_root_port = 8;
        let topology = TopologyConfigInfo {
            hypervisor_name: hypervisor::HYPERVISOR_QEMU.to_string(),
            device_info: hypervisor.config.device_info.clone(),
        };
        Self::with_hypervisor_and_topology(hypervisor, Some(&topology)).await
    }

    async fn with_hypervisor_and_topology(
        hypervisor: FakeHypervisor,
        topology: Option<&TopologyConfigInfo>,
    ) -> Self {
        let hypervisor = Arc::new(hypervisor);
        let device_manager = DeviceManager::new(hypervisor.clone(), topology)
            .await
            .unwrap();
        Self {
            volume_resource: VolumeResource::new(),
            device_manager: RwLock::new(device_manager),
            hypervisor,
            share_fs: None,
            agent: Arc::new(KataAgent::new(AgentConfig::default())),
        }
    }

    async fn handle(&self, spec: &oci::Spec) -> Result<Vec<Arc<dyn resource::volume::Volume>>> {
        let context = VolumeContext {
            share_fs: &self.share_fs,
            d: &self.device_manager,
            sid: "sandbox",
            agent: self.agent.clone(),
            emptydir_mode: EMPTYDIR_MODE_BLOCK_PLAIN,
            fs_sharing_supported: false,
            block_device_discard_supported: true,
        };
        self.volume_resource
            .handler_volumes(&context, "container", spec)
            .await
    }
}

fn emptydir_path(root: &Path, name: &str) -> PathBuf {
    root.join("pods")
        .join("pod")
        .join("volumes")
        .join("kubernetes.io~empty-dir")
        .join(name)
}

fn emptydir_spec(root: &Path, count: usize) -> (oci::Spec, Vec<PathBuf>) {
    let sources = (0..count)
        .map(|index| {
            let source = emptydir_path(root, &format!("volume-{index}"));
            std::fs::create_dir_all(&source).unwrap();
            source
        })
        .collect::<Vec<_>>();
    let mounts: Vec<oci::Mount> = sources
        .iter()
        .enumerate()
        .map(|(index, source)| {
            oci::MountBuilder::default()
                .source(source)
                .destination(format!("/data/{index}"))
                .typ("bind")
                .options(vec!["rbind".to_string()])
                .build()
                .unwrap()
        })
        .collect();
    let spec = oci::SpecBuilder::default().mounts(mounts).build().unwrap();
    (spec, sources)
}

fn disk_path(source: &Path) -> PathBuf {
    source.join("disk.img")
}

fn metadata_path(source: &Path) -> PathBuf {
    join_path(&kata_direct_volume_root_path(), source.to_str().unwrap())
        .unwrap()
        .join(KATA_MOUNT_INFO_FILE_NAME)
}

async fn happy_path(root: &Path) {
    let harness = Harness::new(None, true).await;
    let (spec, sources) = emptydir_spec(root, 1);
    let volumes = harness.handle(&spec).await.unwrap();
    assert_eq!(volumes.len(), 1);
    let source = &sources[0];
    let disk = disk_path(source);
    assert!(disk.exists());
    assert!(metadata_path(source).exists());

    let guest_path = harness
        .volume_resource
        .guest_volume_stats_path(source.to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        harness
            .volume_resource
            .guest_volume_stats_path(disk.to_str().unwrap())
            .await,
        Some(guest_path.clone())
    );
    assert_eq!(
        volumes[0].get_volume_mount().unwrap()[0]
            .source()
            .as_ref()
            .unwrap()
            .to_str(),
        Some(guest_path.as_str())
    );

    let device_id = harness.hypervisor.snapshot().added_devices[0].0.clone();
    harness
        .volume_resource
        .detach_ephemeral_disks(&harness.device_manager)
        .await
        .unwrap();
    assert!(!harness
        .device_manager
        .read()
        .await
        .contains_device(&device_id));
    assert!(disk.exists());
    assert!(metadata_path(source).exists());

    harness.hypervisor.stop();
    harness
        .volume_resource
        .finalize_ephemeral_disks(&harness.device_manager)
        .await
        .unwrap();
    assert!(!disk.exists());
    assert!(!metadata_path(source).exists());
    assert_eq!(
        harness
            .volume_resource
            .guest_volume_stats_path(source.to_str().unwrap())
            .await,
        None
    );
}

async fn all_add_failure_ordinals(root: &Path) {
    for count in [1, 4, 8] {
        for fail_at in 1..=count {
            let case_root = root.join(format!("{count}-{fail_at}"));
            let harness = Harness::new(Some(fail_at), true).await;
            let (spec, sources) = emptydir_spec(&case_root, count);
            assert!(harness.handle(&spec).await.is_err());

            let snapshot = harness.hypervisor.snapshot();
            let attempted_paths = snapshot
                .attempted_devices
                .iter()
                .map(|(_, path)| path.clone())
                .collect::<Vec<_>>();
            let expected_attempted = sources[..fail_at]
                .iter()
                .map(|source| disk_path(source).display().to_string())
                .collect::<Vec<_>>();
            assert_eq!(attempted_paths, expected_attempted);
            assert_eq!(
                snapshot.attempted_devices[fail_at - 1].1,
                disk_path(&sources[fail_at - 1]).display().to_string()
            );
            let expected_rollback = sources[..fail_at - 1]
                .iter()
                .rev()
                .map(|source| disk_path(source).display().to_string())
                .collect::<Vec<_>>();
            assert_eq!(snapshot.removed_paths, expected_rollback);
            for (index, source) in sources.iter().enumerate() {
                let pending = index == fail_at - 1;
                assert_eq!(disk_path(source).exists(), pending);
                assert_eq!(metadata_path(source).exists(), pending);
            }
            for (index, (device_id, _)) in snapshot.attempted_devices.iter().enumerate() {
                assert_eq!(
                    harness
                        .device_manager
                        .read()
                        .await
                        .contains_device(device_id),
                    index == fail_at - 1
                );
            }

            harness
                .volume_resource
                .detach_ephemeral_disks(&harness.device_manager)
                .await
                .unwrap();
            harness.hypervisor.stop();
            harness
                .volume_resource
                .finalize_ephemeral_disks(&harness.device_manager)
                .await
                .unwrap();
            assert!(sources
                .iter()
                .all(|source| { !disk_path(source).exists() && !metadata_path(source).exists() }));
            for (device_id, _) in &snapshot.attempted_devices {
                assert!(!harness
                    .device_manager
                    .read()
                    .await
                    .contains_device(device_id));
            }
        }
    }
}

async fn ordinary_block_attach_failure_releases_manager_state_and_index() {
    let harness = Harness::new(Some(1), true).await;
    let first = hypervisor::device::device_manager::do_handle_device(
        &harness.device_manager,
        &hypervisor::device::DeviceConfig::BlockCfgModern(hypervisor::BlockConfigModern {
            path_on_host: "/tmp/ordinary-block-failure.img".to_string(),
            driver_option: VIRTIO_BLOCK_MMIO.to_string(),
            ..Default::default()
        }),
    )
    .await;
    assert!(first.is_err());
    let first_snapshot = harness.hypervisor.snapshot();
    let failed_id = &first_snapshot.attempted_devices[0].0;
    assert!(!harness
        .device_manager
        .read()
        .await
        .contains_device(failed_id));

    hypervisor::device::device_manager::do_handle_device(
        &harness.device_manager,
        &hypervisor::device::DeviceConfig::BlockCfgModern(hypervisor::BlockConfigModern {
            path_on_host: "/tmp/ordinary-block-success.img".to_string(),
            driver_option: VIRTIO_BLOCK_MMIO.to_string(),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    assert_eq!(harness.hypervisor.snapshot().attempted_indexes, vec![0, 0]);
}

async fn ordinary_emptydir_attach_failure_defers_artifact_cleanup(root: &Path) {
    let harness = Harness::new(Some(1), true).await;
    let (spec, sources) = emptydir_spec(root, 1);
    let error = match harness.handle(&spec).await {
        Ok(_) => panic!("plain block EmptyDir attach failure unexpectedly succeeded"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("preserved block emptyDir artifacts"));

    let snapshot = harness.hypervisor.snapshot();
    let device_id = &snapshot.attempted_devices[0].0;
    let source = &sources[0];
    assert!(harness
        .device_manager
        .read()
        .await
        .contains_device(device_id));
    assert!(disk_path(source).exists());
    assert!(metadata_path(source).exists());

    harness.hypervisor.stop();
    harness
        .volume_resource
        .finalize_ephemeral_disks(&harness.device_manager)
        .await
        .unwrap();
    assert!(!harness
        .device_manager
        .read()
        .await
        .contains_device(device_id));
    assert!(!disk_path(source).exists());
    assert!(!metadata_path(source).exists());
}

async fn unclassified_emptydir_attach_retry_releases_identity(root: &Path) {
    let harness = Harness::new(Some(1), true).await;
    let (spec, sources) = emptydir_spec(root, 1);
    assert!(harness.handle(&spec).await.is_err());

    let first_snapshot = harness.hypervisor.snapshot();
    let device_id = first_snapshot.attempted_devices[0].0.clone();
    assert!(harness
        .device_manager
        .read()
        .await
        .contains_device(&device_id));

    harness.handle(&spec).await.unwrap();
    let retry_snapshot = harness.hypervisor.snapshot();
    assert_eq!(retry_snapshot.attempted_indexes, vec![0, 0]);
    assert_eq!(retry_snapshot.attempted_devices[1].0, device_id);

    harness
        .volume_resource
        .detach_ephemeral_disks(&harness.device_manager)
        .await
        .unwrap();
    assert!(!harness
        .device_manager
        .read()
        .await
        .contains_device(&device_id));
    harness.hypervisor.stop();
    harness
        .volume_resource
        .finalize_ephemeral_disks(&harness.device_manager)
        .await
        .unwrap();
    assert!(!disk_path(&sources[0]).exists());
    assert!(!metadata_path(&sources[0]).exists());
}

async fn concurrent_same_source_constructor(root: &Path) {
    let gate = Arc::new(FirstAddGate::default());
    let harness = Arc::new(Harness::with_first_add_gate(gate.clone()).await);
    let (spec, sources) = emptydir_spec(root, 1);
    let source = &sources[0];
    let disk = disk_path(source);
    let first_harness = harness.clone();
    let first_spec = spec.clone();
    let first = tokio::spawn(async move { first_harness.handle(&first_spec).await });

    timeout(ASYNC_ASSERTION_TIMEOUT, gate.entered.notified())
        .await
        .expect("first add did not enter the gate");
    assert_eq!(harness.hypervisor.snapshot().attempted_devices.len(), 1);

    let second_ready = Arc::new(Barrier::new(2));
    let second_harness = harness.clone();
    let second_spec = spec.clone();
    let second_barrier = second_ready.clone();
    let mut second = tokio::spawn(async move {
        second_barrier.wait().await;
        second_harness.handle(&second_spec).await
    });
    timeout(ASYNC_ASSERTION_TIMEOUT, second_ready.wait())
        .await
        .expect("second constructor did not start");
    assert!(
        timeout(PENDING_ASSERTION_INTERVAL, &mut second)
            .await
            .is_err(),
        "second constructor completed before the first add was released"
    );
    assert_eq!(harness.hypervisor.snapshot().attempted_devices.len(), 1);

    gate.release.notify_one();
    let first_result = timeout(ASYNC_ASSERTION_TIMEOUT, first)
        .await
        .expect("first constructor did not complete")
        .unwrap();
    assert!(first_result.is_err());
    let second_result = timeout(ASYNC_ASSERTION_TIMEOUT, second)
        .await
        .expect("second constructor did not complete")
        .unwrap()
        .unwrap();
    assert_eq!(second_result.len(), 1);

    let snapshot = harness.hypervisor.snapshot();
    assert_eq!(snapshot.attempted_devices.len(), 2);
    assert_eq!(snapshot.added_devices.len(), 1);
    assert_eq!(
        snapshot.add_events,
        vec![
            AddEvent::Attempt(1),
            AddEvent::FirstReleased,
            AddEvent::Attempt(2)
        ]
    );
    let failed_device_id = &snapshot.attempted_devices[0].0;
    let attached_device_id = &snapshot.added_devices[0].0;
    assert_eq!(failed_device_id, attached_device_id);
    let device_manager = harness.device_manager.read().await;
    assert!(device_manager.contains_device(attached_device_id));
    drop(device_manager);
    assert!(disk.exists());
    assert!(metadata_path(source).exists());

    harness
        .volume_resource
        .detach_ephemeral_disks(&harness.device_manager)
        .await
        .unwrap();
    assert!(!harness
        .device_manager
        .read()
        .await
        .contains_device(attached_device_id));
    assert!(disk.exists());
    harness.hypervisor.stop();
    harness
        .volume_resource
        .finalize_ephemeral_disks(&harness.device_manager)
        .await
        .unwrap();
    assert!(!disk.exists());
    assert!(!metadata_path(source).exists());
}

async fn same_source_sharing(root: &Path) {
    let hypervisor = Arc::new(FakeHypervisor::new(None, true));
    let device_manager = RwLock::new(DeviceManager::new(hypervisor.clone(), None).await.unwrap());
    let first = VolumeResource::new();
    let second = VolumeResource::new();
    let share_fs = None;
    let agent: Arc<dyn Agent> = Arc::new(KataAgent::new(AgentConfig::default()));
    let source = emptydir_path(root, "shared");
    std::fs::create_dir_all(&source).unwrap();
    let mount = oci::MountBuilder::default()
        .source(&source)
        .destination("/shared")
        .typ("bind")
        .build()
        .unwrap();
    let spec = oci::SpecBuilder::default()
        .mounts(vec![mount])
        .build()
        .unwrap();
    let context = VolumeContext {
        share_fs: &share_fs,
        d: &device_manager,
        sid: "sandbox",
        agent,
        emptydir_mode: EMPTYDIR_MODE_BLOCK_PLAIN,
        fs_sharing_supported: false,
        block_device_discard_supported: false,
    };
    first
        .handler_volumes(&context, "first", &spec)
        .await
        .unwrap();
    second
        .handler_volumes(&context, "second", &spec)
        .await
        .unwrap();
    let snapshot = hypervisor.snapshot();
    assert_eq!(snapshot.added_devices.len(), 1);
    let device_id = snapshot.added_devices[0].0.clone();
    let disk = disk_path(&source);

    first.detach_ephemeral_disks(&device_manager).await.unwrap();
    assert!(device_manager.read().await.contains_device(&device_id));
    assert!(hypervisor.snapshot().removed_paths.is_empty());
    assert!(disk.exists());
    assert!(metadata_path(&source).exists());

    second
        .detach_ephemeral_disks(&device_manager)
        .await
        .unwrap();
    assert!(!device_manager.read().await.contains_device(&device_id));
    assert_eq!(hypervisor.snapshot().removed_paths.len(), 1);
    assert!(disk.exists());
    assert!(metadata_path(&source).exists());

    hypervisor.stop();
    first
        .finalize_ephemeral_disks(&device_manager)
        .await
        .unwrap();
    second
        .finalize_ephemeral_disks(&device_manager)
        .await
        .unwrap();
    assert!(!disk.exists());
    assert!(!metadata_path(&source).exists());
}

async fn unsupported_hot_unplug(root: &Path) {
    let harness = Harness::new(None, false).await;
    let (spec, sources) = emptydir_spec(root, 1);
    harness.handle(&spec).await.unwrap();
    let snapshot = harness.hypervisor.snapshot();
    let device_id = snapshot.added_devices[0].0.clone();
    let disk = disk_path(&sources[0]);

    assert!(harness
        .volume_resource
        .detach_ephemeral_disks(&harness.device_manager)
        .await
        .is_err());
    assert!(harness
        .device_manager
        .read()
        .await
        .contains_device(&device_id));
    assert!(disk.exists());
    assert!(metadata_path(&sources[0]).exists());

    harness.hypervisor.stop();
    harness
        .volume_resource
        .finalize_ephemeral_disks(&harness.device_manager)
        .await
        .unwrap();
    assert!(!harness
        .device_manager
        .read()
        .await
        .contains_device(&device_id));
    assert!(!disk.exists());
    assert!(!metadata_path(&sources[0]).exists());
}

async fn assert_owned_prefix(
    harness: &Harness,
    sources: &[PathBuf],
    attempted_devices: &[(String, String)],
    registered: usize,
    artifacts: usize,
    mapped: usize,
) {
    for (index, (source, (device_id, _))) in sources.iter().zip(attempted_devices).enumerate() {
        assert_eq!(
            harness
                .device_manager
                .read()
                .await
                .contains_device(device_id),
            index < registered
        );
        assert_eq!(disk_path(source).exists(), index < artifacts);
        assert_eq!(metadata_path(source).exists(), index < artifacts);
        let source_stats = harness
            .volume_resource
            .guest_volume_stats_path(source.to_str().unwrap())
            .await;
        assert_eq!(source_stats.is_some(), index < mapped);
        assert_eq!(
            harness
                .volume_resource
                .guest_volume_stats_path(disk_path(source).to_str().unwrap())
                .await,
            source_stats
        );
    }
}

async fn failed_detach_during_rollback(root: &Path) {
    let harness = Harness::new(Some(2), false).await;
    let (spec, sources) = emptydir_spec(root, 2);
    let error = harness.handle(&spec).await.err().unwrap();
    let error = format!("{error:#}");
    assert!(error.contains("failed to attach volume 2 of 2"));
    assert!(error.contains("injected add_device failure"));
    assert!(error.contains("volume rollback incomplete"));
    assert!(error.contains("hot unplug unsupported"));

    let snapshot = harness.hypervisor.snapshot();
    let expected_attempts = sources
        .iter()
        .map(|source| disk_path(source).display().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        snapshot
            .attempted_devices
            .iter()
            .map(|(_, path)| path.clone())
            .collect::<Vec<_>>(),
        expected_attempts
    );
    assert_eq!(snapshot.added_devices.len(), 1);
    assert_eq!(snapshot.added_devices[0].1, expected_attempts[0]);
    assert!(snapshot.removed_paths.is_empty());
    assert_owned_prefix(&harness, &sources, &snapshot.attempted_devices, 2, 2, 1).await;

    let error = harness
        .volume_resource
        .detach_ephemeral_disks(&harness.device_manager)
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("hot unplug unsupported"));
    assert_owned_prefix(&harness, &sources, &snapshot.attempted_devices, 2, 2, 1).await;

    harness.hypervisor.stop();
    harness
        .volume_resource
        .finalize_ephemeral_disks(&harness.device_manager)
        .await
        .unwrap();
    assert_owned_prefix(&harness, &sources, &snapshot.attempted_devices, 0, 0, 0).await;
}

async fn ambiguous_attach_without_path_lookup(root: &Path) {
    let harness = Harness::with_ambiguous_add().await;
    let (spec, sources) = emptydir_spec(root, 1);
    let error = match harness.handle(&spec).await {
        Ok(_) => panic!("ambiguous attach unexpectedly succeeded"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("injected ambiguous add_device failure"));

    let snapshot = harness.hypervisor.snapshot();
    let (device_id, _) = &snapshot.added_devices[0];
    let source = &sources[0];
    let disk = disk_path(source);
    assert_eq!(
        find_device_id(&harness.device_manager, disk.to_str().unwrap()).await,
        None
    );
    assert!(harness
        .device_manager
        .read()
        .await
        .contains_device(device_id));
    assert!(disk.exists());
    assert!(metadata_path(source).exists());

    assert!(harness
        .volume_resource
        .detach_ephemeral_disks(&harness.device_manager)
        .await
        .is_err());
    assert!(disk.exists());
    assert!(metadata_path(source).exists());

    harness.hypervisor.stop();
    harness
        .volume_resource
        .finalize_ephemeral_disks(&harness.device_manager)
        .await
        .unwrap();
    assert!(!disk.exists());
    assert!(!metadata_path(source).exists());
}

async fn qemu_constructor_owns_pcie_root_port_attachments(root: &Path, block_driver: &str) {
    let harness = Harness::qemu(block_driver).await;
    let (spec, sources) = emptydir_spec(root, 8);
    let volumes = harness.handle(&spec).await.unwrap();
    let snapshot = harness.hypervisor.snapshot();

    assert_eq!(volumes.len(), 8);
    assert_eq!(snapshot.attempted_devices, snapshot.added_devices);
    assert_eq!(snapshot.block_adds.len(), 8);
    for (index, add) in snapshot.block_adds.iter().enumerate() {
        let expected_root_port = format!("rp{index}");
        assert_eq!(add.driver_option, KATA_BLK_DEV_TYPE);
        assert!(add.discard_unmap);
        assert!(add.use_pcie_root_port);
        assert_eq!(
            add.pcie_root_port.as_deref(),
            Some(expected_root_port.as_str())
        );
        assert_eq!(add.index, index as u64);
        assert_eq!(
            add.path_on_host,
            disk_path(&sources[index]).display().to_string()
        );

        let storage = volumes[index].get_storage().unwrap().pop().unwrap();
        assert_eq!(storage.driver, KATA_BLK_DEV_TYPE);
        assert_eq!(storage.source, format!("{:02x}/00", index + 2));
    }
    assert_eq!(
        harness
            .device_manager
            .read()
            .await
            .get_pcie_topology()
            .unwrap()
            .reserved_bus
            .len(),
        8
    );

    harness
        .volume_resource
        .detach_ephemeral_disks(&harness.device_manager)
        .await
        .unwrap();
    let device_manager = harness.device_manager.read().await;
    assert!(snapshot
        .block_adds
        .iter()
        .all(|add| !device_manager.contains_device(&add.device_id)));
    drop(device_manager);
    assert!(harness
        .device_manager
        .read()
        .await
        .get_pcie_topology()
        .unwrap()
        .reserved_bus
        .is_empty());
    assert!(sources
        .iter()
        .all(|source| disk_path(source).exists() && metadata_path(source).exists()));

    harness.hypervisor.stop();
    harness
        .volume_resource
        .finalize_ephemeral_disks(&harness.device_manager)
        .await
        .unwrap();
    assert!(sources
        .iter()
        .all(|source| !disk_path(source).exists() && !metadata_path(source).exists()));
}

static TEST_RUNTIME_DIR: LazyLock<TempDir> = LazyLock::new(|| {
    kata_types::rootless::set_rootless(true);
    let runtime_dir = TempDir::new().unwrap();
    std::env::set_var("XDG_RUNTIME_DIR", runtime_dir.path());
    runtime_dir
});

fn test_root() -> TempDir {
    LazyLock::force(&TEST_RUNTIME_DIR);
    TempDir::new().unwrap()
}

#[tokio::test]
async fn cancellation_before_attach_starts_preserves_cleanup_ownership() {
    let root = test_root();
    let gate = Arc::new(FirstAddGate::default());
    let harness = Arc::new(Harness::with_config_gate(gate.clone()).await);
    let (spec, sources) = emptydir_spec(&root.path().join("cancel-before-attach"), 1);
    let setup_harness = harness.clone();
    let setup = tokio::spawn(async move { setup_harness.handle(&spec).await });

    timeout(ASYNC_ASSERTION_TIMEOUT, gate.entered.notified())
        .await
        .expect("block configuration lookup did not reach the gate");
    let source = &sources[0];
    assert!(disk_path(source).exists());
    assert!(metadata_path(source).exists());
    setup.abort();
    assert!(matches!(setup.await, Err(error) if error.is_cancelled()));

    harness.hypervisor.stop();
    harness
        .volume_resource
        .finalize_ephemeral_disks(&harness.device_manager)
        .await
        .unwrap();
    assert!(!disk_path(source).exists());
    assert!(!metadata_path(source).exists());
}

#[tokio::test]
async fn cancellation_while_add_is_blocked_detaches_and_finalizes() {
    let root = test_root();
    let gate = Arc::new(FirstAddGate::default());
    let harness = Arc::new(Harness::with_first_add_gate(gate.clone()).await);
    let (spec, sources) = emptydir_spec(&root.path().join("cancel-blocked-add"), 1);
    let setup_harness = harness.clone();
    let setup = tokio::spawn(async move { setup_harness.handle(&spec).await });

    timeout(ASYNC_ASSERTION_TIMEOUT, gate.entered.notified())
        .await
        .expect("block attach did not reach the gate");
    let device_id = harness.hypervisor.snapshot().attempted_devices[0].0.clone();
    setup.abort();
    assert!(matches!(setup.await, Err(error) if error.is_cancelled()));

    harness
        .volume_resource
        .detach_ephemeral_disks(&harness.device_manager)
        .await
        .unwrap();
    assert!(!harness
        .device_manager
        .read()
        .await
        .contains_device(&device_id));
    harness.hypervisor.stop();
    harness
        .volume_resource
        .finalize_ephemeral_disks(&harness.device_manager)
        .await
        .unwrap();
    assert!(!disk_path(&sources[0]).exists());
    assert!(!metadata_path(&sources[0]).exists());
}

#[tokio::test]
async fn cancellation_after_backend_add_detaches_and_finalizes() {
    let root = test_root();
    let gate = Arc::new(FirstAddGate::default());
    let harness = Arc::new(Harness::with_successful_add_gate(gate.clone()).await);
    let (spec, sources) = emptydir_spec(&root.path().join("cancel-after-add"), 1);
    let setup_harness = harness.clone();
    let setup = tokio::spawn(async move { setup_harness.handle(&spec).await });

    timeout(ASYNC_ASSERTION_TIMEOUT, gate.entered.notified())
        .await
        .expect("successful block attach did not reach the gate");
    let device_id = harness.hypervisor.snapshot().added_devices[0].0.clone();
    setup.abort();
    assert!(matches!(setup.await, Err(error) if error.is_cancelled()));

    harness
        .volume_resource
        .detach_ephemeral_disks(&harness.device_manager)
        .await
        .unwrap();
    assert!(!harness
        .device_manager
        .read()
        .await
        .contains_device(&device_id));
    assert_eq!(harness.hypervisor.snapshot().removed_paths.len(), 1);
    harness.hypervisor.stop();
    harness
        .volume_resource
        .finalize_ephemeral_disks(&harness.device_manager)
        .await
        .unwrap();
    assert!(!disk_path(&sources[0]).exists());
    assert!(!metadata_path(&sources[0]).exists());
}

#[tokio::test]
async fn concurrent_same_source_survives_canceled_owner_constructor() {
    let root = test_root();
    let gate = Arc::new(FirstAddGate::default());
    let harness = Arc::new(Harness::with_first_add_gate(gate.clone()).await);
    let (spec, sources) = emptydir_spec(&root.path().join("cancel-shared-source"), 1);
    let first_harness = harness.clone();
    let first_spec = spec.clone();
    let first = tokio::spawn(async move { first_harness.handle(&first_spec).await });
    timeout(ASYNC_ASSERTION_TIMEOUT, gate.entered.notified())
        .await
        .expect("first block attach did not reach the gate");

    let second_started = Arc::new(Barrier::new(2));
    let second_harness = harness.clone();
    let second_barrier = second_started.clone();
    let second = tokio::spawn(async move {
        second_barrier.wait().await;
        second_harness.handle(&spec).await
    });
    second_started.wait().await;
    first.abort();
    assert!(matches!(first.await, Err(error) if error.is_cancelled()));
    timeout(ASYNC_ASSERTION_TIMEOUT, second)
        .await
        .expect("second same-source constructor did not complete")
        .unwrap()
        .unwrap();

    harness
        .volume_resource
        .detach_ephemeral_disks(&harness.device_manager)
        .await
        .unwrap();
    harness.hypervisor.stop();
    harness
        .volume_resource
        .finalize_ephemeral_disks(&harness.device_manager)
        .await
        .unwrap();
    assert!(!disk_path(&sources[0]).exists());
    assert!(!metadata_path(&sources[0]).exists());
}

#[tokio::test]
async fn post_stop_finalization_needs_no_canceled_constructor_retry() {
    let root = test_root();
    let gate = Arc::new(FirstAddGate::default());
    let harness = Arc::new(Harness::with_first_add_gate(gate.clone()).await);
    let (spec, sources) = emptydir_spec(&root.path().join("cancel-no-retry"), 1);
    let setup_harness = harness.clone();
    let setup = tokio::spawn(async move { setup_harness.handle(&spec).await });

    timeout(ASYNC_ASSERTION_TIMEOUT, gate.entered.notified())
        .await
        .expect("block attach did not reach the gate");
    let device_id = harness.hypervisor.snapshot().attempted_devices[0].0.clone();
    setup.abort();
    assert!(matches!(setup.await, Err(error) if error.is_cancelled()));

    harness.hypervisor.stop();
    harness
        .volume_resource
        .finalize_ephemeral_disks(&harness.device_manager)
        .await
        .unwrap();
    assert!(!harness
        .device_manager
        .read()
        .await
        .contains_device(&device_id));
    assert!(!disk_path(&sources[0]).exists());
    assert!(!metadata_path(&sources[0]).exists());
}

#[tokio::test]
async fn finalization_waits_for_previously_registered_blocked_attach() {
    let root = test_root();
    let gate = Arc::new(FirstAddGate::default());
    let harness = Arc::new(Harness::with_successful_add_gate(gate.clone()).await);
    let (spec, sources) = emptydir_spec(&root.path().join("seal-blocked-attach"), 1);
    let setup_harness = harness.clone();
    let setup = tokio::spawn(async move { setup_harness.handle(&spec).await });

    timeout(ASYNC_ASSERTION_TIMEOUT, gate.entered.notified())
        .await
        .expect("block attach did not reach the gate");
    harness.hypervisor.stop();
    let finalize_harness = harness.clone();
    let finalize = tokio::spawn(async move {
        finalize_harness
            .volume_resource
            .finalize_ephemeral_disks(&finalize_harness.device_manager)
            .await
    });
    tokio::task::yield_now().await;
    assert!(!finalize.is_finished());

    gate.release.notify_one();
    setup.await.unwrap().unwrap();
    finalize.await.unwrap().unwrap();

    assert!(!disk_path(&sources[0]).exists());
    assert!(!metadata_path(&sources[0]).exists());
}

#[tokio::test]
async fn setup_after_finalization_never_creates_or_attaches() {
    let root = test_root();
    let harness = Harness::new(None, true).await;
    harness.hypervisor.stop();
    harness
        .volume_resource
        .finalize_ephemeral_disks(&harness.device_manager)
        .await
        .unwrap();
    let (spec, sources) = emptydir_spec(&root.path().join("setup-after-seal"), 1);

    let error = match harness.handle(&spec).await {
        Ok(_) => panic!("setup unexpectedly succeeded after ownership was sealed"),
        Err(error) => error,
    };

    assert!(format!("{error:#}").contains("sealed"));
    assert!(harness.hypervisor.snapshot().attempted_devices.is_empty());
    assert!(!disk_path(&sources[0]).exists());
    assert!(!metadata_path(&sources[0]).exists());
}

#[tokio::test]
async fn happy_path_maps_stats_and_cleans_owned_state() {
    let root = test_root();
    happy_path(&root.path().join("happy")).await;
}

#[tokio::test]
async fn every_add_failure_rolls_back_without_residue() {
    let root = test_root();
    all_add_failure_ordinals(&root.path().join("failures")).await;
}

#[tokio::test]
async fn ordinary_block_failure_releases_device_identity() {
    ordinary_block_attach_failure_releases_manager_state_and_index().await;
}

#[tokio::test]
async fn ordinary_emptydir_failure_preserves_artifacts_until_vm_stop() {
    let root = test_root();
    ordinary_emptydir_attach_failure_defers_artifact_cleanup(&root.path().join("ordinary")).await;
}

#[tokio::test]
async fn unclassified_emptydir_failure_retry_clears_device_identity() {
    let root = test_root();
    unclassified_emptydir_attach_retry_releases_identity(&root.path().join("unknown-retry")).await;
}

#[tokio::test]
async fn concurrent_same_source_waits_for_failed_constructor_cleanup() {
    let root = test_root();
    concurrent_same_source_constructor(&root.path().join("constructor")).await;
}

#[tokio::test]
async fn shared_source_detaches_only_after_final_reference() {
    let root = test_root();
    same_source_sharing(&root.path().join("sharing")).await;
}

#[tokio::test]
async fn post_stop_finalization_handles_unsupported_hot_unplug() {
    let root = test_root();
    unsupported_hot_unplug(&root.path().join("unsupported")).await;
}

#[tokio::test]
async fn failed_detach_during_rollback_converges_after_vm_stop() {
    let root = test_root();
    failed_detach_during_rollback(&root.path().join("rollback")).await;
}

#[tokio::test]
async fn ambiguous_attach_preserves_artifacts_without_path_lookup() {
    let root = test_root();
    ambiguous_attach_without_path_lookup(&root.path().join("ambiguous")).await;
}

#[tokio::test]
async fn qemu_constructor_selects_pcie_root_ports_for_eight_emptydirs() {
    let root = test_root();
    qemu_constructor_owns_pcie_root_port_attachments(
        &root.path().join("qemu-converted-scsi"),
        VIRTIO_SCSI,
    )
    .await;
}

#[tokio::test]
async fn qemu_constructor_reserves_root_ports_for_preselected_pci() {
    let root = test_root();
    qemu_constructor_owns_pcie_root_port_attachments(
        &root.path().join("qemu-preselected-pci"),
        VIRTIO_BLOCK_PCI,
    )
    .await;
}
