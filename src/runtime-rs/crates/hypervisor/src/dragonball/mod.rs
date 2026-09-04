// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

mod inner;
mod inner_device;
mod inner_hypervisor;
use super::HypervisorState;
use inner::DragonballInner;
use persist::sandbox_persist::Persist;
mod seccomp;
pub mod vmm_instance;

use std::collections::HashMap;
use std::fs::File;
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use dbs_utils::net::MacAddr as DragonballMacAddr;
use dragonball::api::v1::{
    Backend as DragonballBackend, NetworkInterfaceConfig as DragonballNetworkConfig,
    VirtioConfig as DragonballVirtioConfig,
};
use kata_types::capabilities::{Capabilities, CapabilityBits};
use kata_types::config::hypervisor::Hypervisor as HypervisorConfig;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::instrument;

use crate::{DeviceType, Hypervisor, MemoryConfig, NetworkConfig, VcpuThreadIds};

pub struct Dragonball {
    inner: Arc<RwLock<DragonballInner>>,
    exit_waiter: Mutex<(mpsc::Receiver<i32>, i32)>,
}

impl std::fmt::Debug for Dragonball {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dragonball").finish()
    }
}

impl Default for Dragonball {
    fn default() -> Self {
        Self::new()
    }
}

impl Dragonball {
    pub fn new() -> Self {
        let (exit_notify, exit_waiter) = mpsc::channel(1);

        Self {
            inner: Arc::new(RwLock::new(DragonballInner::new(exit_notify))),
            exit_waiter: Mutex::new((exit_waiter, 0)),
        }
    }

    pub async fn set_hypervisor_config(&self, config: HypervisorConfig) {
        let mut inner = self.inner.write().await;
        inner.set_hypervisor_config(config)
    }

    pub async fn set_passfd_listener_port(&self, port: u32) {
        let mut inner = self.inner.write().await;
        inner.set_passfd_listener_port(port)
    }
}

#[async_trait]
impl Hypervisor for Dragonball {
    #[instrument]
    async fn prepare_vm(
        &self,
        id: &str,
        netns: Option<String>,
        _annotations: &HashMap<String, String>,
        selinux_label: Option<String>,
    ) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.prepare_vm(id, netns, selinux_label).await
    }

    #[instrument]
    async fn start_vm(&self, timeout: i32) -> Result<()> {
        let mut inner = self.inner.write().await;
        let ret = inner.start_vm(timeout).await;

        if ret.is_ok() && inner.config.device_info.reclaim_guest_freed_memory {
            // The virtio-balloon device must be inserted into dragonball and
            // recognized by the guest kernel only after the dragonball upcall is ready.
            // The dragonball upcall is not ready immediately after the VM starts,
            // so here we create an asynchronous task that waits for 5 seconds before
            // inserting the virtio-balloon device.
            let inner_clone = self.inner.clone();
            tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                inner_clone
                    .write()
                    .await
                    .try_insert_balloon_f_reporting()
                    .await;
            });
        }

        ret
    }

    async fn stop_vm(&self) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.stop_vm()
    }

    async fn wait_vm(&self) -> Result<i32> {
        let mut waiter = self.exit_waiter.lock().await;
        if let Some(exit_code) = waiter.0.recv().await {
            waiter.1 = exit_code;
        }

        Ok(waiter.1)
    }

    async fn pause_vm(&self) -> Result<()> {
        let inner = self.inner.read().await;
        inner.pause_vm()
    }

    async fn resume_vm(&self) -> Result<()> {
        let inner = self.inner.read().await;
        inner.resume_vm()
    }

    async fn save_vm(&self) -> Result<()> {
        let inner = self.inner.read().await;
        inner.save_vm().await
    }

    // returns Result<(old_vcpus, new_vcpus)>
    async fn resize_vcpu(&self, old_vcpus: u32, new_vcpus: u32) -> Result<(u32, u32)> {
        let inner = self.inner.read().await;
        inner.resize_vcpu(old_vcpus, new_vcpus).await
    }

    async fn add_device(&self, device: DeviceType) -> Result<DeviceType> {
        let mut inner = self.inner.write().await;
        inner.add_device(device.clone()).await
    }

    async fn remove_device(&self, device: DeviceType) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.remove_device(device).await
    }

    async fn update_device(&self, device: DeviceType) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.update_device(device).await
    }

    async fn get_agent_socket(&self) -> Result<String> {
        let inner = self.inner.read().await;
        inner.get_agent_socket().await
    }

    async fn disconnect(&self) {
        let mut inner = self.inner.write().await;
        inner.disconnect().await
    }

    async fn hypervisor_config(&self) -> HypervisorConfig {
        let inner = self.inner.read().await;
        inner.hypervisor_config()
    }

    async fn get_thread_ids(&self) -> Result<VcpuThreadIds> {
        let inner = self.inner.read().await;
        inner.get_thread_ids().await
    }

    async fn cleanup(&self) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.cleanup().await
    }

    async fn get_pids(&self) -> Result<Vec<u32>> {
        let inner = self.inner.read().await;
        inner.get_pids().await
    }

    async fn get_vmm_master_tid(&self) -> Result<u32> {
        let inner = self.inner.read().await;
        inner.get_vmm_master_tid().await
    }

    async fn get_ns_path(&self) -> Result<String> {
        let inner = self.inner.read().await;
        inner.get_ns_path().await
    }

    async fn get_vmm_netns(&self) -> Result<Option<File>> {
        let inner = self.inner.read().await;
        inner.get_vmm_netns().map(Some)
    }

    async fn check(&self) -> Result<()> {
        let inner = self.inner.read().await;
        inner.check().await
    }

    async fn get_jailer_root(&self) -> Result<String> {
        let inner = self.inner.read().await;
        inner.get_jailer_root().await
    }

    async fn save_state(&self) -> Result<HypervisorState> {
        self.save().await
    }

    async fn capabilities(&self) -> Result<Capabilities> {
        let inner = self.inner.read().await;
        inner.capabilities().await
    }

    fn is_agent_metrics_supported(&self) -> bool {
        // Agent metrics can wedge Dragonball's shared HybridVsock channel,
        // blocking lifecycle and stats RPCs. Keep monitoring host-side.
        false
    }

    async fn get_hypervisor_metrics(&self) -> Result<String> {
        let inner = self.inner.read().await;
        inner.get_hypervisor_metrics().await
    }

    async fn set_capabilities(&self, flag: CapabilityBits) {
        let mut inner = self.inner.write().await;
        inner.set_capabilities(flag)
    }

    async fn set_guest_memory_block_size(&self, size: u32) {
        let mut inner = self.inner.write().await;
        inner.set_guest_memory_block_size(size);
    }

    async fn guest_memory_block_size(&self) -> u32 {
        let inner = self.inner.read().await;
        inner.guest_memory_block_size_mb()
    }

    async fn resize_memory(&self, new_mem_mb: u32) -> Result<(u32, MemoryConfig)> {
        let mut inner = self.inner.write().await;
        inner.resize_memory(new_mem_mb)
    }

    async fn get_passfd_listener_addr(&self) -> Result<(String, u32)> {
        let inner = self.inner.read().await;
        inner.get_passfd_listener_addr().await
    }
}

#[async_trait]
impl Persist for Dragonball {
    type State = HypervisorState;
    type ConstructorArgs = ();
    /// Save a state of the component.
    async fn save(&self) -> Result<Self::State> {
        let inner = self.inner.read().await;
        inner.save().await.context("save hypervisor state")
    }
    /// Restore a component from a specified state.
    async fn restore(
        _hypervisor_args: Self::ConstructorArgs,
        hypervisor_state: Self::State,
    ) -> Result<Self> {
        let (exit_notify, exit_waiter) = mpsc::channel(1);

        let inner = DragonballInner::restore(exit_notify, hypervisor_state).await?;
        Ok(Self {
            inner: Arc::new(RwLock::new(inner)),
            exit_waiter: Mutex::new((exit_waiter, 0)),
        })
    }
}

/// Generate Dragonball network config according to hypervisor config and
/// runtime network config.
pub(crate) fn build_dragonball_network_config(
    hconfig: &HypervisorConfig,
    nconfig: &NetworkConfig,
) -> DragonballNetworkConfig {
    let virtio_config = DragonballVirtioConfig {
        iface_id: nconfig.virt_iface_name.clone(),
        host_dev_name: nconfig.host_dev_name.clone(),
        // TODO(justxuewei): rx_rate_limiter is not supported, see:
        // https://github.com/kata-containers/kata-containers/issues/8327.
        rx_rate_limiter: None,
        // TODO(justxuewei): tx_rate_limiter is not supported, see:
        // https://github.com/kata-containers/kata-containers/issues/8327.
        tx_rate_limiter: None,
        allow_duplicate_mac: nconfig.allow_duplicate_mac,
    };

    let backend = if hconfig.network_info.disable_vhost_net {
        DragonballBackend::Virtio(virtio_config)
    } else {
        DragonballBackend::Vhost(virtio_config)
    };

    // `config.num_queues` is a queue *pair* count (1 RX + 1 TX per pair).
    // Convert pairs into the actual queue count.
    let num_queues = nconfig.queue_num.max(1) * 2;
    DragonballNetworkConfig {
        num_queues: Some(num_queues),
        queue_size: Some(nconfig.queue_size as u16),
        backend,
        guest_mac: nconfig.guest_mac.clone().map(|mac| {
            // We are safety since mac address is checked by endpoints.
            DragonballMacAddr::from_bytes(&mac.0).unwrap()
        }),
        use_shared_irq: nconfig.use_shared_irq,
        use_generic_irq: nconfig.use_generic_irq,
    }
}

#[cfg(test)]
mod tests {
    use std::{convert::TryFrom, path::PathBuf, sync::Arc, thread, time::Duration};

    use crossbeam_channel::Sender;
    use dragonball::api::v1::{BlockHotplugResult, VmmAction, VmmData, VmmResponse};
    use kata_types::config::hypervisor::Hypervisor as HypervisorConfig;
    use tokio::sync::RwLock;

    use super::{vmm_instance::VmmInstance, Dragonball};
    use crate::device::pci_path::PciPath;
    #[cfg(target_arch = "aarch64")]
    use crate::VIRTIO_BLOCK_MMIO;
    #[cfg(target_arch = "x86_64")]
    use crate::VIRTIO_BLOCK_PCI;
    use crate::{
        device::{
            device_manager::{do_handle_device, DeviceManager, DeviceRemoval},
            DeviceConfig, DeviceType,
        },
        BlockConfigModern, Hypervisor, VmmState,
    };

    const RESPONDER_TIMEOUT: Duration = Duration::from_secs(2);
    #[cfg(target_arch = "x86_64")]
    const CALLBACK_SLOTS: [Option<i32>; 8] = [
        Some(6),
        Some(2),
        Some(8),
        Some(4),
        Some(1),
        Some(7),
        Some(3),
        Some(5),
    ];
    #[cfg(target_arch = "aarch64")]
    const CALLBACK_SLOTS: [Option<i32>; 8] = [None; 8];
    #[cfg(target_arch = "x86_64")]
    const REPLACEMENT_CALLBACK_SLOT: Option<i32> = Some(6);
    #[cfg(target_arch = "aarch64")]
    const REPLACEMENT_CALLBACK_SLOT: Option<i32> = None;

    #[test]
    fn test_dragonball_disables_agent_metrics() {
        assert!(!Dragonball::new().is_agent_metrics_supported());
    }

    fn send_block_hotplug_response(
        response_sender: &Sender<VmmResponse>,
        result: BlockHotplugResult,
    ) {
        let (sender, receiver) = std::sync::mpsc::channel();
        response_sender
            .send(Box::new(Ok(VmmData::SyncBlockHotplug((
                sender.clone(),
                receiver,
            )))))
            .unwrap();
        sender.send(result).unwrap();
    }

    #[tokio::test]
    async fn block_lifecycle_uses_dragonball_driver_at_one_four_and_eight_devices() {
        #[cfg(target_arch = "aarch64")]
        let (driver, use_pci_bus) = (VIRTIO_BLOCK_MMIO, false);
        #[cfg(target_arch = "x86_64")]
        let (driver, use_pci_bus) = (VIRTIO_BLOCK_PCI, true);

        let hypervisor = Arc::new(Dragonball::new());
        let mut config = HypervisorConfig::default();
        config.blockdev_info.block_device_driver = driver.to_string();
        hypervisor.set_hypervisor_config(config).await;

        let (instance, request_receiver, response_sender) =
            VmmInstance::test_channels("block-lifecycle-test");
        {
            let mut inner = hypervisor.inner.write().await;
            inner.state = VmmState::VmRunning;
            inner.vmm_instance = instance;
        }

        let responder = thread::spawn(move || {
            let mut insertions = Vec::new();
            for (index, callback_slot) in CALLBACK_SLOTS.iter().copied().enumerate() {
                let request = *request_receiver.recv_timeout(RESPONDER_TIMEOUT).unwrap();
                let VmmAction::InsertBlockDevice(config) = request else {
                    panic!("expected block insertion request, got {:?}", request);
                };
                assert_eq!(
                    config.path_on_host,
                    PathBuf::from(format!("/tmp/dragonball-block-{index}.img"))
                );
                assert_eq!(config.use_pci_bus, Some(use_pci_bus));
                assert!(config.sparse);
                insertions.push(config.drive_id);

                send_block_hotplug_response(&response_sender, Ok(callback_slot));
            }

            let mut removals = Vec::new();
            for _ in 0..8 {
                let prepare = *request_receiver.recv_timeout(RESPONDER_TIMEOUT).unwrap();
                let VmmAction::PrepareRemoveBlockDevice(prepare_id) = prepare else {
                    panic!("expected block removal preparation, got {:?}", prepare);
                };
                send_block_hotplug_response(&response_sender, Ok(None));

                let remove = *request_receiver.recv_timeout(RESPONDER_TIMEOUT).unwrap();
                let VmmAction::RemoveBlockDevice(id) = remove else {
                    panic!("expected block removal request, got {:?}", remove);
                };
                assert_eq!(id, prepare_id);
                removals.push(id);
                response_sender.send(Box::new(Ok(VmmData::Empty))).unwrap();
            }

            let replacement = *request_receiver.recv_timeout(RESPONDER_TIMEOUT).unwrap();
            let VmmAction::InsertBlockDevice(config) = replacement else {
                panic!(
                    "expected replacement block insertion request, got {:?}",
                    replacement
                );
            };
            assert_eq!(
                config.path_on_host,
                PathBuf::from("/tmp/dragonball-block-replacement.img")
            );
            assert_eq!(config.use_pci_bus, Some(use_pci_bus));
            assert!(config.sparse);
            let replacement_insertion = config.drive_id;
            send_block_hotplug_response(&response_sender, Ok(REPLACEMENT_CALLBACK_SLOT));

            let prepare = *request_receiver.recv_timeout(RESPONDER_TIMEOUT).unwrap();
            let VmmAction::PrepareRemoveBlockDevice(replacement_prepare) = prepare else {
                panic!(
                    "expected replacement block removal preparation, got {:?}",
                    prepare
                );
            };
            send_block_hotplug_response(&response_sender, Ok(None));

            let remove = *request_receiver.recv_timeout(RESPONDER_TIMEOUT).unwrap();
            let VmmAction::RemoveBlockDevice(replacement_removal) = remove else {
                panic!(
                    "expected replacement block removal request, got {:?}",
                    remove
                );
            };
            assert_eq!(replacement_removal, replacement_prepare);
            response_sender.send(Box::new(Ok(VmmData::Empty))).unwrap();
            drop(response_sender);

            (
                insertions,
                removals,
                replacement_insertion,
                replacement_removal,
            )
        });

        let manager = RwLock::new(DeviceManager::new(hypervisor.clone(), None).await.unwrap());
        let mut device_ids = Vec::new();
        let mut block_devices = Vec::new();
        for index in 0..8 {
            let device = do_handle_device(
                &manager,
                &DeviceConfig::BlockCfgModern(BlockConfigModern {
                    path_on_host: format!("/tmp/dragonball-block-{index}.img"),
                    driver_option: driver.to_string(),
                    discard_unmap: true,
                    ..Default::default()
                }),
            )
            .await
            .unwrap();
            let DeviceType::BlockModern(block) = device else {
                panic!("expected BlockModern device");
            };
            device_ids.push(block.lock().await.device_id.clone());
            block_devices.push(block);

            if matches!(index + 1, 1 | 4 | 8) {
                let manager = manager.read().await;
                assert_eq!(block_devices.len(), index + 1);
                for (device_index, block) in block_devices.iter().enumerate() {
                    let block = block.lock().await;
                    assert_eq!(block.config.index, device_index as u64);
                    assert_eq!(
                        block.config.virt_path,
                        format!("/dev/vd{}", char::from(b'a' + device_index as u8))
                    );
                    let expected_pci_path = CALLBACK_SLOTS[device_index]
                        .map(|slot| PciPath::try_from(slot as u32).unwrap());
                    assert_eq!(block.config.pci_path.as_ref(), expected_pci_path.as_ref());
                    assert!(manager.contains_device(&block.device_id));
                }
            }
        }

        for id in device_ids.iter().rev() {
            assert_eq!(
                manager
                    .write()
                    .await
                    .try_remove_device_with_outcome(id)
                    .await
                    .unwrap(),
                DeviceRemoval::Detached
            );
            assert!(!manager.read().await.contains_device(id));
        }
        {
            let manager = manager.read().await;
            assert!(device_ids.iter().all(|id| !manager.contains_device(id)));
        }
        assert!(hypervisor
            .inner
            .read()
            .await
            .cached_block_devices
            .is_empty());

        let replacement = do_handle_device(
            &manager,
            &DeviceConfig::BlockCfgModern(BlockConfigModern {
                path_on_host: "/tmp/dragonball-block-replacement.img".to_string(),
                driver_option: driver.to_string(),
                discard_unmap: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        let DeviceType::BlockModern(replacement) = replacement else {
            panic!("expected replacement BlockModern device");
        };
        let replacement_id = {
            let block = replacement.lock().await;
            assert_eq!(block.config.index, 0);
            assert_eq!(block.config.virt_path, "/dev/vda");
            let expected_pci_path =
                REPLACEMENT_CALLBACK_SLOT.map(|slot| PciPath::try_from(slot as u32).unwrap());
            assert_eq!(block.config.pci_path.as_ref(), expected_pci_path.as_ref());
            assert!(manager.read().await.contains_device(&block.device_id));
            block.device_id.clone()
        };
        assert_eq!(
            manager
                .write()
                .await
                .try_remove_device_with_outcome(&replacement_id)
                .await
                .unwrap(),
            DeviceRemoval::Detached
        );
        {
            let manager = manager.read().await;
            assert!(device_ids
                .iter()
                .chain(std::iter::once(&replacement_id))
                .all(|id| !manager.contains_device(id)));
        }
        assert!(hypervisor
            .inner
            .read()
            .await
            .cached_block_devices
            .is_empty());

        let (insertions, removals, replacement_insertion, replacement_removal) =
            responder.join().unwrap();
        assert_eq!(insertions, device_ids);
        assert_eq!(
            removals,
            device_ids.iter().rev().cloned().collect::<Vec<_>>()
        );
        assert_eq!(replacement_insertion, replacement_id);
        assert_eq!(replacement_removal, replacement_id);
    }
}
