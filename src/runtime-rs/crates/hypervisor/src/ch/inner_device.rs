// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use super::inner::CloudHypervisorInner;
use crate::ch::utils::get_rootless_symlink_sandbox_jailer_root;
use crate::device::pci_path::PciPath;
use crate::device::{DeviceStateInDoubt, DeviceType};
use crate::utils::create_dir_all_with_inherit_owner;
use crate::utils::open_named_tuntap;
use crate::HybridVsockDevice;
use crate::NetworkConfig;
use crate::NetworkDevice;
use crate::ProtectionDeviceConfig;
use crate::ShareFsConfig;
use crate::ShareFsDevice;
use crate::VfioDevice;
use crate::VmmState;
use crate::{BlockConfigModern, BlockDeviceModern};
use anyhow::{anyhow, Context, Result};
use ch_config::ch_api::cloud_hypervisor_vm_device_add;
use ch_config::ch_api::{
    cloud_hypervisor_vm_blockdev_add, cloud_hypervisor_vm_device_remove,
    cloud_hypervisor_vm_fs_add, cloud_hypervisor_vm_netdev_add_with_fds,
    cloud_hypervisor_vm_vsock_add, is_api_command_not_dispatched, is_definite_server_response,
    PciDeviceInfo, VmRemoveDeviceData,
};
use ch_config::convert::DEFAULT_NUM_PCI_SEGMENTS;
use ch_config::DiskConfig;
use ch_config::ImageType;
use ch_config::{
    net_util::MacAddr, DeviceConfig, FsConfig, NetConfig, ProtectionDevConfig, VsockConfig,
};
use kata_sys_util::netns::NetnsGuard;
use kata_types::config::hypervisor::RateLimiterConfig;
use kata_types::rootless::is_rootless;

use safe_path::scoped_join;
use std::convert::TryFrom;
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

const VIRTIO_FS: &str = "virtio-fs";

#[derive(Debug)]
pub(super) struct OwnedNetworkConfig {
    pub(super) config: NetConfig,
    pub(super) fds: Vec<OwnedFd>,
}

impl CloudHypervisorInner {
    pub(crate) async fn add_device(&mut self, device: DeviceType) -> Result<DeviceType> {
        if self.state != VmmState::VmRunning {
            // If the VM is not running, add the device to the pending list to
            // be handled later.
            //
            // Note that:
            //
            // - ShareFs (virtiofsd) is only needed in an non-DM and non-TDX scenario
            //   for the container rootfs.
            //
            // - A DeviceType::BlockModern requested before the VM is running
            //   has to be cold-plugged, meaning it is turned into an entry of
            //   VmConfig.disks (see 'convert.rs'). This is required for devices
            //   the guest needs early on in its boot, such as the initdata
            //   image. Container rootfs block devices are unaffected as they
            //   are added *after* the VM has started and hence hot-plugged.
            //
            // - The VM rootfs is handled without waiting for calls to this
            //   method as the file in question (image= or initrd=) is available
            //   from HypervisorConfig.BootInfo.{image,initrd}
            //   (see 'convert.rs').
            //
            // - Network details need to be saved for later application.
            //
            match device {
                DeviceType::ShareFs(_) => self.pending_devices.insert(0, device.clone()),
                DeviceType::Network(_) => self.pending_devices.insert(0, device.clone()),
                DeviceType::Vfio(_) => self.pending_devices.insert(0, device.clone()),
                DeviceType::Protection(_) => self.pending_devices.insert(0, device.clone()),
                DeviceType::BlockModern(_) => self.pending_devices.insert(0, device.clone()),
                _ => {
                    debug!(
                        sl!(),
                        "ignoring early add device request for device: {:?}", device
                    );
                }
            }

            return Ok(device);
        }

        self.handle_add_device(device).await
    }

    async fn handle_add_device(&mut self, device: DeviceType) -> Result<DeviceType> {
        match device {
            DeviceType::ShareFs(sharefs) => self.handle_share_fs_device(sharefs).await,
            DeviceType::HybridVsock(hvsock) => self.handle_hvsock_device(hvsock).await,
            DeviceType::BlockModern(block) => self.handle_block_device(block).await,
            DeviceType::Vfio(vfiodev) => self.handle_vfio_device(vfiodev).await,
            DeviceType::Network(netdev) => self.handle_network_device(netdev).await,
            _ => Err(anyhow!("unhandled device: {:?}", device)),
        }
    }

    /// Add the device that were requested to be added before the VMM was
    /// started.
    #[allow(dead_code)]
    pub(crate) async fn handle_pending_devices_after_boot(&mut self) -> Result<()> {
        if self.state != VmmState::VmRunning {
            return Err(anyhow!(
                "cannot handle pending devices with VMM state {:?}",
                self.state
            ));
        }

        while let Some(dev) = self.pending_devices.pop() {
            self.add_device(dev).await.context("add_device")?;
        }

        Ok(())
    }

    pub(crate) async fn remove_device(&mut self, device: DeviceType) -> Result<()> {
        match device {
            DeviceType::Vfio(vfiodev) => {
                self.inner_remove_device(vfiodev.device_id.as_str(), None)
                    .await
            }
            DeviceType::BlockModern(blockdev) => {
                let device_id = blockdev.lock().await.device_id.clone();
                self.inner_remove_device(device_id.as_str(), Some(device_id.as_str()))
                    .await?;
                blockdev.lock().await.config.pci_path = None;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    pub(crate) async fn update_device(&mut self, _device: DeviceType) -> Result<()> {
        Ok(())
    }

    async fn handle_share_fs_device(&mut self, sharefs: ShareFsDevice) -> Result<DeviceType> {
        let device: ShareFsDevice = sharefs.clone();
        if device.config.fs_type != VIRTIO_FS {
            return Err(anyhow!(
                "cannot handle share fs type: {:?}",
                device.config.fs_type
            ));
        }

        let num_queues = device.config.queue_num as usize;
        let queue_size = u16::try_from(device.config.queue_size)?;

        let socket_path = if device.config.sock_path.starts_with('/') {
            PathBuf::from(device.config.sock_path)
        } else {
            scoped_join(&self.vm_path, device.config.sock_path)?
        };

        let fs_config = FsConfig {
            tag: device.config.mount_tag,
            socket: socket_path,
            num_queues,
            queue_size,
            pci_segment: DEFAULT_NUM_PCI_SEGMENTS,

            ..Default::default()
        };

        let response = cloud_hypervisor_vm_fs_add(&self.api_socket, fs_config).await?;

        if let Some(detail) = response {
            debug!(sl!(), "fs add response: {:?}", detail);
        }

        Ok(DeviceType::ShareFs(sharefs))
    }

    async fn handle_vfio_device(&mut self, device: VfioDevice) -> Result<DeviceType> {
        let mut vfio_device: VfioDevice = device.clone();

        // A device with multi-funtions, or a IOMMU group with one more
        // devices, the Primary device is selected to be passed to VM.
        // And the the first one is Primary device.
        // safe here, devices is not empty.
        let primary_device = device.devices.first().ok_or(anyhow!(
            "Primary device list empty for vfio device {:?}",
            device
        ))?;

        let primary_device = primary_device.clone();

        let sysfsdev = primary_device.sysfs_path.clone();

        let device_config = DeviceConfig {
            path: PathBuf::from(sysfsdev),
            iommu: false,
            ..Default::default()
        };

        let response = cloud_hypervisor_vm_device_add(&self.api_socket, device_config).await?;

        if let Some(detail) = response {
            debug!(sl!(), "VFIO add response: {:?}", detail);

            // Store the cloud-hypervisor device id to be used later for remving the device
            let dev_info: PciDeviceInfo =
                serde_json::from_str(detail.as_str()).map_err(|e| anyhow!(e))?;
            self.device_ids
                .insert(device.device_id.clone(), dev_info.id);

            // Update PCI path for the vfio host device. It is safe to directly access the slice element
            // here as we have already checked if it exists.
            // Todo: Handle vfio-ap mediated devices - return error for them.
            vfio_device.devices[0].guest_pci_path =
                Some(Self::clh_pci_info_to_path(&dev_info.bdf)?);
        }

        Ok(DeviceType::Vfio(vfio_device))
    }

    async fn inner_remove_device(
        &mut self,
        device_id: &str,
        stable_vmm_id: Option<&str>,
    ) -> Result<()> {
        let clh_device_id = self
            .device_ids
            .get(device_id)
            .cloned()
            .or_else(|| stable_vmm_id.map(str::to_string))
            .ok_or_else(|| {
                anyhow!(
                    "cannot detach runtime device {device_id}: Cloud Hypervisor device identity is missing"
                )
            })?;
        let rm_data = VmRemoveDeviceData {
            id: clh_device_id.clone(),
        };

        let response = cloud_hypervisor_vm_device_remove(&self.api_socket, rm_data)
            .await
            .with_context(|| {
                format!(
                    "Cloud Hypervisor failed to detach runtime device {device_id} (VMM device {clh_device_id})"
                )
            })?;

        if let Some(detail) = response {
            debug!(sl!(), "device remove response: {:?}", detail);
        }

        self.device_ids.remove(device_id);

        Ok(())
    }

    // Various cloud-hypervisor APIs report a PCI address in "BB:DD.F"
    // form within the PciDeviceInfo struct.
    // eg "0000:00:DD.F"
    fn clh_pci_info_to_path(bdf: &str) -> Result<PciPath> {
        let tokens: Vec<&str> = bdf.split(':').collect();
        if tokens.len() != 3 || tokens[0] != "0000" || tokens[1] != "00" {
            return Err(anyhow!(
                "Unexpected PCI address {:?} for clh device add",
                bdf
            ));
        }

        let toks: Vec<&str> = tokens[2].split('.').collect();
        if toks.len() != 2 || toks[1] != "0" || toks[0].len() != 2 {
            return Err(anyhow!(
                "Unexpected PCI address {:?} for clh device add",
                bdf
            ));
        }

        PciPath::try_from(toks[0])
    }

    async fn handle_hvsock_device(&mut self, device: HybridVsockDevice) -> Result<DeviceType> {
        let hvsock_config = device.config.clone();

        let vsock_config = VsockConfig {
            cid: hvsock_config.guest_cid,
            socket: hvsock_config.uds_path.into(),
            ..Default::default()
        };

        let response = cloud_hypervisor_vm_vsock_add(&self.api_socket, vsock_config).await?;

        if let Some(detail) = response {
            debug!(sl!(), "hvsock add response: {:?}", detail);
        }

        Ok(DeviceType::HybridVsock(device))
    }

    fn make_disk_config(&self, config: &BlockConfigModern) -> Result<DiskConfig> {
        let mut disk_config = DiskConfig::try_from(config.clone())?;

        disk_config.direct = config
            .is_direct
            .unwrap_or(self.config.blockdev_info.block_device_cache_direct);

        disk_config.rate_limiter_config = RateLimiterConfig::new(
            self.config.blockdev_info.disk_rate_limiter_bw_max_rate,
            self.config.blockdev_info.disk_rate_limiter_ops_max_rate,
            self.config
                .blockdev_info
                .disk_rate_limiter_bw_one_time_burst,
            self.config
                .blockdev_info
                .disk_rate_limiter_ops_one_time_burst,
        );

        Ok(disk_config)
    }

    fn is_vm_boot_file(&self, path: &str) -> bool {
        let boot_info = &self.config.boot_info;

        (!boot_info.image.is_empty() && path == boot_info.image)
            || (!boot_info.initrd.is_empty() && path == boot_info.initrd)
    }

    async fn handle_block_device(
        &mut self,
        device: Arc<Mutex<BlockDeviceModern>>,
    ) -> Result<DeviceType> {
        // Build the cloud-hypervisor DiskConfig from a snapshot of the device config.
        let (device_id, config) = {
            let dev = device.lock().await;
            (dev.device_id.clone(), dev.config.clone())
        };

        let mut disk_config = self.make_disk_config(&config)?;
        disk_config.id = Some(device_id.clone());

        // Claim the stable VMM identity before dispatch. A canceled caller or
        // uncertain response leaves enough state for deterministic cleanup.
        self.device_ids.insert(device_id.clone(), device_id.clone());

        let response = match cloud_hypervisor_vm_blockdev_add(&self.api_socket, disk_config).await {
            Ok(response) => response,
            Err(error)
                if is_api_command_not_dispatched(&error) || is_definite_server_response(&error) =>
            {
                self.device_ids.remove(&device_id);
                return Err(error.context(format!(
                    "Cloud Hypervisor failed to attach block device {device_id} from {}",
                    config.path_on_host
                )));
            }
            Err(error) => {
                let reason = format!(
                    "Cloud Hypervisor may have attached block device {device_id} from {}; cleanup remains pending",
                    config.path_on_host
                );
                return Err(
                    anyhow::Error::new(DeviceStateInDoubt::new(device_id, reason)).context(error),
                );
            }
        };

        let detail = match response {
            Some(detail) => detail,
            None => {
                let error = anyhow!(
                    "Cloud Hypervisor attached block device {device_id} from {} without returning guest device identity",
                    config.path_on_host
                );
                return Err(self
                    .rollback_added_block_device(&device_id, &device_id, error)
                    .await);
            }
        };
        debug!(sl!(), "blockdev add response: {:?}", detail);

        let dev_info: PciDeviceInfo = match serde_json::from_str(detail.as_str()) {
            Ok(info) => info,
            Err(error) => {
                let error = anyhow!(error).context(format!(
                    "Cloud Hypervisor returned invalid identity for block device {device_id}: {detail}"
                ));
                return Err(self
                    .rollback_added_block_device(&device_id, &device_id, error)
                    .await);
            }
        };

        if dev_info.id != device_id {
            let error = anyhow!(
                "Cloud Hypervisor returned device identity {} for block device {device_id}",
                dev_info.id
            );
            return Err(self
                .rollback_added_block_device(&device_id, &dev_info.id, error)
                .await);
        }

        let pci_path = match Self::clh_pci_info_to_path(dev_info.bdf.as_str()) {
            Ok(path) => path,
            Err(error) => {
                let error = error.context(format!(
                    "Cloud Hypervisor returned invalid PCI identity for block device {device_id}"
                ));
                return Err(self
                    .rollback_added_block_device(&device_id, &dev_info.id, error)
                    .await);
            }
        };

        device.lock().await.config.pci_path = Some(pci_path);
        Ok(DeviceType::BlockModern(device))
    }

    async fn rollback_added_block_device(
        &mut self,
        runtime_device_id: &str,
        vmm_device_id: &str,
        attach_error: anyhow::Error,
    ) -> anyhow::Error {
        // A valid add response is authoritative for VMM identity, even when
        // it disagrees with the requested runtime identity. Preserve that
        // mapping before rollback so cancellation cannot lose cleanup state.
        self.device_ids
            .insert(runtime_device_id.to_string(), vmm_device_id.to_string());
        let rollback = cloud_hypervisor_vm_device_remove(
            &self.api_socket,
            VmRemoveDeviceData {
                id: vmm_device_id.to_string(),
            },
        )
        .await;

        match rollback {
            Ok(_) => {
                self.device_ids.remove(runtime_device_id);
                attach_error.context(format!(
                    "rolled back partially attached runtime block device {runtime_device_id} (VMM device {vmm_device_id})"
                ))
            }
            Err(rollback_error) => {
                let reason = format!(
                    "runtime block device {runtime_device_id} (VMM device {vmm_device_id}) remains potentially attached and pending cleanup: {rollback_error:#}"
                );
                anyhow::Error::new(DeviceStateInDoubt::new(runtime_device_id, reason))
                    .context(attach_error)
            }
        }
    }

    async fn handle_network_device(&mut self, device: NetworkDevice) -> Result<DeviceType> {
        let netdev = device.clone();

        let mut clh_net_config = NetConfig::try_from(device.config)?;
        // When using fds to pass the tap device to cloud-hypervisor, tap and id fields should be None
        clh_net_config.tap = None;
        clh_net_config.id = None;
        // The `config.num_queues` is a queue *pair* count (1 RX + 1 TX per pair).
        // Convert pairs into the actual queue count.
        clh_net_config.num_queues = netdev.config.queue_num.max(1) * 2;

        let files = open_named_tuntap(
            &netdev.config.host_dev_name,
            netdev.config.queue_num.max(1) as u32,
        )
        .context("open named tuntap")?;

        let fds = files.iter().map(|f| f.as_raw_fd()).collect();

        let response =
            cloud_hypervisor_vm_netdev_add_with_fds(&self.api_socket, clh_net_config, fds).await?;

        if let Some(detail) = response {
            debug!(sl!(), "netdev add response: {:?}", detail);
        }

        Ok(DeviceType::Network(netdev))
    }

    pub(crate) async fn get_shared_devices(
        &mut self,
    ) -> Result<(
        Option<Vec<FsConfig>>,
        Option<Vec<OwnedNetworkConfig>>,
        Option<Vec<DeviceConfig>>,
        Option<ProtectionDevConfig>,
        Option<Vec<DiskConfig>>,
    )> {
        let mut shared_fs_devices = Vec::<FsConfig>::new();
        let mut network_devices = Vec::<OwnedNetworkConfig>::new();
        let mut host_devices = Vec::<DeviceConfig>::new();
        let mut protection_device = ProtectionDevConfig::default();
        let mut boot_disks = Vec::<DiskConfig>::new();

        while let Some(dev) = self.pending_devices.pop() {
            match dev {
                DeviceType::ShareFs(dev) => {
                    let settings = ShareFsSettings::new(dev.config, self.vm_path.clone());

                    let fs_cfg = if is_rootless() {
                        // TODO: Replace this symlink workaround if a better approach for rootless socket paths appears.
                        // In rootless mode the virtiofsd.sock lives under the rootless directory,
                        // and its full path can exceed the 108-byte Unix domain socket limit.
                        // To ensure the cloud-hypervisor VMM can connect to virtiofsd, create a
                        // short symlink inside the rootless directory and point the VMM at it.
                        let mut fs_cfg = FsConfig::try_from(settings)?;
                        let rootless_symlink_sanbox_jailer_root =
                            get_rootless_symlink_sandbox_jailer_root(self.id.as_str());

                        create_dir_all_with_inherit_owner(
                            rootless_symlink_sanbox_jailer_root.as_str(),
                            0x750,
                        )
                        .map_err(|e| {
                            anyhow!(
                                "failed to create rootless sharefs symlink jailer root dir: {}",
                                e
                            )
                        })?;
                        let virtiofsd_name = fs_cfg.socket.file_name().ok_or_else(|| {
                            anyhow!(
                                "failed to get virtiofsd socket file name from path: {:?}",
                                fs_cfg.socket
                            )
                        })?;
                        let virtiofsd_symlink_path =
                            PathBuf::from(rootless_symlink_sanbox_jailer_root.as_str())
                                .join(virtiofsd_name);

                        symlink(&fs_cfg.socket, &virtiofsd_symlink_path).map_err(|e| {
                            anyhow!(
                                "failed to create symlink for rootless sharefs socket: {}",
                                e
                            )
                        })?;

                        fs_cfg.socket = virtiofsd_symlink_path;

                        fs_cfg
                    } else {
                        FsConfig::try_from(settings)?
                    };

                    shared_fs_devices.push(fs_cfg);
                }
                DeviceType::Network(net_device) => {
                    let network_queues_pairs =
                        self.hypervisor_config().network_info.network_queues as usize;

                    let mut net_config = NetConfig::try_from(net_device.config.clone())?;
                    // When using fds to pass the tap device to cloud-hypervisor, tap and id fields should be None
                    net_config.tap = None;
                    net_config.id = None;

                    net_config.num_queues = network_queues_pairs * 2;
                    info!(
                        sl!(),
                        "network device queue pairs {:?}", network_queues_pairs
                    );

                    // we need ensure opening network device happens in netns.
                    let netns = self.netns.clone().unwrap_or_default();
                    let _netns_guard = NetnsGuard::new(&netns).context("new netns guard")?;
                    let fds = open_named_tuntap(
                        &net_device.config.host_dev_name,
                        network_queues_pairs as u32,
                    )
                    .context("open named tuntap")?
                    .into_iter()
                    .map(OwnedFd::from)
                    .collect::<Vec<_>>();
                    net_config.fds = Some(fds.iter().map(AsRawFd::as_raw_fd).collect());
                    network_devices.push(OwnedNetworkConfig {
                        config: net_config,
                        fds,
                    });
                }
                DeviceType::Vfio(vfio_device) => {
                    // A device with multi-funtions, or a IOMMU group with one more
                    // devices, the Primary device is selected to be passed to VM.
                    // And the the first one is Primary device.
                    // safe here, devices is not empty.
                    let primary_device = vfio_device.devices.first().ok_or(anyhow!(
                        "Primary device list empty for vfio device {:?}",
                        vfio_device
                    ))?;

                    let primary_device = primary_device.clone();
                    let sysfsdev = primary_device.sysfs_path.clone();
                    let device_config = DeviceConfig {
                        path: PathBuf::from(sysfsdev),
                        iommu: false,
                        ..Default::default()
                    };
                    info!(
                        sl!(),
                        "get host_devices primary device {:?}", primary_device
                    );
                    host_devices.push(device_config);
                }
                DeviceType::Protection(pdev) => {
                    let config = pdev.config;
                    match config {
                        ProtectionDeviceConfig::SevSnp(sevsnp_cfg) => {
                            if sevsnp_cfg.is_snp {
                                protection_device.host_data = sevsnp_cfg.host_data;
                            }
                        }
                        ProtectionDeviceConfig::Tdx(tdx_config) => {
                            protection_device.mrconfigid = tdx_config.mrconfigid;
                        }
                        _ => info!(sl!(), "CH: unsupported protection device type"),
                    }
                }
                DeviceType::BlockModern(block_device) => {
                    let config = block_device.lock().await.config.clone();

                    if self.is_vm_boot_file(&config.path_on_host) {
                        // Already handled through the VmConfig payload/disks.
                        continue;
                    }

                    // The disk configuration has no serial field, so a device
                    // the guest finds by serial would be unusable.
                    if !config.serial_override.is_empty() {
                        warn!(
                            sl!(),
                            "not cold-plugging block device {:?}: its serial {:?} cannot be expressed",
                            config.path_on_host,
                            config.serial_override
                        );
                        continue;
                    }

                    info!(sl!(), "cold-plugging block device {:?}", &config);

                    boot_disks.push(self.make_disk_config(&config)?);
                }
                _ => continue,
            }
        }

        Ok((
            Some(shared_fs_devices),
            Some(network_devices),
            Some(host_devices),
            Some(protection_device),
            Some(boot_disks),
        ))
    }
}

impl TryFrom<NetworkConfig> for NetConfig {
    type Error = anyhow::Error;

    fn try_from(cfg: NetworkConfig) -> Result<Self, Self::Error> {
        if let Some(mac) = cfg.guest_mac {
            let net_config = NetConfig {
                tap: Some(cfg.host_dev_name.clone()),
                id: Some(cfg.virt_iface_name.clone()),
                num_queues: cfg.queue_num,
                queue_size: cfg.queue_size as u16,
                mac: MacAddr { bytes: mac.0 },
                ..Default::default()
            };

            return Ok(net_config);
        }

        Err(anyhow!("Missing mac address for network device"))
    }
}

impl TryFrom<BlockConfigModern> for DiskConfig {
    type Error = anyhow::Error;

    fn try_from(blkcfg: BlockConfigModern) -> Result<Self, Self::Error> {
        let disk_config: DiskConfig = DiskConfig {
            path: Some(blkcfg.path_on_host.as_str().into()),
            readonly: blkcfg.is_readonly,
            num_queues: blkcfg.num_queues,
            queue_size: blkcfg.queue_size as u16,
            sparse: blkcfg.discard_unmap,
            image_type: ImageType::Raw,
            ..Default::default()
        };

        Ok(disk_config)
    }
}

#[derive(Debug)]
pub struct ShareFsSettings {
    cfg: ShareFsConfig,
    vm_path: String,
}

impl ShareFsSettings {
    pub fn new(cfg: ShareFsConfig, vm_path: String) -> Self {
        ShareFsSettings { cfg, vm_path }
    }
}

impl TryFrom<ShareFsSettings> for FsConfig {
    type Error = anyhow::Error;

    fn try_from(settings: ShareFsSettings) -> Result<Self, Self::Error> {
        let cfg = settings.cfg;
        let vm_path = settings.vm_path;

        let num_queues = cfg.queue_num as usize;
        let queue_size = u16::try_from(cfg.queue_size)?;

        let socket_path = if cfg.sock_path.starts_with('/') {
            PathBuf::from(cfg.sock_path)
        } else {
            PathBuf::from(vm_path).join(cfg.sock_path)
        };

        let fs_cfg = FsConfig {
            tag: cfg.mount_tag,
            socket: socket_path,
            num_queues,
            queue_size,
            ..Default::default()
        };

        Ok(fs_cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Address;

    #[test]
    fn test_networkconfig_to_netconfig() {
        let mut cfg = NetworkConfig {
            host_dev_name: String::from("tap0"),
            virt_iface_name: String::from("eth0"),
            queue_size: 256,
            queue_num: 2,
            guest_mac: None,
            index: 1,
            allow_duplicate_mac: false,
            use_generic_irq: None,
            use_shared_irq: None,
            pci_path: None,
        };

        let net = NetConfig::try_from(cfg.clone());
        assert_eq!(
            net.unwrap_err().to_string(),
            "Missing mac address for network device"
        );

        let v: [u8; 6] = [10, 11, 128, 3, 4, 5];
        let mac_address = Address(v);
        cfg.guest_mac = Some(mac_address.clone());

        let expected = NetConfig {
            tap: Some(cfg.host_dev_name.clone()),
            id: Some(cfg.virt_iface_name.clone()),
            num_queues: cfg.queue_num,
            queue_size: cfg.queue_size as u16,
            mac: MacAddr { bytes: v },
            ..Default::default()
        };

        let net = NetConfig::try_from(cfg);
        assert!(net.is_ok());
        assert_eq!(net.unwrap(), expected);
    }
}
