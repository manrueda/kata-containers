// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use super::HypervisorState;
use crate::device::{device_state_in_doubt, DeviceStateInDoubt, DeviceType};
use crate::{BlockDeviceModern, Hypervisor, MemoryConfig, VcpuThreadIds};
use anyhow::{Context, Result};
use async_trait::async_trait;
use futures::FutureExt;
use kata_types::capabilities::{Capabilities, CapabilityBits};
use kata_types::config::hypervisor::Hypervisor as HypervisorConfig;
use persist::sandbox_persist::Persist;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, Notify, RwLock};

// Convenience macro to obtain the scope logger
#[macro_export]
macro_rules! sl {
      () => {
          slog_scope::logger().new(o!("subsystem" => "cloud-hypervisor"))
      };
  }

mod inner;
mod inner_device;
mod inner_hypervisor;
mod utils;

use inner::CloudHypervisorInner;

#[derive(Debug)]
struct SharedOperation<T> {
    outcome: Mutex<Option<T>>,
    completed: Notify,
    finished: AtomicBool,
}

impl<T> Default for SharedOperation<T> {
    fn default() -> Self {
        Self {
            outcome: Mutex::new(None),
            completed: Notify::new(),
            finished: AtomicBool::new(false),
        }
    }
}

impl<T: Clone> SharedOperation<T> {
    async fn complete(&self, outcome: T) {
        *self.outcome.lock().await = Some(outcome);
        self.finished.store(true, Ordering::Release);
        self.completed.notify_waiters();
    }

    async fn wait(&self) -> T {
        loop {
            let completed = self.completed.notified();
            if let Some(outcome) = self.outcome.lock().await.as_ref().cloned() {
                return outcome;
            }
            completed.await;
        }
    }

    fn is_complete(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }
}

#[derive(Clone, Debug)]
struct SharedOperationError(Arc<anyhow::Error>);

impl fmt::Display for SharedOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl StdError for SharedOperationError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.0.as_ref().as_ref())
    }
}

#[derive(Clone, Debug)]
enum BlockAddOutcome {
    Success(Box<DeviceType>),
    Failure(Arc<anyhow::Error>),
}

impl BlockAddOutcome {
    fn from_result(result: Result<DeviceType>) -> Self {
        match result {
            Ok(device) => Self::Success(Box::new(device)),
            Err(error) => Self::Failure(Arc::new(error)),
        }
    }

    fn is_in_doubt(&self) -> bool {
        match self {
            Self::Success(_) => false,
            Self::Failure(error) => device_state_in_doubt(error).is_some(),
        }
    }

    fn into_result(self) -> Result<DeviceType> {
        match self {
            Self::Success(device) => Ok(*device),
            Self::Failure(error) => Err(anyhow::Error::new(SharedOperationError(error))),
        }
    }
}

#[derive(Clone, Debug)]
struct BlockAddIdentity {
    device: Arc<Mutex<BlockDeviceModern>>,
    device_id: String,
    config: crate::BlockConfigModern,
}

impl BlockAddIdentity {
    async fn from_device(device: Arc<Mutex<BlockDeviceModern>>) -> Self {
        let snapshot = device.lock().await;
        let mut config = snapshot.config.clone();
        // The attach worker fills this output field. It is not part of the
        // request identity used to decide whether a retry can join.
        config.pci_path = None;
        Self {
            device: device.clone(),
            device_id: snapshot.device_id.clone(),
            config,
        }
    }

    fn matches(&self, other: &Self) -> bool {
        self.device_id == other.device_id
            && self.config == other.config
            && Arc::ptr_eq(&self.device, &other.device)
    }
}

#[derive(Debug)]
struct BlockAddOperation {
    identity: BlockAddIdentity,
    completion: SharedOperation<BlockAddOutcome>,
}

impl BlockAddOperation {
    fn new(identity: BlockAddIdentity) -> Self {
        Self {
            identity,
            completion: SharedOperation::default(),
        }
    }

    async fn complete(&self, result: Result<DeviceType>) {
        self.completion
            .complete(BlockAddOutcome::from_result(result))
            .await;
    }

    async fn wait(&self) -> BlockAddOutcome {
        self.completion.wait().await
    }

    fn is_complete(&self) -> bool {
        self.completion.is_complete()
    }
}

#[derive(Clone, Debug)]
enum VmOperationOutcome {
    Success,
    Failure(Arc<anyhow::Error>),
}

impl VmOperationOutcome {
    fn from_result(result: Result<()>) -> Self {
        match result {
            Ok(()) => Self::Success,
            Err(error) => Self::Failure(Arc::new(error)),
        }
    }

    fn into_result(self) -> Result<()> {
        match self {
            Self::Success => Ok(()),
            Self::Failure(error) => Err(anyhow::Error::new(SharedOperationError(error))),
        }
    }
}

type VmStopOperation = SharedOperation<VmOperationOutcome>;
type VmStartOperation = SharedOperation<VmOperationOutcome>;

#[derive(Debug)]
struct BlockAddState {
    admission_open: bool,
    operations: HashMap<String, Arc<BlockAddOperation>>,
    stop: Option<Arc<VmStopOperation>>,
    start: Option<Arc<VmStartOperation>>,
    cleanup_unresolved: Option<Arc<anyhow::Error>>,
}

impl Default for BlockAddState {
    fn default() -> Self {
        Self {
            admission_open: true,
            operations: HashMap::new(),
            stop: None,
            start: None,
            cleanup_unresolved: None,
        }
    }
}

#[derive(Debug)]
pub struct CloudHypervisor {
    inner: Arc<RwLock<CloudHypervisorInner>>,
    block_adds: Arc<Mutex<BlockAddState>>,
    exit_waiter: Mutex<(mpsc::Receiver<i32>, i32)>,
}

impl CloudHypervisor {
    pub fn new() -> Self {
        let (exit_notify, exit_waiter) = mpsc::channel(1);

        Self {
            inner: Arc::new(RwLock::new(CloudHypervisorInner::new(Some(exit_notify)))),
            block_adds: Arc::new(Mutex::new(BlockAddState::default())),
            exit_waiter: Mutex::new((exit_waiter, 0)),
        }
    }

    async fn add_block_device(&self, device: Arc<Mutex<BlockDeviceModern>>) -> Result<DeviceType> {
        let identity = BlockAddIdentity::from_device(device).await;
        let device_id = identity.device_id.clone();
        let (operation, start) = {
            let mut state = self.block_adds.lock().await;
            match state.operations.get(&device_id) {
                Some(operation) if operation.identity.matches(&identity) => {
                    (operation.clone(), false)
                }
                Some(operation) => {
                    let reason = format!(
                        "Cloud Hypervisor block add retry for device {device_id} does not match the admitted device at {}; original cleanup remains pending",
                        operation.identity.config.path_on_host
                    );
                    return Err(anyhow::Error::new(DeviceStateInDoubt::new(
                        device_id, reason,
                    )));
                }
                None => {
                    if !state.admission_open {
                        return Err(anyhow::anyhow!(
                            "Cloud Hypervisor block add for device {device_id} was not admitted because VM stop has begun"
                        ));
                    }
                    let operation = Arc::new(BlockAddOperation::new(identity.clone()));
                    state
                        .operations
                        .insert(device_id.clone(), operation.clone());
                    (operation, true)
                }
            }
        };

        if start {
            let inner = self.inner.clone();
            let worker_operation = operation.clone();
            let worker_device_id = device_id.clone();
            tokio::spawn(async move {
                let result = AssertUnwindSafe(async move {
                    inner
                        .write()
                        .await
                        .add_device(DeviceType::BlockModern(identity.device))
                        .await
                })
                .catch_unwind()
                .await
                .unwrap_or_else(|_| {
                    Err(anyhow::Error::new(DeviceStateInDoubt::new(
                        worker_device_id,
                        "Cloud Hypervisor block attach worker panicked; cleanup remains pending",
                    )))
                });
                worker_operation.complete(result).await;
            });
        }

        let outcome = operation.wait().await;
        if !outcome.is_in_doubt() {
            let mut state = self.block_adds.lock().await;
            if state
                .operations
                .get(&device_id)
                .is_some_and(|active| Arc::ptr_eq(active, &operation))
            {
                state.operations.remove(&device_id);
            }
        }
        outcome.into_result()
    }

    async fn stop_vm_shared(&self) -> Result<()> {
        let (operation, start, active_start, block_adds) = {
            let mut state = self.block_adds.lock().await;
            if let Some(operation) = &state.stop {
                (operation.clone(), false, None, Vec::new())
            } else {
                let operation = Arc::new(VmStopOperation::default());
                let active_start = state.start.clone();
                let block_adds = state.operations.values().cloned().collect::<Vec<_>>();
                state.stop = Some(operation.clone());
                state.admission_open = false;
                (operation, true, active_start, block_adds)
            }
        };

        if start {
            let inner = self.inner.clone();
            let state = self.block_adds.clone();
            let worker_operation = operation.clone();
            tokio::spawn(async move {
                let (outcome, can_hot_add) = AssertUnwindSafe(async {
                    if let Some(active_start) = active_start {
                        active_start.wait().await;
                    }

                    let unresolved_start = {
                        let state = state.lock().await;
                        state.cleanup_unresolved.clone()
                    };

                    for block_add in block_adds {
                        block_add.wait().await;
                    }

                    {
                        let mut inner = inner.write().await;
                        let mut result = if let Some(error) = unresolved_start {
                            match inner.terminate_launched_hypervisor().await {
                                Ok(()) => Ok(()),
                                Err(cleanup_error) => Err(anyhow::Error::new(
                                    SharedOperationError(error),
                                )
                                .context(format!(
                                    "Cloud Hypervisor stop cleanup remains unresolved: {cleanup_error:#}"
                                ))),
                            }
                        } else {
                            inner.stop_vm().await
                        };

                        let resources_remain = inner.has_active_epoch_resources().await;
                        if result.is_ok() && resources_remain {
                            result = Err(anyhow::anyhow!(
                                "Cloud Hypervisor stop returned before all epoch resources were cleaned"
                            ));
                        }
                        (
                            VmOperationOutcome::from_result(result),
                            inner.state == crate::VmmState::VmRunning,
                        )
                    }
                })
                .catch_unwind()
                .await
                .unwrap_or_else(|_| {
                    (
                        VmOperationOutcome::Failure(Arc::new(anyhow::anyhow!(
                            "Cloud Hypervisor stop worker panicked; VM state remains unresolved"
                        ))),
                        false,
                    )
                });

                {
                    let mut state = state.lock().await;
                    if state
                        .stop
                        .as_ref()
                        .is_some_and(|active| Arc::ptr_eq(active, &worker_operation))
                    {
                        match &outcome {
                            VmOperationOutcome::Success => {
                                state.admission_open = false;
                                state.operations.clear();
                                state.cleanup_unresolved = None;
                            }
                            VmOperationOutcome::Failure(_) if can_hot_add => {
                                state.admission_open = true;
                                state.stop = None;
                                state.cleanup_unresolved = None;
                            }
                            VmOperationOutcome::Failure(error) => {
                                state.admission_open = false;
                                state.stop = None;
                                state.cleanup_unresolved = Some(error.clone());
                            }
                        }
                    }
                }
                worker_operation.complete(outcome).await;
            });
        }

        operation.wait().await.into_result()
    }

    async fn start_vm_shared(&self, timeout: i32) -> Result<()> {
        let operation = loop {
            let (cleanup_unresolved, active_start, previous_stop) = {
                let state = self.block_adds.lock().await;
                (
                    state.cleanup_unresolved.clone(),
                    state.start.clone(),
                    state.stop.clone(),
                )
            };
            if let Some(error) = cleanup_unresolved {
                return Err(anyhow::Error::new(SharedOperationError(error)).context(
                    "Cloud Hypervisor cannot start while the previous VM shutdown is unresolved because process cleanup remains unresolved",
                ));
            }
            if let Some(active_start) = active_start {
                return active_start.wait().await.into_result();
            }

            if let Some(previous_stop) = &previous_stop {
                return match previous_stop.wait().await {
                    VmOperationOutcome::Success => Err(anyhow::anyhow!(
                        "Cloud Hypervisor VM has stopped; this sandbox lifecycle cannot restart"
                    )),
                    VmOperationOutcome::Failure(error) => Err(anyhow::Error::new(
                        SharedOperationError(error),
                    )
                    .context(
                        "Cloud Hypervisor cannot start while the previous VM shutdown is unresolved",
                    )),
                };
            }

            let mut state = self.block_adds.lock().await;
            if state.cleanup_unresolved.is_some() || state.stop.is_some() || state.start.is_some() {
                continue;
            }
            let operation = Arc::new(VmStartOperation::default());
            state.start = Some(operation.clone());
            break operation;
        };

        let inner = self.inner.clone();
        let state = self.block_adds.clone();
        let worker_operation = operation.clone();
        tokio::spawn(async move {
            let (worker_result, cleanup_unresolved) = {
                let mut inner = inner.write().await;
                if inner.state == crate::VmmState::VmRunning {
                    (
                        Err(anyhow::anyhow!("Cloud Hypervisor VM is already running")),
                        false,
                    )
                } else {
                    match AssertUnwindSafe(inner.start_vm(timeout))
                        .catch_unwind()
                        .await
                    {
                        Ok(result) => {
                            let unresolved =
                                result.is_err() && inner.has_active_epoch_resources().await;
                            (result, unresolved)
                        }
                        Err(_) => {
                            let cleanup = AssertUnwindSafe(inner.terminate_launched_hypervisor())
                                .catch_unwind()
                                .await;
                            match cleanup {
                                Ok(Ok(())) => (
                                    Err(anyhow::anyhow!(
                                        "Cloud Hypervisor start worker panicked; spawned process resources were cleaned"
                                    )),
                                    false,
                                ),
                                Ok(Err(cleanup_error)) => (
                                    Err(anyhow::anyhow!(
                                        "Cloud Hypervisor start worker panicked; process cleanup remains unresolved: {cleanup_error:#}"
                                    )),
                                    true,
                                ),
                                Err(_) => (
                                    Err(anyhow::anyhow!(
                                        "Cloud Hypervisor start worker panicked; process cleanup also panicked"
                                    )),
                                    true,
                                ),
                            }
                        }
                    }
                }
            };
            let outcome = VmOperationOutcome::from_result(worker_result);
            {
                let mut state = state.lock().await;
                if state
                    .start
                    .as_ref()
                    .is_some_and(|active| Arc::ptr_eq(active, &worker_operation))
                {
                    state.start = None;
                    if cleanup_unresolved {
                        if let VmOperationOutcome::Failure(error) = &outcome {
                            state.cleanup_unresolved = Some(error.clone());
                            state.admission_open = false;
                        }
                    } else if matches!(outcome, VmOperationOutcome::Success) {
                        state.cleanup_unresolved = None;
                        state
                            .operations
                            .retain(|_, operation| !operation.is_complete());
                        if state.stop.is_none() {
                            state.admission_open = true;
                        }
                    }
                }
            }
            worker_operation.complete(outcome).await;
        });

        operation.wait().await.into_result()
    }

    pub async fn set_hypervisor_config(&self, config: HypervisorConfig) {
        let mut inner = self.inner.write().await;
        inner.set_hypervisor_config(config)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) async fn set_test_api_socket(&self, socket: std::os::unix::net::UnixStream) {
        let mut inner = self.inner.write().await;
        inner.api_socket.replace(socket, None).await;
        inner.state = crate::VmmState::VmRunning;
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        inner.shutdown_tx = Some(shutdown_tx);
        inner.logger_task = Some(tokio::spawn(async move {
            let _ = shutdown_rx.changed().await;
            Ok(())
        }));
    }

    #[cfg(test)]
    pub(crate) async fn set_test_panic_after_spawn(&self, enabled: bool) {
        self.inner.write().await.panic_after_spawn = enabled;
    }

    #[cfg(test)]
    pub(crate) async fn set_test_cleanup_uncertain(&self, enabled: bool) {
        self.inner.write().await.report_cleanup_uncertain = enabled;
    }

    #[cfg(test)]
    pub(crate) async fn set_test_process_cleanup_faults(
        &self,
        faults: impl IntoIterator<Item = inner::ProcessCleanupFault>,
    ) {
        let process = self
            .inner
            .read()
            .await
            .process
            .clone()
            .expect("Cloud Hypervisor process is present");
        process
            .lock()
            .await
            .as_mut()
            .expect("Cloud Hypervisor child is present")
            .cleanup_faults
            .extend(faults);
    }

    #[cfg(test)]
    pub(crate) async fn set_test_api_unavailable(&self) {
        let mut inner = self.inner.write().await;
        inner.api_socket = ch_config::ch_api::ApiSocket::new(None);
        inner.state = crate::VmmState::VmRunning;
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) async fn test_device_ids(&self) -> HashMap<String, String> {
        self.inner.read().await.device_ids.clone()
    }
}

impl Default for CloudHypervisor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Hypervisor for CloudHypervisor {
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

    async fn start_vm(&self, timeout: i32) -> Result<()> {
        self.start_vm_shared(timeout).await
    }

    async fn stop_vm(&self) -> Result<()> {
        self.stop_vm_shared().await
    }

    async fn wait_vm(&self) -> Result<i32> {
        debug!(sl!(), "Waiting CH vmm");
        let mut waiter = self.exit_waiter.lock().await;
        if let Some(exitcode) = waiter.0.recv().await {
            waiter.1 = exitcode;
        }

        Ok(waiter.1)
    }

    async fn pause_vm(&self) -> Result<()> {
        let inner = self.inner.write().await;
        inner.pause_vm().await
    }

    async fn resume_vm(&self) -> Result<()> {
        let inner = self.inner.write().await;
        inner.resume_vm().await
    }

    async fn save_vm(&self) -> Result<()> {
        let inner = self.inner.write().await;
        inner.save_vm().await
    }

    async fn add_device(&self, device: DeviceType) -> Result<DeviceType> {
        match device {
            DeviceType::BlockModern(device) => self.add_block_device(device).await,
            device => {
                let mut inner = self.inner.write().await;
                inner.add_device(device).await
            }
        }
    }

    async fn remove_device(&self, device: DeviceType) -> Result<()> {
        let block_device_id = match &device {
            DeviceType::BlockModern(device) => Some(device.lock().await.device_id.clone()),
            _ => None,
        };
        let mut inner = self.inner.write().await;
        let result = inner.remove_device(device).await;
        drop(inner);
        if result.is_ok() {
            if let Some(device_id) = block_device_id {
                self.block_adds.lock().await.operations.remove(&device_id);
            }
        }
        result
    }

    async fn update_device(&self, device: DeviceType) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.update_device(device).await
    }

    fn block_device_add_is_independently_owned(&self) -> bool {
        true
    }

    async fn get_agent_socket(&self) -> Result<String> {
        let inner = self.inner.write().await;
        inner.get_agent_socket().await
    }

    async fn disconnect(&self) {
        let mut inner = self.inner.write().await;
        inner.disconnect().await
    }

    async fn hypervisor_config(&self) -> HypervisorConfig {
        let inner = self.inner.write().await;
        inner.hypervisor_config()
    }

    async fn get_thread_ids(&self) -> Result<VcpuThreadIds> {
        let inner = self.inner.read().await;
        inner.get_thread_ids().await
    }

    async fn cleanup(&self) -> Result<()> {
        let inner = self.inner.read().await;
        inner.cleanup().await
    }

    async fn resize_vcpu(&self, old_vcpu: u32, new_vcpu: u32) -> Result<(u32, u32)> {
        let inner = self.inner.read().await;
        inner.resize_vcpu(old_vcpu, new_vcpu).await
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
        let inner = self.inner.read().await;
        inner.resize_memory(new_mem_mb).await
    }

    async fn get_passfd_listener_addr(&self) -> Result<(String, u32)> {
        Err(anyhow::anyhow!("Not yet supported"))
    }
}

#[async_trait]
impl Persist for CloudHypervisor {
    type State = HypervisorState;
    type ConstructorArgs = ();

    async fn save(&self) -> Result<Self::State> {
        let inner = self.inner.read().await;
        inner.save().await.context("save CH hypervisor state")
    }

    async fn restore(
        _hypervisor_args: Self::ConstructorArgs,
        hypervisor_state: Self::State,
    ) -> Result<Self> {
        let (exit_notify, exit_waiter) = mpsc::channel(1);

        let inner = CloudHypervisorInner::restore(exit_notify, hypervisor_state).await?;
        Ok(Self {
            inner: Arc::new(RwLock::new(inner)),
            block_adds: Arc::new(Mutex::new(BlockAddState::default())),
            exit_waiter: Mutex::new((exit_waiter, 0)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::inner_device::{read_request, write_response, ApiRequest};
    use super::*;
    use crate::device::device_manager::{do_handle_device, DeviceManager};
    use crate::device::driver::VIRTIO_BLOCK_PCI;
    use crate::device::DeviceConfig;
    use crate::{BlockConfigModern, BlockDeviceModern};
    use std::future::Future;
    use std::os::unix::net::UnixStream;
    use std::task::{Context as TaskContext, Poll, Waker};
    use std::thread;
    use std::time::Duration;

    fn block_device(device_id: &str, path: &str) -> DeviceType {
        DeviceType::BlockModern(Arc::new(Mutex::new(BlockDeviceModern {
            device_id: device_id.to_string(),
            config: BlockConfigModern {
                path_on_host: path.to_string(),
                driver_option: crate::KATA_BLK_DEV_TYPE.to_string(),
                ..Default::default()
            },
            ..Default::default()
        })))
    }

    fn poll_once<F: Future>(future: std::pin::Pin<&mut F>) -> Poll<F::Output> {
        let mut context = TaskContext::from_waker(Waker::noop());
        future.poll(&mut context)
    }

    fn block_config(path: &str) -> DeviceConfig {
        DeviceConfig::BlockCfgModern(BlockConfigModern {
            path_on_host: path.to_string(),
            driver_option: VIRTIO_BLOCK_PCI.to_string(),
            ..Default::default()
        })
    }

    #[cfg(target_os = "linux")]
    fn sleeping_launcher(directory: &std::path::Path) -> std::path::PathBuf {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let launcher_path = directory.join("fake-cloud-hypervisor");
        fs::write(&launcher_path, "#!/bin/sh\nexec sleep 30\n").unwrap();
        fs::set_permissions(&launcher_path, fs::Permissions::from_mode(0o755)).unwrap();
        launcher_path
    }

    #[cfg(target_os = "linux")]
    fn blocking_launcher(directory: &std::path::Path) -> std::path::PathBuf {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let launcher_path = directory.join("blocking-cloud-hypervisor");
        fs::write(&launcher_path, "#!/bin/sh\nexec tail -f /dev/null\n").unwrap();
        fs::set_permissions(&launcher_path, fs::Permissions::from_mode(0o755)).unwrap();
        launcher_path
    }

    async fn stop_test_hypervisor(socket: UnixStream) -> Arc<CloudHypervisor> {
        let hypervisor = Arc::new(CloudHypervisor::new());
        hypervisor.set_test_api_socket(socket).await;
        hypervisor
    }

    async fn wait_for_thread_signal(
        receiver: std::sync::mpsc::Receiver<()>,
        message: &'static str,
    ) {
        tokio::task::spawn_blocking(move || receiver.recv_timeout(Duration::from_secs(2)))
            .await
            .expect("signal waiter panicked")
            .expect(message);
    }

    #[tokio::test]
    async fn canceled_stop_during_add_drain_still_shuts_down() {
        let (client, mut server_socket) = UnixStream::pair().unwrap();
        let (add_seen_tx, add_seen_rx) = std::sync::mpsc::channel();
        let (release_add_tx, release_add_rx) = std::sync::mpsc::channel();
        let (shutdown_seen_tx, shutdown_seen_rx) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let add = read_request(&mut server_socket);
            add_seen_tx.send(()).unwrap();
            release_add_rx.recv().unwrap();
            write_response(
                &mut server_socket,
                "200",
                Some(r#"{"id":"canceled-drain","bdf":"0000:00:05.0"}"#),
            );
            let shutdown = read_request(&mut server_socket);
            shutdown_seen_tx.send(()).unwrap();
            write_response(&mut server_socket, "204", None);
            (add, shutdown)
        });
        let hypervisor = stop_test_hypervisor(client).await;

        let add_hypervisor = hypervisor.clone();
        let add = tokio::spawn(async move {
            add_hypervisor
                .add_device(block_device(
                    "canceled-drain",
                    "/var/lib/kata/canceled-drain/disk.img",
                ))
                .await
        });
        wait_for_thread_signal(add_seen_rx, "add request was not received").await;

        let mut stop = Box::pin(hypervisor.stop_vm());
        assert!(poll_once(stop.as_mut()).is_pending());
        drop(stop);

        release_add_tx.send(()).unwrap();
        add.await.unwrap().unwrap();
        wait_for_thread_signal(
            shutdown_seen_rx,
            "shutdown was abandoned when its caller was canceled",
        )
        .await;
        let (add_request, _) = server.join().unwrap();
        assert_eq!(add_request.body["id"], "canceled-drain");
    }

    #[tokio::test]
    async fn canceled_stop_waiting_for_inner_lock_still_shuts_down() {
        let (client, mut server_socket) = UnixStream::pair().unwrap();
        let (shutdown_seen_tx, shutdown_seen_rx) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let shutdown = read_request(&mut server_socket);
            shutdown_seen_tx.send(()).unwrap();
            write_response(&mut server_socket, "204", None);
            shutdown
        });
        let hypervisor = stop_test_hypervisor(client).await;
        let inner_guard = hypervisor.inner.write().await;

        let mut stop = Box::pin(hypervisor.stop_vm());
        assert!(poll_once(stop.as_mut()).is_pending());
        drop(stop);
        drop(inner_guard);

        wait_for_thread_signal(
            shutdown_seen_rx,
            "shutdown was abandoned while waiting for the inner lock",
        )
        .await;
        server.join().unwrap();
    }

    #[tokio::test]
    async fn definite_stop_failure_reopens_block_add_admission() {
        let hypervisor = Arc::new(CloudHypervisor::new());
        hypervisor.set_test_api_unavailable().await;

        let stop_error = hypervisor.stop_vm().await.unwrap_err();
        assert!(ch_config::ch_api::is_api_command_not_dispatched(
            &stop_error
        ));

        let (client, mut server_socket) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            let add = read_request(&mut server_socket);
            write_response(
                &mut server_socket,
                "200",
                Some(r#"{"id":"after-stop-failure","bdf":"0000:00:05.0"}"#),
            );
            add
        });
        hypervisor.set_test_api_socket(client).await;

        hypervisor
            .add_device(block_device(
                "after-stop-failure",
                "/var/lib/kata/after-stop-failure/disk.img",
            ))
            .await
            .unwrap();
        assert_eq!(server.join().unwrap().body["id"], "after-stop-failure");

        let start_error = hypervisor.start_vm(1).await.unwrap_err();
        assert!(start_error.to_string().contains("already running"));
    }

    #[tokio::test]
    async fn ambiguous_stop_failure_keeps_block_add_admission_closed() {
        let (client, mut server_socket) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            let shutdown = read_request(&mut server_socket);
            drop(server_socket);
            shutdown
        });
        let hypervisor = stop_test_hypervisor(client).await;

        let stop_error = hypervisor.stop_vm().await.unwrap_err();
        assert!(!ch_config::ch_api::is_api_command_not_dispatched(
            &stop_error
        ));
        server.join().unwrap();

        let (replacement, _server_socket) = UnixStream::pair().unwrap();
        hypervisor.set_test_api_socket(replacement).await;
        let add_error = hypervisor
            .add_device(block_device(
                "after-ambiguous-stop",
                "/var/lib/kata/after-ambiguous-stop/disk.img",
            ))
            .await
            .unwrap_err();
        assert!(add_error.to_string().contains("VM stop has begun"));

        let start_error = hypervisor.start_vm(1).await.unwrap_err();
        assert!(start_error
            .to_string()
            .contains("previous VM shutdown is unresolved"));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn successful_stop_terminally_rejects_restart_without_spawning() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let (client, mut server_socket) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            let shutdown = read_request(&mut server_socket);
            write_response(&mut server_socket, "204", None);
            shutdown
        });
        let hypervisor = stop_test_hypervisor(client).await;
        hypervisor.stop_vm().await.unwrap();
        server.join().unwrap();
        assert!(
            !hypervisor
                .inner
                .read()
                .await
                .has_active_epoch_resources()
                .await
        );

        let temp_dir = tempfile::tempdir().unwrap();
        let marker_path = temp_dir.path().join("spawned");
        let launcher_path = temp_dir.path().join("must-not-spawn");
        fs::write(
            &launcher_path,
            format!("#!/bin/sh\ntouch '{}'\n", marker_path.display()),
        )
        .unwrap();
        fs::set_permissions(&launcher_path, fs::Permissions::from_mode(0o755)).unwrap();
        hypervisor.inner.write().await.config.path = launcher_path.to_string_lossy().into_owned();

        let error = hypervisor.start_vm(1).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("sandbox lifecycle cannot restart"));
        assert!(!marker_path.exists());
        let state = hypervisor.block_adds.lock().await;
        assert!(state.cleanup_unresolved.is_none());
        let stopped = state.stop.clone().unwrap();
        drop(state);
        assert!(matches!(stopped.wait().await, VmOperationOutcome::Success));
    }

    #[tokio::test]
    async fn concurrent_stop_callers_share_failure() {
        let (client, mut server_socket) = UnixStream::pair().unwrap();
        let (shutdown_seen_tx, shutdown_seen_rx) = std::sync::mpsc::channel();
        let (release_shutdown_tx, release_shutdown_rx) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let shutdown = read_request(&mut server_socket);
            shutdown_seen_tx.send(()).unwrap();
            release_shutdown_rx.recv().unwrap();
            write_response(&mut server_socket, "500", Some(r#"["shutdown refused"]"#));
            shutdown
        });
        let hypervisor = stop_test_hypervisor(client).await;

        let first_hypervisor = hypervisor.clone();
        let first = tokio::spawn(async move { first_hypervisor.stop_vm().await });
        wait_for_thread_signal(shutdown_seen_rx, "shutdown request was not received").await;
        let mut second = Box::pin(hypervisor.stop_vm());
        assert!(
            poll_once(second.as_mut()).is_pending(),
            "second stop did not join the active stop operation"
        );
        release_shutdown_tx.send(()).unwrap();

        assert!(first.await.unwrap().is_err());
        assert!(second.await.is_err());
        server.join().unwrap();
    }

    #[tokio::test]
    async fn canceled_start_worker_finishes_and_releases_its_epoch() {
        let hypervisor = Arc::new(CloudHypervisor::new());
        hypervisor.set_test_api_unavailable().await;
        let inner_guard = hypervisor.inner.write().await;

        let mut start = Box::pin(hypervisor.start_vm(1));
        assert!(poll_once(start.as_mut()).is_pending());
        let operation = hypervisor.block_adds.lock().await.start.clone().unwrap();
        drop(start);
        drop(inner_guard);

        let VmOperationOutcome::Failure(error) = operation.wait().await else {
            panic!("expected repeated start failure");
        };
        assert!(error.to_string().contains("already running"));
        assert!(hypervisor.block_adds.lock().await.start.is_none());

        let repeated_error = hypervisor.start_vm(1).await.unwrap_err();
        assert!(repeated_error.to_string().contains("already running"));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn post_spawn_start_panic_reaps_process_and_allows_initial_retry() {
        use std::path::Path;

        let temp_dir = tempfile::tempdir().unwrap();
        let launcher_path = sleeping_launcher(temp_dir.path());

        let hypervisor = Arc::new(CloudHypervisor::new());
        {
            let mut inner = hypervisor.inner.write().await;
            inner.id = format!("post-spawn-panic-{}", std::process::id());
            inner.config.path = launcher_path.to_string_lossy().into_owned();
        }
        hypervisor.set_test_panic_after_spawn(true).await;

        let error = hypervisor.start_vm(1).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("spawned process resources were cleaned"));
        let pid = hypervisor.inner.read().await.last_spawned_pid.unwrap();
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        assert!(!hypervisor.inner.read().await.has_active_process_resources());
        assert!(hypervisor
            .block_adds
            .lock()
            .await
            .cleanup_unresolved
            .is_none());

        hypervisor.set_test_panic_after_spawn(false).await;
        let retry_error = hypervisor.start_vm(1).await.unwrap_err();
        assert!(retry_error.to_string().contains("comms setup failed"));
        assert!(!hypervisor.inner.read().await.has_active_process_resources());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn unresolved_cleanup_retries_share_only_each_active_attempt() {
        use std::path::Path;

        let temp_dir = tempfile::tempdir().unwrap();
        let launcher_path = sleeping_launcher(temp_dir.path());
        let hypervisor = Arc::new(CloudHypervisor::new());
        {
            let mut inner = hypervisor.inner.write().await;
            inner.id = format!("uncertain-start-cleanup-{}", std::process::id());
            inner.config.path = launcher_path.to_string_lossy().into_owned();
        }
        hypervisor.set_test_panic_after_spawn(true).await;
        hypervisor.set_test_cleanup_uncertain(true).await;

        let error = hypervisor.start_vm(1).await.unwrap_err();
        assert!(error.to_string().contains("cleanup remains unresolved"));
        let pid = hypervisor.inner.read().await.last_spawned_pid.unwrap();
        assert!(Path::new(&format!("/proc/{pid}")).exists());
        assert!(hypervisor
            .block_adds
            .lock()
            .await
            .cleanup_unresolved
            .is_some());

        let retry_error = hypervisor.start_vm(1).await.unwrap_err();
        assert!(retry_error
            .to_string()
            .contains("process cleanup remains unresolved"));

        let inner_guard = hypervisor.inner.write().await;
        let mut first_stop = Box::pin(hypervisor.stop_vm());
        assert!(poll_once(first_stop.as_mut()).is_pending());
        let first_operation = hypervisor.block_adds.lock().await.stop.clone().unwrap();
        let mut first_joiner = Box::pin(hypervisor.stop_vm());
        assert!(poll_once(first_joiner.as_mut()).is_pending());
        assert!(Arc::ptr_eq(
            hypervisor.block_adds.lock().await.stop.as_ref().unwrap(),
            &first_operation
        ));
        drop(inner_guard);

        assert!(first_stop.await.is_err());
        assert!(first_joiner.await.is_err());
        assert!(hypervisor.block_adds.lock().await.stop.is_none());
        assert!(Path::new(&format!("/proc/{pid}")).exists());

        hypervisor.set_test_cleanup_uncertain(false).await;
        let inner_guard = hypervisor.inner.write().await;
        let mut second_stop = Box::pin(hypervisor.stop_vm());
        assert!(poll_once(second_stop.as_mut()).is_pending());
        let second_operation = hypervisor.block_adds.lock().await.stop.clone().unwrap();
        assert!(!Arc::ptr_eq(&first_operation, &second_operation));
        let mut second_joiner = Box::pin(hypervisor.stop_vm());
        assert!(poll_once(second_joiner.as_mut()).is_pending());
        assert!(Arc::ptr_eq(
            hypervisor.block_adds.lock().await.stop.as_ref().unwrap(),
            &second_operation
        ));
        drop(inner_guard);

        second_stop.await.unwrap();
        second_joiner.await.unwrap();
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        assert!(!hypervisor.inner.read().await.has_active_process_resources());
        assert!(
            !hypervisor
                .inner
                .read()
                .await
                .has_active_epoch_resources()
                .await
        );

        hypervisor.stop_vm().await.unwrap();
        assert!(Arc::ptr_eq(
            hypervisor.block_adds.lock().await.stop.as_ref().unwrap(),
            &second_operation
        ));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn concurrent_stop_callers_share_injected_kill_failure_and_retry() {
        use std::path::Path;

        let temp_dir = tempfile::tempdir().unwrap();
        let launcher_path = blocking_launcher(temp_dir.path());
        let hypervisor = Arc::new(CloudHypervisor::new());
        {
            let mut inner = hypervisor.inner.write().await;
            inner.id = format!("kill-retry-{}", std::process::id());
            inner.config.path = launcher_path.to_string_lossy().into_owned();
        }
        hypervisor.set_test_panic_after_spawn(true).await;
        hypervisor.set_test_cleanup_uncertain(true).await;
        let start_error = hypervisor.start_vm(1).await.unwrap_err();
        assert!(start_error
            .to_string()
            .contains("cleanup remains unresolved"));
        let (pid, original_process) = {
            let inner = hypervisor.inner.read().await;
            (inner.pid.unwrap(), inner.process.clone().unwrap())
        };
        hypervisor.set_test_cleanup_uncertain(false).await;
        hypervisor
            .set_test_process_cleanup_faults([inner::ProcessCleanupFault::StartKill])
            .await;

        let inner_guard = hypervisor.inner.write().await;
        let mut first_stop = Box::pin(hypervisor.stop_vm());
        assert!(poll_once(first_stop.as_mut()).is_pending());
        let first_operation = hypervisor.block_adds.lock().await.stop.clone().unwrap();
        let mut first_joiner = Box::pin(hypervisor.stop_vm());
        assert!(poll_once(first_joiner.as_mut()).is_pending());
        assert!(Arc::ptr_eq(
            hypervisor.block_adds.lock().await.stop.as_ref().unwrap(),
            &first_operation
        ));
        drop(inner_guard);

        assert!(
            format!("{:#}", first_stop.await.unwrap_err()).contains("injected start_kill failure")
        );
        assert!(format!("{:#}", first_joiner.await.unwrap_err())
            .contains("injected start_kill failure"));
        assert!(hypervisor.block_adds.lock().await.stop.is_none());
        assert!(Path::new(&format!("/proc/{pid}")).exists());
        assert!(Arc::ptr_eq(
            hypervisor.inner.read().await.process.as_ref().unwrap(),
            &original_process
        ));

        let inner_guard = hypervisor.inner.write().await;
        let mut retry = Box::pin(hypervisor.stop_vm());
        assert!(poll_once(retry.as_mut()).is_pending());
        let retry_operation = hypervisor.block_adds.lock().await.stop.clone().unwrap();
        assert!(!Arc::ptr_eq(&first_operation, &retry_operation));
        let mut retry_joiner = Box::pin(hypervisor.stop_vm());
        assert!(poll_once(retry_joiner.as_mut()).is_pending());
        assert!(Arc::ptr_eq(
            hypervisor.block_adds.lock().await.stop.as_ref().unwrap(),
            &retry_operation
        ));
        drop(inner_guard);

        retry.await.unwrap();
        retry_joiner.await.unwrap();
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        assert!(!hypervisor.inner.read().await.has_active_process_resources());
        assert!(
            !hypervisor
                .inner
                .read()
                .await
                .has_active_epoch_resources()
                .await
        );
    }

    #[tokio::test]
    async fn pause_and_resume_do_not_change_block_add_admission() {
        let (client, mut server_socket) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            let pause = read_request(&mut server_socket);
            write_response(&mut server_socket, "204", None);
            let resume = read_request(&mut server_socket);
            write_response(&mut server_socket, "204", None);
            (pause, resume)
        });
        let hypervisor = stop_test_hypervisor(client).await;
        hypervisor.block_adds.lock().await.admission_open = false;

        hypervisor.pause_vm().await.unwrap();
        assert!(!hypervisor.block_adds.lock().await.admission_open);
        hypervisor.resume_vm().await.unwrap();
        assert!(!hypervisor.block_adds.lock().await.admission_open);
        let (pause, resume) = server.join().unwrap();
        assert_eq!(pause.request_line, "PUT /api/v1/vm.pause HTTP/1.1");
        assert_eq!(resume.request_line, "PUT /api/v1/vm.resume HTTP/1.1");
    }

    #[tokio::test]
    async fn stop_winning_before_admission_rejects_new_block_add() {
        let (client, mut server_socket) = UnixStream::pair().unwrap();
        let (shutdown_seen_tx, shutdown_seen_rx) = std::sync::mpsc::channel();
        let (release_shutdown_tx, release_shutdown_rx) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let shutdown = read_request(&mut server_socket);
            shutdown_seen_tx.send(()).unwrap();
            release_shutdown_rx.recv().unwrap();
            write_response(&mut server_socket, "204", None);
            shutdown
        });
        let hypervisor = stop_test_hypervisor(client).await;

        let stop_hypervisor = hypervisor.clone();
        let stop = tokio::spawn(async move { stop_hypervisor.stop_vm().await });
        tokio::task::spawn_blocking(move || shutdown_seen_rx.recv().unwrap())
            .await
            .unwrap();

        let error = hypervisor
            .add_device(block_device(
                "late-device",
                "/var/lib/kata/late-device/disk.img",
            ))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("VM stop has begun"));
        assert!(device_state_in_doubt(&error).is_none());

        release_shutdown_tx.send(()).unwrap();
        stop.await.unwrap().unwrap();
        server.join().unwrap();
    }

    #[derive(Clone, Copy, Debug)]
    enum AdmittedAddCase {
        Success,
        DefiniteFailure,
        AmbiguousFailure,
    }

    impl AdmittedAddCase {
        fn device_id(self) -> &'static str {
            match self {
                Self::Success => "admitted-success",
                Self::DefiniteFailure => "definite-failure",
                Self::AmbiguousFailure => "ambiguous-add",
            }
        }
    }

    async fn assert_admitted_add_completes_before_stop(case: AdmittedAddCase) {
        let (client, mut server_socket) = UnixStream::pair().unwrap();
        let (add_seen_tx, add_seen_rx) = std::sync::mpsc::channel();
        let (release_add_tx, release_add_rx) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let add = read_request(&mut server_socket);
            add_seen_tx.send(()).unwrap();
            release_add_rx.recv().unwrap();
            let rollback = match case {
                AdmittedAddCase::Success => {
                    let response =
                        format!(r#"{{"id":"{}","bdf":"0000:00:05.0"}}"#, case.device_id());
                    write_response(&mut server_socket, "200", Some(&response));
                    None
                }
                AdmittedAddCase::DefiniteFailure => {
                    write_response(
                        &mut server_socket,
                        "500",
                        Some(r#"["backing file is busy"]"#),
                    );
                    None
                }
                AdmittedAddCase::AmbiguousFailure => {
                    write_response(
                        &mut server_socket,
                        "200",
                        Some(r#"{"id":"unexpected-vmm-id","bdf":"0000:00:07.0"}"#),
                    );
                    let rollback = read_request(&mut server_socket);
                    write_response(
                        &mut server_socket,
                        "500",
                        Some(r#"["device remains busy"]"#),
                    );
                    Some(rollback)
                }
            };
            let shutdown = read_request(&mut server_socket);
            write_response(&mut server_socket, "204", None);
            (add, rollback, shutdown)
        });
        let hypervisor = stop_test_hypervisor(client).await;
        let device_id = case.device_id();

        let add_hypervisor = hypervisor.clone();
        let add = tokio::spawn(async move {
            add_hypervisor
                .add_device(block_device(
                    device_id,
                    &format!("/var/lib/kata/{device_id}/disk.img"),
                ))
                .await
        });
        wait_for_thread_signal(add_seen_rx, "add request was not received").await;

        let mut stop = Box::pin(hypervisor.stop_vm());
        assert!(
            poll_once(stop.as_mut()).is_pending(),
            "stop completed before the admitted {:?}",
            case
        );

        release_add_tx.send(()).unwrap();
        let add_result = add.await.unwrap();
        match case {
            AdmittedAddCase::Success => {
                add_result.unwrap();
            }
            AdmittedAddCase::DefiniteFailure => {
                let error = add_result.unwrap_err();
                assert!(device_state_in_doubt(&error).is_none());
            }
            AdmittedAddCase::AmbiguousFailure => {
                let error = add_result.unwrap_err();
                assert!(device_state_in_doubt(&error).is_some());
            }
        };
        stop.await.unwrap();
        let (_, rollback, _) = server.join().unwrap();
        if let Some(rollback) = rollback {
            assert_eq!(rollback.body["id"], "unexpected-vmm-id");
            let device_ids = hypervisor.test_device_ids().await;
            assert!(!device_ids.contains_key(device_id));
        }
    }

    #[tokio::test]
    async fn admitted_add_outcomes_complete_before_stop() {
        for case in [
            AdmittedAddCase::Success,
            AdmittedAddCase::DefiniteFailure,
            AdmittedAddCase::AmbiguousFailure,
        ] {
            assert_admitted_add_completes_before_stop(case).await;
        }
    }

    #[tokio::test]
    async fn admitted_worker_queued_behind_inner_lock_precedes_stop_transition() {
        let (client, mut server_socket) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            let add = read_request(&mut server_socket);
            write_response(
                &mut server_socket,
                "200",
                Some(r#"{"id":"queued-worker","bdf":"0000:00:06.0"}"#),
            );
            let shutdown = read_request(&mut server_socket);
            write_response(&mut server_socket, "204", None);
            (add, shutdown)
        });
        let hypervisor = stop_test_hypervisor(client).await;
        let inner_guard = hypervisor.inner.write().await;

        let device = block_device("queued-worker", "/var/lib/kata/queued-worker/disk.img");
        let mut add = Box::pin(hypervisor.add_device(device));
        assert!(poll_once(add.as_mut()).is_pending());

        let mut stop = Box::pin(hypervisor.stop_vm());
        assert!(
            poll_once(stop.as_mut()).is_pending(),
            "stop completed while the admitted worker was queued"
        );
        drop(inner_guard);

        add.await.unwrap();
        stop.await.unwrap();
        let (add_request, _) = server.join().unwrap();
        assert_eq!(add_request.body["id"], "queued-worker");
    }

    #[tokio::test]
    async fn never_dispatched_block_add_releases_manager_ownership_and_index() {
        let hypervisor = Arc::new(CloudHypervisor::new());
        let mut config = HypervisorConfig::default();
        config.blockdev_info.block_device_driver = VIRTIO_BLOCK_PCI.to_string();
        hypervisor.set_hypervisor_config(config).await;
        hypervisor.set_test_api_unavailable().await;
        let device_manager =
            RwLock::new(DeviceManager::new(hypervisor.clone(), None).await.unwrap());

        let path = "/var/lib/kata/never-dispatched/disk.img";
        let error = do_handle_device(&device_manager, &block_config(path))
            .await
            .unwrap_err();

        assert!(ch_config::ch_api::is_api_command_not_dispatched(&error));
        assert!(crate::device::device_state_in_doubt(&error).is_none());
        let (client, mut server_socket) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            let add = read_request(&mut server_socket);
            let id = add.body["id"].as_str().unwrap();
            let response = format!(r#"{{"id":"{id}","bdf":"0000:00:05.0"}}"#);
            write_response(&mut server_socket, "200", Some(&response));
            let _remove = read_request(&mut server_socket);
            write_response(&mut server_socket, "204", None);
        });
        hypervisor.set_test_api_socket(client).await;

        let replacement = do_handle_device(&device_manager, &block_config(path))
            .await
            .unwrap();
        let DeviceType::BlockModern(replacement) = replacement else {
            panic!("expected BlockModern device");
        };
        let replacement = replacement.lock().await;
        let replacement_id = replacement.device_id.clone();
        assert_eq!(replacement.config.index, 0);
        drop(replacement);

        device_manager
            .write()
            .await
            .try_remove_device(&replacement_id)
            .await
            .unwrap();
        server.join().unwrap();
    }

    #[tokio::test]
    async fn canceled_queued_block_add_retry_waits_for_original_completion() {
        let (client, mut server_socket) = UnixStream::pair().unwrap();
        let (blocker_seen_tx, blocker_seen_rx) = std::sync::mpsc::channel();
        let (release_blocker_tx, release_blocker_rx) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let blocker = read_request(&mut server_socket);
            blocker_seen_tx.send(()).unwrap();
            release_blocker_rx.recv().unwrap();
            write_response(
                &mut server_socket,
                "200",
                Some(r#"{"id":"blocker","bdf":"0000:00:05.0"}"#),
            );

            let add = read_request(&mut server_socket);
            let id = add.body["id"].as_str().unwrap();
            let response = format!(r#"{{"id":"{id}","bdf":"0000:00:06.0"}}"#);
            write_response(&mut server_socket, "200", Some(&response));

            let remove = read_request(&mut server_socket);
            write_response(&mut server_socket, "204", None);
            (blocker, add, remove)
        });

        let hypervisor = Arc::new(CloudHypervisor::new());
        let mut config = HypervisorConfig::default();
        config.blockdev_info.block_device_driver = VIRTIO_BLOCK_PCI.to_string();
        hypervisor.set_hypervisor_config(config).await;
        hypervisor.set_test_api_socket(client).await;

        let blocker_hypervisor = hypervisor.clone();
        let blocker = tokio::spawn(async move {
            blocker_hypervisor
                .add_device(block_device("blocker", "/var/lib/kata/blocker/disk.img"))
                .await
        });
        tokio::task::spawn_blocking(move || blocker_seen_rx.recv().unwrap())
            .await
            .unwrap();

        let device_manager = Arc::new(RwLock::new(
            DeviceManager::new(hypervisor.clone(), None).await.unwrap(),
        ));
        let path = "/var/lib/kata/canceled-queued/disk.img";
        let canceled_config = block_config(path);
        let mut canceled = Box::pin(do_handle_device(device_manager.as_ref(), &canceled_config));
        assert!(poll_once(canceled.as_mut()).is_pending());
        drop(canceled);

        let retry_manager = device_manager.clone();
        let retry_config = block_config(path);
        let mut retry = Box::pin(do_handle_device(retry_manager.as_ref(), &retry_config));
        assert!(
            poll_once(retry.as_mut()).is_pending(),
            "same-path retry returned before the original queued attach completed"
        );

        release_blocker_tx.send(()).unwrap();
        blocker.await.unwrap().unwrap();
        let retried = retry.await.unwrap();
        let DeviceType::BlockModern(retried) = retried else {
            panic!("expected BlockModern device");
        };
        let device_id = retried.lock().await.device_id.clone();

        device_manager
            .write()
            .await
            .try_remove_device(&device_id)
            .await
            .unwrap();
        let (_, add, remove) = server.join().unwrap();
        assert_eq!(add.body["id"], device_id);
        assert_eq!(remove.body["id"], device_id);
    }

    #[tokio::test]
    async fn canceled_dispatched_block_add_retry_waits_for_original_completion() {
        let (client, mut server_socket) = UnixStream::pair().unwrap();
        let (add_seen_tx, add_seen_rx) = std::sync::mpsc::channel();
        let (close_tx, close_rx) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let add = read_request(&mut server_socket);
            add_seen_tx
                .send(add.body["id"].as_str().unwrap().to_string())
                .unwrap();
            close_rx.recv().unwrap();
            add
        });

        let hypervisor = Arc::new(CloudHypervisor::new());
        let mut config = HypervisorConfig::default();
        config.blockdev_info.block_device_driver = VIRTIO_BLOCK_PCI.to_string();
        hypervisor.set_hypervisor_config(config).await;
        hypervisor.set_test_api_socket(client).await;
        let device_manager = Arc::new(RwLock::new(
            DeviceManager::new(hypervisor.clone(), None).await.unwrap(),
        ));

        let path = "/var/lib/kata/canceled-dispatched/disk.img";
        let canceled_config = block_config(path);
        let mut canceled = Box::pin(do_handle_device(device_manager.as_ref(), &canceled_config));
        assert!(poll_once(canceled.as_mut()).is_pending());
        let dispatched_id = tokio::task::spawn_blocking(move || add_seen_rx.recv().unwrap())
            .await
            .unwrap();
        drop(canceled);

        let retry_manager = device_manager.clone();
        let retry_config = block_config(path);
        let mut retry = Box::pin(do_handle_device(retry_manager.as_ref(), &retry_config));
        assert!(
            poll_once(retry.as_mut()).is_pending(),
            "same-path retry returned before the original dispatched attach completed"
        );

        close_tx.send(()).unwrap();
        let error = retry.await.unwrap_err();
        assert!(crate::device::device_state_in_doubt(&error).is_some());
        assert!(device_manager.read().await.contains_device(&dispatched_id));
        server.join().unwrap();

        let (cleanup_client, mut cleanup_socket) = UnixStream::pair().unwrap();
        let cleanup_server = thread::spawn(move || {
            let remove_pending = read_request(&mut cleanup_socket);
            write_response(&mut cleanup_socket, "204", None);
            remove_pending
        });
        hypervisor.set_test_api_socket(cleanup_client).await;
        device_manager
            .write()
            .await
            .try_remove_device(&dispatched_id)
            .await
            .unwrap();
        assert!(!device_manager.read().await.contains_device(&dispatched_id));

        let remove_pending = cleanup_server.join().unwrap();
        assert_eq!(remove_pending.body["id"], dispatched_id);
    }

    #[tokio::test]
    async fn retry_joins_admitted_add_while_stop_admission_is_closed() {
        let (client, mut server_socket) = UnixStream::pair().unwrap();
        let (add_seen_tx, add_seen_rx) = std::sync::mpsc::channel();
        let (release_add_tx, release_add_rx) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let add = read_request(&mut server_socket);
            add_seen_tx
                .send(add.body["id"].as_str().unwrap().to_string())
                .unwrap();
            release_add_rx.recv().unwrap();
            let device_id = add.body["id"].as_str().unwrap();
            let response = format!(r#"{{"id":"{device_id}","bdf":"0000:00:08.0"}}"#);
            write_response(&mut server_socket, "200", Some(&response));

            let shutdown = read_request(&mut server_socket);
            write_response(&mut server_socket, "500", Some(r#"["shutdown refused"]"#));
            let remove = read_request(&mut server_socket);
            write_response(&mut server_socket, "204", None);
            (add, shutdown, remove)
        });

        let hypervisor = stop_test_hypervisor(client).await;
        let mut config = HypervisorConfig::default();
        config.blockdev_info.block_device_driver = VIRTIO_BLOCK_PCI.to_string();
        hypervisor.set_hypervisor_config(config).await;
        let device_manager = Arc::new(RwLock::new(
            DeviceManager::new(hypervisor.clone(), None).await.unwrap(),
        ));
        let path = "/var/lib/kata/retry-during-stop/disk.img";
        let canceled_config = block_config(path);
        let mut canceled = Box::pin(do_handle_device(device_manager.as_ref(), &canceled_config));
        assert!(poll_once(canceled.as_mut()).is_pending());
        let device_id = tokio::task::spawn_blocking(move || add_seen_rx.recv().unwrap())
            .await
            .unwrap();
        let operation = hypervisor
            .block_adds
            .lock()
            .await
            .operations
            .get(&device_id)
            .unwrap()
            .clone();
        drop(canceled);

        let mut stop = Box::pin(hypervisor.stop_vm());
        assert!(poll_once(stop.as_mut()).is_pending());

        let mismatch = hypervisor
            .add_device(block_device(
                &device_id,
                "/var/lib/kata/retry-during-stop/different.img",
            ))
            .await
            .unwrap_err();
        assert!(device_state_in_doubt(&mismatch).is_some());
        assert!(Arc::ptr_eq(
            hypervisor
                .block_adds
                .lock()
                .await
                .operations
                .get(&device_id)
                .unwrap(),
            &operation
        ));

        let retry_config = block_config(path);
        let mut retry = Box::pin(do_handle_device(device_manager.as_ref(), &retry_config));
        assert!(
            poll_once(retry.as_mut()).is_pending(),
            "retry returned before its admitted add completed"
        );

        release_add_tx.send(()).unwrap();
        let retried = retry.await.unwrap();
        assert!(stop.await.is_err());
        let DeviceType::BlockModern(retried) = retried else {
            panic!("expected BlockModern device");
        };
        let BlockAddOutcome::Success(original) = operation.wait().await else {
            panic!("expected successful original add");
        };
        let DeviceType::BlockModern(original) = *original else {
            panic!("expected original BlockModern device");
        };
        assert!(Arc::ptr_eq(&original, &retried));

        let retried_guard = retried.lock().await;
        assert_eq!(retried_guard.device_id, device_id);
        assert_eq!(retried_guard.attach_count, 1);
        assert_eq!(retried_guard.config.index, 0);
        assert_eq!(retried_guard.config.path_on_host, path);
        assert_eq!(
            retried_guard.config.pci_path.as_ref().unwrap().to_string(),
            "08"
        );
        drop(retried_guard);

        device_manager
            .write()
            .await
            .try_remove_device(&device_id)
            .await
            .unwrap();
        let (add, _, remove) = server.join().unwrap();
        assert_eq!(add.body["id"], device_id);
        assert_eq!(remove.body["id"], device_id);
    }

    #[tokio::test]
    async fn block_lifecycle_integrates_driver_through_eighth_volume() {
        for count in [1_usize, 4, 8] {
            let (client, mut server_socket) = UnixStream::pair().unwrap();
            server_socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let server = thread::spawn(move || {
                let mut add_requests = Vec::new();
                for ordinal in 0..count {
                    let request = read_request(&mut server_socket);
                    let id = request.body["id"].as_str().unwrap();
                    let response =
                        format!(r#"{{"id":"{id}","bdf":"0000:00:{:02x}.0"}}"#, ordinal + 5);
                    write_response(&mut server_socket, "200", Some(&response));
                    add_requests.push(request);
                }

                let mut remove_requests = Vec::new();
                for _ in 0..count {
                    let request = read_request(&mut server_socket);
                    write_response(&mut server_socket, "204", None);
                    remove_requests.push(request);
                }
                (add_requests, remove_requests)
            });

            let hypervisor = Arc::new(CloudHypervisor::new());
            let mut config = HypervisorConfig::default();
            config.blockdev_info.block_device_driver = VIRTIO_BLOCK_PCI.to_string();
            hypervisor.set_hypervisor_config(config).await;
            hypervisor.set_test_api_socket(client).await;
            let device_manager =
                RwLock::new(DeviceManager::new(hypervisor.clone(), None).await.unwrap());
            let mut device_ids = Vec::new();

            for ordinal in 0..count {
                let path = format!("/var/lib/kata/emptydir-{ordinal}/disk.img");
                let device = do_handle_device(
                    &device_manager,
                    &DeviceConfig::BlockCfgModern(BlockConfigModern {
                        path_on_host: path,
                        driver_option: VIRTIO_BLOCK_PCI.to_string(),
                        num_queues: 2,
                        queue_size: 256,
                        discard_unmap: true,
                        ..Default::default()
                    }),
                )
                .await
                .unwrap();
                let DeviceType::BlockModern(device) = device else {
                    panic!("expected BlockModern device");
                };
                let device_guard = device.lock().await;
                let device_id = device_guard.device_id.clone();
                let pci_path = device_guard.config.pci_path.as_ref().unwrap().to_string();

                assert_eq!(device_guard.config.index, ordinal as u64);
                assert_eq!(pci_path, format!("{:02x}", ordinal + 5));
                drop(device_guard);
                device_ids.push(device_id);
            }

            for device_id in device_ids.iter().rev() {
                device_manager
                    .write()
                    .await
                    .try_remove_device(device_id)
                    .await
                    .unwrap();
            }
            let (add_requests, remove_requests): (Vec<ApiRequest>, Vec<ApiRequest>) =
                server.join().unwrap();
            assert_eq!(add_requests.len(), count);
            for (ordinal, request) in add_requests.iter().enumerate() {
                assert_eq!(request.body["id"], device_ids[ordinal]);
            }
            assert_eq!(remove_requests.len(), count);
            for (ordinal, request) in remove_requests.iter().enumerate() {
                assert_eq!(
                    request.body,
                    serde_json::json!({"id": device_ids[count - ordinal - 1]})
                );
            }
        }
    }
}
