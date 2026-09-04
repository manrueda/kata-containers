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
