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
            Self::Failure(error) => Err(anyhow::Error::new(SharedBlockAddError(error))),
        }
    }
}

#[derive(Clone, Debug)]
struct SharedBlockAddError(Arc<anyhow::Error>);

impl fmt::Display for SharedBlockAddError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl StdError for SharedBlockAddError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.0.as_ref().as_ref())
    }
}

#[derive(Debug, Default)]
struct BlockAddOperation {
    outcome: Mutex<Option<BlockAddOutcome>>,
    completed: Notify,
}

impl BlockAddOperation {
    async fn complete(&self, result: Result<DeviceType>) {
        *self.outcome.lock().await = Some(BlockAddOutcome::from_result(result));
        self.completed.notify_waiters();
    }

    async fn wait(&self) -> BlockAddOutcome {
        loop {
            let completed = self.completed.notified();
            if let Some(outcome) = self.outcome.lock().await.as_ref().cloned() {
                return outcome;
            }
            completed.await;
        }
    }
}

#[derive(Debug)]
struct BlockAddState {
    admission_open: bool,
    operations: HashMap<String, Arc<BlockAddOperation>>,
}

impl Default for BlockAddState {
    fn default() -> Self {
        Self {
            admission_open: true,
            operations: HashMap::new(),
        }
    }
}

#[derive(Debug)]
pub struct CloudHypervisor {
    inner: Arc<RwLock<CloudHypervisorInner>>,
    block_adds: Mutex<BlockAddState>,
    exit_waiter: Mutex<(mpsc::Receiver<i32>, i32)>,
}

impl CloudHypervisor {
    pub fn new() -> Self {
        let (exit_notify, exit_waiter) = mpsc::channel(1);

        Self {
            inner: Arc::new(RwLock::new(CloudHypervisorInner::new(Some(exit_notify)))),
            block_adds: Mutex::new(BlockAddState::default()),
            exit_waiter: Mutex::new((exit_waiter, 0)),
        }
    }

    async fn add_block_device(&self, device: Arc<Mutex<BlockDeviceModern>>) -> Result<DeviceType> {
        let device_id = device.lock().await.device_id.clone();
        let (operation, start) = {
            let mut state = self.block_adds.lock().await;
            if !state.admission_open {
                return Err(anyhow::anyhow!(
                    "Cloud Hypervisor block add for device {device_id} was not admitted because VM stop has begun"
                ));
            }
            match state.operations.get(&device_id) {
                Some(operation) => (operation.clone(), false),
                None => {
                    let operation = Arc::new(BlockAddOperation::default());
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
                        .add_device(DeviceType::BlockModern(device))
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

    async fn close_block_add_admission_and_drain(&self) {
        let operations = {
            let mut state = self.block_adds.lock().await;
            state.admission_open = false;
            state.operations.values().cloned().collect::<Vec<_>>()
        };

        for operation in operations {
            operation.wait().await;
        }
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
        let mut inner = self.inner.write().await;
        inner.start_vm(timeout).await
    }

    async fn stop_vm(&self) -> Result<()> {
        self.close_block_add_admission_and_drain().await;
        let mut inner = self.inner.write().await;
        inner.stop_vm().await
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
            block_adds: Mutex::new(BlockAddState::default()),
            exit_waiter: Mutex::new((exit_waiter, 0)),
        })
    }
}
