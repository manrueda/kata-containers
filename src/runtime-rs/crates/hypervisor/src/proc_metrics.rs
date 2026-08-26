// Copyright (c) 2026 Authors of Kata Containers
//
// SPDX-License-Identifier: Apache-2.0
//

//! Procfs-backed Prometheus metrics for external hypervisor processes.
//!
//! Mirrors the Go runtime's `kata_hypervisor_*` metrics so kata-monitor can
//! attribute VMM RSS per sandbox for QEMU runtime-rs.

extern crate procfs;

use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use prometheus::{Encoder, Gauge, GaugeVec, Opts, Registry, TextEncoder};
use slog::warn;
use std::convert::TryFrom;
use std::sync::Mutex;

const NAMESPACE_KATA_HYPERVISOR: &str = "kata_hypervisor";

macro_rules! sl {
    () => {
        slog_scope::logger().new(o!("subsystem" => "metrics"))
    };
}

lazy_static! {
    static ref REGISTERED: Mutex<bool> = Mutex::new(false);
    static ref REGISTRY: Registry = Registry::new();
    static ref HYPERVISOR_THREADS: Gauge = Gauge::new(
        format!("{}_{}", NAMESPACE_KATA_HYPERVISOR, "threads"),
        "Hypervisor process threads."
    )
    .unwrap();
    static ref HYPERVISOR_PROC_STATUS: GaugeVec = GaugeVec::new(
        Opts::new(
            format!("{}_{}", NAMESPACE_KATA_HYPERVISOR, "proc_status"),
            "Hypervisor process status."
        ),
        &["item"]
    )
    .unwrap();
    static ref HYPERVISOR_PROC_STAT: GaugeVec = GaugeVec::new(
        Opts::new(
            format!("{}_{}", NAMESPACE_KATA_HYPERVISOR, "proc_stat"),
            "Hypervisor process statistics."
        ),
        &["item"]
    )
    .unwrap();
    static ref HYPERVISOR_IO_STAT: GaugeVec = GaugeVec::new(
        Opts::new(
            format!("{}_{}", NAMESPACE_KATA_HYPERVISOR, "io_stat"),
            "Hypervisor process IO statistics."
        ),
        &["item"]
    )
    .unwrap();
    static ref HYPERVISOR_OPEN_FDS: Gauge = Gauge::new(
        format!("{}_{}", NAMESPACE_KATA_HYPERVISOR, "fds"),
        "Open FDs for hypervisor."
    )
    .unwrap();
}

/// Collect `kata_hypervisor_*` metrics for the process identified by `pid`.
///
/// Returns an empty string when `pid` is zero or the process cannot be read.
pub fn get_hypervisor_metrics(pid: u32) -> Result<String> {
    if pid == 0 {
        return Ok(String::new());
    }

    let mut registered = REGISTERED
        .lock()
        .map_err(|e| anyhow!("failed to check hypervisor metrics register status {:?}", e))?;

    if !(*registered) {
        register_hypervisor_metrics()?;
        *registered = true;
    }

    if !update_hypervisor_metrics(pid)? {
        return Ok(String::new());
    }

    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    encoder.encode(&metric_families, &mut buffer)?;

    Ok(String::from_utf8(buffer)?)
}

fn register_hypervisor_metrics() -> Result<()> {
    REGISTRY.register(Box::new(HYPERVISOR_THREADS.clone()))?;
    REGISTRY.register(Box::new(HYPERVISOR_PROC_STATUS.clone()))?;
    REGISTRY.register(Box::new(HYPERVISOR_PROC_STAT.clone()))?;
    REGISTRY.register(Box::new(HYPERVISOR_IO_STAT.clone()))?;
    REGISTRY.register(Box::new(HYPERVISOR_OPEN_FDS.clone()))?;

    Ok(())
}

/// Returns `false` when the process could not be sampled.
fn update_hypervisor_metrics(pid: u32) -> Result<bool> {
    let process = match procfs::process::Process::new(i32::try_from(pid)?) {
        Ok(p) => p,
        Err(e) => {
            warn!(
                sl!(),
                "failed to open hypervisor process {} for metrics: {:?}", pid, e
            );
            return Ok(false);
        }
    };

    HYPERVISOR_THREADS.set(process.stat.num_threads as f64);

    match process.status() {
        Err(err) => warn!(sl!(), "failed to get hypervisor process status: {:?}", err),
        Ok(status) => set_gauge_vec_proc_status(&HYPERVISOR_PROC_STATUS, &status),
    }

    match process.stat() {
        Err(err) => warn!(sl!(), "failed to get hypervisor process stat: {:?}", err),
        Ok(stat) => set_gauge_vec_proc_stat(&HYPERVISOR_PROC_STAT, &stat),
    }

    match process.io() {
        Err(err) => warn!(sl!(), "failed to get hypervisor process io stat: {:?}", err),
        Ok(io) => set_gauge_vec_proc_io(&HYPERVISOR_IO_STAT, &io),
    }

    match process.fd_count() {
        Err(err) => warn!(sl!(), "failed to get hypervisor open fds number: {:?}", err),
        Ok(fds) => HYPERVISOR_OPEN_FDS.set(fds as f64),
    }

    Ok(true)
}

fn set_gauge_vec_proc_status(gv: &GaugeVec, status: &procfs::process::Status) {
    gv.with_label_values(&["vmpeak"])
        .set(status.vmpeak.unwrap_or(0) as f64);
    gv.with_label_values(&["vmsize"])
        .set(status.vmsize.unwrap_or(0) as f64);
    gv.with_label_values(&["vmlck"])
        .set(status.vmlck.unwrap_or(0) as f64);
    gv.with_label_values(&["vmpin"])
        .set(status.vmpin.unwrap_or(0) as f64);
    gv.with_label_values(&["vmhwm"])
        .set(status.vmhwm.unwrap_or(0) as f64);
    gv.with_label_values(&["vmrss"])
        .set(status.vmrss.unwrap_or(0) as f64);
    gv.with_label_values(&["rssanon"])
        .set(status.rssanon.unwrap_or(0) as f64);
    gv.with_label_values(&["rssfile"])
        .set(status.rssfile.unwrap_or(0) as f64);
    gv.with_label_values(&["rssshmem"])
        .set(status.rssshmem.unwrap_or(0) as f64);
    gv.with_label_values(&["vmdata"])
        .set(status.vmdata.unwrap_or(0) as f64);
    gv.with_label_values(&["vmstk"])
        .set(status.vmstk.unwrap_or(0) as f64);
    gv.with_label_values(&["vmexe"])
        .set(status.vmexe.unwrap_or(0) as f64);
    gv.with_label_values(&["vmlib"])
        .set(status.vmlib.unwrap_or(0) as f64);
    gv.with_label_values(&["vmpte"])
        .set(status.vmpte.unwrap_or(0) as f64);
    gv.with_label_values(&["vmswap"])
        .set(status.vmswap.unwrap_or(0) as f64);
    gv.with_label_values(&["hugetlbpages"])
        .set(status.hugetlbpages.unwrap_or(0) as f64);
    gv.with_label_values(&["voluntary_ctxt_switches"])
        .set(status.voluntary_ctxt_switches.unwrap_or(0) as f64);
    gv.with_label_values(&["nonvoluntary_ctxt_switches"])
        .set(status.nonvoluntary_ctxt_switches.unwrap_or(0) as f64);
}

fn set_gauge_vec_proc_stat(gv: &GaugeVec, stat: &procfs::process::Stat) {
    gv.with_label_values(&["utime"]).set(stat.utime as f64);
    gv.with_label_values(&["stime"]).set(stat.stime as f64);
    gv.with_label_values(&["cutime"]).set(stat.cutime as f64);
    gv.with_label_values(&["cstime"]).set(stat.cstime as f64);
}

fn set_gauge_vec_proc_io(gv: &GaugeVec, io_stat: &procfs::process::Io) {
    gv.with_label_values(&["rchar"]).set(io_stat.rchar as f64);
    gv.with_label_values(&["wchar"]).set(io_stat.wchar as f64);
    gv.with_label_values(&["syscr"]).set(io_stat.syscr as f64);
    gv.with_label_values(&["syscw"]).set(io_stat.syscw as f64);
    gv.with_label_values(&["read_bytes"])
        .set(io_stat.read_bytes as f64);
    gv.with_label_values(&["write_bytes"])
        .set(io_stat.write_bytes as f64);
    gv.with_label_values(&["cancelled_write_bytes"])
        .set(io_stat.cancelled_write_bytes as f64);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_hypervisor_metrics_for_current_process() {
        let pid = std::process::id();
        let metrics = get_hypervisor_metrics(pid).expect("metrics collection should succeed");

        assert!(
            metrics.contains("kata_hypervisor_proc_status"),
            "expected proc_status metrics, got: {}",
            metrics
        );
        assert!(
            metrics.contains(r#"item="vmrss""#),
            "expected vmrss label, got: {}",
            metrics
        );
        assert!(
            metrics.contains("kata_hypervisor_threads"),
            "expected threads metric, got: {}",
            metrics
        );
    }

    #[test]
    fn test_get_hypervisor_metrics_for_zero_pid_is_empty() {
        assert_eq!(get_hypervisor_metrics(0).unwrap(), "");
    }
}
