//! Implementation of task execution backends.

use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Result;
use futures::future::BoxFuture;
use indexmap::IndexMap;

use crate::Engine;
use crate::Value;

pub mod local;

/// Represents a completed task execution.
pub struct CompletedTask {
    /// The status code from the process that executed the task.
    pub status_code: i32,
    /// The path to the task's working directory
    pub work_dir: PathBuf,
    /// The path to the task's temp directory.
    pub temp_dir: PathBuf,
    /// The path to the file containing the task's evaluated command.
    pub command: PathBuf,
    /// The path to the file containing the task's standard output stream.
    pub stdout: PathBuf,
    /// The path to the file containing the task's standard error stream.
    pub stderr: PathBuf,
}

/// Represents constraints applied to a task's execution.
pub struct TaskExecutionConstraints {
    /// The container the task will run in.
    ///
    /// A value of `None` indicates the task will run on the host.
    pub container: Option<String>,
    /// The allocated number of CPUs; must be greater than 0.
    pub cpu: f64,
    /// The allocated memory in bytes; must be greater than 0.
    pub memory: i64,
    /// A list with one specification per allocated GPU.
    ///
    /// The specification is execution engine-specific.
    ///
    /// If no GPUs were allocated, then the value must be an empty list.
    pub gpu: Vec<String>,
    /// A list with one specification per allocated FPGA.
    ///
    /// The specification is execution engine-specific.
    ///
    /// If no FPGAs were allocated, then the value must be an empty list.
    pub fpga: Vec<String>,
    /// A map with one entry for each disk mount point.
    ///
    /// The key is the mount point and the value is the initial amount of disk
    /// space allocated, in bytes.
    ///
    /// The execution engine must, at a minimum, provide one entry for each disk
    /// mount point requested, but may provide more.
    ///
    /// The amount of disk space available for a given mount point may increase
    /// during the lifetime of the task (e.g., autoscaling volumes provided by
    /// some cloud services).
    pub disks: IndexMap<String, i64>,
}

/// Represents the execution of a particular task.
pub trait TaskExecution: Send {
    /// Maps a host path to a guest path.
    ///
    /// Returns `None` if the execution directly uses host paths.
    fn map_path(&mut self, path: &Path) -> Option<PathBuf>;

    /// Gets the execution constraints for the task given the task's
    /// requirements and hints.
    ///
    /// Returns an error if the task cannot be constrained for the execution
    /// environment or if the task specifies invalid requirements.
    fn constraints(
        &self,
        engine: &Engine,
        requirements: &HashMap<String, Value>,
        hints: &HashMap<String, Value>,
    ) -> Result<TaskExecutionConstraints>;

    /// Spawns the execution of a task given the task's command, requirements,
    /// and hints.
    ///
    /// Upon success, returns a future that will complete when the task's
    /// execution has finished.
    fn spawn(
        &self,
        command: String,
        requirements: &HashMap<String, Value>,
        hints: &HashMap<String, Value>,
    ) -> Result<BoxFuture<'static, Result<CompletedTask>>>;

    /// Gets the path to the execution's working directory.
    fn work_dir(&self) -> &Path;

    /// Gets the path to the execution's temp directory.
    fn temp_dir(&self) -> &Path;
}

/// Represents a task execution backend.
pub trait TaskExecutionBackend {
    /// Creates a new task execution.
    ///
    /// The specified directory serves as the root location of where a task
    /// execution may keep its files.
    ///
    /// Note that this does not spawn the task's execution; see
    /// [TaskExecution::spawn](TaskExecution::spawn).
    fn create_execution(&self, root: &Path) -> Result<Box<dyn TaskExecution>>;
}
