//! Implementation of input and output files.

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use wdl_analysis::document::Document;

use crate::Engine;
use crate::Value;

/// Represents inputs to a WDL workflow or task.
#[derive(Default, Debug, Clone)]
pub struct Inputs {
    values: HashMap<String, Value>,
}

impl Inputs {
    /// Reads a JSON input file from the given file path.
    ///
    /// The expected file format is described in the [WDL specification][1].
    ///
    /// [1]: https://github.com/openwdl/wdl/blob/wdl-1.2/SPEC.md#json-input-format
    pub fn read(document: &Document, engine: &mut Engine, path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let file = File::open(path).with_context(|| {
            format!("failed to open input file `{path}`", path = path.display())
        })?;
        let reader = BufReader::new(file);

        let inputs: serde_json::Value = serde_json::from_reader(reader).with_context(|| {
            format!("failed to parse input file `{path}`", path = path.display())
        })?;
        match inputs {
            serde_json::Value::Object(items) => {
                if items.is_empty() {
                    return Ok(Self::default());
                }

                let mut name = None;
                let mut inputs = None;
                for (key, value) in items {
                    match key.split_once(".") {
                        Some((prefix, value_name)) => {
                            // Ensure the value's prefix matches the previous one
                            let name = name.get_or_insert_with(|| prefix.to_string());
                            if prefix != name {
                                bail!(
                                    "invalid input name `{key}`: expected the value to be \
                                     prefixed with `{name}`, but found prefix `{prefix}`"
                                );
                            }

                            // Check for nested inputs
                            if value_name.contains(".") {
                                // TODO: support nested inputs; to implement this, we need more
                                // information in analysis
                                bail!("nested inputs are not yet supported");
                            }

                            match inputs.get_or_insert_with(|| {
                                match (document.task_by_name(prefix), document.workflow()) {
                                    (Some(task), _) => Some(task.inputs()),
                                    (None, Some(workflow)) if workflow.name() == prefix => {
                                        Some(workflow.inputs())
                                    }
                                    _ => None,
                                }
                            }) {
                                Some(inputs) => {}
                                None => bail!(
                                    "invalid input name `{key}`: no task or workflow named \
                                     `{prefix}` exists in the document"
                                ),
                            }
                        }
                        None => bail!(
                            "invalid input name `{key}`: expected the value to be prefixed with \
                             the workflow or task name"
                        ),
                    }
                }

                todo!()
            }
            _ => bail!(
                "expected input file `{path}` to be a JSON object",
                path = path.display()
            ),
        }
    }

    /// Gets an input value by name.
    pub fn get(&self, name: &str) -> Option<Value> {
        self.values.get(name).copied()
    }

    /// Sets an input value by name.
    pub fn set(&mut self, name: impl Into<String>, value: impl Into<Value>) {
        self.values.insert(name.into(), value.into());
    }

    /// Gets an iterator over the input values.
    pub fn values(&self) -> impl Iterator<Item = (&str, Value)> {
        self.values.iter().map(|(n, v)| (n.as_str(), *v))
    }
}

/// Represents outputs of a WDL workflow or task.
#[derive(Default, Debug, Clone)]
pub struct Outputs {
    values: HashMap<String, Value>,
}

impl Outputs {
    /// Writes the outputs to a JSON output file at the given file path.
    ///
    /// The output file format is described in the [WDL specification][1].
    ///
    /// [1]: https://github.com/openwdl/wdl/blob/wdl-1.2/SPEC.md#json-output-format
    pub fn write(engine: &Engine, path: impl AsRef<Path>) -> Result<()> {
        todo!()
    }
}
