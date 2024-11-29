//! Module for evaluation.

use std::path::Path;

use indexmap::IndexMap;
use wdl_analysis::document::Task;
use wdl_analysis::types::Type;
use wdl_analysis::types::Types;
use wdl_ast::Diagnostic;
use wdl_ast::Ident;
use wdl_ast::SupportedVersion;

use crate::Value;

pub mod v1;

/// Represents an error that may occur when evaluating a workflow or task.
#[derive(Debug)]
pub enum EvaluationError {
    /// The error came from WDL source evaluation.
    Source(Diagnostic),
    /// The error came from another source.
    Other(anyhow::Error),
}

impl From<Diagnostic> for EvaluationError {
    fn from(diagnostic: Diagnostic) -> Self {
        Self::Source(diagnostic)
    }
}

impl From<anyhow::Error> for EvaluationError {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e)
    }
}

/// Represents a result from evaluating a workflow or task.
pub type EvaluationResult<T> = Result<T, EvaluationError>;

/// Represents context to an expression evaluator.
pub trait EvaluationContext {
    /// Gets the supported version of the document being evaluated.
    fn version(&self) -> SupportedVersion;

    /// Gets the types collection associated with the evaluation.
    fn types(&self) -> &Types;

    /// Gets the mutable types collection associated with the evaluation.
    fn types_mut(&mut self) -> &mut Types;

    /// Gets the value of the given name in scope.
    fn resolve_name(&self, name: &Ident) -> Result<Value, Diagnostic>;

    /// Resolves a type name to a type.
    fn resolve_type_name(&mut self, name: &Ident) -> Result<Type, Diagnostic>;

    /// Gets the working directory for the evaluation.
    fn work_dir(&self) -> &Path;

    /// Gets the temp directory for the evaluation.
    fn temp_dir(&self) -> &Path;

    /// Gets the value to return for a call to the `stdout` function.
    ///
    /// This is `Some` only when evaluating task outputs.
    fn stdout(&self) -> Option<&Value>;

    /// Gets the value to return for a call to the `stderr` function.
    ///
    /// This is `Some` only when evaluating task outputs.
    fn stderr(&self) -> Option<&Value>;

    /// Gets the task associated with the evaluation context.
    ///
    /// This is only `Some` when evaluating task hints sections.
    fn task(&self) -> Option<&Task>;

    /// Gets the types collection associated with the document being evaluated.
    fn document_types(&self) -> &Types;
}

/// Represents an index of a scope in a collection of scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScopeIndex(usize);

impl From<usize> for ScopeIndex {
    fn from(index: usize) -> Self {
        Self(index)
    }
}

impl From<ScopeIndex> for usize {
    fn from(index: ScopeIndex) -> Self {
        index.0
    }
}

/// Represents an evaluation scope in a WDL document.
#[derive(Default, Debug)]
pub struct Scope {
    /// The index of the parent scope.
    ///
    /// This is `None` for task and workflow scopes.
    parent: Option<ScopeIndex>,
    /// The map of names in scope to their values.
    names: IndexMap<String, Value>,
}

impl Scope {
    /// Creates a new scope given the parent scope.
    pub fn new(parent: Option<ScopeIndex>) -> Self {
        Self {
            parent,
            names: Default::default(),
        }
    }

    /// Inserts a name into the scope.
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<Value>) {
        self.names.insert(name.into(), value.into());
    }

    /// Gets a mutable reference to an existing name in scope.
    pub(crate) fn get_mut(&mut self, name: &str) -> Option<&mut Value> {
        self.names.get_mut(name)
    }
}

impl From<Scope> for IndexMap<String, Value> {
    fn from(scope: Scope) -> Self {
        scope.names
    }
}

/// Represents a reference to a scope.
#[derive(Debug, Clone, Copy)]
pub struct ScopeRef<'a> {
    /// The reference to the scopes collection.
    scopes: &'a [Scope],
    /// The index of the scope in the collection.
    index: ScopeIndex,
}

impl<'a> ScopeRef<'a> {
    /// Creates a new scope reference given the scope index.
    pub fn new(scopes: &'a [Scope], index: impl Into<ScopeIndex>) -> Self {
        Self {
            scopes,
            index: index.into(),
        }
    }

    /// Gets the parent scope.
    ///
    /// Returns `None` if there is no parent scope.
    pub fn parent(&self) -> Option<Self> {
        self.scopes[self.index.0].parent.map(|p| Self {
            scopes: self.scopes,
            index: p,
        })
    }

    /// Gets all of the name and values available at this scope.
    pub fn names(&self) -> impl Iterator<Item = (&str, &Value)> + use<'_> {
        self.scopes[self.index.0]
            .names
            .iter()
            .map(|(n, name)| (n.as_str(), name))
    }

    /// Gets the value of a name local to this scope.
    ///
    /// Returns `None` if a name local to this scope was not found.
    pub fn local(&self, name: &str) -> Option<&Value> {
        self.scopes[self.index.0].names.get(name)
    }

    /// Lookups a name in the scope.
    ///
    /// Returns `None` if the name is not available in the scope.
    pub fn lookup(&self, name: &str) -> Option<&Value> {
        let mut current = Some(self.index);

        while let Some(index) = current {
            if let Some(name) = self.scopes[index.0].names.get(name) {
                return Some(name);
            }

            current = self.scopes[index.0].parent;
        }

        None
    }
}
