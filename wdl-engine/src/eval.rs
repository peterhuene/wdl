//! Module for evaluation.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt;
use std::path::MAIN_SEPARATOR;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use indexmap::IndexMap;
use url::Url;
use wdl_analysis::document::Task;
use wdl_analysis::types::Type;
use wdl_ast::Diagnostic;
use wdl_ast::Span;
use wdl_ast::SupportedVersion;
use wdl_ast::v1::TASK_REQUIREMENT_RETURN_CODES;
use wdl_ast::v1::TASK_REQUIREMENT_RETURN_CODES_ALIAS;

use crate::CompoundValue;
use crate::Outputs;
use crate::PrimitiveValue;
use crate::TaskExecutionResult;
use crate::TaskExecutionRoot;
use crate::Value;
use crate::http::Downloader;

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
pub trait EvaluationContext: Send + Sync {
    /// Gets the supported version of the document being evaluated.
    fn version(&self) -> SupportedVersion;

    /// Gets the value of the given name in scope.
    fn resolve_name(&self, name: &str, span: Span) -> Result<Value, Diagnostic>;

    /// Resolves a type name to a type.
    fn resolve_type_name(&self, name: &str, span: Span) -> Result<Type, Diagnostic>;

    /// Gets the working directory for the evaluation.
    ///
    /// Returns `None` if the task execution hasn't occurred yet.
    ///
    /// Represents as a URL to support remote working directories.
    fn work_dir(&self) -> Option<&Url>;

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

    /// Translates a host path to a guest path.
    ///
    /// Returns `None` if no translation is available.
    fn translate_path(&self, path: &str) -> Option<Cow<'_, Path>>;

    /// Gets the downloader to use for evaluating expressions.
    fn downloader(&self) -> &dyn Downloader;
}

/// Represents an index of a scope in a collection of scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScopeIndex(usize);

impl ScopeIndex {
    /// Constructs a new scope index from a raw index.
    pub const fn new(index: usize) -> Self {
        Self(index)
    }
}

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
    /// This is `None` for the root scopes.
    parent: Option<ScopeIndex>,
    /// The map of names in scope to their values.
    names: IndexMap<String, Value>,
}

impl Scope {
    /// Creates a new scope given the parent scope.
    pub fn new(parent: ScopeIndex) -> Self {
        Self {
            parent: Some(parent),
            names: Default::default(),
        }
    }

    /// Inserts a name into the scope.
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<Value>) {
        let prev = self.names.insert(name.into(), value.into());
        assert!(prev.is_none(), "conflicting name in scope");
    }

    /// Iterates over the local names and values in the scope.
    pub fn local(&self) -> impl Iterator<Item = (&str, &Value)> + use<'_> {
        self.names.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Gets a mutable reference to an existing name in scope.
    pub(crate) fn get_mut(&mut self, name: &str) -> Option<&mut Value> {
        self.names.get_mut(name)
    }

    /// Clears the scope.
    pub(crate) fn clear(&mut self) {
        self.parent = None;
        self.names.clear();
    }

    /// Sets the scope's parent.
    pub(crate) fn set_parent(&mut self, parent: ScopeIndex) {
        self.parent = Some(parent);
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

    /// Iterates over each name and value visible to the scope and calls the
    /// provided callback.
    ///
    /// Stops iterating and returns an error if the callback returns an error.
    pub fn for_each(&self, mut cb: impl FnMut(&str, &Value) -> Result<()>) -> Result<()> {
        let mut current = Some(self.index);

        while let Some(index) = current {
            for (n, v) in self.scopes[index.0].local() {
                cb(n, v)?;
            }

            current = self.scopes[index.0].parent;
        }

        Ok(())
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

/// Represents an evaluated task.
#[derive(Debug)]
pub struct EvaluatedTask {
    /// The evaluated task's exit code.
    exit_code: i32,
    /// The working directory of the executed task.
    work_dir: Url,
    /// The value to return from the `stdout` function.
    stdout: Value,
    /// The value to return from the `stderr` function.
    stderr: Value,
    /// The evaluated outputs of the task.
    ///
    /// This is `Ok` when the task executes successfully and all of the task's
    /// outputs evaluated without error.
    ///
    /// Otherwise, this contains the error that occurred while attempting to
    /// evaluate the task's outputs.
    outputs: EvaluationResult<Outputs>,
}

impl EvaluatedTask {
    /// Constructs a new evaluated task.
    ///
    /// Returns an error if the stdout or stderr paths are not UTF-8.
    fn new(root: &TaskExecutionRoot, result: TaskExecutionResult) -> anyhow::Result<Self> {
        let stdout = PrimitiveValue::new_file(root.stdout().to_str().with_context(|| {
            format!(
                "path to stdout file `{path}` is not UTF-8",
                path = root.stdout().display()
            )
        })?)
        .into();
        let stderr = PrimitiveValue::new_file(root.stderr().to_str().with_context(|| {
            format!(
                "path to stderr file `{path}` is not UTF-8",
                path = root.stderr().display()
            )
        })?)
        .into();

        Ok(Self {
            exit_code: result.exit_code,
            work_dir: result.work_dir,
            stdout,
            stderr,
            outputs: Ok(Default::default()),
        })
    }

    /// Gets the exit code of the evaluated task.
    pub fn exit_code(&self) -> i32 {
        self.exit_code
    }

    /// Gets the working directory of the evaluated task.
    pub fn work_dir(&self) -> &Url {
        &self.work_dir
    }

    /// Gets the stdout value of the evaluated task.
    pub fn stdout(&self) -> &Value {
        &self.stdout
    }

    /// Gets the stderr value of the evaluated task.
    pub fn stderr(&self) -> &Value {
        &self.stderr
    }

    /// Gets the outputs of the evaluated task.
    ///
    /// This is `Ok` when the task executes successfully and all of the task's
    /// outputs evaluated without error.
    ///
    /// Otherwise, this contains the error that occurred while attempting to
    /// evaluate the task's outputs.
    pub fn outputs(&self) -> &EvaluationResult<Outputs> {
        &self.outputs
    }

    /// Converts the evaluated task into an evaluation result.
    ///
    /// Returns `Ok(_)` if the task outputs were evaluated.
    ///
    /// Returns `Err(_)` if the task outputs could not be evaluated.
    pub fn into_result(self) -> EvaluationResult<Outputs> {
        self.outputs
    }

    /// Handles the exit of a task execution.
    ///
    /// Returns an error if the task failed.
    fn handle_exit(&self, requirements: &HashMap<String, Value>) -> anyhow::Result<()> {
        let mut error = true;
        if let Some(return_codes) = requirements
            .get(TASK_REQUIREMENT_RETURN_CODES)
            .or_else(|| requirements.get(TASK_REQUIREMENT_RETURN_CODES_ALIAS))
        {
            match return_codes {
                Value::Primitive(PrimitiveValue::String(s)) if s.as_ref() == "*" => {
                    error = false;
                }
                Value::Primitive(PrimitiveValue::String(s)) => {
                    bail!(
                        "invalid return code value `{s}`: only `*` is accepted when the return \
                         code is specified as a string"
                    );
                }
                Value::Primitive(PrimitiveValue::Integer(ok)) => {
                    if self.exit_code == i32::try_from(*ok).unwrap_or_default() {
                        error = false;
                    }
                }
                Value::Compound(CompoundValue::Array(codes)) => {
                    error = !codes.as_slice().iter().any(|v| {
                        v.as_integer()
                            .map(|i| i32::try_from(i).unwrap_or_default() == self.exit_code)
                            .unwrap_or(false)
                    });
                }
                _ => unreachable!("unexpected return codes value"),
            }
        } else {
            error = self.exit_code != 0;
        }

        if error {
            bail!(
                "task process has terminated with status code {code}; see the `stdout` and \
                 `stderr` files in execution directory `{dir}{MAIN_SEPARATOR}` for task command \
                 output",
                code = self.exit_code,
                dir = Path::new(self.stderr.as_file().unwrap().as_str())
                    .parent()
                    .expect("parent should exist")
                    .display(),
            );
        }

        Ok(())
    }
}

/// Represents the access for a mount.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum MountAccess {
    /// The mount will be read-only.
    ReadOnly,
    /// The mount will be read-write.
    ReadWrite,
}

impl fmt::Display for MountAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadOnly => write!(f, "read-only"),
            Self::ReadWrite => write!(f, "read-write"),
        }
    }
}

/// Represents a mount of a file or directory for backends that use containers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// The host URI for the mount.
    pub host: Url,
    /// The guest path for the mount.
    pub guest: PathBuf,
    /// The access for the mount.
    pub access: MountAccess,
}

impl Mount {
    /// Creates a new mount with the given host and guest paths.
    pub fn new(host: impl Into<Url>, guest: impl Into<PathBuf>, access: MountAccess) -> Self {
        Self {
            host: host.into(),
            guest: guest.into(),
            access,
        }
    }
}

/// Represents a collection of mounts for mapping host and guest paths for task
/// execution backends that use containers.
#[derive(Debug, Default)]
pub struct Mounts(Vec<Mount>);

impl Mounts {
    /// Gets the guest path for the given host URI.
    ///
    /// Returns `None` if there is no guest path mapped for the given path.
    pub fn guest(&self, host: &str) -> Option<Cow<'_, Path>> {
        for mp in &self.0 {
            if let Some(stripped) = host.strip_prefix(mp.host.as_str()) {
                if stripped.is_empty() {
                    return Some(mp.guest.as_path().into());
                }

                // Strip off the query string or fragment
                let stripped = if let Some(pos) = stripped.find('?') {
                    &stripped[..pos]
                } else if let Some(pos) = stripped.find('#') {
                    &stripped[..pos]
                } else {
                    stripped
                };

                return Some(mp.guest.join(stripped).into());
            }
        }

        None
    }

    /// Gets the host path for the given guest path.
    ///
    /// Returns `None` if there is no host path mapped for the given path.
    pub fn host(&self, guest: impl AsRef<Path>) -> Option<Cow<'_, Url>> {
        let guest = guest.as_ref();

        for mp in &self.0 {
            if let Ok(stripped) = guest.strip_prefix(&mp.guest) {
                if stripped.as_os_str().is_empty() {
                    return Some(Cow::Borrowed(&mp.host));
                }

                // For joining, we push an empty path segment so `Url::join` will treat the last
                // segment as a directory
                let mut host = mp.host.clone();
                if let Ok(mut segments) = host.path_segments_mut() {
                    segments.pop_if_empty();
                    segments.push("");
                }

                return Some(Cow::Owned(host.join(stripped.to_str()?).ok()?));
            }
        }

        None
    }

    /// Returns an iterator of mounts within the collection.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Mount> {
        self.0.iter()
    }

    /// Returns the number of mounts in the collection.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Inserts a mount into the collection.
    pub fn insert(&mut self, mp: impl Into<Mount>) {
        self.0.push(mp.into());
    }
}

/// Represents a URL component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum UrlComponent<'a> {
    /// The component is the scheme.
    Scheme(&'a str),
    /// The component is the authority.
    Authority(&'a str),
    /// The component is a path segment.
    Path(&'a str),
    /// The component is the query string.
    Query(&'a str),
    /// The component is the fragment.
    Fragment(&'a str),
}

/// Represents a node in a URL trie.
#[derive(Debug)]
struct UrlTrieNode<'a> {
    /// The URL component represented by this node.
    component: UrlComponent<'a>,
    /// The children of this node.
    ///
    /// A `BTreeMap` is used here to get a consistent walk of the tree.
    children: BTreeMap<&'a str, Self>,
    /// The identifier of the node in the trie.
    ///
    /// A node's identifier is used when formatting guest paths of children.
    id: usize,
    /// Whether or not the node is terminal.
    ///
    /// A value of `true` indicates that the URL was explicitly inserted into
    /// the trie.
    terminal: bool,
    /// The mount access to use when the node is terminal.
    access: MountAccess,
}

impl<'a> UrlTrieNode<'a> {
    /// Constructs a new URL trie node with the given URL component.
    fn new(component: UrlComponent<'a>, id: usize) -> Self {
        Self {
            component,
            children: Default::default(),
            id,
            terminal: false,
            access: MountAccess::ReadOnly,
        }
    }

    /// Inserts any mounts for the node.
    fn insert_mounts(
        &self,
        root: &'a Path,
        host: &mut String,
        mounts: &mut Mounts,
        parent_id: usize,
    ) {
        // Push the component onto the host URL and pop it after any traversals
        let len = host.len();
        match self.component {
            UrlComponent::Scheme(scheme) => {
                assert!(
                    host.is_empty(),
                    "scheme should always be the first child in the tree"
                );
                host.push_str(scheme);
                host.push_str(":");
            }
            UrlComponent::Authority(authority) => {
                host.push_str("//");
                host.push_str(authority);
            }
            UrlComponent::Path(segment) => {
                host.push_str("/");
                host.push_str(segment)
            }
            UrlComponent::Query(query) => {
                host.push_str("?");
                host.push_str(query);
            }
            UrlComponent::Fragment(fragment) => {
                host.push_str("#");
                host.push_str(fragment);
            }
        }

        // For terminal nodes, we add a mount and stop recursing
        // Any terminal nodes that are descendant from this node will be treated as
        // relative to this node in any mappings
        if self.terminal {
            let filename = Path::new(host)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            // Strip off the query string or fragment
            let filename = if let Some(pos) = filename.find('?') {
                &filename[..pos]
            } else if let Some(pos) = filename.find('#') {
                &filename[..pos]
            } else {
                filename
            };

            // Use format! for the path so that it always appears unix-style
            // The parent id is used so that children of the same parent share the same
            // parent directory
            mounts.0.push(Mount {
                host: host.parse().expect("should build a valid URL"),
                guest: format!(
                    "{root}{sep}{parent_id}{sep2}{filename}",
                    root = root.display(),
                    sep = if root.as_os_str().as_encoded_bytes().last() == Some(&b'/') {
                        ""
                    } else {
                        "/"
                    },
                    sep2 = if filename.is_empty() { "" } else { "/" },
                )
                .into(),
                access: self.access,
            });
        } else {
            // Otherwise, traverse into the children
            for child in self.children.values() {
                child.insert_mounts(root, host, mounts, self.id);
            }
        }

        host.truncate(len);
    }
}

/// Represents a prefix trie based on URLs.
///
/// This is used to determine container mounts.
///
/// From the root to a terminal node represents a unique URL.
///
/// If a terminal URL has descendants that are also terminal, only the ancestor
/// nearest the root will be added as a mount; its descendants will be mapped as
/// relative paths.
///
/// Host and guest paths are mapped according to the mounts.
#[derive(Debug)]
pub struct UrlTrie<'a> {
    /// The children of this tree.
    ///
    /// The key in the map is the scheme of each URL.
    ///
    /// A `BTreeMap` is used here to get a consistent walk of the tree.
    children: BTreeMap<&'a str, UrlTrieNode<'a>>,
    /// The number of nodes in the trie.
    ///
    /// Used to provide an identifier to each node.
    ///
    /// The trie always has at least one node (the root).
    count: usize,
}

impl<'a> UrlTrie<'a> {
    /// Inserts a new URL into the trie.
    pub fn insert(&mut self, url: &'a Url, access: MountAccess) {
        // Insert for scheme
        let mut node = self.children.entry(url.scheme()).or_insert_with(|| {
            let node = UrlTrieNode::new(UrlComponent::Scheme(url.scheme()), self.count);
            self.count += 1;
            node
        });

        // Insert the authority
        node = node.children.entry(url.authority()).or_insert_with(|| {
            let node = UrlTrieNode::new(UrlComponent::Authority(url.authority()), self.count);
            self.count += 1;
            node
        });

        // Insert the path segments
        if let Some(segments) = url.path_segments() {
            for segment in segments {
                node = node.children.entry(segment).or_insert_with(|| {
                    let node = UrlTrieNode::new(UrlComponent::Path(segment), self.count);
                    self.count += 1;
                    node
                });
            }
        }

        // Insert the query string
        if let Some(query) = url.query() {
            node = node.children.entry(query).or_insert_with(|| {
                let node = UrlTrieNode::new(UrlComponent::Query(query), self.count);
                self.count += 1;
                node
            });
        }

        // Insert the fragment
        if let Some(fragment) = url.fragment() {
            node = node.children.entry(fragment).or_insert_with(|| {
                let node = UrlTrieNode::new(UrlComponent::Fragment(fragment), self.count);
                self.count += 1;
                node
            });
        }

        node.terminal = true;
        node.access = access;
    }

    /// Converts the path trie into mounts based on the provided guest root
    /// directory.
    pub fn into_mounts(self, guest_root: impl AsRef<Path>) -> Mounts {
        let mut mounts = Mounts::default();
        let mut host = String::new();

        for (_, child) in &self.children {
            child.insert_mounts(guest_root.as_ref(), &mut host, &mut mounts, 0);
        }

        mounts
    }
}

impl Default for UrlTrie<'_> {
    fn default() -> Self {
        Self {
            children: Default::default(),
            count: 1,
        }
    }
}

#[cfg(test)]
mod test {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn empty_trie() {
        let empty = UrlTrie::default();
        let mounts = empty.into_mounts("/mnt/");
        assert_eq!(mounts.iter().count(), 0);
        assert_eq!(mounts.len(), 0);
        assert!(mounts.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn trie_with_terminal_root_unix() {
        let mut trie = UrlTrie::default();
        let urls = [
            "file:///".parse().unwrap(),
            "file:///relative/from/root".parse().unwrap(),
        ];
        trie.insert(&urls[0], MountAccess::ReadOnly);
        trie.insert(&urls[1], MountAccess::ReadOnly);
        let mounts = trie.into_mounts("/mnt/");
        assert_eq!(mounts.iter().count(), 1);
        assert_eq!(mounts.len(), 1);
        assert!(!mounts.is_empty());

        // Note: the mounts are always in lexical order
        let collected: Vec<_> = mounts.iter().collect();
        assert_eq!(
            collected,
            [&Mount::new(
                urls[0].clone(),
                "/mnt/0",
                MountAccess::ReadOnly
            )]
        );

        for (host, guest) in [
            (&urls[0], "/mnt/0"),
            ("/foo/bar/foo.txt", "/mnt/0/foo/bar/foo.txt"),
            ("/bar/foo/foo.txt", "/mnt/0/bar/foo/foo.txt"),
            ("/any/other/path", "/mnt/0/any/other/path"),
        ] {
            assert_eq!(
                mounts.guest(host).as_deref(),
                Some(Path::new(guest)),
                "unexpected guest path for host path `{host}`"
            );
            assert_eq!(
                mounts.host(guest).as_deref(),
                Some(host),
                "unexpected host path for guest path `{guest}`"
            );
        }
    }

    // #[cfg(windows)]
    // #[test]
    // fn root_with_terminal_root_windows() {
    //     let mut trie = PathTrie::default();
    //     trie.insert(Path::new("C:\\"), true);
    //     trie.insert(Path::new("C:\\relative\\from\\root"), true);
    //     let mounts = trie.into_mounts("/mnt/");
    //     assert_eq!(mounts.iter().count(), 1);
    //     assert_eq!(mounts.len(), 1);
    //     assert!(!mounts.is_empty());

    //     // Note: the mounts are always in lexical order
    //     let collected: Vec<_> = mounts.iter().collect();
    //     assert_eq!(collected, [&Mount::new("C:\\", "/mnt/0", true)]);

    //     for (host, guest) in [
    //         ("C:\\", "/mnt/0"),
    //         ("C:\\foo\\bar\\foo.txt", "/mnt/0/foo/bar/foo.txt"),
    //         ("C:\\bar\\foo\\foo.txt", "/mnt/0/bar/foo/foo.txt"),
    //         ("C:\\any\\other\\path", "/mnt/0/any/other/path"),
    //     ] {
    //         assert_eq!(
    //             mounts.guest(host).as_deref(),
    //             Some(Path::new(guest)),
    //             "unexpected guest path for host path `{host}`"
    //         );
    //         assert_eq!(
    //             mounts.host(guest).as_deref(),
    //             Some(Path::new(host)),
    //             "unexpected host path for guest path `{guest}`"
    //         );
    //     }
    // }

    // #[cfg(unix)]
    // #[test]
    // fn trie_with_common_paths_unix() {
    //     let mut trie = PathTrie::default();
    //     trie.insert(Path::new("/foo/bar/foo.txt"), true);
    //     trie.insert(Path::new("/foo/bar/bar.txt"), true);
    //     trie.insert(Path::new("/foo/baz/foo.txt"), true);
    //     trie.insert(Path::new("/foo/baz/bar.txt"), true);
    //     trie.insert(Path::new("/bar/foo/foo.txt"), true);
    //     trie.insert(Path::new("/bar/foo/bar.txt"), true);
    //     trie.insert(Path::new("/baz"), true);

    //     let mounts = trie.into_mounts("/mnt");

    //     // Note: the mounts are always in lexical order
    //     let collected: Vec<_> = mounts.iter().collect();
    //     assert_eq!(
    //         collected,
    //         [
    //             &Mount::new("/bar/foo/bar.txt", "/mnt/9/bar.txt", true),
    //             &Mount::new("/bar/foo/foo.txt", "/mnt/9/foo.txt", true),
    //             &Mount::new("/baz", "/mnt/0/baz", true),
    //             &Mount::new("/foo/bar/bar.txt", "/mnt/2/bar.txt", true),
    //             &Mount::new("/foo/bar/foo.txt", "/mnt/2/foo.txt", true),
    //             &Mount::new("/foo/baz/bar.txt", "/mnt/5/bar.txt", true),
    //             &Mount::new("/foo/baz/foo.txt", "/mnt/5/foo.txt", true),
    //         ]
    //     );

    //     for (host, guest) in [
    //         ("/foo/bar/foo.txt", "/mnt/2/foo.txt"),
    //         ("/foo/bar/bar.txt", "/mnt/2/bar.txt"),
    //         ("/foo/baz/foo.txt", "/mnt/5/foo.txt"),
    //         ("/foo/baz/bar.txt", "/mnt/5/bar.txt"),
    //         ("/bar/foo/foo.txt", "/mnt/9/foo.txt"),
    //         ("/bar/foo/bar.txt", "/mnt/9/bar.txt"),
    //         ("/baz", "/mnt/0/baz"),
    //         ("/baz/any/other/path", "/mnt/0/baz/any/other/path"),
    //     ] {
    //         assert_eq!(
    //             mounts.guest(host).as_deref(),
    //             Some(Path::new(guest)),
    //             "unexpected guest path for host path `{host}`"
    //         );
    //         assert_eq!(
    //             mounts.host(guest).as_deref(),
    //             Some(Path::new(host)),
    //             "unexpected host path for guest path `{guest}`"
    //         );
    //     }

    //     // Check for paths not in the host or guest mapping
    //     assert!(mounts.guest("/tmp/foo.txt").is_none());
    //     assert!(mounts.host("/tmp/bar.txt").is_none());
    // }

    // #[cfg(windows)]
    // #[test]
    // fn trie_with_common_paths_windows() {
    //     let mut trie = PathTrie::default();
    //     trie.insert(Path::new("C:\\foo\\bar\\foo.txt"), true);
    //     trie.insert(Path::new("C:\\foo\\bar\\bar.txt"), true);
    //     trie.insert(Path::new("C:\\foo\\baz\\foo.txt"), true);
    //     trie.insert(Path::new("C:\\foo\\baz\\bar.txt"), true);
    //     trie.insert(Path::new("C:\\bar\\foo\\foo.txt"), true);
    //     trie.insert(Path::new("C:\\bar\\foo\\bar.txt"), true);
    //     trie.insert(Path::new("C:\\baz"), true);

    //     let mounts = trie.into_mounts("/mnt");

    //     // Note: the mounts are always in lexical order
    //     let collected: Vec<_> = mounts.iter().collect();
    //     assert_eq!(
    //         collected,
    //         [
    //             &Mount::new("C:\\bar\\foo\\bar.txt", "/mnt/10/bar.txt",
    // true),             &Mount::new("C:\\bar\\foo\\foo.txt",
    // "/mnt/10/foo.txt", true),             &Mount::new("C:\\baz",
    // "/mnt/1/baz", true),             &Mount::new("C:\\foo\\bar\\bar.txt",
    // "/mnt/3/bar.txt", true),
    // &Mount::new("C:\\foo\\bar\\foo.txt", "/mnt/3/foo.txt", true),
    //             &Mount::new("C:\\foo\\baz\\bar.txt", "/mnt/6/bar.txt", true),
    //             &Mount::new("C:\\foo\\baz\\foo.txt", "/mnt/6/foo.txt", true),
    //         ]
    //     );

    //     for (host, guest) in [
    //         ("C:\\foo\\bar\\foo.txt", "/mnt/3/foo.txt"),
    //         ("C:\\foo\\bar\\bar.txt", "/mnt/3/bar.txt"),
    //         ("C:\\foo\\baz\\foo.txt", "/mnt/6/foo.txt"),
    //         ("C:\\foo\\baz\\bar.txt", "/mnt/6/bar.txt"),
    //         ("C:\\bar\\foo\\foo.txt", "/mnt/10/foo.txt"),
    //         ("C:\\bar\\foo\\bar.txt", "/mnt/10/bar.txt"),
    //         ("C:\\baz", "/mnt/1/baz"),
    //         ("C:\\baz\\any\\other\\path", "/mnt/1/baz/any/other/path"),
    //     ] {
    //         assert_eq!(
    //             mounts.guest(host).as_deref(),
    //             Some(Path::new(guest)),
    //             "unexpected guest path for host path `{host}`"
    //         );
    //         assert_eq!(
    //             mounts.host(guest).as_deref(),
    //             Some(Path::new(host)),
    //             "unexpected host path for guest path `{guest}`"
    //         );
    //     }

    //     // Check for paths not in the host or guest mapping
    //     assert!(mounts.guest("/tmp/foo.txt").is_none());
    //     assert!(mounts.host("/tmp/bar.txt").is_none());
    // }
}
