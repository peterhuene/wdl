//! Implementation of the analysis engine.

use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::mem;
use std::ops::Deref;
use std::path::absolute;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use futures::stream::FuturesUnordered;
use futures::Future;
use futures::StreamExt;
use parking_lot::RwLock;
use path_clean::clean;
use petgraph::algo::has_path_connecting;
use petgraph::algo::DfsSpace;
use petgraph::graph::NodeIndex;
use petgraph::stable_graph::StableDiGraph;
use petgraph::visit::EdgeRef;
use petgraph::visit::Visitable;
use petgraph::Direction;
use reqwest::Client;
use rowan::GreenNode;
use tokio::runtime::Handle;
use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use url::Url;
use wdl_ast::Ast;
use wdl_ast::AstNode;
use wdl_ast::AstToken;
use wdl_ast::Diagnostic;
use wdl_ast::SyntaxNode;
use wdl_ast::Validator;

use crate::rayon::RayonHandle;
use crate::Analyzer;

/// The minimum number of milliseconds between analysis progress reports.
const MINIMUM_PROGRESS_MILLIS: u128 = 50;

/// Represents the identifier of an analyzed document.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum DocumentId {
    /// The identifier is by absolute file path.
    Path(PathBuf),
    /// The identifier is by URI.
    Uri(Url),
}

impl DocumentId {
    /// Makes a document identifier relative to another.
    pub(crate) fn relative_to(base: &DocumentId, id: &str) -> Result<Self> {
        if let Ok(uri) = id.parse() {
            return Ok(Self::Uri(uri));
        }

        match base {
            Self::Path(base) => Ok(Self::Path(clean(
                base.parent().expect("expected a parent").join(id),
            ))),
            Self::Uri(base) => Ok(Self::Uri(base.join(id)?)),
        }
    }
}

impl fmt::Display for DocumentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DocumentId::Path(path) => write!(f, "{}", path.display()),
            DocumentId::Uri(uri) => write!(f, "{}", uri),
        }
    }
}

impl TryFrom<&Path> for DocumentId {
    type Error = anyhow::Error;

    fn try_from(value: &Path) -> Result<Self> {
        Ok(Self::Path(clean(absolute(value).with_context(|| {
            format!(
                "failed to determine the absolute path of `{path}`",
                path = value.display()
            )
        })?)))
    }
}

impl TryFrom<&str> for DocumentId {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        match Url::parse(value) {
            Ok(uri) => Ok(Self::Uri(uri)),
            Err(_) => Self::try_from(Path::new(value)),
        }
    }
}

impl From<Url> for DocumentId {
    fn from(value: Url) -> Self {
        Self::Uri(value)
    }
}

/// Represents a document's diagnostics.
#[derive(Debug)]
pub(crate) enum Diagnostics {
    /// The diagnostics are mutable.
    ///
    /// Diagnostics are mutable while analysis is in progress.
    Mutable(Vec<Diagnostic>),
    /// The diagnostics are immutable
    ///
    /// Diagnostics are immutable once analysis has completed.
    Immutable(Arc<[Diagnostic]>),
}

impl Default for Diagnostics {
    fn default() -> Self {
        Diagnostics::Mutable(Vec::new())
    }
}

impl Deref for Diagnostics {
    type Target = [Diagnostic];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Mutable(diagnostics) => diagnostics,
            Self::Immutable(diagnostics) => diagnostics,
        }
    }
}

impl Diagnostics {
    /// Gets a mutable collection of diagnostics.
    ///
    /// # Panics
    ///
    /// Panics if the diagnostics are not mutable.
    pub(crate) fn as_vec_mut(&mut self) -> &mut Vec<Diagnostic> {
        match self {
            Self::Mutable(diagnostics) => diagnostics,
            Self::Immutable(_) => panic!("diagnostics are not mutable"),
        }
    }

    /// Gets a shareable, immutable reference to the diagnostics.
    ///
    /// # Panics
    ///
    /// Panics if the diagnostics are mutable.
    fn shared(&self) -> &Arc<[Diagnostic]> {
        match self {
            Self::Mutable(_) => panic!("diagnostics are mutable"),
            Self::Immutable(diagnostics) => diagnostics,
        }
    }
}

/// Represents an analyzed document.
#[derive(Debug)]
pub(crate) struct Document {
    /// The identifier of the analyzed document.
    pub(crate) id: Arc<DocumentId>,
    /// The root node of the document.
    ///
    /// If `None`, it means we failed to read the document's source.
    pub(crate) root: Option<GreenNode>,
    /// The error when attempting to read the document's source.
    ///
    /// This is only `Some` if `root` is `None`.
    pub(crate) error: Option<anyhow::Error>,
    /// The diagnostics of the document.
    pub(crate) diagnostics: Diagnostics,
    /// Whether or not this document is a GC root in the document graph.
    ///
    /// A GC root won't be removed from the document graph even if there are no
    /// outgoing edges.
    gc_root: bool,
}

impl Document {
    /// Creates a new empty document.
    fn new(id: Arc<DocumentId>, gc_root: bool) -> Self {
        Self {
            id,
            root: None,
            error: None,
            diagnostics: Diagnostics::Mutable(Vec::new()),
            gc_root,
        }
    }

    /// Creates a new document from the result of a parse.
    fn from_parse(
        id: Arc<DocumentId>,
        root: GreenNode,
        diagnostics: Vec<Diagnostic>,
        gc_root: bool,
    ) -> Self {
        Self {
            id,
            root: Some(root),
            error: None,
            diagnostics: Diagnostics::Mutable(diagnostics),
            gc_root,
        }
    }

    /// Creates a new document from an error attempting to read the document.
    fn from_error(id: Arc<DocumentId>, error: anyhow::Error, gc_root: bool) -> Self {
        Self {
            id,
            root: None,
            error: Some(error),
            diagnostics: Diagnostics::Mutable(Vec::new()),
            gc_root,
        }
    }

    /// Called to complete the analysis on the document.
    pub(crate) fn complete(&mut self) {
        let mut diagnostics = std::mem::take(self.diagnostics.as_vec_mut());
        diagnostics.sort_by(|a, b| match (a.labels().next(), b.labels().next()) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(a), Some(b)) => a.span().start().cmp(&b.span().start()),
        });
        self.diagnostics = Diagnostics::Immutable(diagnostics.into());
    }
}

/// Represents the kind of analysis progress being reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressKind {
    /// The progress is for parsing documents.
    Parsing,
    /// The progress is for analyzing documents.
    Analyzing,
}

impl fmt::Display for ProgressKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parsing => write!(f, "parsing"),
            Self::Analyzing => write!(f, "analyzing"),
        }
    }
}

/// Represents analysis state.
#[derive(Debug, Default)]

pub(crate) struct State {
    /// The document graph being built.
    pub(crate) graph: DocumentGraph,
    /// Represents dependency edges that, if they were added to the document
    /// graph, would form a cycle.
    ///
    /// The first in the pair is the importing node and the second is the
    /// imported node.
    ///
    /// This is used to break import cycles; when analyzing the document, if the
    /// import exists in this set, a diagnostic will be added and the import
    /// otherwise ignored.
    pub(crate) cycles: HashSet<(NodeIndex, NodeIndex)>,
    /// Space for DFS operations on the document graph.
    space: DfsSpace<NodeIndex, <StableDiGraph<Document, ()> as Visitable>::Map>,
}

/// Represents a document graph.
#[derive(Debug, Default)]
pub(crate) struct DocumentGraph {
    /// The inner graph.
    ///
    /// Each node in the graph represents an analyzed file and edges denote
    /// import dependency relationships.
    pub(crate) inner: StableDiGraph<Document, ()>,
    /// Map from document identifier to graph node index.
    indexes: HashMap<Arc<DocumentId>, NodeIndex>,
}

impl DocumentGraph {
    /// Gets a document from the graph.
    pub(crate) fn document(&self, id: &DocumentId) -> Option<(NodeIndex, &Document)> {
        self.indexes
            .get(id)
            .map(|index| (*index, &self.inner[*index]))
    }

    /// Adds a document to the graph.
    ///
    /// If the document with the same identifier exists in the graph, it is
    /// replaced.
    fn add_document(&mut self, document: Document) -> NodeIndex {
        if let Some(index) = self.indexes.get(&document.id) {
            self.inner[*index] = document;
            return *index;
        }

        let id = document.id.clone();
        let index = self.inner.add_node(document);
        let prev = self.indexes.insert(id, index);
        assert!(prev.is_none());
        index
    }

    /// Merges this document graph with the provided one.
    ///
    /// Returns the result of the analysis.
    ///
    /// This also performs a GC on the graph to remove non-rooted nodes that
    /// have no outgoing edges.
    fn merge(&mut self, mut other: Self) -> Vec<AnalysisResult> {
        let mut remapped = HashMap::new();
        let mut results = Vec::new();
        for (id, other_index) in other.indexes {
            let Document {
                id: _,
                root,
                error,
                diagnostics,
                gc_root,
            } = &mut other.inner[other_index];
            match self.indexes.get(&id) {
                Some(index) => {
                    remapped.insert(other_index, *index);

                    // Existing node, so replace the document contents
                    let existing = &mut self.inner[*index];
                    *existing = Document {
                        id,
                        root: mem::take(root),
                        error: mem::take(error),
                        diagnostics: mem::take(diagnostics),
                        gc_root: existing.gc_root | *gc_root,
                    };

                    // If we parsed a local document, add a result for it
                    if existing.root.is_some()
                        && matches!(existing.id.as_ref(), DocumentId::Path(_))
                    {
                        results.push(AnalysisResult::new(existing));
                    }

                    // Remove all edges to this node in self; we'll add the latest edges below.
                    for edge in self.inner.edges(*index).map(|e| e.id()).collect::<Vec<_>>() {
                        self.inner.remove_edge(edge);
                    }
                }
                None => {
                    let document = Document {
                        id: id.clone(),
                        root: mem::take(root),
                        error: mem::take(error),
                        diagnostics: mem::take(diagnostics),
                        gc_root: *gc_root,
                    };

                    // If we parsed a local document, add a result for it
                    if document.root.is_some()
                        && matches!(document.id.as_ref(), DocumentId::Path(_))
                    {
                        results.push(AnalysisResult::new(&document));
                    }

                    // New node, insert it into the graph
                    let index = self.inner.add_node(document);

                    remapped.insert(other_index, index);
                    self.indexes.insert(id, index);
                }
            }
        }

        // Now add the edges for the remapped nodes
        for edge in other.inner.edge_indices() {
            let (from, to) = other.inner.edge_endpoints(edge).expect("edge should exist");
            let from = remapped[&from];
            let to = remapped[&to];
            self.inner.add_edge(from, to, ());
        }

        // Finally, GC any non-gc-root nodes that have no outgoing edges
        let mut gc = Vec::new();
        for node in self.inner.node_indices() {
            if self.inner[node].gc_root {
                continue;
            }

            if self
                .inner
                .edges_directed(node, Direction::Outgoing)
                .next()
                .is_none()
            {
                gc.push(node);
            }
        }

        for node in gc {
            self.inner.remove_node(node);
        }

        results.sort_by(|a, b| a.path.cmp(&b.path));
        results
    }
}

/// Represents the type for progress callbacks.
type ProgressCallback = dyn Fn(ProgressKind, usize, usize) + Send + Sync;

/// Represents a request to perform analysis.
///
/// This request is sent to the analysis queue for processing.
struct AnalysisRequest {
    /// The identifiers of the documents to analyze.
    documents: Vec<Arc<DocumentId>>,
    /// The progress callback to use for the request.
    progress: Option<Box<ProgressCallback>>,
    /// The sender for completing the analysis request.
    completed: oneshot::Sender<Vec<AnalysisResult>>,
}

/// Represents the result of an analysis.
#[derive(Debug)]
pub struct AnalysisResult {
    /// The path to the file that was analyzed.
    path: PathBuf,
    /// The root node of the document.
    ///
    /// This is `None` if the document failed to load.
    root: Option<GreenNode>,
    /// The diagnostics for the document.
    diagnostics: Arc<[Diagnostic]>,
}

impl AnalysisResult {
    /// Constructs a new analysis result for the given document.
    fn new(document: &Document) -> Self {
        Self {
            path: match document.id.as_ref() {
                DocumentId::Path(p) => p.clone(),
                DocumentId::Uri(_) => panic!("analysis result was not for a local path"),
            },
            root: document.root.clone(),
            diagnostics: document.diagnostics.shared().clone(),
        }
    }

    /// Gets the path of the document that was analyzed.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Gets the AST document that was analyzed.
    pub fn root(&self) -> Option<&GreenNode> {
        self.root.as_ref()
    }

    /// Gets the diagnostics associated with the document.
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }
}

/// Represents a Workflow Description Language (WDL) analysis engine.
///
/// By default, analysis parses documents, performs validation checks, resolves
/// imports, and performs type checking.
///
/// Each analysis operation is processed in order of request; however, the
/// individual parsing, resolution, and analysis of documents is performed
/// across a thread pool.
#[derive(Debug)]
pub struct AnalysisEngine {
    /// The document graph.
    graph: Arc<RwLock<DocumentGraph>>,
    /// The sender for sending analysis requests.
    sender: UnboundedSender<AnalysisRequest>,
    /// The join handle of the queue task.
    queue: JoinHandle<()>,
}

impl AnalysisEngine {
    /// Creates a new analysis engine using a default validator.
    ///
    /// The engine must be constructed from the context of a Tokio runtime.
    pub fn new() -> Result<Self> {
        let graph: Arc<RwLock<DocumentGraph>> = Default::default();
        let (sender, queue) = Self::spawn_analysis_queue_task(graph.clone(), None);
        Ok(Self {
            graph,
            sender,
            queue,
        })
    }

    /// Creates a new analysis engine with the given function that produces a
    /// validator to use.
    ///
    /// The provided function will be called once per worker thread to
    /// initialize a thread-local validator.
    ///
    /// The engine must be constructed from the context of a Tokio runtime.
    pub fn new_with_validator<V>(validator: V) -> Result<Self>
    where
        V: Fn() -> Validator + Send + Sync + 'static,
    {
        let graph: Arc<RwLock<DocumentGraph>> = Default::default();
        let (sender, queue) =
            Self::spawn_analysis_queue_task(graph.clone(), Some(Arc::new(validator)));
        Ok(Self {
            graph,
            sender,
            queue,
        })
    }

    /// Analyzes the given file system path.
    ///
    /// If the path is a directory, the directory will be recursively searched
    /// for files with a `.wdl` extension to analyze.
    ///
    /// Otherwise, a single file is analyzed.
    ///
    /// # Panics
    ///
    /// Panics if the engine has been shut down.
    pub async fn analyze(&self, path: &Path) -> Vec<AnalysisResult> {
        let documents = Self::find_documents(path).await;
        if documents.is_empty() {
            log::info!(
                "no WDL documents were found for path `{path}`",
                path = path.display()
            );
            return Vec::new();
        }

        let (tx, rx) = oneshot::channel();
        self.sender
            .send(AnalysisRequest {
                documents,
                progress: None,
                completed: tx,
            })
            .expect("failed to send analysis request");

        rx.await.expect("failed to receive analysis results")
    }

    /// Analyzes the given file system path and reports progress to the given
    /// callback.
    ///
    /// If the path is a directory, the directory will be recursively searched
    /// for files with a `.wdl` extension to analyze.
    ///
    /// Otherwise, a single file is analyzed.
    ///
    /// Progress is reported to the provided callback function with a minimum
    /// 50ms interval.
    ///
    /// # Panics
    ///
    /// Panics if the engine has been shut down.
    pub async fn analyze_with_progress<F>(&self, path: &Path, progress: F) -> Vec<AnalysisResult>
    where
        F: Fn(ProgressKind, usize, usize) + Send + Sync + 'static,
    {
        let documents = Self::find_documents(path).await;
        if documents.is_empty() {
            log::info!(
                "no WDL documents were found for path `{path}`",
                path = path.display()
            );
            return Vec::new();
        }

        let (tx, rx) = oneshot::channel();
        self.sender
            .send(AnalysisRequest {
                documents,
                progress: Some(Box::new(progress)),
                completed: tx,
            })
            .expect("failed to send analysis request");

        rx.await.expect("failed to receive analysis results")
    }

    /// Gets a previous analysis result for a file.
    ///
    /// Returns `None` if the file has not been analyzed yet.
    pub fn result(&self, path: &Path) -> Option<AnalysisResult> {
        let id = DocumentId::try_from(path).ok()?;
        let graph = self.graph.read();
        let index = graph.indexes.get(&id)?;
        Some(AnalysisResult::new(&graph.inner[*index]))
    }

    /// Shuts down the engine and waits for the queue task to complete.
    ///
    /// Calling the analyze methods after this method will cause them to panic.
    pub async fn shutdown(self) {
        drop(self.sender);
        self.queue.await.expect("expected the queue to shut down");
    }

    /// Spawns the analysis queue task.
    fn spawn_analysis_queue_task(
        graph: Arc<RwLock<DocumentGraph>>,
        validator: Option<Arc<dyn Fn() -> Validator + Send + Sync>>,
    ) -> (UnboundedSender<AnalysisRequest>, JoinHandle<()>) {
        let (tx, rx) = unbounded_channel::<AnalysisRequest>();
        let handle = tokio::spawn(Self::process_analysis_queue(graph, validator, rx));
        (tx, handle)
    }

    /// Processes the analysis queue.
    ///
    /// The queue task processes analysis requests in the order of insertion
    /// into the queue.
    ///
    /// It is also the only writer to the shared document graph.
    async fn process_analysis_queue(
        graph: Arc<RwLock<DocumentGraph>>,
        validator: Option<Arc<dyn Fn() -> Validator + Send + Sync>>,
        mut receiver: UnboundedReceiver<AnalysisRequest>,
    ) {
        log::info!("analysis queue has started");

        let client = Client::default();
        while let Some(request) = receiver.recv().await {
            log::info!(
                "received request to analyze {count} document(s)",
                count = request.documents.len()
            );

            // We start by populating the parse set with the request documents
            // After each parse set completes, we search for imports to add to the parse set
            // and continue until the parse set is empty; once the graph is built, we spawn
            // analysis tasks to process every node in the graph.
            let start = Instant::now();
            let mut state = State::default();
            let mut parse_set = request.documents.into_iter().collect::<HashSet<_>>();
            let mut requested = true;
            let handle = Handle::current();
            while !parse_set.is_empty() {
                let tasks = parse_set
                    .iter()
                    .map(|id| {
                        Self::spawn_parse_task(&handle, &client, &validator, id.clone(), requested)
                    })
                    .collect::<FuturesUnordered<_>>();

                // The remaining files to parse were not part of the request
                requested = false;

                let parsed = Self::await_with_progress::<_, _, Vec<_>>(
                    ProgressKind::Parsing,
                    tasks,
                    &request.progress,
                )
                .await;

                parse_set.clear();
                (state, parse_set) = Self::add_import_dependencies(state, parsed, parse_set).await;
            }

            let total = state.graph.inner.node_count();
            let state = Self::spawn_analysis_tasks(state, &request.progress).await;

            // Spawn a task for merging the graph as this takes a lock
            let graph = graph.clone();
            let results = RayonHandle::spawn(move || {
                log::info!("merging document graphs");
                let mut graph = graph.write();
                graph.merge(state.graph)
            })
            .await;

            log::info!(
                "analysis request completed with {total} document(s) analyzed in {elapsed:?}",
                elapsed = start.elapsed()
            );

            request
                .completed
                .send(results)
                .expect("failed to send analysis results");
        }

        log::info!("analysis queue has shut down");
    }

    /// Finds documents for the given path.
    ///
    /// If the path is a directory, it is searched for `.wdl` files.
    ///
    /// Otherwise, returns a single identifier for the given path.
    async fn find_documents(path: &Path) -> Vec<Arc<DocumentId>> {
        if path.is_dir() {
            let pattern = format!("{path}/**/*.wdl", path = path.display());
            return RayonHandle::spawn(move || {
                let options = glob::MatchOptions {
                    case_sensitive: true,
                    require_literal_separator: false,
                    require_literal_leading_dot: true,
                };

                match glob::glob_with(&pattern, options) {
                    Ok(paths) => paths
                        .filter_map(|p| match p {
                            Ok(path) => Some(Arc::new(DocumentId::try_from(path.as_path()).ok()?)),
                            Err(e) => {
                                log::error!("error while searching for WDL documents: {e}");
                                None
                            }
                        })
                        .collect(),
                    Err(e) => {
                        log::error!("error while searching for WDL documents: {e}");
                        Vec::new()
                    }
                }
            })
            .await;
        }

        DocumentId::try_from(path)
            .map(|id| vec![Arc::new(id)])
            .unwrap_or_default()
    }

    /// Awaits the given set of futures while providing progress to the given
    /// callback.
    async fn await_with_progress<T, R, C>(
        kind: ProgressKind,
        tasks: FuturesUnordered<T>,
        progress: &Option<Box<ProgressCallback>>,
    ) -> C
    where
        T: Future<Output = R>,
        C: Extend<R> + Default,
    {
        if tasks.is_empty() {
            return Default::default();
        }

        let total = tasks.len();
        if let Some(progress) = &progress {
            progress(kind, 0, total);
        }

        let mut completed = 0;
        let mut last_progress = Instant::now();
        let collection = tasks
            .map(|r| {
                completed += 1;

                if let Some(progress) = progress {
                    let now = Instant::now();
                    if completed < total
                        && (now - last_progress).as_millis() > MINIMUM_PROGRESS_MILLIS
                    {
                        log::info!("{completed} out of {total} {kind} task(s) have completed");
                        last_progress = now;
                        progress(kind, completed, total);
                    }
                }

                r
            })
            .collect()
            .await;

        log::info!("{total} {kind} task(s) have completed");
        if let Some(progress) = &progress {
            progress(kind, total, total);
        }

        collection
    }

    /// Spawns a parse task on a rayon thread.
    fn spawn_parse_task(
        handle: &Handle,
        client: &Client,
        validator: &Option<Arc<dyn Fn() -> Validator + Send + Sync>>,
        id: Arc<DocumentId>,
        requested: bool,
    ) -> RayonHandle<Document> {
        thread_local! {
            static VALIDATOR: RefCell<Option<Validator>> = const { RefCell::new(None) };
        }

        let handle = handle.clone();
        let client = client.clone();
        let validator = validator.clone();
        RayonHandle::spawn(move || {
            VALIDATOR.with_borrow_mut(|v| {
                let validator = v.get_or_insert_with(|| validator.map(|v| v()).unwrap_or_default());
                match Self::parse(&handle, &client, Some(validator), &id) {
                    Ok((root, diagnostics)) => {
                        Document::from_parse(id, root, diagnostics, requested)
                    }
                    Err(e) => {
                        log::warn!("{e:#}");
                        Document::from_error(id, e, requested)
                    }
                }
            })
        })
    }

    /// Parses the given document by URI.
    ///
    /// If the URI is `http` or `https` scheme, it fetches the source from the
    /// network.
    ///
    /// If the URI is `file` scheme, it reads the file from the local file
    /// system.
    ///
    /// Returns the root node and diagnostics upon success or a single document
    /// if there was a problem with accessing the document's source.
    fn parse(
        tokio: &Handle,
        client: &Client,
        validator: Option<&mut Validator>,
        id: &DocumentId,
    ) -> Result<(GreenNode, Vec<Diagnostic>)> {
        let source = match id {
            DocumentId::Path(path) => fs::read_to_string(path)?,
            DocumentId::Uri(uri) => match uri.scheme() {
                "https" | "http" => Self::download_source(tokio, client, uri)?,
                "file" => {
                    let path = uri
                        .to_file_path()
                        .map_err(|_| anyhow!("invalid file URI `{uri}`"))?;
                    log::info!("reading document `{path}`", path = path.display());
                    fs::read_to_string(&path)?
                }
                scheme => {
                    bail!("unsupported URI scheme `{scheme}`");
                }
            },
        };

        Ok(Self::parse_source(id, &source, validator))
    }

    /// Parses the given source and validates the result with the given
    /// validator.
    fn parse_source(
        id: &DocumentId,
        source: &str,
        validator: Option<&mut Validator>,
    ) -> (GreenNode, Vec<Diagnostic>) {
        let start = Instant::now();
        let (document, mut diagnostics) = wdl_ast::Document::parse(source);
        if let Some(validator) = validator {
            diagnostics.extend(validator.validate(&document).err().unwrap_or_default());
        }
        log::info!("parsing of `{id}` completed in {:?}", start.elapsed());
        (document.syntax().green().into(), diagnostics)
    }

    /// Downloads the source of a `http` or `https` scheme URI.
    ///
    /// This makes a request on the provided tokio runtime to download the
    /// source.
    fn download_source(tokio: &Handle, client: &Client, uri: &Url) -> Result<String> {
        /// The timeout for downloading the source, in seconds.
        const TIMEOUT_IN_SECS: u64 = 30;

        log::info!("downloading source from `{uri}`");

        // TODO: we should be caching these responses on disk somewhere
        tokio.block_on(async {
            let resp = client
                .get(uri.as_str())
                .timeout(Duration::from_secs(TIMEOUT_IN_SECS))
                .send()
                .await?;

            let code = resp.status();
            if !code.is_success() {
                bail!("server returned HTTP status {code}");
            }

            resp.text().await.context("failed to read response body")
        })
    }

    /// Adds import dependencies of parsed documents to the state.
    ///
    /// This will add empty nodes to the graph for any missing imports and
    /// populate the parse set with documents that need to be parsed.
    async fn add_import_dependencies(
        mut state: State,
        parsed: Vec<Document>,
        mut parse_set: HashSet<Arc<DocumentId>>,
    ) -> (State, HashSet<Arc<DocumentId>>) {
        RayonHandle::spawn(move || {
            for document in parsed {
                // Add the newly parsed document to the graph; if the document was previously
                // added as an import dependency, it is replaced with the newly parsed document
                let id = document.id.clone();
                state.graph.add_document(document);

                let (doc_index, document) = state
                    .graph
                    .document(&id)
                    .expect("document was just added to the state");
                let root = match &document.root {
                    Some(root) => root,
                    None => continue,
                };

                match wdl_ast::Document::cast(SyntaxNode::new_root(root.clone()))
                    .expect("root should cast")
                    .ast()
                {
                    Ast::Unsupported => {}
                    Ast::V1(ast) => {
                        for import in ast.imports() {
                            let text = match import.uri().text() {
                                Some(text) => text,
                                None => continue,
                            };

                            let import_id = match DocumentId::relative_to(&id, text.as_str()) {
                                Ok(id) => Arc::new(id),
                                Err(_) => continue,
                            };

                            match state.graph.document(&import_id) {
                                Some((dep_index, _)) => {
                                    // The dependency is already in the graph, so add a dependency
                                    // edge; however, we must detect a cycle before doing so
                                    if has_path_connecting(
                                        &state.graph.inner,
                                        doc_index,
                                        dep_index,
                                        Some(&mut state.space),
                                    ) {
                                        // Adding the edge would cause a cycle, so record the cycle
                                        // instead
                                        log::info!(
                                            "an import cycle was detected between `{id}` and \
                                             `{import_id}`"
                                        );
                                        state.cycles.insert((doc_index, dep_index));
                                    } else {
                                        // The edge won't cause a cycle, so add it
                                        log::info!(
                                            "updating dependency edge from `{id}` to `{import_id}`"
                                        );
                                        state.graph.inner.update_edge(dep_index, doc_index, ());
                                    }
                                }
                                None => {
                                    // The dependency isn't in the graph; add a new node and
                                    // dependency edge
                                    log::info!(
                                        "updating dependency edge from `{id}` to `{import_id}` \
                                         (added to parse queue)"
                                    );
                                    let dep_index = state
                                        .graph
                                        .add_document(Document::new(import_id.clone(), false));
                                    state.graph.inner.update_edge(dep_index, doc_index, ());
                                    parse_set.insert(import_id);
                                }
                            }
                        }
                    }
                }
            }

            (state, parse_set)
        })
        .await
    }

    /// Spawns analysis tasks.
    ///
    /// Analysis tasks are spawned in topological order.
    async fn spawn_analysis_tasks(state: State, progress: &Option<Box<ProgressCallback>>) -> State {
        // As we're going to be analyzing on multiple threads, wrap the state with a
        // `RwLock`.
        let mut state = Arc::new(RwLock::new(state));
        let mut remaining: Option<StableDiGraph<Arc<DocumentId>, ()>> = None;
        let mut set = Vec::new();
        while remaining
            .as_ref()
            .map(|g| g.node_count() > 0)
            .unwrap_or(true)
        {
            (state, remaining, set) = RayonHandle::spawn(move || {
                // Insert a copy of the graph where we just map the nodes to the document
                // identifiers; we need a copy as we are going to be removing nodes from the
                // graph as we process them in topological order
                let g = remaining.get_or_insert_with(|| {
                    state.read().graph.inner.map(|_, n| n.id.clone(), |_, _| ())
                });

                // Build a set of nodes with no incoming edges
                set.clear();
                for node in g.node_indices() {
                    if g.edges_directed(node, Direction::Incoming).next().is_none() {
                        set.push(node);
                    }
                }

                // Remove the nodes we're about to analyze from the "remaining" graph
                // This also removes the outgoing edges from those nodes
                for index in &set {
                    g.remove_node(*index);
                }

                (state, remaining, set)
            })
            .await;

            let tasks = set
                .iter()
                .map(|index| {
                    let index = *index;
                    let state = state.clone();
                    RayonHandle::spawn(move || {
                        let analyzer = Analyzer::new(state, index);
                        analyzer.analyze();
                    })
                })
                .collect::<FuturesUnordered<_>>();

            Self::await_with_progress::<_, _, Vec<_>>(ProgressKind::Analyzing, tasks, progress)
                .await;
        }

        // We're finished with the tasks; there should be no outstanding references to
        // the state
        Arc::into_inner(state)
            .expect("only one reference should remain")
            .into_inner()
    }
}

/// Constant that asserts `AnalysisEngine` is `Send + Sync`; if not, it fails to
/// compile.
const _: () = {
    /// Helper that will fail to compile if T is not `Send + Sync`.
    const fn _assert<T: Send + Sync>() {}
    _assert::<AnalysisEngine>();
};
