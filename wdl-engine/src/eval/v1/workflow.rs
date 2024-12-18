//! Implementation of evaluation for V1 workflows.

use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::mem;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use anyhow::anyhow;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use itertools::Itertools;
use petgraph::Direction;
use petgraph::graph::DiGraph;
use petgraph::graph::NodeIndex;
use petgraph::visit::Bfs;
use petgraph::visit::EdgeRef;
use tracing::debug;
use tracing::info;
use wdl_analysis::diagnostics::type_is_not_array;
use wdl_analysis::diagnostics::unknown_name;
use wdl_analysis::document::Document;
use wdl_analysis::document::Task;
use wdl_analysis::document::Workflow;
use wdl_analysis::eval::v1::WorkflowGraphBuilder;
use wdl_analysis::eval::v1::WorkflowGraphNode;
use wdl_analysis::types::ArrayType;
use wdl_analysis::types::Optional;
use wdl_analysis::types::PrimitiveTypeKind;
use wdl_analysis::types::Type;
use wdl_analysis::types::TypeEq;
use wdl_analysis::types::Types;
use wdl_ast::Ast;
use wdl_ast::AstNode;
use wdl_ast::AstNodeExt;
use wdl_ast::AstToken;
use wdl_ast::Diagnostic;
use wdl_ast::Ident;
use wdl_ast::Severity;
use wdl_ast::SupportedVersion;
use wdl_ast::SyntaxNode;
use wdl_ast::TokenStrHash;
use wdl_ast::v1::ConditionalStatement;
use wdl_ast::v1::Decl;
use wdl_ast::v1::ScatterStatement;

use crate::Array;
use crate::Coercible;
use crate::Engine;
use crate::EvaluationContext;
use crate::EvaluationResult;
use crate::Outputs;
use crate::Scope;
use crate::ScopeIndex;
use crate::ScopeRef;
use crate::Value;
use crate::WorkflowInputs;
use crate::diagnostics::if_conditional_mismatch;
use crate::diagnostics::output_evaluation_failed;
use crate::diagnostics::runtime_type_mismatch;
use crate::v1::ExprEvaluator;

/// The index of a workflow's root scope.
const ROOT_SCOPE_INDEX: ScopeIndex = ScopeIndex::new(0);

/// The index of a workflow's output scope.
const OUTPUT_SCOPE_INDEX: ScopeIndex = ScopeIndex::new(1);

/// A hidden variable in conditional scopes that record the result of the
/// conditional expression. The name is intentionally chosen to not be a valid
/// WDL identifier.
const CONDITIONAL_VAR_NAME: &str = "$cond";

/// Used to evaluate expressions in workflows.
struct WorkflowEvaluationContext<'a> {
    /// The associated evaluation engine.
    engine: &'a mut Engine,
    /// The workflow evaluation state.
    state: &'a State<'a>,
    /// The current evaluation scope.
    scope: ScopeIndex,
}

impl<'a> WorkflowEvaluationContext<'a> {
    /// Constructs a new expression evaluation context.
    pub fn new(engine: &'a mut Engine, state: &'a State<'a>, scope: ScopeIndex) -> Self {
        Self {
            engine,
            state,
            scope,
        }
    }
}

impl EvaluationContext for WorkflowEvaluationContext<'_> {
    fn version(&self) -> SupportedVersion {
        self.state
            .document
            .version()
            .expect("document should have a version")
    }

    fn types(&self) -> &Types {
        self.engine.types()
    }

    fn types_mut(&mut self) -> &mut Types {
        self.engine.types_mut()
    }

    fn resolve_name(&self, name: &Ident) -> Result<Value, Diagnostic> {
        ScopeRef::new(&self.state.scopes, self.scope)
            .lookup(name.as_str())
            .cloned()
            .ok_or_else(|| unknown_name(name.as_str(), name.span()))
    }

    fn resolve_type_name(&mut self, name: &Ident) -> Result<Type, Diagnostic> {
        self.engine.resolve_type_name(self.state.document, name)
    }

    fn work_dir(&self) -> &Path {
        &self.state.work_dir
    }

    fn temp_dir(&self) -> &Path {
        &self.state.temp_dir
    }

    fn stdout(&self) -> Option<&Value> {
        None
    }

    fn stderr(&self) -> Option<&Value> {
        None
    }

    fn task(&self) -> Option<&Task> {
        None
    }

    fn document_types(&self) -> &Types {
        self.state.document.types()
    }
}

/// Represents workflow evaluation state.
struct State<'a> {
    /// The document containing the workflow being evaluated.
    document: &'a Document,
    /// The workflow being evaluated.
    workflow: &'a Workflow,
    /// The scopes defined in workflow evaluation.
    ///
    /// The first scope is always the root scope and the second scope is always
    /// the output scope.
    scopes: Vec<Scope>,
    /// Indexes into `scopes` that are currently "free".
    ///
    /// This helps reduce memory usage by reusing scopes from scatter
    /// statements.
    free_scopes: Vec<usize>,
    /// The workflow evaluation working directory path.
    work_dir: PathBuf,
    /// The workflow evaluation temp directory path.
    temp_dir: PathBuf,
}

impl<'a> State<'a> {
    /// Constructs a new workflow evaluation state.
    fn new(document: &'a Document, workflow: &'a Workflow, root: &Path) -> anyhow::Result<Self> {
        let work_dir = root.join("work");

        // Create the temp directory now as it may be needed for workflow evaluation
        let temp_dir = root.join("tmp");
        fs::create_dir_all(&temp_dir).with_context(|| {
            format!(
                "failed to create directory `{path}`",
                path = temp_dir.display()
            )
        })?;

        Ok(Self {
            document,
            workflow,
            scopes: vec![Scope::new(None), Scope::new(Some(ROOT_SCOPE_INDEX))],
            free_scopes: Default::default(),
            work_dir,
            temp_dir,
        })
    }

    /// Allocates a new scope and returns the scope index.
    fn alloc_scope(&mut self, parent: Option<ScopeIndex>) -> ScopeIndex {
        if let Some(index) = self.free_scopes.pop() {
            if let Some(parent) = parent {
                self.scopes[index].set_parent(parent);
            }

            return index.into();
        }

        let index = self.scopes.len();
        self.scopes.push(Scope::new(parent));
        index.into()
    }

    /// Frees a scope that is no longer used.
    fn free_scope(&mut self, index: ScopeIndex) {
        self.scopes[index.0].reset();
        self.free_scopes.push(index.0);
    }
}

/// Represents a subgraph of a workflow evaluation graph.
///
/// The subgraph stores relevant node indexes mapped to their current indegrees.
#[derive(Debug, Clone)]
struct Subgraph(HashMap<NodeIndex, usize>);

impl Subgraph {
    /// Constructs a new subgraph from the given graph.
    ///
    /// Initially, the subgraph will represent the entire graph, but will be
    /// reduced as nodes are processed.
    fn new_root(graph: &DiGraph<WorkflowGraphNode, ()>) -> Self {
        let mut map = HashMap::with_capacity(graph.node_count());
        for index in graph.node_indices() {
            map.insert(
                index,
                graph.edges_directed(index, Direction::Incoming).count(),
            );
        }

        Self(map)
    }

    /// Constructs a new subgraph for a scatter given the scatter's entry and
    /// exit nodes.
    ///
    /// This works by "stealing" the nodes between the entry and exit nodes from
    /// the parent subgraph.
    ///
    /// The exit node of the parent graph is reduced to an indegree of 1; only
    /// the connection between the entry and exit node remains.
    fn new_scatter(
        graph: &DiGraph<WorkflowGraphNode, ()>,
        parent: &mut HashMap<NodeIndex, usize>,
        entry: NodeIndex,
        exit: NodeIndex,
    ) -> Self {
        let mut map = HashMap::new();
        let mut bfs = Bfs::new(graph, entry);
        while let Some(node) = {
            // Don't BFS into the exit node
            if bfs.stack.front() == Some(&exit) {
                bfs.stack.pop_front();
            }
            bfs.next(&graph)
        } {
            // Don't include the entry or exit nodes in the subgraph
            if node == entry || node == exit {
                continue;
            }

            // Steal the node from the parent subgraph
            let prev = map.insert(
                node,
                parent.remove(&node).expect("node should exist in parent"),
            );
            assert!(prev.is_none());
        }

        // Decrement the indegree the nodes connected to the entry as we're not
        // including it in the subgraph
        for edge in graph.edges_directed(entry, Direction::Outgoing) {
            if edge.target() != exit {
                *map.get_mut(&edge.target()).expect("should be in subgraph") -= 1;
            }
        }

        // Set the parent's exit node to an indegree of 1
        *parent.get_mut(&exit).expect("should have exit node") = 1;

        Self(map)
    }

    /// Creates subgraphs for each scatter node within this subgraph.
    ///
    /// The provided callback is called for every contained scatter subgraph.
    ///
    /// This subgraph is modified to replace any direct scatter subgraphs with
    /// only the scatter entry and exit nodes.
    fn scatter_subgraphs<F>(&mut self, graph: &DiGraph<WorkflowGraphNode, ()>, cb: &mut F)
    where
        F: FnMut(NodeIndex, Subgraph),
    {
        for index in graph.node_indices() {
            if !self.0.contains_key(&index) {
                continue;
            }

            if let WorkflowGraphNode::Scatter(_, exit) = &graph[index] {
                let mut subgraph = Subgraph::new_scatter(graph, &mut self.0, index, *exit);
                subgraph.scatter_subgraphs(graph, cb);
                cb(index, subgraph);
            }
        }
    }

    /// Removes the given node from the subgraph.
    ///
    /// # Panics
    ///
    /// Panics if the node's indegree is not 0.
    fn remove_node(&mut self, graph: &DiGraph<WorkflowGraphNode, ()>, node: NodeIndex) {
        let indegree = self.0.remove(&node);
        assert_eq!(
            indegree,
            Some(0),
            "removed a node with an indegree greater than 0"
        );

        // Decrement the indegrees of connected nodes
        for edge in graph.edges_directed(node, Direction::Outgoing) {
            *self
                .0
                .get_mut(&edge.target())
                .expect("should have target node") -= 1;
        }
    }
}

/// Represents the state machine used for evaluating a workflow.
///
/// The state machine is responsible for processing evaluation graph nodes and
/// awaiting calls.
struct StateMachine<'a> {
    /// The associated evaluation engine.
    engine: &'a mut Engine,
    /// The workflow evaluation graph.
    graph: &'a DiGraph<WorkflowGraphNode, ()>,
    /// The root subgraph.
    ///
    /// Initially, the root subgraph contains every node of the evaluation
    /// graph.
    ///
    /// The scatter subgraphs are then split out from the root subgraph; only
    /// the entry and exit nodes of the top-level scatters will remain.
    root: Subgraph,
    /// The map of scatter node entry indexes to the scatter subgraphs.
    subgraphs: Arc<HashMap<NodeIndex, Subgraph>>,
    /// The set of in-progress scatters.
    scatters: Vec<Scatter>,
    /// The list of free scatter slots.
    free_scatters: Vec<usize>,
}

impl<'a> StateMachine<'a> {
    fn new(engine: &'a mut Engine, graph: &'a DiGraph<WorkflowGraphNode, ()>) -> Self {
        let mut root = Subgraph::new_root(graph);

        // Create subgraphs for every scatter node in the graph
        let mut subgraphs = HashMap::new();
        root.scatter_subgraphs(graph, &mut |entry, subgraph| {
            subgraphs.insert(entry, subgraph);
        });

        Self {
            engine,
            graph,
            root,
            subgraphs: Arc::new(subgraphs),
            scatters: Default::default(),
        }
    }

    /// Runs the state machine to completion.
    async fn run(mut self, mut state: State<'a>, inputs: &WorkflowInputs) -> EvaluationResult<()> {
        // Stores the in-progress calls
        let mut calls = FuturesUnordered::new();
        // The set of nodes being processed
        let mut processing = Vec::new();
        // The set of nodes being awaited on
        let mut awaiting = HashSet::new();
        // The set of in-progress scatters
        let mut scatters: Vec<Scatter> = Vec::new();
        // The scopes associated with an AST node
        let mut scopes: HashMap<SyntaxNode, Vec<ScopeIndex>> = HashMap::new();

        while !self.root.0.is_empty() {
            // Add nodes with indegree 0 that we aren't already waiting on
            // This is across the root subgraph as well as all in-progress scatter subgraphs
            processing.extend(
                self.root
                    .0
                    .iter()
                    .filter_map(|(node, count)| {
                        if *count == 0 && !awaiting.contains(node) {
                            Some((None, *node))
                        } else {
                            None
                        }
                    })
                    .chain(scatters.iter_mut().enumerate().flat_map(|(i, s)| {
                        s.ready(
                            &mut state,
                            &awaiting,
                            &scopes[&s.variable.syntax().parent().expect("should have parent")],
                        )
                        .map(move |node| (Some(i), node))
                    })),
            );

            // If no graph nodes can be processed, await on calls
            if processing.is_empty() {
                let (scatter, index) = calls.next().await.expect("should have a future to wait on");
                match &self.graph[index] {
                    WorkflowGraphNode::Call(call) => {
                        debug!(
                            "call `{name}` has completed; removing from evaluation graph",
                            name = call
                                .alias()
                                .map(|a| a.name())
                                .unwrap_or_else(|| call.target().names().last().unwrap())
                                .as_str()
                        );
                    }
                    _ => unreachable!(),
                }

                awaiting.remove(&index);
                match scatter {
                    Some(i) => {
                        let scatter: &mut Scatter = &mut scatters[i];
                        scatter.current.remove_node(self.graph, index);
                        if scatter.completed() {
                            awaiting.remove(&scatter.exit);
                        }
                    }
                    None => self.root.remove_node(self.graph, index),
                }

                continue;
            }

            // Process the node now or push a future for later completion
            for (scatter, node) in processing.iter().copied() {
                match &self.graph[node] {
                    WorkflowGraphNode::Input(decl) => {
                        self.evaluate_input(&mut state, decl, inputs)?;
                    }
                    WorkflowGraphNode::Decl(decl) => {
                        self.evaluate_decl(
                            &mut state,
                            scopes
                                .get(&decl.syntax().parent().expect("should have parent"))
                                .map(Vec::as_slice)
                                .unwrap_or(&[ROOT_SCOPE_INDEX])
                                .iter()
                                .copied(),
                            decl,
                        )?;
                    }
                    WorkflowGraphNode::Output(decl) => {
                        self.evaluate_output(&mut state, decl)?;
                    }
                    // WorkflowGraphNode::Conditional(stmt) => {
                    //     self.evaluate_conditional(&mut state, &mut scope_indexes, stmt)?;
                    // }
                    WorkflowGraphNode::Scatter(stmt, exit) => {
                        self.evaluate_scatter(&mut state, &mut scope_indexes, stmt)?;
                    }
                    WorkflowGraphNode::Call(call) => {
                        calls.push(async move { (scatter, node) });
                        awaiting.insert(node);
                    }
                    // WorkflowGraphNode::ExitConditional(stmt) => {
                    //     self.evaluate_conditional_exit(&mut state, &mut scope_indexes, stmt)?
                    // }
                    // WorkflowGraphNode::ExitScatter(stmt) => {
                    //     self.evaluate_scatter_exit(&mut state, &mut scope_indexes, stmt)?;
                    // }
                    _ => {}
                }
            }

            // Remove nodes that have completed from the relevant subgraphs
            for (scatter, node) in processing.drain(..) {
                if awaiting.contains(&node) {
                    continue;
                }

                match scatter {
                    Some(i) => {
                        let scatter = &mut scatters[i];
                        scatter.current.remove_node(self.graph, node);
                        if scatter.completed() {
                            awaiting.remove(&scatter.exit);
                        }
                    }
                    None => self.root.remove_node(self.graph, node),
                }
            }
        }

        Ok(())
    }

    fn alloc_scatter(&mut self) -> usize {
        if let Some(index) = self.free_scatters.pop() {
            return index;
        }

        let index = self.scatters.len();
        self.scatters.push()
    }

    /// Evaluates a workflow input.
    fn evaluate_input(
        &mut self,
        state: &mut State<'_>,
        decl: &Decl,
        inputs: &WorkflowInputs,
    ) -> EvaluationResult<()> {
        let name = decl.name();
        let decl_ty = decl.ty();
        let ty = self.engine.convert_ast_type_v1(state.document, &decl_ty)?;

        let (value, span) = match inputs.get(name.as_str()) {
            Some(input) => (input.clone(), name.span()),
            None => {
                if let Some(expr) = decl.expr() {
                    debug!(
                        "evaluating input `{name}` for workflow `{workflow}` in `{uri}`",
                        name = name.as_str(),
                        workflow = state.workflow.name(),
                        uri = state.document.uri(),
                    );

                    let mut evaluator = ExprEvaluator::new(WorkflowEvaluationContext::new(
                        self.engine,
                        state,
                        ROOT_SCOPE_INDEX,
                    ));
                    let value = evaluator.evaluate_expr(&expr)?;
                    (value, expr.span())
                } else {
                    assert!(decl.ty().is_optional(), "type should be optional");
                    (Value::None, name.span())
                }
            }
        };

        let value = value.coerce(self.engine.types_mut(), ty).map_err(|e| {
            runtime_type_mismatch(self.engine.types(), e, ty, name.span(), value.ty(), span)
        })?;

        state.scopes[ROOT_SCOPE_INDEX.0].insert(name.as_str(), value);
        Ok(())
    }

    /// Evaluates a workflow private declaration.
    fn evaluate_decl(
        &mut self,
        state: &mut State<'_>,
        scopes: impl Iterator<Item = ScopeIndex>,
        decl: &Decl,
    ) -> EvaluationResult<()> {
        let name = decl.name();
        debug!(
            "evaluating private declaration `{name}` for workflow `{workflow}` in `{uri}`",
            name = name.as_str(),
            workflow = state.workflow.name(),
            uri = state.document.uri(),
        );

        let decl_ty = decl.ty();
        let ty = self.engine.convert_ast_type_v1(state.document, &decl_ty)?;

        // Evaluate the declaration for every scope associated with the decl's parent
        // node
        for scope in scopes {
            // Don't evaluate if a parent scope was introduced by a conditional statement
            // that evaluated to false
            if !ScopeRef::new(&state.scopes, scope)
                .lookup(CONDITIONAL_VAR_NAME)
                .and_then(|v| v.as_boolean())
                .unwrap_or(true)
            {
                continue;
            }

            let mut evaluator =
                ExprEvaluator::new(WorkflowEvaluationContext::new(self.engine, state, scope));

            let expr = decl.expr().expect("private decls should have expressions");
            let value = evaluator.evaluate_expr(&expr)?;
            let value = value.coerce(self.engine.types_mut(), ty).map_err(|e| {
                runtime_type_mismatch(
                    self.engine.types(),
                    e,
                    ty,
                    name.span(),
                    value.ty(),
                    expr.span(),
                )
            })?;

            state.scopes[scope.0].insert(name.as_str(), value);
        }

        Ok(())
    }

    /// Evaluates a workflow output.
    fn evaluate_output(&mut self, state: &mut State<'_>, decl: &Decl) -> EvaluationResult<()> {
        let name = decl.name();
        debug!(
            "evaluating output `{name}` for workflow `{workflow}` in `{uri}`",
            name = name.as_str(),
            workflow = state.workflow.name(),
            uri = state.document.uri()
        );

        let decl_ty = decl.ty();
        let ty = self.engine.convert_ast_type_v1(state.document, &decl_ty)?;
        let mut evaluator = ExprEvaluator::new(WorkflowEvaluationContext::new(
            self.engine,
            state,
            OUTPUT_SCOPE_INDEX,
        ));

        let expr = decl.expr().expect("outputs should have expressions");
        let value = evaluator.evaluate_expr(&expr)?;

        // First coerce the output value to the expected type
        let mut value = value.coerce(self.engine.types(), ty).map_err(|e| {
            runtime_type_mismatch(
                self.engine.types(),
                e,
                ty,
                name.span(),
                value.ty(),
                expr.span(),
            )
        })?;

        // Finally, join any paths with the working directory, checking for existence
        value
            .join_paths(self.engine.types(), &state.work_dir, true, ty.is_optional())
            .map_err(|e| output_evaluation_failed(e, state.workflow.name(), false, &name))?;

        state.scopes[OUTPUT_SCOPE_INDEX.0].insert(name.as_str(), value);
        Ok(())
    }
}

#[derive(Debug)]
struct Scatter {
    /// The original subgraph of the scatter.
    subgraph: Arc<Subgraph>,
    /// The graph node index for the scatter's exit node.
    exit: NodeIndex,
    /// The current subgraph of the scatter.
    current: Subgraph,
    /// The scatter variable identifier.
    variable: Ident,
    // The scatter array being iterated over.
    array: Array,
    /// The current starting offset into the scatter array.
    offset: usize,
}

impl Scatter {
    pub fn new(subgraph: Arc<Subgraph>, exit: NodeIndex, variable: Ident, array: Array) -> Self {
        // let scopes: Vec<_> = (0..concurrency.min(array.len()))
        //     .map(|_| state.alloc_scope(Some(parent)))
        //     .collect();
        let current = subgraph.as_ref().clone();

        Self {
            subgraph,
            exit,
            current,
            variable,
            array,
            offset: 0,
        }
    }

    /// Gets an iterator over the nodes in the scatter that are ready to
    /// process.
    fn ready<'a>(
        &'a mut self,
        state: &mut State<'_>,
        awaiting: &'a HashSet<NodeIndex>,
        scopes: &[ScopeIndex],
    ) -> impl Iterator<Item = NodeIndex> + use<'a> {
        // Check to see if the current subgraph has exhausted
        if self.current.0.is_empty() && self.offset < self.array.len() {
            // Extend the current subgraph from the original
            self.current.0.extend(self.subgraph.0.iter());

            // Clear the scopes and add back the scatter variable with the next value
            for (i, scope) in scopes.iter().enumerate() {
                state.scopes[scope.0].clear();

                if let Some(v) = self.array.as_slice().get(self.offset + i) {
                    state.scopes[scope.0].insert(self.variable.as_str(), v.clone());
                }
            }

            // Adjust the offset
            self.offset += scopes.len();
        }

        self.current.0.iter().filter_map(|(index, count)| {
            if *count == 0 && !awaiting.contains(index) {
                Some(*index)
            } else {
                None
            }
        })
    }

    /// Determines if the scatter has completed.
    fn completed(&self) -> bool {
        self.current.0.is_empty() && self.offset >= self.array.len()
    }
}

/// Represents a WDL V1 workflow evaluator.
pub struct WorkflowEvaluator<'a> {
    /// The associated evaluation engine.
    engine: &'a mut Engine,
}

impl<'a> WorkflowEvaluator<'a> {
    /// Constructs a new workflow evaluator.
    pub fn new(engine: &'a mut Engine) -> Self {
        Self { engine }
    }

    /// Evaluates the workflow of the given document.
    ///
    /// Upon success, returns the evaluated workflow outputs.
    #[allow(clippy::redundant_closure_call)]
    pub async fn evaluate(
        &mut self,
        document: &'a Document,
        inputs: &WorkflowInputs,
        root: &Path,
    ) -> EvaluationResult<Outputs> {
        // Return the first error analysis diagnostic if there was one
        // With this check, we can assume certain correctness properties of the document
        if let Some(diagnostic) = document
            .diagnostics()
            .iter()
            .find(|d| d.severity() == Severity::Error)
        {
            return Err(diagnostic.clone().into());
        }

        // Validate the inputs for the workflow
        let workflow = document
            .workflow()
            .context("document does not contain a workflow")?;
        inputs
            .validate(self.engine.types_mut(), document, workflow)
            .with_context(|| {
                format!(
                    "failed to validate the inputs to workflow `{workflow}`",
                    workflow = workflow.name()
                )
            })?;

        let ast = match document.node().ast() {
            Ast::V1(ast) => ast,
            _ => return Err(anyhow!("document is not a 1.x document").into()),
        };

        // Find the workflow in the AST
        let definition = ast
            .workflows()
            .next()
            .expect("workflow should exist in the AST");

        // Build an evaluation graph for the workflow
        let mut diagnostics = Vec::new();
        let graph = WorkflowGraphBuilder::default().build(&definition, &mut diagnostics);
        if let Some(diagnostic) = diagnostics.pop() {
            return Err(diagnostic.into());
        }

        info!(
            "evaluating workflow `{workflow}` in `{uri}`",
            workflow = workflow.name(),
            uri = document.uri()
        );

        let sm = StateMachine::new(self.engine, &graph);

        // A map of syntax node to the scopes introduced by that node
        // Note that scatter statements may introduce multiple scopes (one per length of
        // the array being evaluated)
        let mut scope_indexes = Default::default();

        // Build a map of node index to indegree count
        let mut indegrees = HashMap::with_capacity(graph.node_count());
        for index in graph.node_indices() {
            indegrees.insert(
                index,
                graph.edges_directed(index, Direction::Incoming).count(),
            );
        }

        // This algorithm intends to parallelize as much of the evaluation graph as
        // possible.
        //
        // Instead of doing a topological sort that can't inform us of
        // which nodes could be performed in parallel, this works by:
        //
        // * Building a set of nodes with indegree 0 and also not currently processing
        //   asynchronously; this means the node doesn't depend on any other node to
        //   process.
        // * If the set is empty, it means we can't process any new node to move
        //   evaluation forward; instead, await on the next asynchronously processing
        //   node to complete.
        // * Otherwise, the set represents independent nodes that can be evaluated in
        //   parallel; we only asynchronously process call statements in parallel and
        //   other nodes are just evaluated serially.
        // * Once a node has been processed, we remove it from the indegree map and
        //   decrement the counts for any connected nodes.
        let mut processing = Vec::new();
        let mut waiting = HashSet::new();
        let mut futures = FuturesUnordered::new();
        let mut state = State::new(document, workflow, root)?;
        while !indegrees.is_empty() {
            // Add nodes with indegree 0 that we aren't already waiting on
            processing.clear();
            processing.extend(indegrees.iter().filter_map(|(index, count)| {
                if *count == 0 && !waiting.contains(index) {
                    Some(*index)
                } else {
                    None
                }
            }));

            // If we can't process any new nodes, wait for an in-progress node to complete
            // When it does, remove the node from the graph and attempt to drive graph
            // evaluation forward
            if processing.is_empty() {
                let index = futures
                    .next()
                    .await
                    .expect("should have a future to wait on");
                match &graph[index] {
                    WorkflowGraphNode::Call(call) => {
                        debug!(
                            "call `{name}` has completed; removing from evaluation graph",
                            name = call
                                .alias()
                                .map(|a| a.name())
                                .unwrap_or_else(|| call.target().names().last().unwrap())
                                .as_str()
                        );
                    }
                    _ => unreachable!(),
                }
                waiting.remove(&index);
                indegrees.remove(&index);
                for edge in graph.edges_directed(index, Direction::Outgoing) {
                    *indegrees.get_mut(&edge.target()).unwrap() -= 1
                }
                continue;
            }

            // Process the node now or push a future for later completion
            for index in &processing {
                let index = *index;
                match &graph[index] {
                    WorkflowGraphNode::Input(decl) => {
                        self.evaluate_input(&mut state, decl, inputs)?;
                    }
                    WorkflowGraphNode::Decl(decl) => {
                        self.evaluate_decl(&mut state, &mut scope_indexes, decl)?;
                    }
                    WorkflowGraphNode::Output(decl) => {
                        self.evaluate_output(&mut state, decl)?;
                    }
                    WorkflowGraphNode::Conditional(stmt) => {
                        self.evaluate_conditional(&mut state, &mut scope_indexes, stmt)?;
                    }
                    WorkflowGraphNode::Scatter(stmt, _) => {
                        // For scatter statements, we split out a subgraph representing the scatter
                        // This allows us to iterate over the subgraph for each element in the
                        // scatter array We push the subgraph into the list
                        // of graphs being evaluated so that we can attempt to make progress on any
                        // of the graphs
                        self.evaluate_scatter(&mut state, &mut scope_indexes, stmt)?;
                    }
                    WorkflowGraphNode::Call(call) => {
                        futures.push(async move { index });
                        waiting.insert(index);
                    }
                    WorkflowGraphNode::ExitConditional(stmt) => {
                        self.evaluate_conditional_exit(&mut state, &mut scope_indexes, stmt)?
                    }
                    WorkflowGraphNode::ExitScatter(stmt) => {
                        self.evaluate_scatter_exit(&mut state, &mut scope_indexes, stmt)?;
                    }
                }
            }

            // Remove any nodes from the map that aren't being waiting on
            for index in &processing {
                if !waiting.contains(index) {
                    indegrees.remove(index);
                    for edge in graph.edges_directed(*index, Direction::Outgoing) {
                        *indegrees.get_mut(&edge.target()).unwrap() -= 1
                    }
                }
            }
        }

        let mut outputs: Outputs = mem::take(&mut state.scopes[OUTPUT_SCOPE_INDEX.0]).into();
        if let Some(section) = definition.output() {
            let indexes: HashMap<_, _> = section
                .declarations()
                .enumerate()
                .map(|(i, d)| (TokenStrHash::new(d.name()), i))
                .collect();
            outputs.sort_by(move |a, b| indexes[a].cmp(&indexes[b]))
        }

        Ok(outputs)
    }

    /// Evaluates a workflow input.
    fn evaluate_input(
        &mut self,
        state: &mut State<'_>,
        decl: &Decl,
        inputs: &WorkflowInputs,
    ) -> EvaluationResult<()> {
        let name = decl.name();
        let decl_ty = decl.ty();
        let ty = self.engine.convert_ast_type_v1(state.document, &decl_ty)?;

        let (value, span) = match inputs.get(name.as_str()) {
            Some(input) => (input.clone(), name.span()),
            None => {
                if let Some(expr) = decl.expr() {
                    debug!(
                        "evaluating input `{name}` for workflow `{workflow}` in `{uri}`",
                        name = name.as_str(),
                        workflow = state.workflow.name(),
                        uri = state.document.uri(),
                    );

                    let mut evaluator = ExprEvaluator::new(WorkflowEvaluationContext::new(
                        self.engine,
                        state,
                        ROOT_SCOPE_INDEX,
                    ));
                    let value = evaluator.evaluate_expr(&expr)?;
                    (value, expr.span())
                } else {
                    assert!(decl.ty().is_optional(), "type should be optional");
                    (Value::None, name.span())
                }
            }
        };

        let value = value.coerce(self.engine.types_mut(), ty).map_err(|e| {
            runtime_type_mismatch(self.engine.types(), e, ty, name.span(), value.ty(), span)
        })?;

        state.scopes[ROOT_SCOPE_INDEX.0].insert(name.as_str(), value);
        Ok(())
    }

    /// Evaluates a workflow private declaration.
    fn evaluate_decl(
        &mut self,
        state: &mut State<'_>,
        scope_indexes: &mut HashMap<SyntaxNode, Vec<ScopeIndex>>,
        decl: &Decl,
    ) -> EvaluationResult<()> {
        let name = decl.name();
        debug!(
            "evaluating private declaration `{name}` for workflow `{workflow}` in `{uri}`",
            name = name.as_str(),
            workflow = state.workflow.name(),
            uri = state.document.uri(),
        );

        let decl_ty = decl.ty();
        let ty = self.engine.convert_ast_type_v1(state.document, &decl_ty)?;

        // Evaluate the declaration for every scope associated with the decl's parent
        // node
        for parent in scope_indexes
            .get(&decl.syntax().parent().expect("should have parent"))
            .map(|s| s.as_slice())
            .unwrap_or(&[ROOT_SCOPE_INDEX])
        {
            // Don't evaluate if a parent scope was introduced by a conditional statement
            // that evaluated to false
            if !ScopeRef::new(&state.scopes, *parent)
                .lookup(CONDITIONAL_VAR_NAME)
                .and_then(|v| v.as_boolean())
                .unwrap_or(true)
            {
                continue;
            }

            let mut evaluator =
                ExprEvaluator::new(WorkflowEvaluationContext::new(self.engine, state, *parent));

            let expr = decl.expr().expect("private decls should have expressions");
            let value = evaluator.evaluate_expr(&expr)?;
            let value = value.coerce(self.engine.types_mut(), ty).map_err(|e| {
                runtime_type_mismatch(
                    self.engine.types(),
                    e,
                    ty,
                    name.span(),
                    value.ty(),
                    expr.span(),
                )
            })?;

            state.scopes[parent.0].insert(name.as_str(), value);
        }

        Ok(())
    }

    /// Evaluates a workflow output.
    fn evaluate_output(&mut self, state: &mut State<'_>, decl: &Decl) -> EvaluationResult<()> {
        let name = decl.name();
        debug!(
            "evaluating output `{name}` for workflow `{workflow}` in `{uri}`",
            name = name.as_str(),
            workflow = state.workflow.name(),
            uri = state.document.uri()
        );

        let decl_ty = decl.ty();
        let ty = self.engine.convert_ast_type_v1(state.document, &decl_ty)?;
        let mut evaluator = ExprEvaluator::new(WorkflowEvaluationContext::new(
            self.engine,
            state,
            OUTPUT_SCOPE_INDEX,
        ));

        let expr = decl.expr().expect("outputs should have expressions");
        let value = evaluator.evaluate_expr(&expr)?;

        // First coerce the output value to the expected type
        let mut value = value.coerce(self.engine.types(), ty).map_err(|e| {
            runtime_type_mismatch(
                self.engine.types(),
                e,
                ty,
                name.span(),
                value.ty(),
                expr.span(),
            )
        })?;

        // Finally, join any paths with the working directory, checking for existence
        value
            .join_paths(self.engine.types(), &state.work_dir, true, ty.is_optional())
            .map_err(|e| output_evaluation_failed(e, state.workflow.name(), false, &name))?;

        state.scopes[OUTPUT_SCOPE_INDEX.0].insert(name.as_str(), value);
        Ok(())
    }

    /// Evaluates a workflow conditional statement.
    fn evaluate_conditional(
        &mut self,
        state: &mut State<'_>,
        scope_indexes: &mut HashMap<SyntaxNode, Vec<ScopeIndex>>,
        stmt: &ConditionalStatement,
    ) -> EvaluationResult<()> {
        let expr = stmt.expr();

        debug!(
            "evaluating conditional statement `{expr}` for workflow `{workflow}` in `{uri}`",
            expr = expr.syntax().text(),
            workflow = state.workflow.name(),
            uri = state.document.uri()
        );

        // Create scopes for the conditional in each parent scope and record the result
        // of the conditional expression
        let mut scopes = Vec::new();
        for parent in scope_indexes
            .get(&stmt.syntax().parent().expect("should have parent"))
            .map(|s| s.as_slice())
            .unwrap_or(&[ROOT_SCOPE_INDEX])
        {
            let scope: ScopeIndex = state.scopes.len().into();
            state.scopes.push(Scope::new(Some(*parent)));
            scopes.push(scope);

            let mut evaluator =
                ExprEvaluator::new(WorkflowEvaluationContext::new(self.engine, state, scope));

            let value = evaluator.evaluate_expr(&expr)?;
            let value = value
                .coerce(self.engine.types(), PrimitiveTypeKind::Boolean.into())
                .map_err(|e| {
                    if_conditional_mismatch(self.engine.types(), e, value.ty(), expr.span())
                })?;

            state.scopes[scope.0].insert(CONDITIONAL_VAR_NAME, value);
        }

        // Associate the node with the scopes
        scope_indexes.insert(stmt.syntax().clone(), scopes);
        Ok(())
    }

    /// Evaluates the exit of a workflow conditional statement.
    fn evaluate_conditional_exit(
        &mut self,
        state: &mut State<'_>,
        scope_indexes: &mut HashMap<SyntaxNode, Vec<ScopeIndex>>,
        stmt: &ConditionalStatement,
    ) -> EvaluationResult<()> {
        let expr = stmt.expr();

        debug!(
            "exiting conditional statement `{expr}` for workflow `{workflow}`",
            expr = expr.syntax().text(),
            workflow = state.workflow.name(),
        );

        for index in scope_indexes.get(stmt.syntax()).unwrap() {
            // We need to split the scopes as we want to read from one part of the slice and
            // write to another; the left side will contain the parent at its index and the
            // right side will contain the child scope at its index minus the parent's
            let parent = state.scopes[index.0].parent.expect("should have parent");
            let (left, right) = state.scopes.split_at_mut(parent.0 + 1);
            let scope = &right[index.0 - parent.0 - 1];
            let parent = &mut left[parent.0];

            if scope
                .names
                .get(CONDITIONAL_VAR_NAME)
                .expect("should have conditional variable")
                .as_boolean()
                .expect("should be boolean")
            {
                // Clone every value in the scope as optional into the parent's scope
                for (name, value) in scope
                    .names
                    .iter()
                    .filter(|(n, _)| *n != CONDITIONAL_VAR_NAME)
                {
                    parent.insert(name.to_string(), value.clone_as_optional());
                }
            } else {
                // As we didn't evaluate anything into the conditional's scope, use the names
                // from analysis to populate the parent scope with `None` values
                let scope = state
                    .document
                    .find_scope_by_position(
                        stmt.braced_scope_span()
                            .expect("should have braced scope span")
                            .start(),
                    )
                    .expect("should have scope");

                for (name, _) in scope.names() {
                    parent.insert(name.to_string(), Value::None);
                }
            }
        }

        // Finally, free up the conditional's scope space
        for index in scope_indexes
            .remove(stmt.syntax())
            .expect("should have scopes")
        {
            mem::take(&mut state.scopes[index.0]);
        }

        Ok(())
    }

    /// Evaluates a workflow scatter statement.
    fn evaluate_scatter(
        &mut self,
        state: &mut State<'_>,
        scope_indexes: &mut HashMap<SyntaxNode, Vec<ScopeIndex>>,
        stmt: &ScatterStatement,
    ) -> EvaluationResult<()> {
        let variable = stmt.variable();
        let expr = stmt.expr();

        debug!(
            "evaluating scatter statement `{var}` for workflow `{workflow}` in `{uri}`",
            var = variable.as_str(),
            workflow = state.workflow.name(),
            uri = state.document.uri()
        );

        // Evaluate the array expression for each parent scope
        let mut scopes = Vec::new();
        for parent in scope_indexes
            .get(&stmt.syntax().parent().expect("should have parent"))
            .map(|s| s.as_slice())
            .unwrap_or(&[ROOT_SCOPE_INDEX])
        {
            // Don't evaluate if a parent scope was introduced by a conditional statement
            // that evaluated to false
            if !ScopeRef::new(&state.scopes, *parent)
                .lookup(CONDITIONAL_VAR_NAME)
                .and_then(|v| v.as_boolean())
                .unwrap_or(true)
            {
                continue;
            }

            let mut evaluator =
                ExprEvaluator::new(WorkflowEvaluationContext::new(self.engine, state, *parent));

            let value = evaluator.evaluate_expr(&expr)?;
            let array = value
                .as_array()
                .ok_or_else(|| type_is_not_array(self.engine.types(), value.ty(), expr.span()))?;

            // Introduce a new scope for each array element with the scatter variable set to
            // the element
            for v in array.as_slice() {
                let scope: ScopeIndex = state.scopes.len().into();
                state.scopes.push(Scope::new(Some(*parent)));
                scopes.push(scope);
                state.scopes[scope.0].insert(variable.as_str(), v.clone());
            }
        }

        // Associate the node with the scopes
        scope_indexes.insert(stmt.syntax().clone(), scopes);
        Ok(())
    }

    /// Evaluates the exit of a workflow scatter statement.
    fn evaluate_scatter_exit(
        &mut self,
        state: &mut State<'_>,
        scope_indexes: &mut HashMap<SyntaxNode, Vec<ScopeIndex>>,
        stmt: &ScatterStatement,
    ) -> EvaluationResult<()> {
        let variable = stmt.variable();

        debug!(
            "exiting scatter statement `{var}` for workflow `{workflow}` in `{uri}`",
            var = variable.as_str(),
            workflow = state.workflow.name(),
            uri = state.document.uri()
        );

        // Stores the array types being introduced into each parent scope
        let mut types = Vec::new();

        // Chunk the scopes by parent to collect the values
        // Ultimately, this produces a collection of parent scopes paired with the names
        // to insert (each value will be an array)
        let insert = scope_indexes
            .get(stmt.syntax())
            .expect("should have scopes")
            .iter()
            .chunk_by(|i| state.scopes[i.0].parent.expect("should have a parent"))
            .into_iter()
            .map(|(parent, scopes)| {
                let names = scopes
                    .enumerate()
                    .fold(Vec::new(), |mut names, (i, scope)| {
                        // If the array types haven't been populated yet, do so now
                        // Each name being introduced will have the same type
                        if types.is_empty() {
                            for v in state.scopes[scope.0].names.values() {
                                let ty = self.engine.types_mut().add_array(ArrayType::new(v.ty()));
                                types.push(ty);
                            }
                        }

                        // For the first iteration, create a new array of values
                        if i == 0 {
                            for (n, v) in state.scopes[scope.0]
                                .names
                                .iter()
                                .filter(|(k, _)| *k != variable.as_str())
                            {
                                names.push((n.to_string(), vec![v.clone()]));
                            }
                        } else {
                            // For subsequent iterations, push the value onto the existing array
                            for (i, (n, v)) in state.scopes[scope.0]
                                .names
                                .iter()
                                .filter(|(k, _)| *k != variable.as_str())
                                .enumerate()
                            {
                                assert_eq!(
                                    &names[i].0, n,
                                    "scope evaluation should have been in a stable order"
                                );
                                debug_assert!(
                                    names[i].1[0].ty().type_eq(self.engine.types(), &v.ty()),
                                    "all array elements must have the same type"
                                );
                                names[i].1.push(v.clone());
                            }
                        }

                        names
                    });

                assert!(
                    !names.is_empty(),
                    "there should be names to insert into the parent scope"
                );
                (parent, names)
            })
            .collect::<Vec<_>>();

        // Insert the names into the parent scopes
        for (parent, names) in insert {
            let parent = &mut state.scopes[parent.0];
            for (i, (name, elements)) in names.into_iter().enumerate() {
                parent.insert(name, Array::new_unchecked(types[i], elements));
            }
        }

        // Finally, free up the scatter's scope space
        for index in scope_indexes
            .remove(stmt.syntax())
            .expect("should have scopes")
        {
            mem::take(&mut state.scopes[index.0]);
        }

        Ok(())
    }
}
