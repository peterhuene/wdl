//! Implementation of evaluation for V1 workflows.

use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::mem;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::anyhow;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use itertools::Itertools;
use petgraph::Direction;
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
            work_dir,
            temp_dir,
        })
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
                    WorkflowGraphNode::Scatter(stmt) => {
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
