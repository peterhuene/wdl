//! Implements the per-document analyzer.

use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use petgraph::graph::NodeIndex;
use wdl_ast::Ast;
use wdl_ast::AstNode;
use wdl_ast::AstToken;
use wdl_ast::Diagnostic;
use wdl_ast::SyntaxNode;
use wdl_ast::ToSpan;

use crate::DocumentId;
use crate::State;

/// Represents a single-document analyzer.
#[derive(Debug)]
pub(crate) struct Analyzer {
    /// The shared analysis state.
    state: Arc<RwLock<State>>,
    /// The index of the node being analyzed.
    index: NodeIndex,
}

impl Analyzer {
    /// Constructs a new analyzer for the given document.
    pub fn new(state: Arc<RwLock<State>>, index: NodeIndex) -> Self {
        Self { state, index }
    }

    /// Analyzes the document and returns the set of analysis diagnostics.
    pub fn analyze(&self) {
        let (id, root) = {
            // scope for read lock
            let state = self.state.read();
            let node = &state.graph.inner[self.index];
            (node.id.clone(), node.root.clone())
        };

        log::info!("analyzing `{id}`");
        let start = Instant::now();
        let mut diagnostics = Vec::new();
        if let Some(root) = root {
            let document =
                wdl_ast::Document::cast(SyntaxNode::new_root(root)).expect("root should cast");
            match document.ast() {
                Ast::Unsupported => {}
                Ast::V1(ast) => {
                    // Currently analysis is limited to whether or not an import had an error
                    // In the future, analysis will walk the whole tree and record things like:
                    // * name scopes (names introduced from imports and declarations)
                    // * type checks
                    // * name resolution
                    // * various bookkeeping information we'd use for future LSP requests

                    {
                        // Scope for read lock
                        let state = self.state.read();
                        for import in ast.imports() {
                            let uri = import.uri();
                            let text = match uri.text() {
                                Some(text) => text,
                                None => continue,
                            };

                            let import_id = match DocumentId::relative_to(&id, text.as_str()) {
                                Ok(id) => Arc::new(id),
                                Err(_) => continue,
                            };

                            let (dep_index, dep) = state
                                .graph
                                .document(&import_id)
                                .expect("missing import node in graph");

                            if state.cycles.contains(&(self.index, dep_index)) {
                                // There was a cycle for this import, add a diagnostic
                                diagnostics.push(
                                    Diagnostic::error("import introduces a dependency cycle")
                                        .with_label(
                                            "this import has been skipped to break the cycle",
                                            uri.syntax().text_range().to_span(),
                                        ),
                                );
                                continue;
                            }

                            if let Some(e) = &dep.error {
                                // There was an error for this import
                                diagnostics.push(
                                    Diagnostic::error(format!(
                                        "failed to import `{uri}`: {e:#}",
                                        uri = text.as_str()
                                    ))
                                    .with_highlight(uri.syntax().text_range().to_span()),
                                );
                                continue;
                            }
                        }
                    }
                }
            }
        }

        {
            // Scope for write lock
            // Write the result of the analysis to the document
            let mut state = self.state.write();
            let doc = &mut state.graph.inner[self.index];
            if !diagnostics.is_empty() {
                doc.diagnostics.as_vec_mut().extend(diagnostics);
            }

            // Complete the analysis of the document
            doc.complete();
        }

        log::info!(
            "analysis of `{id}` completed in {elapsed:?}",
            elapsed = start.elapsed()
        )
    }
}
