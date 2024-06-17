//! A lint rule for unused imports in a document.

use std::collections::HashMap;

use wdl_ast::v1::BoundDecl;
use wdl_ast::v1::CallStatement;
use wdl_ast::v1::Expr;
use wdl_ast::v1::ImportStatement;
use wdl_ast::v1::LiteralExpr;
use wdl_ast::v1::Type;
use wdl_ast::v1::UnboundDecl;
use wdl_ast::v1::Visitor;
use wdl_ast::AstNode;
use wdl_ast::AstToken;
use wdl_ast::Diagnostic;
use wdl_ast::Diagnostics;
use wdl_ast::Document;
use wdl_ast::Span;
use wdl_ast::ToSpan;
use wdl_ast::VisitReason;

use super::Rule;
use crate::Tag;
use crate::TagSet;

/// The identifier for the unused import rule.
const ID: &str = "UnusedImport";

/// Creates an "unused import" diagnostic.
fn unused_import(span: Span) -> Diagnostic {
    Diagnostic::warning("unused import")
        .with_rule(ID)
        .with_label("this import is not referenced in the document", span)
        .with_fix("remove the unused import")
}

/// Detects unused imports in the document.
#[derive(Debug, Clone, Copy)]
pub struct UnusedImportRule;

impl Rule for UnusedImportRule {
    fn id(&self) -> &'static str {
        ID
    }

    fn description(&self) -> &'static str {
        "Ensures that imported documents are used."
    }

    fn explanation(&self) -> &'static str {
        "An imported document should be used by the document containing the import. An unused \
         import may cause unnecessary parsing of WDL source and may also confuse readers of the \
         document."
    }

    fn tags(&self) -> TagSet {
        TagSet::new(&[Tag::Clarity])
    }

    fn visitor(&self) -> Box<dyn Visitor<State = Diagnostics>> {
        Box::<UnusedImportVisitor>::default()
    }
}

/// Implements the visitor for the unused rule.
#[derive(Default)]
struct UnusedImportVisitor {
    /// The list of import spans and a flag that indicates if the import was
    /// used.
    imports: Vec<(Span, bool)>,
    /// A map from name to the index in `imports` for the import statement that
    /// introduced it.
    names: HashMap<String, usize>,
}

impl Visitor for UnusedImportVisitor {
    type State = Diagnostics;

    fn document(&mut self, state: &mut Self::State, reason: VisitReason, _: &Document) {
        if reason == VisitReason::Enter {
            return;
        }

        // Upon exiting the document, report on all unused imports
        for (span, used) in self.imports.iter() {
            if !used {
                state.add(unused_import(*span));
            }
        }
    }

    fn import_statement(
        &mut self,
        _: &mut Self::State,
        reason: VisitReason,
        stmt: &ImportStatement,
    ) {
        if reason == VisitReason::Exit {
            return;
        }

        if let Some(ns) = stmt.namespace() {
            // Insert an entry for this import
            let index = self.imports.len();
            let uri = stmt.uri();
            self.imports
                .push((uri.syntax().text_range().to_span(), false));
            self.names.insert(ns, index);

            // TODO: to correctly identify all references to the import, we need to parse
            // the imported document and determine any "copied" struct names;
            // thus, this rule cannot work on a single document alone

            for alias in stmt.aliases() {
                let (_, to) = alias.names();
                self.names.insert(to.as_str().to_string(), index);
            }
        }
    }

    fn bound_decl(&mut self, _: &mut Self::State, reason: VisitReason, decl: &BoundDecl) {
        if reason == VisitReason::Exit {
            return;
        }

        // If the type is a name reference, mark the import that introduced the name as
        // used
        if let Type::Ref(ty) = decl.ty() {
            if let Some(index) = self.names.get_mut(ty.name().as_str()) {
                self.imports[*index].1 = true;
            }
        }
    }

    fn unbound_decl(&mut self, _: &mut Self::State, reason: VisitReason, decl: &UnboundDecl) {
        if reason == VisitReason::Exit {
            return;
        }

        // If the type is a name reference, mark the import that introduced the name as
        // used
        if let Type::Ref(ty) = decl.ty() {
            if let Some(index) = self.names.get_mut(ty.name().as_str()) {
                self.imports[*index].1 = true;
            }
        }
    }

    fn expr(&mut self, _: &mut Self::State, reason: VisitReason, expr: &Expr) {
        if reason == VisitReason::Exit {
            return;
        }

        match expr {
            Expr::Literal(LiteralExpr::Struct(s)) => {
                // Mark the import that introduced the struct name as used
                if let Some(index) = self.names.get_mut(s.name().as_str()) {
                    self.imports[*index].1 = true;
                }
            }
            Expr::Name(r) => {
                // Mark the import that introduced the name being referenced as used
                if let Some(index) = self.names.get_mut(r.name().as_str()) {
                    self.imports[*index].1 = true;
                }
            }
            _ => {}
        }
    }

    fn call_statement(&mut self, _: &mut Self::State, reason: VisitReason, stmt: &CallStatement) {
        if reason == VisitReason::Exit {
            return;
        }

        // If the call target has a namespace, mark the corresponding import as used
        if let Some(ns) = stmt.target().name().0 {
            if let Some(index) = self.names.get_mut(ns.as_str()) {
                self.imports[*index].1 = true;
            }
        }
    }
}
