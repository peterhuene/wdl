//! Validation of imports in an AST.

use rowan::ast::AstNode;
use wdl_grammar::ToSpan;

use crate::v1;
use crate::v1::StringPart;
use crate::Diagnostic;
use crate::Diagnostics;
use crate::Document;
use crate::Span;
use crate::VisitReason;
use crate::Visitor;

/// Creates a "placeholder in import" diagnostic
fn placeholder_in_import(span: Span) -> Diagnostic {
    Diagnostic::error("import URI must not contain placeholders")
        .with_label("remove this placeholder", span)
}

/// A visitor of import URIs within an AST.
///
/// Ensures that the import URI contain no placeholders.
#[derive(Default, Debug)]
pub struct ImportVisitor;

impl Visitor for ImportVisitor {
    type State = Diagnostics;

    fn document(&mut self, _: &mut Self::State, reason: VisitReason, _: &Document) {
        if reason != VisitReason::Enter {
            return;
        }

        // Reset the visitor upon document entry
        *self = Default::default();
    }

    fn import_statement(
        &mut self,
        state: &mut Self::State,
        reason: VisitReason,
        stmt: &v1::ImportStatement,
    ) {
        if reason == VisitReason::Exit {
            return;
        }

        let uri = stmt.uri();
        if uri.text().is_none() {
            let span = uri
                .parts()
                .find_map(|p| match p {
                    StringPart::Text(_) => None,
                    StringPart::Placeholder(p) => Some(p),
                })
                .expect("should contain a placeholder")
                .syntax()
                .text_range()
                .to_span();
            state.add(placeholder_in_import(span));
        }
    }
}
