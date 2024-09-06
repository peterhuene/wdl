//! Implementation of common diagnostics.
use std::fmt;

use wdl_ast::AstToken;
use wdl_ast::Diagnostic;
use wdl_ast::Ident;
use wdl_ast::Span;
use wdl_ast::SupportedVersion;

use crate::types::Type;
use crate::types::Types;

/// Represents a comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparisonOperator {
    /// The `==` operator.
    Equality,
    /// The `!=` operator.
    Inequality,
    /// The `>` operator.
    Less,
    /// The `<=` operator.
    LessEqual,
    /// The `>` operator.
    Greater,
    /// The `>=` operator.
    GreaterEqual,
}

impl fmt::Display for ComparisonOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Equality => "==",
                Self::Inequality => "!=",
                Self::Less => "<",
                Self::LessEqual => "<=",
                Self::Greater => ">",
                Self::GreaterEqual => ">=",
            }
        )
    }
}

/// Represents a numeric operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumericOperator {
    /// The `+` operator.
    Addition,
    /// The `-` operator.
    Subtraction,
    /// The `*` operator.
    Multiplication,
    /// The `/` operator.
    Division,
    /// The `%` operator.
    Modulo,
    /// The `**` operator.
    Exponentiation,
}

impl fmt::Display for NumericOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Addition => "addition",
                Self::Subtraction => "subtraction",
                Self::Multiplication => "multiplication",
                Self::Division => "division",
                Self::Modulo => "remainder",
                Self::Exponentiation => "exponentiation",
            }
        )
    }
}

/// Creates an "unknown name" diagnostic.
pub fn unknown_name(name: &str, span: Span) -> Diagnostic {
    // Handle special case names here
    let message = match name {
        "task" => "the `task` variable may only be used within a task command section or task \
                   output section using WDL 1.2 or later"
            .to_string(),
        _ => format!("unknown name `{name}`"),
    };

    Diagnostic::error(message).with_highlight(span)
}

/// Creates an "unknown type" diagnostic.
pub fn unknown_type(name: &str, span: Span) -> Diagnostic {
    Diagnostic::error(format!("unknown type name `{name}`")).with_highlight(span)
}

/// Creates a "type mismatch" diagnostic.
pub fn type_mismatch(
    types: &Types,
    expected: Type,
    expected_span: Span,
    actual: Type,
    actual_span: Span,
) -> Diagnostic {
    Diagnostic::error(format!(
        "type mismatch: expected type `{expected}`, but found type `{actual}`",
        expected = expected.display(types),
        actual = actual.display(types)
    ))
    .with_label(
        format!("this is type `{actual}`", actual = actual.display(types)),
        actual_span,
    )
    .with_label(
        format!(
            "this is type `{expected}`",
            expected = expected.display(types)
        ),
        expected_span,
    )
}

/// Creates a custom "type mismatch" diagnostic.
pub fn type_mismatch_custom(
    types: &Types,
    expected: &str,
    expected_span: Span,
    actual: Type,
    actual_span: Span,
) -> Diagnostic {
    Diagnostic::error(format!(
        "type mismatch: expected {expected}, but found type `{actual}`",
        actual = actual.display(types)
    ))
    .with_label(
        format!("this is type `{actual}`", actual = actual.display(types)),
        actual_span,
    )
    .with_label(format!("this expects {expected}"), expected_span)
}

/// Creates a "not a task member" diagnostic.
pub fn not_a_task_member(member: &Ident) -> Diagnostic {
    Diagnostic::error(format!(
        "the `task` variable does not have a member named `{member}`",
        member = member.as_str()
    ))
    .with_highlight(member.span())
}

/// Creates a "not an I/O name" diagnostic.
pub fn not_io_name(name: &Ident, input: bool) -> Diagnostic {
    Diagnostic::error(format!(
        "an {kind} with name `{name}` does not exist",
        kind = if input { "input" } else { "output" },
        name = name.as_str(),
    ))
    .with_highlight(name.span())
}

/// Creates a "not a struct" diagnostic.
pub fn not_a_struct(member: &Ident, input: bool) -> Diagnostic {
    Diagnostic::error(format!(
        "{kind} `{member}` is not a struct",
        kind = if input { "input" } else { "struct member" },
        member = member.as_str()
    ))
    .with_highlight(member.span())
}

/// Creates a "not a struct member" diagnostic.
pub fn not_a_struct_member(name: &str, member: &Ident) -> Diagnostic {
    Diagnostic::error(format!(
        "struct `{name}` does not have a member named `{member}`",
        member = member.as_str()
    ))
    .with_highlight(member.span())
}

/// Creates a "not a pair accessor" diagnostic.
pub fn not_a_pair_accessor(name: &Ident) -> Diagnostic {
    Diagnostic::error(format!(
        "cannot access a pair with name `{name}`",
        name = name.as_str()
    ))
    .with_highlight(name.span())
    .with_fix("use `left` or `right` to access a pair")
}

/// Creates a "missing struct members" diagnostic.
pub fn missing_struct_members(name: &Ident, count: usize, members: &str) -> Diagnostic {
    Diagnostic::error(format!(
        "struct `{name}` requires a value for member{s} {members}",
        name = name.as_str(),
        s = if count > 1 { "s" } else { "" },
    ))
    .with_highlight(name.span())
}

/// Creates a "map key not primitive" diagnostic.
pub fn map_key_not_primitive(types: &Types, actual: Type, actual_span: Span) -> Diagnostic {
    Diagnostic::error("expected map literal to use primitive type keys").with_label(
        format!("this is type `{actual}`", actual = actual.display(types)),
        actual_span,
    )
}

/// Creates a "if conditional mismatch" diagnostic.
pub fn if_conditional_mismatch(types: &Types, actual: Type, actual_span: Span) -> Diagnostic {
    Diagnostic::error(format!(
        "type mismatch: expected `if` conditional expression to be type `Boolean`, but found type \
         `{actual}`",
        actual = actual.display(types)
    ))
    .with_label(
        format!("this is type `{actual}`", actual = actual.display(types)),
        actual_span,
    )
}

/// Creates a "logical not mismatch" diagnostic.
pub fn logical_not_mismatch(types: &Types, actual: Type, actual_span: Span) -> Diagnostic {
    Diagnostic::error(format!(
        "type mismatch: expected `logical not` operand to be type `Boolean`, but found type \
         `{actual}`",
        actual = actual.display(types)
    ))
    .with_label(
        format!("this is type `{actual}`", actual = actual.display(types)),
        actual_span,
    )
}

/// Creates a "negation mismatch" diagnostic.
pub fn negation_mismatch(types: &Types, actual: Type, actual_span: Span) -> Diagnostic {
    Diagnostic::error(format!(
        "type mismatch: expected negation operand to be type `Int` or `Float`, but found type \
         `{actual}`",
        actual = actual.display(types)
    ))
    .with_label(
        format!("this is type `{actual}`", actual = actual.display(types)),
        actual_span,
    )
}

/// Creates a "logical or mismatch" diagnostic.
pub fn logical_or_mismatch(types: &Types, actual: Type, actual_span: Span) -> Diagnostic {
    Diagnostic::error(format!(
        "type mismatch: expected `logical or` operand to be type `Boolean`, but found type \
         `{actual}`",
        actual = actual.display(types)
    ))
    .with_label(
        format!("this is type `{actual}`", actual = actual.display(types)),
        actual_span,
    )
}

/// Creates a "logical and mismatch" diagnostic.
pub fn logical_and_mismatch(types: &Types, actual: Type, actual_span: Span) -> Diagnostic {
    Diagnostic::error(format!(
        "type mismatch: expected `logical and` operand to be type `Boolean`, but found type \
         `{actual}`",
        actual = actual.display(types)
    ))
    .with_label(
        format!("this is type `{actual}`", actual = actual.display(types)),
        actual_span,
    )
}

/// Creates a "comparison mismatch" diagnostic.
pub fn comparison_mismatch(
    types: &Types,
    op: ComparisonOperator,
    span: Span,
    lhs: Type,
    lhs_span: Span,
    rhs: Type,
    rhs_span: Span,
) -> Diagnostic {
    Diagnostic::error(format!(
        "type mismatch: operator `{op}` cannot compare type `{lhs}` to type `{rhs}`",
        lhs = lhs.display(types),
        rhs = rhs.display(types),
    ))
    .with_highlight(span)
    .with_label(
        format!("this is type `{lhs}`", lhs = lhs.display(types)),
        lhs_span,
    )
    .with_label(
        format!("this is type `{rhs}`", rhs = rhs.display(types)),
        rhs_span,
    )
}

/// Creates a "numeric mismatch" diagnostic.
pub fn numeric_mismatch(
    types: &Types,
    op: NumericOperator,
    span: Span,
    lhs: Type,
    lhs_span: Span,
    rhs: Type,
    rhs_span: Span,
) -> Diagnostic {
    Diagnostic::error(format!(
        "type mismatch: {op} operator is not supported for type `{lhs}` and type `{rhs}`",
        lhs = lhs.display(types),
        rhs = rhs.display(types)
    ))
    .with_highlight(span)
    .with_label(
        format!("this is type `{lhs}`", lhs = lhs.display(types)),
        lhs_span,
    )
    .with_label(
        format!("this is type `{rhs}`", rhs = rhs.display(types)),
        rhs_span,
    )
}

/// Creates a "string concat mismatch" diagnostic.
pub fn string_concat_mismatch(types: &Types, actual: Type, actual_span: Span) -> Diagnostic {
    Diagnostic::error(format!(
        "type mismatch: string concatenation is not supported for type `{actual}`",
        actual = actual.display(types),
    ))
    .with_label(
        format!("this is type `{actual}`", actual = actual.display(types)),
        actual_span,
    )
}

/// Creates an "unknown function" diagnostic.
pub fn unknown_function(name: &str, span: Span) -> Diagnostic {
    Diagnostic::error(format!("unknown function `{name}`")).with_label(
        "the WDL standard library does not have a function with this name",
        span,
    )
}

/// Creates an "unsupported function" diagnostic.
pub fn unsupported_function(minimum: SupportedVersion, name: &str, span: Span) -> Diagnostic {
    Diagnostic::error(format!(
        "function `{name}` requires a minimum WDL version of {minimum}"
    ))
    .with_highlight(span)
}

/// Creates a "too few arguments" diagnostic.
pub fn too_few_arguments(name: &str, span: Span, minimum: usize, count: usize) -> Diagnostic {
    Diagnostic::error(format!(
        "function `{name}` requires at least {minimum} argument{s} but {count} {v} supplied",
        s = if minimum == 1 { "" } else { "s" },
        v = if count == 1 { "was" } else { "were" },
    ))
    .with_highlight(span)
}

/// Creates a "too many arguments" diagnostic.
pub fn too_many_arguments(
    name: &str,
    span: Span,
    maximum: usize,
    count: usize,
    excessive: impl Iterator<Item = Span>,
) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(format!(
        "function `{name}` requires no more than {maximum} argument{s} but {count} {v} supplied",
        s = if maximum == 1 { "" } else { "s" },
        v = if count == 1 { "was" } else { "were" },
    ))
    .with_highlight(span);

    for span in excessive {
        diagnostic = diagnostic.with_label("this argument is unexpected", span);
    }

    diagnostic
}

/// Constructs an "argument type mismatch" diagnostic.
pub fn argument_type_mismatch(
    types: &Types,
    expected: &str,
    actual: Type,
    span: Span,
) -> Diagnostic {
    Diagnostic::error(format!(
        "argument type mismatch: expected type {expected}, but found type `{actual}`",
        actual = actual.display(types)
    ))
    .with_label(
        format!("this is type `{actual}`", actual = actual.display(types)),
        span,
    )
}

/// Constructs an "ambiguous argument" diagnostic.
pub fn ambiguous_argument(name: &str, span: Span, first: &str, second: &str) -> Diagnostic {
    Diagnostic::error(format!(
        "ambiguous call to function `{name}` with conflicting signatures `{first}` and `{second}`",
    ))
    .with_highlight(span)
}

/// Constructs an "index type mismatch" diagnostic.
pub fn index_type_mismatch(
    types: &Types,
    expected: Type,
    actual: Type,
    actual_span: Span,
) -> Diagnostic {
    Diagnostic::error(format!(
        "index type mismatch: expected type `{expected}`, but found type `{actual}`",
        expected = expected.display(types),
        actual = actual.display(types)
    ))
    .with_label(
        format!("this is type `{actual}`", actual = actual.display(types)),
        actual_span,
    )
}

/// Constructs an "cannot index" diagnostic.
pub fn cannot_index(types: &Types, actual: Type, actual_span: Span) -> Diagnostic {
    Diagnostic::error(format!(
        "cannot index type `{actual}`",
        actual = actual.display(types)
    ))
    .with_label(
        format!("this is type `{actual}`", actual = actual.display(types)),
        actual_span,
    )
}

/// Constructs a "cannot access" diagnostic.
pub fn cannot_access(types: &Types, actual: Type, actual_span: Span) -> Diagnostic {
    Diagnostic::error(format!(
        "cannot access type `{actual}`",
        actual = actual.display(types)
    ))
    .with_label(
        format!("this is type `{actual}`", actual = actual.display(types)),
        actual_span,
    )
}

/// Constructs a "cannot coerce to string" diagnostic.
pub fn cannot_coerce_to_string(types: &Types, actual: Type, span: Span) -> Diagnostic {
    Diagnostic::error(format!(
        "cannot coerce type `{actual}` to `String`",
        actual = actual.display(types)
    ))
    .with_label(
        format!("this is type `{actual}`", actual = actual.display(types)),
        span,
    )
}
