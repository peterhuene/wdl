//! Implements the `write_objects` function from the WDL standard library.

use std::io::BufWriter;
use std::io::Write;
use std::path::Path;

use tempfile::NamedTempFile;
use wdl_analysis::types::CompoundTypeDef;
use wdl_analysis::types::PrimitiveTypeKind;
use wdl_analysis::types::Type;
use wdl_ast::Diagnostic;

use super::CallContext;
use super::Function;
use super::Signature;
use crate::CompoundValue;
use crate::Object;
use crate::PrimitiveValue;
use crate::Struct;
use crate::Value;
use crate::diagnostics::function_call_failed;
use crate::stdlib::write_tsv::write_tsv_value;

/// Writes a tab-separated value (TSV) file with the contents of a Array[Struct]
/// or Array[Object].
///
/// All elements of the Array must have the same member names, or an error is
/// raised.
///
/// The file contains N+1 tab-delimited lines, where N is the number of elements
/// in the Array. The first line is the names of the Struct/Object members, and
/// the subsequent lines are the corresponding values for each element. Each
/// line is terminated by a newline (\n) character. The lines are written in the
/// same order as the elements in the Array. The ordering of the columns is the
/// same as the order in which the Struct's members are defined; the column
/// ordering for Objects is unspecified. If the Array is empty, an empty file is
/// written.
///
/// The member values must be serializable to strings, meaning that only
/// primitive types are supported. Attempting to write a Struct or Object that
/// has a compound member value results in an error.
///
/// https://github.com/openwdl/wdl/blob/wdl-1.2/SPEC.md#write_objects
fn write_objects(context: CallContext<'_>) -> Result<Value, Diagnostic> {
    debug_assert!(context.arguments.len() == 1);
    debug_assert!(context.return_type_eq(PrimitiveTypeKind::File));

    // Helper for handling errors while writing to the file.
    let write_error = |e: std::io::Error| {
        function_call_failed(
            "write_objects",
            format!("failed to write to temporary file: {e}"),
            context.call_site,
        )
    };

    let array = context.arguments[0]
        .value
        .as_array()
        .expect("argument should be an array");

    // Create a temporary file that will be persisted after writing the map
    let mut file = NamedTempFile::new_in(context.tmp()).map_err(|e| {
        function_call_failed(
            "write_objects",
            format!("failed to create temporary file: {e}"),
            context.call_site,
        )
    })?;

    let element_type = match context.arguments[0].value.ty() {
        Type::Compound(ty) => match context.types().type_definition(ty.definition()) {
            CompoundTypeDef::Array(ty) => ty.element_type(),
            _ => panic!("expected an array type for the argument"),
        },
        _ => panic!("expected a compound type for the argument"),
    };

    // If it's an array of objects, we need to ensure each object has the exact same
    // member names
    let mut empty = array.is_empty();
    if matches!(element_type, Type::Object) {
        let mut iter = array.elements().iter();
        let expected = iter
            .next()
            .expect("should be non-empty")
            .as_object()
            .expect("should be object")
            .members();

        empty = expected.is_empty();
        for v in iter {
            let next = v
                .as_object()
                .expect("element should be an object")
                .members();
            if next.len() != expected.len() || next.keys().any(|k| !expected.contains_key(k)) {
                return Err(function_call_failed(
                    "write_objects",
                    "expected every object to have the same member names",
                    context.call_site,
                ));
            }
        }
    }

    let mut writer = BufWriter::new(file.as_file_mut());
    if !empty {
        // Write the header first
        let keys = match array.elements().first().expect("array should not be empty") {
            Value::Compound(CompoundValue::Object(Object { members, .. }))
            | Value::Compound(CompoundValue::Struct(Struct { members, .. })) => members.keys(),
            _ => unreachable!("value should either be an object or struct"),
        };

        for (i, key) in keys.enumerate() {
            if i > 0 {
                writer.write(b"\t").map_err(write_error)?;
            }

            writer.write(key.as_bytes()).map_err(write_error)?;
        }

        writeln!(&mut writer).map_err(write_error)?;

        // Next, write a row for each object/struct
        for v in array.elements().iter() {
            let members = match v {
                Value::Compound(CompoundValue::Object(Object { members, .. }))
                | Value::Compound(CompoundValue::Struct(Struct { members, .. })) => members,
                _ => unreachable!("value should either be an object or struct"),
            };

            for (i, (k, v)) in members.iter().enumerate() {
                if i > 0 {
                    writer.write(b"\t").map_err(write_error)?;
                }

                match v {
                    Value::Primitive(v) => {
                        if !write_tsv_value(&mut writer, v).map_err(write_error)? {
                            return Err(function_call_failed(
                                "write_objects",
                                format!("member `{k}` contains a tab character"),
                                context.call_site,
                            ));
                        }
                    }
                    _ => {
                        return Err(function_call_failed(
                            "write_objects",
                            format!("member `{k}` is not a primitive value"),
                            context.call_site,
                        ));
                    }
                }
            }

            writeln!(&mut writer).map_err(write_error)?;
        }
    }

    // Consume the writer, flushing the buffer to disk.
    writer
        .into_inner()
        .map_err(|e| write_error(e.into_error()))?;

    let (_, path) = file.keep().map_err(|e| {
        function_call_failed(
            "write_objects",
            format!("failed to keep temporary file: {e}"),
            context.call_site,
        )
    })?;

    Ok(
        PrimitiveValue::new_file(path.into_os_string().into_string().map_err(|path| {
            function_call_failed(
                "write_objects",
                format!(
                    "path `{path}` cannot be represented as UTF-8",
                    path = Path::new(&path).display()
                ),
                context.call_site,
            )
        })?)
        .into(),
    )
}

/// Gets the function describing `write_objects`.
pub const fn descriptor() -> Function {
    Function::new(
        const {
            &[
                Signature::new("(Array[Object]) -> File", write_objects),
                Signature::new(
                    "(Array[S]) -> File where `S`: any structure containing only primitive types",
                    write_objects,
                ),
            ]
        },
    )
}

#[cfg(test)]
mod test {
    use std::fs;

    use pretty_assertions::assert_eq;
    use wdl_analysis::types::PrimitiveTypeKind;
    use wdl_analysis::types::StructType;
    use wdl_ast::version::V1;

    use crate::v1::test::TestEnv;
    use crate::v1::test::eval_v1_expr;

    #[test]
    fn write_objects() {
        let mut env = TestEnv::default();

        let ty = env.types_mut().add_struct(StructType::new("Foo", [
            ("foo", PrimitiveTypeKind::Integer),
            ("bar", PrimitiveTypeKind::String),
            ("baz", PrimitiveTypeKind::Boolean),
        ]));

        env.insert_struct("Foo", ty);

        let value = eval_v1_expr(&mut env, V1::Two, "write_objects([object {}])").unwrap();
        assert!(
            value
                .as_file()
                .expect("should be file")
                .as_str()
                .starts_with(env.tmp().to_str().expect("should be UTF-8")),
            "file should be in temp directory"
        );
        assert_eq!(
            fs::read_to_string(value.unwrap_file().as_str()).expect("failed to read file"),
            "",
        );

        let value = eval_v1_expr(
            &mut env,
            V1::Two,
            "write_objects([object { foo: 'bar', bar: 1, baz: 3.5 }, object { foo: 'foo', bar: \
             101, baz: 1234 }, ])",
        )
        .unwrap();
        assert!(
            value
                .as_file()
                .expect("should be file")
                .as_str()
                .starts_with(env.tmp().to_str().expect("should be UTF-8")),
            "file should be in temp directory"
        );
        assert_eq!(
            fs::read_to_string(value.unwrap_file().as_str()).expect("failed to read file"),
            "foo\tbar\tbaz\nbar\t1\t3.5\nfoo\t101\t1234\n",
        );

        let value = eval_v1_expr(
            &mut env,
            V1::Two,
            "write_objects([Foo { foo: 1, bar: 'foo', baz: true }, Foo { foo: -10, bar: 'bar', \
             baz: false }])",
        )
        .unwrap();
        assert!(
            value
                .as_file()
                .expect("should be file")
                .as_str()
                .starts_with(env.tmp().to_str().expect("should be UTF-8")),
            "file should be in temp directory"
        );
        assert_eq!(
            fs::read_to_string(value.unwrap_file().as_str()).expect("failed to read file"),
            "foo\tbar\tbaz\n1\tfoo\ttrue\n-10\tbar\tfalse\n",
        );

        let diagnostic =
            eval_v1_expr(&mut env, V1::Two, "write_objects([object { foo: [] }])").unwrap_err();
        assert_eq!(
            diagnostic.message(),
            "call to function `write_objects` failed: member `foo` is not a primitive value"
        );

        let diagnostic = eval_v1_expr(
            &mut env,
            V1::Two,
            "write_objects([object { foo: '\tbar' }])",
        )
        .unwrap_err();
        assert_eq!(
            diagnostic.message(),
            "call to function `write_objects` failed: member `foo` contains a tab character"
        );

        let diagnostic = eval_v1_expr(
            &mut env,
            V1::Two,
            "write_objects([object { foo: 1 }, object { bar: 2 }])",
        )
        .unwrap_err();
        assert_eq!(
            diagnostic.message(),
            "call to function `write_objects` failed: expected every object to have the same \
             member names"
        );
    }
}