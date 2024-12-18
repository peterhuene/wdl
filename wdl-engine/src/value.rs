//! Implementation of the WDL runtime and values.

use std::cmp::Ordering;
use std::fmt;
use std::hash::Hash;
use std::hash::Hasher;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use indexmap::IndexMap;
use ordered_float::OrderedFloat;
use serde_json::Value as JsonValue;
use wdl_analysis::types::ArrayType;
use wdl_analysis::types::CompoundTypeDef;
use wdl_analysis::types::Optional;
use wdl_analysis::types::PrimitiveTypeKind;
use wdl_analysis::types::Type;
use wdl_analysis::types::TypeEq;
use wdl_analysis::types::Types;

/// Implemented on coercible values.
pub trait Coercible: Sized {
    /// Coerces the value into the given type.
    ///
    /// Returns an error if the coercion is not supported.
    ///
    /// # Panics
    ///
    /// Panics if the provided target type is not from the given types
    /// collection.
    fn coerce(&self, types: &Types, target: Type) -> Result<Self>;
}

/// Represents a WDL runtime value.
#[derive(Debug, Clone)]
pub enum Value {
    /// The value is a literal `None` value.
    None,
    /// The value is a primitive value.
    Primitive(PrimitiveValue),
    /// The value is a compound value.
    Compound(CompoundValue),
}

impl Value {
    /// Converts a JSON value into a WDL value.
    ///
    /// Returns an error if the JSON value cannot be represented as a WDL value.
    pub fn from_json(types: &mut Types, value: JsonValue) -> Result<Self> {
        match value {
            JsonValue::Null => Ok(Value::None),
            JsonValue::Bool(value) => Ok(value.into()),
            JsonValue::Number(number) => {
                if let Some(value) = number.as_i64() {
                    Ok(value.into())
                } else if let Some(value) = number.as_f64() {
                    Ok(value.into())
                } else {
                    bail!("number `{number}` is out of range for a WDL value")
                }
            }
            JsonValue::String(s) => Ok(PrimitiveValue::new_string(s).into()),
            JsonValue::Array(elements) => {
                let elements = elements
                    .into_iter()
                    .map(|v| Self::from_json(types, v))
                    .collect::<Result<Vec<_>>>()?;

                let element_ty = elements
                    .iter()
                    .try_fold(None, |mut ty, element| {
                        let element_ty = element.ty();
                        let ty = ty.get_or_insert(element_ty);
                        ty.common_type(types, element_ty).map(Some).ok_or_else(|| {
                            anyhow!(
                                "a common element type does not exist between `{ty}` and \
                                 `{element_ty}`",
                                ty = ty.display(types),
                                element_ty = element_ty.display(types)
                            )
                        })
                    })
                    .context("invalid WDL array value")?
                    .unwrap_or(Type::Union);

                let ty = types.add_array(ArrayType::new(element_ty));
                Ok(Array::new(types, ty, elements)
                    .with_context(|| {
                        format!("cannot coerce value to `{ty}`", ty = ty.display(types))
                    })?
                    .into())
            }
            JsonValue::Object(elements) => Ok(Object::new(
                elements
                    .into_iter()
                    .map(|(k, v)| Ok((k, Self::from_json(types, v)?)))
                    .collect::<Result<Vec<_>>>()?,
            )
            .into()),
        }
    }

    /// Gets the type of the value.
    pub fn ty(&self) -> Type {
        match self {
            Self::None => Type::None,
            Self::Primitive(v) => v.ty(),
            Self::Compound(v) => v.ty(),
        }
    }

    /// Determines if the value is `None`.
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    /// Gets the value as a `Boolean`.
    ///
    /// Returns `None` if the value is not a `Boolean`.
    pub fn as_boolean(&self) -> Option<bool> {
        match self {
            Self::Primitive(PrimitiveValue::Boolean(v)) => Some(*v),
            _ => None,
        }
    }

    /// Unwraps the value into a `Boolean`.
    ///
    /// # Panics
    ///
    /// Panics if the value is not a `Boolean`.
    pub fn unwrap_boolean(self) -> bool {
        match self {
            Self::Primitive(PrimitiveValue::Boolean(v)) => v,
            _ => panic!("value is not a boolean"),
        }
    }

    /// Gets the value as an `Int`.
    ///
    /// Returns `None` if the value is not an `Int`.
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Primitive(PrimitiveValue::Integer(v)) => Some(*v),
            _ => None,
        }
    }

    /// Unwraps the value into an integer.
    ///
    /// # Panics
    ///
    /// Panics if the value is not an integer.
    pub fn unwrap_integer(self) -> i64 {
        match self {
            Self::Primitive(PrimitiveValue::Integer(v)) => v,
            _ => panic!("value is not an integer"),
        }
    }

    /// Gets the value as a `Float`.
    ///
    /// Returns `None` if the value is not a `Float`.
    pub fn as_float(&self) -> Option<f64> {
        match self {
            Self::Primitive(PrimitiveValue::Float(v)) => Some((*v).into()),
            _ => None,
        }
    }

    /// Unwraps the value into a `Float`.
    ///
    /// # Panics
    ///
    /// Panics if the value is not a `Float`.
    pub fn unwrap_float(self) -> f64 {
        match self {
            Self::Primitive(PrimitiveValue::Float(v)) => v.into(),
            _ => panic!("value is not a float"),
        }
    }

    /// Gets the value as a `String`.
    ///
    /// Returns `None` if the value is not a `String`.
    pub fn as_string(&self) -> Option<&Arc<String>> {
        match self {
            Self::Primitive(PrimitiveValue::String(s)) => Some(s),
            _ => panic!("value is not a string"),
        }
    }

    /// Unwraps the value into a `String`.
    ///
    /// # Panics
    ///
    /// Panics if the value is not a `String`.
    pub fn unwrap_string(self) -> Arc<String> {
        match self {
            Self::Primitive(PrimitiveValue::String(s)) => s,
            _ => panic!("value is not a string"),
        }
    }

    /// Gets the value as a `File`.
    ///
    /// Returns `None` if the value is not a `File`.
    pub fn as_file(&self) -> Option<&Arc<String>> {
        match self {
            Self::Primitive(PrimitiveValue::File(s)) => Some(s),
            _ => None,
        }
    }

    /// Unwraps the value into a `File`.
    ///
    /// # Panics
    ///
    /// Panics if the value is not a `File`.
    pub fn unwrap_file(self) -> Arc<String> {
        match self {
            Self::Primitive(PrimitiveValue::File(s)) => s,
            _ => panic!("value is not a file"),
        }
    }

    /// Gets the value as a `Directory`.
    ///
    /// Returns `None` if the value is not a `Directory`.
    pub fn as_directory(&self) -> Option<&Arc<String>> {
        match self {
            Self::Primitive(PrimitiveValue::Directory(s)) => Some(s),
            _ => None,
        }
    }

    /// Unwraps the value into a `Directory`.
    ///
    /// # Panics
    ///
    /// Panics if the value is not a `Directory`.
    pub fn unwrap_directory(self) -> Arc<String> {
        match self {
            Self::Primitive(PrimitiveValue::Directory(s)) => s,
            _ => panic!("value is not a directory"),
        }
    }

    /// Gets the value as a `Pair`.
    ///
    /// Returns `None` if the value is not a `Pair`.
    pub fn as_pair(&self) -> Option<&Pair> {
        match self {
            Self::Compound(CompoundValue::Pair(v)) => Some(v),
            _ => None,
        }
    }

    /// Unwraps the value into a `Pair`.
    ///
    /// # Panics
    ///
    /// Panics if the value is not a `Pair`.
    pub fn unwrap_pair(self) -> Pair {
        match self {
            Self::Compound(CompoundValue::Pair(v)) => v,
            _ => panic!("value is not a pair"),
        }
    }

    /// Gets the value as an `Array`.
    ///
    /// Returns `None` if the value is not an `Array`.
    pub fn as_array(&self) -> Option<&Array> {
        match self {
            Self::Compound(CompoundValue::Array(v)) => Some(v),
            _ => None,
        }
    }

    /// Unwraps the value into an `Array`.
    ///
    /// # Panics
    ///
    /// Panics if the value is not an `Array`.
    pub fn unwrap_array(self) -> Array {
        match self {
            Self::Compound(CompoundValue::Array(v)) => v,
            _ => panic!("value is not an array"),
        }
    }

    /// Gets the value as a `Map`.
    ///
    /// Returns `None` if the value is not a `Map`.
    pub fn as_map(&self) -> Option<&Map> {
        match self {
            Self::Compound(CompoundValue::Map(v)) => Some(v),
            _ => None,
        }
    }

    /// Unwraps the value into a `Map`.
    ///
    /// # Panics
    ///
    /// Panics if the value is not a `Map`.
    pub fn unwrap_map(self) -> Map {
        match self {
            Self::Compound(CompoundValue::Map(v)) => v,
            _ => panic!("value is not a map"),
        }
    }

    /// Gets the value as an `Object`.
    ///
    /// Returns `None` if the value is not an `Object`.
    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Self::Compound(CompoundValue::Object(v)) => Some(v),
            _ => None,
        }
    }

    /// Unwraps the value into an `Object`.
    ///
    /// # Panics
    ///
    /// Panics if the value is not an `Object`.
    pub fn unwrap_object(self) -> Object {
        match self {
            Self::Compound(CompoundValue::Object(v)) => v,
            _ => panic!("value is not an object"),
        }
    }

    /// Gets the value as a `Struct`.
    ///
    /// Returns `None` if the value is not a `Struct`.
    pub fn as_struct(&self) -> Option<&Struct> {
        match self {
            Self::Compound(CompoundValue::Struct(v)) => Some(v),
            _ => None,
        }
    }

    /// Unwraps the value into a `Struct`.
    ///
    /// # Panics
    ///
    /// Panics if the value is not a `Map`.
    pub fn unwrap_struct(self) -> Struct {
        match self {
            Self::Compound(CompoundValue::Struct(v)) => v,
            _ => panic!("value is not a struct"),
        }
    }

    /// Determines if two values have equality according to the WDL
    /// specification.
    ///
    /// Returns `None` if the two values cannot be compared for equality.
    pub fn equals(types: &Types, left: &Self, right: &Self) -> Option<bool> {
        match (left, right) {
            (Value::None, Value::None) => Some(true),
            (Value::None, _) | (_, Value::None) => Some(false),
            (Value::Primitive(left), Value::Primitive(right)) => {
                Some(PrimitiveValue::compare(left, right)? == Ordering::Equal)
            }
            (Value::Compound(left), Value::Compound(right)) => {
                CompoundValue::equals(types, left, right)
            }
            _ => None,
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::None => write!(f, "None"),
            Value::Primitive(v) => v.fmt(f),
            Value::Compound(v) => v.fmt(f),
        }
    }
}

impl Coercible for Value {
    fn coerce(&self, types: &Types, target: Type) -> Result<Self> {
        if self.ty().type_eq(types, &target) {
            return Ok(self.clone());
        }

        match self {
            Self::None => {
                if target.is_optional() {
                    Ok(Self::None)
                } else {
                    bail!(
                        "cannot coerce `None` to non-optional type `{target}`",
                        target = target.display(types)
                    );
                }
            }
            Self::Primitive(v) => v.coerce(types, target).map(Self::Primitive),
            Self::Compound(v) => v.coerce(types, target).map(Self::Compound),
        }
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Primitive(value.into())
    }
}

impl From<i64> for Value {
    fn from(value: i64) -> Self {
        Self::Primitive(value.into())
    }
}

impl From<f64> for Value {
    fn from(value: f64) -> Self {
        Self::Primitive(value.into())
    }
}

impl From<PrimitiveValue> for Value {
    fn from(value: PrimitiveValue) -> Self {
        Self::Primitive(value)
    }
}

impl From<Pair> for Value {
    fn from(value: Pair) -> Self {
        Self::Compound(value.into())
    }
}

impl From<Array> for Value {
    fn from(value: Array) -> Self {
        Self::Compound(value.into())
    }
}

impl From<Map> for Value {
    fn from(value: Map) -> Self {
        Self::Compound(value.into())
    }
}

impl From<Object> for Value {
    fn from(value: Object) -> Self {
        Self::Compound(value.into())
    }
}

impl From<Struct> for Value {
    fn from(value: Struct) -> Self {
        Self::Compound(value.into())
    }
}

impl From<CompoundValue> for Value {
    fn from(value: CompoundValue) -> Self {
        Self::Compound(value)
    }
}

/// Represents a primitive WDL value.
#[derive(Debug, Clone)]
pub enum PrimitiveValue {
    /// The value is a `Boolean`.
    Boolean(bool),
    /// The value is an `Int`.
    Integer(i64),
    /// The value is a `Float`.
    Float(OrderedFloat<f64>),
    /// The value is a `String`.
    String(Arc<String>),
    /// The value is a `File`.
    File(Arc<String>),
    /// The value is a `Directory`.
    Directory(Arc<String>),
}

impl PrimitiveValue {
    /// Creates a new `String` value.
    pub fn new_string(s: impl Into<String>) -> Self {
        Self::String(Arc::new(s.into()))
    }

    /// Creates a new `File` value.
    pub fn new_file(s: impl Into<String>) -> Self {
        Self::File(Arc::new(s.into()))
    }

    /// Creates a new `Directory` value.
    pub fn new_directory(s: impl Into<String>) -> Self {
        Self::Directory(Arc::new(s.into()))
    }

    /// Gets the type of the value.
    pub fn ty(&self) -> Type {
        match self {
            Self::Boolean(_) => PrimitiveTypeKind::Boolean.into(),
            Self::Integer(_) => PrimitiveTypeKind::Integer.into(),
            Self::Float(_) => PrimitiveTypeKind::Float.into(),
            Self::String(_) => PrimitiveTypeKind::String.into(),
            Self::File(_) => PrimitiveTypeKind::File.into(),
            Self::Directory(_) => PrimitiveTypeKind::Directory.into(),
        }
    }

    /// Gets the value as a `Boolean`.
    ///
    /// Returns `None` if the value is not a `Boolean`.
    pub fn as_boolean(&self) -> Option<bool> {
        match self {
            Self::Boolean(v) => Some(*v),
            _ => None,
        }
    }

    /// Unwraps the value into a `Boolean`.
    ///
    /// # Panics
    ///
    /// Panics if the value is not a `Boolean`.
    pub fn unwrap_boolean(self) -> bool {
        match self {
            Self::Boolean(v) => v,
            _ => panic!("value is not a boolean"),
        }
    }

    /// Gets the value as an `Int`.
    ///
    /// Returns `None` if the value is not an `Int`.
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(v) => Some(*v),
            _ => None,
        }
    }

    /// Unwraps the value into an integer.
    ///
    /// # Panics
    ///
    /// Panics if the value is not an integer.
    pub fn unwrap_integer(self) -> i64 {
        match self {
            Self::Integer(v) => v,
            _ => panic!("value is not an integer"),
        }
    }

    /// Gets the value as a `Float`.
    ///
    /// Returns `None` if the value is not a `Float`.
    pub fn as_float(&self) -> Option<f64> {
        match self {
            Self::Float(v) => Some((*v).into()),
            _ => None,
        }
    }

    /// Unwraps the value into a `Float`.
    ///
    /// # Panics
    ///
    /// Panics if the value is not a `Float`.
    pub fn unwrap_float(self) -> f64 {
        match self {
            Self::Float(v) => v.into(),
            _ => panic!("value is not a float"),
        }
    }

    /// Gets the value as a `String`.
    ///
    /// Returns `None` if the value is not a `String`.
    pub fn as_string(&self) -> Option<&Arc<String>> {
        match self {
            Self::String(s) => Some(s),
            _ => panic!("value is not a string"),
        }
    }

    /// Unwraps the value into a `String`.
    ///
    /// # Panics
    ///
    /// Panics if the value is not a `String`.
    pub fn unwrap_string(self) -> Arc<String> {
        match self {
            Self::String(s) => s,
            _ => panic!("value is not a string"),
        }
    }

    /// Gets the value as a `File`.
    ///
    /// Returns `None` if the value is not a `File`.
    pub fn as_file(&self) -> Option<&Arc<String>> {
        match self {
            Self::File(s) => Some(s),
            _ => None,
        }
    }

    /// Unwraps the value into a `File`.
    ///
    /// # Panics
    ///
    /// Panics if the value is not a `File`.
    pub fn unwrap_file(self) -> Arc<String> {
        match self {
            Self::File(s) => s,
            _ => panic!("value is not a file"),
        }
    }

    /// Gets the value as a `Directory`.
    ///
    /// Returns `None` if the value is not a `Directory`.
    pub fn as_directory(&self) -> Option<&Arc<String>> {
        match self {
            Self::Directory(s) => Some(s),
            _ => None,
        }
    }

    /// Unwraps the value into a `Directory`.
    ///
    /// # Panics
    ///
    /// Panics if the value is not a `Directory`.
    pub fn unwrap_directory(self) -> Arc<String> {
        match self {
            Self::Directory(s) => s,
            _ => panic!("value is not a directory"),
        }
    }

    /// Compares two values for an ordering according to the WDL specification.
    ///
    /// Unlike a `PartialOrd` implementation, this takes into account automatic
    /// coercions.
    ///
    /// Returns `None` if the values cannot be compared based on their types.
    pub fn compare(left: &Self, right: &Self) -> Option<Ordering> {
        match (left, right) {
            (PrimitiveValue::Boolean(left), PrimitiveValue::Boolean(right)) => {
                Some(left.cmp(right))
            }
            (PrimitiveValue::Integer(left), PrimitiveValue::Integer(right)) => {
                Some(left.cmp(right))
            }
            (PrimitiveValue::Integer(left), PrimitiveValue::Float(right)) => {
                Some(OrderedFloat(*left as f64).cmp(right))
            }
            (PrimitiveValue::Float(left), PrimitiveValue::Integer(right)) => {
                Some(left.cmp(&OrderedFloat(*right as f64)))
            }
            (PrimitiveValue::Float(left), PrimitiveValue::Float(right)) => Some(left.cmp(right)),
            (PrimitiveValue::String(left), PrimitiveValue::String(right))
            | (PrimitiveValue::String(left), PrimitiveValue::File(right))
            | (PrimitiveValue::String(left), PrimitiveValue::Directory(right))
            | (PrimitiveValue::File(left), PrimitiveValue::File(right))
            | (PrimitiveValue::File(left), PrimitiveValue::String(right))
            | (PrimitiveValue::Directory(left), PrimitiveValue::Directory(right))
            | (PrimitiveValue::Directory(left), PrimitiveValue::String(right)) => {
                Some(left.cmp(right))
            }
            _ => None,
        }
    }
}

impl fmt::Display for PrimitiveValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrimitiveValue::Boolean(v) => write!(f, "{v}"),
            PrimitiveValue::Integer(v) => write!(f, "{v}"),
            PrimitiveValue::Float(v) => write!(f, "{v:?}"),
            PrimitiveValue::String(s) | PrimitiveValue::File(s) | PrimitiveValue::Directory(s) => {
                // TODO: handle necessary escape sequences
                write!(f, "\"{s}\"")
            }
        }
    }
}

impl PartialEq for PrimitiveValue {
    fn eq(&self, other: &Self) -> bool {
        Self::compare(self, other) == Some(Ordering::Equal)
    }
}

impl Eq for PrimitiveValue {}

impl Hash for PrimitiveValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Self::Boolean(v) => {
                0.hash(state);
                v.hash(state);
            }
            Self::Integer(v) => {
                1.hash(state);
                v.hash(state);
            }
            Self::Float(v) => {
                // Hash this with the same discriminant as integer; this allows coercion from
                // int to float.
                1.hash(state);
                v.hash(state);
            }
            Self::String(v) | Self::File(v) | Self::Directory(v) => {
                // Hash these with the same discriminant; this allows coercion from file and
                // directory to string
                2.hash(state);
                v.hash(state);
            }
        }
    }
}

impl From<bool> for PrimitiveValue {
    fn from(value: bool) -> Self {
        Self::Boolean(value)
    }
}

impl From<i64> for PrimitiveValue {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<f64> for PrimitiveValue {
    fn from(value: f64) -> Self {
        Self::Float(value.into())
    }
}

impl Coercible for PrimitiveValue {
    fn coerce(&self, types: &Types, target: Type) -> Result<Self> {
        if self.ty().type_eq(types, &target) {
            return Ok(self.clone());
        }

        match self {
            Self::Boolean(v) => {
                target
                    .as_primitive()
                    .and_then(|ty| match ty.kind() {
                        // Boolean -> Boolean
                        PrimitiveTypeKind::Boolean => Some(Self::Boolean(*v)),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        anyhow!(
                            "cannot coerce type `Boolean` to type `{target}`",
                            target = target.display(types)
                        )
                    })
            }
            Self::Integer(v) => {
                target
                    .as_primitive()
                    .and_then(|ty| match ty.kind() {
                        // Int -> Int
                        PrimitiveTypeKind::Integer => Some(Self::Integer(*v)),
                        // Int -> Float
                        PrimitiveTypeKind::Float => Some(Self::Float((*v as f64).into())),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        anyhow!(
                            "cannot coerce type `Int` to type `{target}`",
                            target = target.display(types)
                        )
                    })
            }
            Self::Float(v) => {
                target
                    .as_primitive()
                    .and_then(|ty| match ty.kind() {
                        // Float -> Float
                        PrimitiveTypeKind::Float => Some(Self::Float(*v)),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        anyhow!(
                            "cannot coerce type `Float` to type `{target}`",
                            target = target.display(types)
                        )
                    })
            }
            Self::String(s) => {
                target
                    .as_primitive()
                    .and_then(|ty| match ty.kind() {
                        // String -> String
                        PrimitiveTypeKind::String => Some(Self::String(s.clone())),
                        // String -> File
                        PrimitiveTypeKind::File => Some(Self::File(s.clone())),
                        // String -> Directory
                        PrimitiveTypeKind::Directory => Some(Self::Directory(s.clone())),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        anyhow!(
                            "cannot coerce type `String` to type `{target}`",
                            target = target.display(types)
                        )
                    })
            }
            Self::File(s) => {
                target
                    .as_primitive()
                    .and_then(|ty| match ty.kind() {
                        // File -> File
                        PrimitiveTypeKind::File => Some(Self::File(s.clone())),
                        // File -> String
                        PrimitiveTypeKind::String => Some(Self::String(s.clone())),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        anyhow!(
                            "cannot coerce type `File` to type `{target}`",
                            target = target.display(types)
                        )
                    })
            }
            Self::Directory(s) => {
                target
                    .as_primitive()
                    .and_then(|ty| match ty.kind() {
                        // Directory -> Directory
                        PrimitiveTypeKind::Directory => Some(Self::Directory(s.clone())),
                        // Directory -> String
                        PrimitiveTypeKind::String => Some(Self::String(s.clone())),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        anyhow!(
                            "cannot coerce type `Directory` to type `{target}`",
                            target = target.display(types)
                        )
                    })
            }
        }
    }
}

/// Represents a `Pair` value.
#[derive(Debug, Clone)]
pub struct Pair {
    /// The type of the pair.
    ty: Type,
    /// The left value of the pair.
    left: Arc<Value>,
    /// The right value of the pair.
    right: Arc<Value>,
}

impl Pair {
    /// Creates a new `Pair` value.
    ///
    /// Returns an error if either the `left` value or the `right` value did not
    /// coerce to the pair's `left` type or `right` type, respectively.
    ///
    /// # Panics
    ///
    /// Panics if the given type is not a pair type from the given types
    /// collection.
    pub fn new(
        types: &Types,
        ty: Type,
        left: impl Into<Value>,
        right: impl Into<Value>,
    ) -> Result<Self> {
        if let Type::Compound(compound_ty) = ty {
            if let CompoundTypeDef::Pair(pair_ty) = types.type_definition(compound_ty.definition())
            {
                let left_ty = pair_ty.left_type();
                let right_ty = pair_ty.right_type();
                return Ok(Self {
                    ty,
                    left: left
                        .into()
                        .coerce(types, left_ty)
                        .context("failed to coerce pair's left value")?
                        .into(),
                    right: right
                        .into()
                        .coerce(types, right_ty)
                        .context("failed to coerce pair's right value")?
                        .into(),
                });
            }
        }

        panic!("type `{ty}` is not a pair type", ty = ty.display(types));
    }

    /// Gets the type of the `Pair`.
    pub fn ty(&self) -> Type {
        self.ty
    }

    /// Gets the left value of the `Pair`.
    pub fn left(&self) -> &Value {
        &self.left
    }

    /// Gets the right value of the `Pair`.
    pub fn right(&self) -> &Value {
        &self.right
    }
}

impl fmt::Display for Pair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({left}, {right})", left = self.left, right = self.right)
    }
}

/// Represents an `Array` value.
#[derive(Debug, Clone)]
pub struct Array {
    /// The type of the array.
    ty: Type,
    /// The array's elements.
    elements: Arc<[Value]>,
}

impl Array {
    /// Creates a new `Array` value for the given array type.
    ///
    /// Returns an error if an element did not coerce to the array's element
    /// type.
    ///
    /// # Panics
    ///
    /// Panics if the given type is not an array type from the types collection.
    pub fn new<V>(types: &Types, ty: Type, elements: impl IntoIterator<Item = V>) -> Result<Self>
    where
        V: Into<Value>,
    {
        if let Type::Compound(compound_ty) = ty {
            if let CompoundTypeDef::Array(array_ty) =
                types.type_definition(compound_ty.definition())
            {
                let element_type = array_ty.element_type();
                return Ok(Self {
                    ty,
                    elements: elements
                        .into_iter()
                        .enumerate()
                        .map(|(i, v)| {
                            let v = v.into();
                            v.coerce(types, element_type).with_context(|| {
                                format!("failed to coerce array element at index {i}")
                            })
                        })
                        .collect::<Result<_>>()?,
                });
            }
        }

        panic!("type `{ty}` is not an array type", ty = ty.display(types));
    }

    /// Gets the type of the `Array` value.
    pub fn ty(&self) -> Type {
        self.ty
    }

    /// Gets the elements of the `Array` value.
    pub fn elements(&self) -> &[Value] {
        &self.elements
    }
}

impl fmt::Display for Array {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;

        for (i, element) in self.elements.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }

            write!(f, "{element}")?;
        }

        write!(f, "]")
    }
}

/// Represents a `Map` value.
#[derive(Debug, Clone)]
pub struct Map {
    /// The type of the map value.
    ty: Type,
    /// The elements of the map value.
    elements: Arc<IndexMap<PrimitiveValue, Value>>,
}

impl Map {
    /// Creates a new `Map` value.
    ///
    /// Returns an error if an key or value did not coerce to the map's key or
    /// value type, respectively.
    ///
    /// # Panics
    ///
    /// Panics if the given type is not a map type from the given types
    /// collection.
    pub fn new<K, V>(
        types: &Types,
        ty: Type,
        elements: impl IntoIterator<Item = (K, V)>,
    ) -> Result<Self>
    where
        K: Into<PrimitiveValue>,
        V: Into<Value>,
    {
        if let Type::Compound(compound_ty) = ty {
            if let CompoundTypeDef::Map(map_ty) = types.type_definition(compound_ty.definition()) {
                let key_type = map_ty.key_type();
                let value_type = map_ty.value_type();

                return Ok(Self {
                    ty,
                    elements: Arc::new(
                        elements
                            .into_iter()
                            .enumerate()
                            .map(|(i, (k, v))| {
                                let k = k.into();
                                let v = v.into();
                                Ok((
                                    k.coerce(types, key_type).with_context(|| {
                                        format!("failed to coerce map key for element at index {i}")
                                    })?,
                                    v.coerce(types, value_type).with_context(|| {
                                        format!(
                                            "failed to coerce map value for element at index {i}"
                                        )
                                    })?,
                                ))
                            })
                            .collect::<Result<_>>()?,
                    ),
                });
            }
        }

        panic!("type `{ty}` is not a map type", ty = ty.display(types));
    }

    /// Gets the type of the `Map` value.
    pub fn ty(&self) -> Type {
        self.ty
    }

    /// Gets the elements of the `Map` value.
    pub fn elements(&self) -> &IndexMap<PrimitiveValue, Value> {
        &self.elements
    }
}

impl fmt::Display for Map {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{")?;

        for (i, (k, v)) in self.elements.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }

            write!(f, "{k}: {v}")?;
        }

        write!(f, "}}")
    }
}

/// Represents an `Object` value.
#[derive(Debug, Clone)]
pub struct Object {
    /// The members of the object.
    members: Arc<IndexMap<String, Value>>,
}

impl Object {
    /// Creates a new `Object` value.
    pub fn new<S, V>(items: impl IntoIterator<Item = (S, V)>) -> Self
    where
        S: Into<String>,
        V: Into<Value>,
    {
        Self {
            members: Arc::new(
                items
                    .into_iter()
                    .map(|(n, v)| {
                        let n = n.into();
                        let v = v.into();
                        (n, v)
                    })
                    .collect(),
            ),
        }
    }

    /// Gets the type of the `Object` value.
    pub fn ty(&self) -> Type {
        Type::Object
    }

    /// Gets the members of the `Object` value.
    pub fn members(&self) -> &IndexMap<String, Value> {
        &self.members
    }
}

impl fmt::Display for Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "object {{")?;

        for (i, (k, v)) in self.members.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }

            write!(f, "{k}: {v}")?;
        }

        write!(f, "}}")
    }
}

impl From<IndexMap<String, Value>> for Object {
    fn from(members: IndexMap<String, Value>) -> Self {
        Self {
            members: Arc::new(members),
        }
    }
}

/// Represents a `Struct` value.
#[derive(Debug, Clone)]
pub struct Struct {
    /// The type of the struct value.
    ty: Type,
    /// The name of the struct.
    name: Arc<String>,
    /// The members of the struct value.
    members: Arc<IndexMap<String, Value>>,
}

impl Struct {
    /// Creates a new struct value.
    ///
    /// Returns an error if the struct type does not contain a member of a given
    /// name or if a value does not coerce to the corresponding member's type.
    ///
    /// # Panics
    ///
    /// Panics if the given type is not a struct type from the given types
    /// collection.
    pub fn new<S, V>(
        types: &Types,
        ty: Type,
        members: impl IntoIterator<Item = (S, V)>,
    ) -> Result<Self>
    where
        S: Into<String>,
        V: Into<Value>,
    {
        let mut members = members
            .into_iter()
            .map(|(n, v)| {
                let n = n.into();
                let v = v.into();
                let v = v
                    .coerce(
                        types,
                        *types.struct_type(ty).members().get(&n).ok_or_else(|| {
                            anyhow!("struct does not contain a member named `{n}`")
                        })?,
                    )
                    .with_context(|| format!("failed to coerce struct member `{n}`"))?;
                Ok((n, v))
            })
            .collect::<Result<IndexMap<_, _>>>()?;

        for (name, ty) in types.struct_type(ty).members().iter() {
            // Check for optional members that should be set to `None`
            if ty.is_optional() {
                if !members.contains_key(name) {
                    members.insert(name.clone(), Value::None);
                }
            } else {
                // Check for a missing required member
                if !members.contains_key(name) {
                    bail!("missing a value for struct member `{name}`");
                }
            }
        }

        Ok(Self {
            ty,
            name: types.struct_type(ty).name().clone(),
            members: Arc::new(members),
        })
    }

    /// Constructs a new struct without checking the given members conform to
    /// the given type.
    pub(crate) fn new_unchecked(
        ty: Type,
        name: Arc<String>,
        members: Arc<IndexMap<String, Value>>,
    ) -> Self {
        Self { ty, name, members }
    }

    /// Gets the type of the `Struct` value.
    pub fn ty(&self) -> Type {
        self.ty
    }

    /// Gets the name of the struct.
    pub fn name(&self) -> &Arc<String> {
        &self.name
    }

    /// Gets the members of the `Struct` value.
    pub fn members(&self) -> &IndexMap<String, Value> {
        &self.members
    }
}

impl fmt::Display for Struct {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{name} {{", name = self.name)?;

        for (i, (k, v)) in self.members.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }

            write!(f, "{k}: {v}")?;
        }

        write!(f, "}}")
    }
}

/// Represents a compound value.
///
/// Compound values may be trivially cloned.
#[derive(Debug, Clone)]
pub enum CompoundValue {
    /// The value is a `Pair` of values.
    Pair(Pair),
    /// The value is an `Array` of values.
    Array(Array),
    /// The value is a `Map` of values.
    Map(Map),
    /// The value is an `Object.`
    Object(Object),
    /// The value is a struct.
    Struct(Struct),
}

impl CompoundValue {
    /// Gets the type of the compound value.
    pub fn ty(&self) -> Type {
        match self {
            CompoundValue::Pair(v) => v.ty(),
            CompoundValue::Array(v) => v.ty(),
            CompoundValue::Map(v) => v.ty(),
            CompoundValue::Object(v) => v.ty(),
            CompoundValue::Struct(v) => v.ty(),
        }
    }

    /// Gets the value as a `Pair`.
    ///
    /// Returns `None` if the value is not a `Pair`.
    pub fn as_pair(&self) -> Option<&Pair> {
        match self {
            Self::Pair(v) => Some(v),
            _ => None,
        }
    }

    /// Unwraps the value into a `Pair`.
    ///
    /// # Panics
    ///
    /// Panics if the value is not a `Pair`.
    pub fn unwrap_pair(self) -> Pair {
        match self {
            Self::Pair(v) => v,
            _ => panic!("value is not a pair"),
        }
    }

    /// Gets the value as an `Array`.
    ///
    /// Returns `None` if the value is not an `Array`.
    pub fn as_array(&self) -> Option<&Array> {
        match self {
            Self::Array(v) => Some(v),
            _ => None,
        }
    }

    /// Unwraps the value into an `Array`.
    ///
    /// # Panics
    ///
    /// Panics if the value is not an `Array`.
    pub fn unwrap_array(self) -> Array {
        match self {
            Self::Array(v) => v,
            _ => panic!("value is not an array"),
        }
    }

    /// Gets the value as a `Map`.
    ///
    /// Returns `None` if the value is not a `Map`.
    pub fn as_map(&self) -> Option<&Map> {
        match self {
            Self::Map(v) => Some(v),
            _ => None,
        }
    }

    /// Unwraps the value into a `Map`.
    ///
    /// # Panics
    ///
    /// Panics if the value is not a `Map`.
    pub fn unwrap_map(self) -> Map {
        match self {
            Self::Map(v) => v,
            _ => panic!("value is not a map"),
        }
    }

    /// Gets the value as an `Object`.
    ///
    /// Returns `None` if the value is not an `Object`.
    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Self::Object(v) => Some(v),
            _ => None,
        }
    }

    /// Unwraps the value into an `Object`.
    ///
    /// # Panics
    ///
    /// Panics if the value is not an `Object`.
    pub fn unwrap_object(self) -> Object {
        match self {
            Self::Object(v) => v,
            _ => panic!("value is not an object"),
        }
    }

    /// Gets the value as a `Struct`.
    ///
    /// Returns `None` if the value is not a `Struct`.
    pub fn as_struct(&self) -> Option<&Struct> {
        match self {
            Self::Struct(v) => Some(v),
            _ => None,
        }
    }

    /// Unwraps the value into a `Struct`.
    ///
    /// # Panics
    ///
    /// Panics if the value is not a `Map`.
    pub fn unwrap_struct(self) -> Struct {
        match self {
            Self::Struct(v) => v,
            _ => panic!("value is not a struct"),
        }
    }

    /// Compares two compound values for equality based on the WDL
    /// specification.
    ///
    /// Returns `None` if the two compound values cannot be compared for
    /// equality.
    pub fn equals(types: &Types, left: &Self, right: &Self) -> Option<bool> {
        // The values must have type equivalence to compare for compound values
        // Coercion doesn't take place for this check
        if !left.ty().type_eq(types, &right.ty()) {
            return None;
        }

        match (left, right) {
            (Self::Pair(left), Self::Pair(right)) => Some(
                Value::equals(types, &left.left, &right.left)?
                    && Value::equals(types, &left.right, &right.right)?,
            ),
            (CompoundValue::Array(left), CompoundValue::Array(right)) => Some(
                left.elements.len() == right.elements.len()
                    && left
                        .elements
                        .iter()
                        .zip(right.elements.iter())
                        .all(|(l, r)| Value::equals(types, l, r).unwrap_or(false)),
            ),
            (CompoundValue::Map(left), CompoundValue::Map(right)) => Some(
                left.elements.len() == right.elements.len()
                    && left
                        .elements
                        .iter()
                        .all(|(k, left)| match right.elements.get(k) {
                            Some(right) => Value::equals(types, left, right).unwrap_or(false),
                            None => false,
                        }),
            ),
            (
                CompoundValue::Object(Object { members: left }),
                CompoundValue::Object(Object { members: right }),
            )
            | (
                CompoundValue::Struct(Struct { members: left, .. }),
                CompoundValue::Struct(Struct { members: right, .. }),
            ) => Some(
                left.len() == right.len()
                    && left.iter().all(|(k, left)| match right.get(k) {
                        Some(right) => Value::equals(types, left, right).unwrap_or(false),
                        None => false,
                    }),
            ),
            _ => None,
        }
    }
}

impl fmt::Display for CompoundValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompoundValue::Pair(v) => v.fmt(f),
            CompoundValue::Array(v) => v.fmt(f),
            CompoundValue::Map(v) => v.fmt(f),
            CompoundValue::Object(v) => v.fmt(f),
            CompoundValue::Struct(v) => v.fmt(f),
        }
    }
}

impl Coercible for CompoundValue {
    fn coerce(&self, types: &Types, target: Type) -> Result<Self> {
        if self.ty().type_eq(types, &target) {
            return Ok(self.clone());
        }

        if let Type::Compound(compound_ty) = target {
            match (self, types.type_definition(compound_ty.definition())) {
                // Array[X] -> Array[Y](+) where X -> Y
                (Self::Array(v), CompoundTypeDef::Array(array_ty)) => {
                    // Don't allow coercion when the source is empty but the target has the
                    // non-empty qualifier
                    if v.elements.is_empty() && array_ty.is_non_empty() {
                        bail!(
                            "cannot coerce empty array value to non-empty array type `{ty}`",
                            ty = array_ty.display(types)
                        );
                    }

                    return Ok(Self::Array(Array::new(
                        types,
                        target,
                        v.elements.iter().cloned(),
                    )?));
                }
                // Map[W, Y] -> Map[X, Z] where W -> X and Y -> Z
                (Self::Map(v), CompoundTypeDef::Map(_)) => {
                    return Ok(Self::Map(Map::new(
                        types,
                        target,
                        v.elements.iter().map(|(k, v)| (k.clone(), v.clone())),
                    )?));
                }
                // Pair[W, Y] -> Pair[X, Z] where W -> X and Y -> Z
                (Self::Pair(v), CompoundTypeDef::Pair(_)) => {
                    return Ok(Self::Pair(Pair::new(
                        types,
                        target,
                        v.left.as_ref().clone(),
                        v.right.as_ref().clone(),
                    )?));
                }
                // Map[String, Y] -> Struct
                (Self::Map(v), CompoundTypeDef::Struct(struct_ty)) => {
                    let len = v.elements.len();
                    let expected_len = types.struct_type(target).members().len();

                    if len != expected_len {
                        bail!(
                            "cannot coerce a map of {len} element{s1} to struct type `{ty}` as \
                             the struct has {expected_len} member{s2}",
                            s1 = if len == 1 { "" } else { "s" },
                            ty = compound_ty.display(types),
                            s2 = if expected_len == 1 { "" } else { "s" }
                        );
                    }

                    return Ok(Self::Struct(Struct {
                        ty: target,
                        name: struct_ty.name().clone(),
                        members: Arc::new(
                            v.elements
                                .iter()
                                .map(|(k, v)| {
                                    let k: String = k
                                        .as_string()
                                        .ok_or_else(|| {
                                            anyhow!(
                                                "cannot coerce a map with a non-string key type \
                                                 to struct type `{ty}`",
                                                ty = compound_ty.display(types)
                                            )
                                        })?
                                        .to_string();
                                    let ty =
                                        *types.struct_type(target).members().get(&k).ok_or_else(
                                            || {
                                                anyhow!(
                                                    "cannot coerce a map with key `{k}` to struct \
                                                     type `{ty}` as the struct does not contain a \
                                                     member with that name",
                                                    ty = compound_ty.display(types)
                                                )
                                            },
                                        )?;
                                    let v = v.coerce(types, ty).with_context(|| {
                                        format!("failed to coerce value of map key `{k}")
                                    })?;
                                    Ok((k, v))
                                })
                                .collect::<Result<_>>()?,
                        ),
                    }));
                }
                // Struct -> Map[String, Y]
                // Object -> Map[String, Y]
                (Self::Struct(Struct { members, .. }), CompoundTypeDef::Map(map_ty))
                | (Self::Object(Object { members }), CompoundTypeDef::Map(map_ty)) => {
                    if map_ty.key_type().as_primitive() != Some(PrimitiveTypeKind::String.into()) {
                        bail!(
                            "cannot coerce a struct or object to type `{ty}` as it requires a \
                             `String` key type",
                            ty = compound_ty.display(types)
                        );
                    }

                    let value_ty = map_ty.value_type();
                    return Ok(Self::Map(Map {
                        ty: target,
                        elements: Arc::new(
                            members
                                .iter()
                                .map(|(n, v)| {
                                    let v = v.coerce(types, value_ty).with_context(|| {
                                        format!("failed to coerce member `{n}`")
                                    })?;
                                    Ok((PrimitiveValue::new_string(n), v))
                                })
                                .collect::<Result<_>>()?,
                        ),
                    }));
                }
                // Object -> Struct
                (Self::Object(v), CompoundTypeDef::Struct(struct_ty)) => {
                    let len = v.members.len();
                    let expected_len = struct_ty.members().len();

                    if len != expected_len {
                        bail!(
                            "cannot coerce an object of {len} members{s1} to struct type `{ty}` \
                             as the target struct has {expected_len} member{s2}",
                            s1 = if len == 1 { "" } else { "s" },
                            ty = compound_ty.display(types),
                            s2 = if expected_len == 1 { "" } else { "s" }
                        );
                    }

                    return Ok(Self::Struct(Struct {
                        ty: target,
                        name: struct_ty.name().clone(),
                        members: Arc::new(
                            v.members
                                .iter()
                                .map(|(k, v)| {
                                    let ty =
                                        types.struct_type(target).members().get(k).ok_or_else(
                                            || {
                                                anyhow!(
                                                    "cannot coerce an object with member `{k}` to \
                                                     struct type `{ty}` as the struct does not \
                                                     contain a member with that name",
                                                    ty = compound_ty.display(types)
                                                )
                                            },
                                        )?;
                                    let v = v.coerce(types, *ty)?;
                                    Ok((k.clone(), v))
                                })
                                .collect::<Result<_>>()?,
                        ),
                    }));
                }
                // Struct -> Struct
                (Self::Struct(v), CompoundTypeDef::Struct(struct_ty)) => {
                    let len = v.members.len();
                    let expected_len = struct_ty.members().len();

                    if len != expected_len {
                        bail!(
                            "cannot coerce a struct of {len} members{s1} to struct type `{ty}` as \
                             the target struct has {expected_len} member{s2}",
                            s1 = if len == 1 { "" } else { "s" },
                            ty = compound_ty.display(types),
                            s2 = if expected_len == 1 { "" } else { "s" }
                        );
                    }

                    return Ok(Self::Struct(Struct {
                        ty: target,
                        name: struct_ty.name().clone(),
                        members: Arc::new(
                            v.members
                                .iter()
                                .map(|(k, v)| {
                                    let ty =
                                        types.struct_type(target).members().get(k).ok_or_else(
                                            || {
                                                anyhow!(
                                                    "cannot coerce a struct with member `{k}` to \
                                                     struct type `{ty}` as the target struct does \
                                                     not contain a member with that name",
                                                    ty = compound_ty.display(types)
                                                )
                                            },
                                        )?;
                                    let v = v.coerce(types, *ty).with_context(|| {
                                        format!("failed to coerce member `{k}`")
                                    })?;
                                    Ok((k.clone(), v))
                                })
                                .collect::<Result<_>>()?,
                        ),
                    }));
                }
                _ => {}
            };
        }

        if let Type::Object = target {
            match self {
                // Map[String, Y] -> Object
                Self::Map(v) => {
                    return Ok(Self::Object(Object {
                        members: Arc::new(
                            v.elements
                                .iter()
                                .map(|(k, v)| {
                                    let k = k
                                        .as_string()
                                        .ok_or_else(|| {
                                            anyhow!(
                                                "cannot coerce a map with a non-string key type \
                                                 to type `Object`"
                                            )
                                        })?
                                        .to_string();
                                    Ok((k, v.clone()))
                                })
                                .collect::<Result<_>>()?,
                        ),
                    }));
                }
                // Struct -> Object
                Self::Struct(v) => {
                    return Ok(Self::Object(Object {
                        members: v.members.clone(),
                    }));
                }
                _ => {}
            };
        }

        bail!(
            "cannot coerce a value of type `{ty}` to type `{expected}`",
            ty = self.ty().display(types),
            expected = target.display(types)
        );
    }
}

impl From<Pair> for CompoundValue {
    fn from(value: Pair) -> Self {
        Self::Pair(value)
    }
}

impl From<Array> for CompoundValue {
    fn from(value: Array) -> Self {
        Self::Array(value)
    }
}

impl From<Map> for CompoundValue {
    fn from(value: Map) -> Self {
        Self::Map(value)
    }
}

impl From<Object> for CompoundValue {
    fn from(value: Object) -> Self {
        Self::Object(value)
    }
}

impl From<Struct> for CompoundValue {
    fn from(value: Struct) -> Self {
        Self::Struct(value)
    }
}

#[cfg(test)]
mod test {
    use approx::assert_relative_eq;
    use pretty_assertions::assert_eq;
    use wdl_analysis::types::ArrayType;
    use wdl_analysis::types::MapType;
    use wdl_analysis::types::PairType;
    use wdl_analysis::types::StructType;

    use super::*;

    #[test]
    fn boolean_coercion() {
        let types = Types::default();

        // Boolean -> Boolean
        assert_eq!(
            Value::from(false)
                .coerce(&types, PrimitiveTypeKind::Boolean.into())
                .expect("should coerce")
                .unwrap_boolean(),
            Value::from(false).unwrap_boolean()
        );
        // Boolean -> String (invalid)
        assert_eq!(
            format!(
                "{e:?}",
                e = Value::from(true)
                    .coerce(&types, PrimitiveTypeKind::String.into())
                    .unwrap_err()
            ),
            "cannot coerce type `Boolean` to type `String`"
        );
    }

    #[test]
    fn boolean_display() {
        assert_eq!(Value::from(false).to_string(), "false");
        assert_eq!(Value::from(true).to_string(), "true");
    }

    #[test]
    fn integer_coercion() {
        let types = Types::default();

        // Int -> Int
        assert_eq!(
            Value::from(12345)
                .coerce(&types, PrimitiveTypeKind::Integer.into())
                .expect("should coerce")
                .unwrap_integer(),
            Value::from(12345).unwrap_integer()
        );
        // Int -> Float
        assert_relative_eq!(
            Value::from(12345)
                .coerce(&types, PrimitiveTypeKind::Float.into())
                .expect("should coerce")
                .unwrap_float(),
            Value::from(12345.0).unwrap_float()
        );
        // Int -> Boolean (invalid)
        assert_eq!(
            format!(
                "{e:?}",
                e = Value::from(12345)
                    .coerce(&types, PrimitiveTypeKind::Boolean.into())
                    .unwrap_err()
            ),
            "cannot coerce type `Int` to type `Boolean`"
        );
    }

    #[test]
    fn integer_display() {
        assert_eq!(Value::from(12345).to_string(), "12345");
        assert_eq!(Value::from(-12345).to_string(), "-12345");
    }

    #[test]
    fn float_coercion() {
        let types = Types::default();

        // Float -> Float
        assert_relative_eq!(
            Value::from(12345.0)
                .coerce(&types, PrimitiveTypeKind::Float.into())
                .expect("should coerce")
                .unwrap_float(),
            Value::from(12345.0).unwrap_float()
        );
        // Float -> Int (invalid)
        assert_eq!(
            format!(
                "{e:?}",
                e = Value::from(12345.0)
                    .coerce(&types, PrimitiveTypeKind::Integer.into())
                    .unwrap_err()
            ),
            "cannot coerce type `Float` to type `Int`"
        );
    }

    #[test]
    fn float_display() {
        assert_eq!(Value::from(12345.12345).to_string(), "12345.12345");
        assert_eq!(Value::from(-12345.12345).to_string(), "-12345.12345");
    }

    #[test]
    fn string_coercion() {
        let types = Types::default();

        let value = PrimitiveValue::new_string("foo");
        // String -> String
        assert_eq!(
            value
                .coerce(&types, PrimitiveTypeKind::String.into())
                .expect("should coerce"),
            value
        );
        // String -> File
        assert_eq!(
            value
                .coerce(&types, PrimitiveTypeKind::File.into())
                .expect("should coerce"),
            PrimitiveValue::File(value.as_string().expect("should be string").clone())
        );
        // String -> Directory
        assert_eq!(
            value
                .coerce(&types, PrimitiveTypeKind::Directory.into())
                .expect("should coerce"),
            PrimitiveValue::Directory(value.as_string().expect("should be string").clone())
        );
        // String -> Boolean (invalid)
        assert_eq!(
            format!(
                "{e:?}",
                e = value
                    .coerce(&types, PrimitiveTypeKind::Boolean.into())
                    .unwrap_err()
            ),
            "cannot coerce type `String` to type `Boolean`"
        );
    }

    #[test]
    fn string_display() {
        let value = PrimitiveValue::new_string("hello world!");
        assert_eq!(value.to_string(), "\"hello world!\"");
    }

    #[test]
    fn file_coercion() {
        let types = Types::default();

        let value = PrimitiveValue::new_file("foo");

        // File -> File
        assert_eq!(
            value
                .coerce(&types, PrimitiveTypeKind::File.into())
                .expect("should coerce"),
            value
        );
        // File -> String
        assert_eq!(
            value
                .coerce(&types, PrimitiveTypeKind::String.into())
                .expect("should coerce"),
            PrimitiveValue::String(value.as_file().expect("should be file").clone())
        );
        // File -> Directory (invalid)
        assert_eq!(
            format!(
                "{e:?}",
                e = value
                    .coerce(&types, PrimitiveTypeKind::Directory.into())
                    .unwrap_err()
            ),
            "cannot coerce type `File` to type `Directory`"
        );
    }

    #[test]
    fn file_display() {
        let value = PrimitiveValue::new_file("/foo/bar/baz.txt");
        assert_eq!(value.to_string(), "\"/foo/bar/baz.txt\"");
    }

    #[test]
    fn directory_coercion() {
        let types = Types::default();
        let value = PrimitiveValue::new_directory("foo");

        // Directory -> Directory
        assert_eq!(
            value
                .coerce(&types, PrimitiveTypeKind::Directory.into())
                .expect("should coerce"),
            value
        );
        // Directory -> String
        assert_eq!(
            value
                .coerce(&types, PrimitiveTypeKind::String.into())
                .expect("should coerce"),
            PrimitiveValue::String(value.as_directory().expect("should be directory").clone())
        );
        // Directory -> File (invalid)
        assert_eq!(
            format!(
                "{e:?}",
                e = value
                    .coerce(&types, PrimitiveTypeKind::File.into())
                    .unwrap_err()
            ),
            "cannot coerce type `Directory` to type `File`"
        );
    }

    #[test]
    fn directory_display() {
        let value = PrimitiveValue::new_directory("/foo/bar/baz");
        assert_eq!(value.to_string(), "\"/foo/bar/baz\"");
    }

    #[test]
    fn none_coercion() {
        let types = Types::default();

        // None -> String?
        assert!(
            Value::None
                .coerce(&types, Type::from(PrimitiveTypeKind::String).optional())
                .expect("should coerce")
                .is_none(),
        );

        // None -> String (invalid)
        assert_eq!(
            format!(
                "{e:?}",
                e = Value::None
                    .coerce(&types, PrimitiveTypeKind::String.into())
                    .unwrap_err()
            ),
            "cannot coerce `None` to non-optional type `String`"
        );
    }

    #[test]
    fn none_display() {
        assert_eq!(Value::None.to_string(), "None");
    }

    #[test]
    fn array_coercion() {
        let mut types = Types::default();

        let src_ty = types.add_array(ArrayType::new(PrimitiveTypeKind::Integer));
        let target_ty = types.add_array(ArrayType::new(PrimitiveTypeKind::Float));

        // Array[Int] -> Array[Float]
        let src: CompoundValue = Array::new(&types, src_ty, [1, 2, 3])
            .expect("should create array value")
            .into();
        let target = src.coerce(&types, target_ty).expect("should coerce");
        assert_eq!(target.unwrap_array().to_string(), "[1.0, 2.0, 3.0]");

        // Array[Int] -> Array[String] (invalid)
        let target_ty = types.add_array(ArrayType::new(PrimitiveTypeKind::String));
        assert_eq!(
            format!("{e:?}", e = src.coerce(&types, target_ty).unwrap_err()),
            r#"failed to coerce array element at index 0

Caused by:
    cannot coerce type `Int` to type `String`"#
        );
    }

    #[test]
    fn non_empty_array_coercion() {
        let mut types = Types::default();

        let ty = types.add_array(ArrayType::new(PrimitiveTypeKind::String));
        let target_ty = types.add_array(ArrayType::non_empty(PrimitiveTypeKind::String));

        // Array[String] (non-empty) -> Array[String]+
        let string = PrimitiveValue::new_string("foo");
        let value: Value = Array::new(&types, ty, [string])
            .expect("should create array")
            .into();
        assert!(value.coerce(&types, target_ty).is_ok(), "should coerce");

        // Array[String] (empty) -> Array[String]+ (invalid)
        let value: Value = Array::new::<Value>(&types, ty, [])
            .expect("should create array")
            .into();
        assert_eq!(
            format!("{e:?}", e = value.coerce(&types, target_ty).unwrap_err()),
            "cannot coerce empty array value to non-empty array type `Array[String]+`"
        );
    }

    #[test]
    fn array_display() {
        let mut types = Types::default();

        let ty = types.add_array(ArrayType::new(PrimitiveTypeKind::Integer));
        let value: Value = Array::new(&types, ty, [1, 2, 3])
            .expect("should create array")
            .into();

        assert_eq!(value.to_string(), "[1, 2, 3]");
    }

    #[test]
    fn map_coerce() {
        let mut types = Types::default();

        let key1 = PrimitiveValue::new_file("foo");
        let value1 = PrimitiveValue::new_string("bar");
        let key2 = PrimitiveValue::new_file("baz");
        let value2 = PrimitiveValue::new_string("qux");

        let ty = types.add_map(MapType::new(
            PrimitiveTypeKind::File,
            PrimitiveTypeKind::String,
        ));
        let value: Value = Map::new(&types, ty, [(key1, value1), (key2, value2)])
            .expect("should create map value")
            .into();

        // Map[File, String] -> Map[String, File]
        let ty = types.add_map(MapType::new(
            PrimitiveTypeKind::String,
            PrimitiveTypeKind::File,
        ));
        let value = value.coerce(&types, ty).expect("value should coerce");
        assert_eq!(value.to_string(), r#"{"foo": "bar", "baz": "qux"}"#);

        // Map[String, File] -> Map[Int, File] (invalid)
        let ty = types.add_map(MapType::new(
            PrimitiveTypeKind::Integer,
            PrimitiveTypeKind::File,
        ));
        assert_eq!(
            format!("{e:?}", e = value.coerce(&types, ty).unwrap_err()),
            r#"failed to coerce map key for element at index 0

Caused by:
    cannot coerce type `String` to type `Int`"#
        );

        // Map[String, File] -> Map[String, Int] (invalid)
        let ty = types.add_map(MapType::new(
            PrimitiveTypeKind::String,
            PrimitiveTypeKind::Integer,
        ));
        assert_eq!(
            format!("{e:?}", e = value.coerce(&types, ty).unwrap_err()),
            r#"failed to coerce map value for element at index 0

Caused by:
    cannot coerce type `File` to type `Int`"#
        );

        // Map[String, File] -> Struct
        let ty = types.add_struct(StructType::new("Foo", [
            ("foo", PrimitiveTypeKind::File),
            ("baz", PrimitiveTypeKind::File),
        ]));
        let struct_value = value.coerce(&types, ty).expect("value should coerce");
        assert_eq!(struct_value.to_string(), r#"Foo {foo: "bar", baz: "qux"}"#);

        // Map[String, File] -> Struct (invalid)
        let ty = types.add_struct(StructType::new("Foo", [
            ("foo", PrimitiveTypeKind::File),
            ("baz", PrimitiveTypeKind::File),
            ("qux", PrimitiveTypeKind::File),
        ]));
        assert_eq!(
            format!("{e:?}", e = value.coerce(&types, ty).unwrap_err()),
            "cannot coerce a map of 2 elements to struct type `Foo` as the struct has 3 members"
        );

        // Map[String, File] -> Object
        let object_value = value
            .coerce(&types, Type::Object)
            .expect("value should coerce");
        assert_eq!(
            object_value.to_string(),
            r#"object {foo: "bar", baz: "qux"}"#
        );
    }

    #[test]
    fn map_display() {
        let mut types = Types::default();

        let ty = types.add_map(MapType::new(
            PrimitiveTypeKind::Integer,
            PrimitiveTypeKind::Boolean,
        ));

        let value: Value = Map::new(&types, ty, [(1, true), (2, false)])
            .expect("should create map value")
            .into();
        assert_eq!(value.to_string(), "{1: true, 2: false}");
    }

    #[test]
    fn pair_coercion() {
        let mut types = Types::default();

        let left = PrimitiveValue::new_file("foo");
        let right = PrimitiveValue::new_string("bar");

        let ty = types.add_pair(PairType::new(
            PrimitiveTypeKind::File,
            PrimitiveTypeKind::String,
        ));
        let value: Value = Pair::new(&types, ty, left, right)
            .expect("should create map value")
            .into();

        // Pair[File, String] -> Pair[String, File]
        let ty = types.add_pair(PairType::new(
            PrimitiveTypeKind::String,
            PrimitiveTypeKind::File,
        ));
        let value = value.coerce(&types, ty).expect("value should coerce");
        assert_eq!(value.to_string(), r#"("foo", "bar")"#);

        // Pair[String, File] -> Pair[Int, Int]
        let ty = types.add_pair(PairType::new(
            PrimitiveTypeKind::Integer,
            PrimitiveTypeKind::Integer,
        ));
        assert_eq!(
            format!("{e:?}", e = value.coerce(&types, ty).unwrap_err()),
            r#"failed to coerce pair's left value

Caused by:
    cannot coerce type `String` to type `Int`"#
        );
    }

    #[test]
    fn pair_display() {
        let mut types = Types::default();

        let ty = types.add_pair(PairType::new(
            PrimitiveTypeKind::Integer,
            PrimitiveTypeKind::Boolean,
        ));

        let value: Value = Pair::new(&types, ty, 12345, false)
            .expect("should create pair value")
            .into();
        assert_eq!(value.to_string(), "(12345, false)");
    }

    #[test]
    fn struct_coercion() {
        let mut types = Types::default();

        let ty = types.add_struct(StructType::new("Foo", [
            ("foo", PrimitiveTypeKind::Float),
            ("bar", PrimitiveTypeKind::Float),
            ("baz", PrimitiveTypeKind::Float),
        ]));
        let value: Value = Struct::new(&types, ty, [("foo", 1.0), ("bar", 2.0), ("baz", 3.0)])
            .expect("should create map value")
            .into();

        // Struct -> Map[String, Float]
        let ty = types.add_map(MapType::new(
            PrimitiveTypeKind::String,
            PrimitiveTypeKind::Float,
        ));
        let map_value = value.coerce(&types, ty).expect("value should coerce");
        assert_eq!(
            map_value.to_string(),
            r#"{"foo": 1.0, "bar": 2.0, "baz": 3.0}"#
        );

        // Struct -> Struct
        let ty = types.add_struct(StructType::new("Bar", [
            ("foo", PrimitiveTypeKind::Float),
            ("bar", PrimitiveTypeKind::Float),
            ("baz", PrimitiveTypeKind::Float),
        ]));
        let struct_value = value.coerce(&types, ty).expect("value should coerce");
        assert_eq!(
            struct_value.to_string(),
            r#"Bar {foo: 1.0, bar: 2.0, baz: 3.0}"#
        );

        // Struct -> Object
        let object_value = value
            .coerce(&types, Type::Object)
            .expect("value should coerce");
        assert_eq!(
            object_value.to_string(),
            r#"object {foo: 1.0, bar: 2.0, baz: 3.0}"#
        );
    }

    #[test]
    fn struct_display() {}
}
