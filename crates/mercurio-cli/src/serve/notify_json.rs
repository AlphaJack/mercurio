//! The JSON body of `POST /notify`, as the generated API reads it. It depends on no other module of `serve`, so the
//! generated `api` names it without a cycle.

use serde_json::{Map, Value};

/// A JSON notification or alert webhook as the client sent it: `definitions/mercurio.overlay.yaml` maps the JSON bodies of `/notify` here
/// (`x-rust-type`). `payload::load_notify` reads the fields and checks their types. It is a map and not the generated
/// struct because field mapping (`?:src=dest`, `payload::remap_fields`) renames, removes and sets arbitrary fields, nested
/// ones too, before the fields are read.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub(crate) struct NotifyJson(pub Map<String, Value>);
