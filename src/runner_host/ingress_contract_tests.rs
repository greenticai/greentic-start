//! `handle-webhook` export selection, against real components built from WAT.
//!
//! Each fixture's `handle-webhook` answers with a string that names the export
//! it ran as, so a test can tell which contract the host picked. The
//! `@0.0.3` export answers with its `config-json` argument verbatim.

use super::*;
use wasmtime::component::{Component, Linker};
use wasmtime::{Engine, Store};

/// Core module shared by every fixture: a bump allocator for the host to lower
/// strings into, and three bodies that write a `result<string, string>` to a
/// return area at offset 0 (discriminant, then pointer and length).
const CORE_MODULE: &str = r#"
  (core module $m
    (memory (export "mem") 1)
    (global $bump (mut i32) (i32.const 1024))
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      (local $p i32)
      (local.set $p (global.get $bump))
      (global.set $bump (i32.add (global.get $bump) (local.get 3)))
      (local.get $p))
    (data (i32.const 16) "v2")
    (func (export "v3") (param i32 i32 i32 i32 i32 i32) (result i32)
      (i32.store8 (i32.const 0) (i32.const 0))
      (i32.store (i32.const 4) (local.get 4))
      (i32.store (i32.const 8) (local.get 5))
      (i32.const 0))
    (func (export "v2") (param i32 i32 i32 i32) (result i32)
      (i32.store8 (i32.const 0) (i32.const 0))
      (i32.store (i32.const 4) (i32.const 16))
      (i32.store (i32.const 8) (i32.const 2))
      (i32.const 0))
  )
  (core instance $i (instantiate $m))
"#;

const V2_FUNC: &str = r#"
  (func $v2 (param "headers-json" string) (param "body-json" string)
    (result (result string (error string)))
    (canon lift (core func $i "v2") (memory $i "mem") (realloc (func $i "realloc"))))
  (instance $ing2 (export "handle-webhook" (func $v2)))
  (export "provider:common/ingress@0.0.2" (instance $ing2))
"#;

const V3_FUNC: &str = r#"
  (func $v3 (param "headers-json" string) (param "body-json" string) (param "config-json" string)
    (result (result string (error string)))
    (canon lift (core func $i "v3") (memory $i "mem") (realloc (func $i "realloc"))))
  (instance $ing3 (export "handle-webhook" (func $v3)))
  (export "provider:common/ingress@0.0.3" (instance $ing3))
"#;

/// An `@0.0.3` export whose `handle-webhook` has the OLD two-argument shape.
const V3_WRONG_SHAPE: &str = r#"
  (func $bad (param "headers-json" string) (param "body-json" string)
    (result (result string (error string)))
    (canon lift (core func $i "v2") (memory $i "mem") (realloc (func $i "realloc"))))
  (instance $bad3 (export "handle-webhook" (func $bad)))
  (export "provider:common/ingress@0.0.3" (instance $bad3))
"#;

fn component(exports: &[&str]) -> String {
    format!("(component {CORE_MODULE} {})", exports.join("\n"))
}

fn run(wat: &str, config: Option<JsonValue>) -> anyhow::Result<String> {
    let engine = Engine::default();
    let bytes = wat::parse_str(wat)?;
    let component = Component::from_binary(&engine, &bytes)?;
    let mut store = Store::new(&engine, ());
    let instance = Linker::new(&engine).instantiate(&mut store, &component)?;
    let handle = resolve_ingress_handle(&instance, &mut store, "handle-webhook")?;
    let call = IngressExtensionCall {
        headers_json: "{}".to_string(),
        body_json: "{}".to_string(),
        config,
    };
    call_ingress_handle(&handle, &mut store, &call)?.map_err(anyhow::Error::msg)
}

#[test]
fn a_component_exporting_both_contracts_receives_the_config() {
    let wat = component(&[V2_FUNC, V3_FUNC]);
    let out = run(&wat, Some(json!({"auto_start_on_open": false}))).expect("call");
    assert_eq!(out, r#"{"auto_start_on_open":false}"#);
}

#[test]
fn absent_config_reaches_the_configured_contract_as_json_null() {
    let wat = component(&[V2_FUNC, V3_FUNC]);
    assert_eq!(run(&wat, None).expect("call"), "null");
}

#[test]
fn a_component_built_before_the_configured_contract_still_serves() {
    let wat = component(&[V2_FUNC]);
    let out = run(&wat, Some(json!({"auto_start_on_open": false}))).expect("call");
    assert_eq!(out, "v2");
}

#[test]
fn a_malformed_configured_export_falls_back_instead_of_failing() {
    let wat = component(&[V2_FUNC, V3_WRONG_SHAPE]);
    let out = run(&wat, Some(json!({"k": "v"}))).expect("call");
    assert_eq!(out, "v2");
}

#[test]
fn a_component_with_no_ingress_export_is_still_an_error() {
    let wat = component(&[]);
    let err = run(&wat, None).expect_err("no ingress export");
    assert!(
        format!("{err:#}").contains("get provider-common ingress export"),
        "{err:#}"
    );
}
