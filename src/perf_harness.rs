use std::io::Write;
use std::path::Path;

use zip::write::FileOptions;

use crate::discovery::{self, DiscoveryOptions};
use crate::gmap::{self, GmapPath};

pub struct DiscoveryFixture {
    root: std::path::PathBuf,
}

impl DiscoveryFixture {
    pub fn root(&self) -> &Path {
        &self.root
    }
}

pub fn create_discovery_fixture(pack_count: usize) -> anyhow::Result<DiscoveryFixture> {
    let root = std::env::temp_dir().join(format!(
        "greentic-start-perf-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let providers_dir = root.join("providers").join("events");
    std::fs::create_dir_all(&providers_dir)?;

    for idx in 0..pack_count {
        let pack_path = providers_dir.join(format!("provider-{idx:04}.gtpack"));
        write_pack(
            &pack_path,
            &[(
                "manifest.cbor",
                manifest_bytes(format!("events-provider-{idx:04}"))?,
            )],
        )?;
    }

    Ok(DiscoveryFixture { root })
}

pub fn run_discovery(fixture: &DiscoveryFixture, cbor_only: bool) -> anyhow::Result<usize> {
    Ok(
        discovery::discover_with_options(fixture.root(), DiscoveryOptions { cbor_only })?
            .providers
            .len(),
    )
}

pub fn make_gmap_source(rule_count: usize) -> String {
    let mut source = String::with_capacity(rule_count * 32);
    source.push_str("# synthetic gmap benchmark\n");
    source.push_str("_ = forbidden\n");
    for idx in 0..rule_count {
        source.push_str(&format!("pack-{idx}/flow-{idx}/node-{idx} = public\n"));
    }
    source
}

pub fn run_gmap_parse(source: &str) -> anyhow::Result<usize> {
    Ok(gmap::parse_str(source)?.len())
}

pub fn run_gmap_eval(source: &str, target_idx: usize) -> anyhow::Result<bool> {
    let rules = gmap::parse_str(source)?;
    let target = GmapPath {
        pack: Some(format!("pack-{target_idx}")),
        flow: Some(format!("flow-{target_idx}")),
        node: Some(format!("node-{target_idx}")),
    };
    Ok(gmap::eval_policy(&rules, &target).is_some())
}

fn write_pack(path: &Path, entries: &[(&str, Vec<u8>)]) -> anyhow::Result<()> {
    let file = std::fs::File::create(path)?;
    let mut zip = zip::ZipWriter::new(file);
    for (name, bytes) in entries {
        zip.start_file(*name, FileOptions::<()>::default())?;
        zip.write_all(bytes)?;
    }
    zip.finish()?;
    Ok(())
}

fn manifest_bytes(pack_id: String) -> anyhow::Result<Vec<u8>> {
    use serde_cbor::Value as CborValue;
    use std::collections::BTreeMap;

    let manifest = CborValue::Map(BTreeMap::from([
        (
            CborValue::Text("symbols".to_string()),
            CborValue::Map(BTreeMap::from([(
                CborValue::Text("pack_ids".to_string()),
                CborValue::Array(vec![CborValue::Text(pack_id)]),
            )])),
        ),
        (
            CborValue::Text("meta".to_string()),
            CborValue::Map(BTreeMap::from([(
                CborValue::Text("pack_id".to_string()),
                CborValue::Integer(0),
            )])),
        ),
    ]));
    Ok(serde_cbor::to_vec(&manifest)?)
}

impl Drop for DiscoveryFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
