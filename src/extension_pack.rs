use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtensionPackClass {
    CorePlatform,
    OptionalExtension,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionPackRole {
    pub class: ExtensionPackClass,
    pub reason: &'static str,
}

pub fn classify_extension_pack_path(bundle_root: &Path, pack_path: &Path) -> ExtensionPackRole {
    let relative = pack_path
        .strip_prefix(bundle_root)
        .unwrap_or(pack_path)
        .to_path_buf();
    classify_relative_path(&relative)
}

pub fn classify_extension_pack_id(pack_id: &str) -> ExtensionPackRole {
    let normalized = pack_id.trim().to_ascii_lowercase();
    if normalized.contains("telemetry")
        || normalized.contains("oauth")
        || normalized.contains("messaging")
        || normalized.contains("state")
        || normalized.contains("events")
        || normalized.contains("secrets")
    {
        return ExtensionPackRole {
            class: ExtensionPackClass::CorePlatform,
            reason: "domain-runtime",
        };
    }
    if normalized.contains("hook")
        || normalized.contains("contract")
        || normalized.contains("capabilit")
        || normalized.contains("subscription")
        || normalized.contains("extension")
    {
        return ExtensionPackRole {
            class: ExtensionPackClass::OptionalExtension,
            reason: "feature-extension",
        };
    }
    ExtensionPackRole {
        class: ExtensionPackClass::OptionalExtension,
        reason: "default-optional",
    }
}

fn classify_relative_path(path: &PathBuf) -> ExtensionPackRole {
    let value = path.to_string_lossy().to_ascii_lowercase();
    if value.starts_with("providers/")
        || value.starts_with("messaging/")
        || value.starts_with("events/")
        || value.starts_with("oauth/")
        || value.starts_with("secrets/")
        || value.starts_with("telemetry/")
        || value.starts_with("state/")
    {
        return ExtensionPackRole {
            class: ExtensionPackClass::CorePlatform,
            reason: "bundle-platform-dir",
        };
    }
    ExtensionPackRole {
        class: ExtensionPackClass::OptionalExtension,
        reason: "bundle-extension-dir",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_dirs_are_classified_as_core() {
        let bundle = Path::new("/tmp/bundle");
        let role = classify_extension_pack_path(
            bundle,
            Path::new("/tmp/bundle/providers/messaging/a.gtpack"),
        );
        assert_eq!(role.class, ExtensionPackClass::CorePlatform);
    }

    #[test]
    fn hook_like_ids_are_optional() {
        let role = classify_extension_pack_id("contracts-and-hooks");
        assert_eq!(role.class, ExtensionPackClass::OptionalExtension);
    }
}
