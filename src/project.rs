use std::path::Path;

pub fn add_tenant(root: &Path, tenant: &str) -> anyhow::Result<()> {
    let tenant_dir = root.join("tenants").join(tenant);
    std::fs::create_dir_all(tenant_dir.join("teams"))?;
    let gmap_path = tenant_dir.join("tenant.gmap");
    if !gmap_path.exists() {
        std::fs::write(gmap_path, "_ = forbidden\n")?;
    }
    Ok(())
}

pub fn add_team(root: &Path, tenant: &str, team: &str) -> anyhow::Result<()> {
    let team_dir = root.join("tenants").join(tenant).join("teams").join(team);
    std::fs::create_dir_all(&team_dir)?;
    let gmap_path = team_dir.join("team.gmap");
    if !gmap_path.exists() {
        std::fs::write(gmap_path, "_ = forbidden\n")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_tenant_creates_default_structure_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        add_tenant(dir.path(), "acme").expect("add tenant");

        let tenant_dir = dir.path().join("tenants").join("acme");
        assert!(tenant_dir.join("teams").is_dir());
        assert_eq!(
            std::fs::read_to_string(tenant_dir.join("tenant.gmap")).expect("tenant gmap"),
            "_ = forbidden\n"
        );

        std::fs::write(tenant_dir.join("tenant.gmap"), "custom = allow\n").expect("custom gmap");
        add_tenant(dir.path(), "acme").expect("add tenant again");
        assert_eq!(
            std::fs::read_to_string(tenant_dir.join("tenant.gmap")).expect("tenant gmap"),
            "custom = allow\n"
        );
    }

    #[test]
    fn add_team_creates_team_gmap_without_overwriting_existing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        add_team(dir.path(), "acme", "ops").expect("add team");

        let team_dir = dir
            .path()
            .join("tenants")
            .join("acme")
            .join("teams")
            .join("ops");
        assert!(team_dir.is_dir());
        assert_eq!(
            std::fs::read_to_string(team_dir.join("team.gmap")).expect("team gmap"),
            "_ = forbidden\n"
        );

        std::fs::write(team_dir.join("team.gmap"), "team = custom\n").expect("custom team gmap");
        add_team(dir.path(), "acme", "ops").expect("add team again");
        assert_eq!(
            std::fs::read_to_string(team_dir.join("team.gmap")).expect("team gmap"),
            "team = custom\n"
        );
    }
}
