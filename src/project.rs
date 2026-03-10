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
