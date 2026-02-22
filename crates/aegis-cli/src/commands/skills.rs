//! CLI implementation for the `aegis skills` subcommand.
//!
//! Provides skill registry management: list, search, install, update,
//! uninstall, and info.

use std::path::PathBuf;

use aegis_skills::hub::{RegistryClient, RegistryConfig};
use aegis_skills::installer::validate_installation;
use anyhow::{Context, Result};
use chrono::Local;

use super::DATETIME_SHORT_FMT;

/// List all locally installed skills.
pub async fn list_skills(cache_dir: Option<PathBuf>) -> Result<()> {
    let client = build_client(cache_dir);
    let installed = client.list_installed()?;

    if installed.is_empty() {
        println!("No skills installed.");
        println!();
        println!("Install skills with: aegis skills install <name>");
        println!("Search the registry:  aegis skills search <query>");
        return Ok(());
    }

    println!(
        "{:<20} {:<10} {:<40} INSTALLED",
        "NAME", "VERSION", "DESCRIPTION"
    );
    println!("{}", "-".repeat(90));

    for skill in &installed {
        let installed_at = skill
            .installed_at
            .with_timezone(&Local)
            .format(DATETIME_SHORT_FMT);
        let desc = if skill.manifest.description.len() > 38 {
            format!("{}...", &skill.manifest.description[..35])
        } else {
            skill.manifest.description.clone()
        };
        println!(
            "{:<20} {:<10} {:<40} {}",
            skill.name, skill.version, desc, installed_at
        );
    }

    println!();
    println!("{} skill(s) installed.", installed.len());
    Ok(())
}

/// Search the registry for skills.
pub async fn search_skills(query: &str, cache_dir: Option<PathBuf>) -> Result<()> {
    let client = build_client(cache_dir);
    let results = client.search(query).await?;

    if results.is_empty() {
        println!("No skills found matching '{query}'.");
        return Ok(());
    }

    println!(
        "{:<20} {:<10} DESCRIPTION",
        "NAME", "VERSION"
    );
    println!("{}", "-".repeat(70));

    for skill in &results {
        let desc = if skill.description.len() > 38 {
            format!("{}...", &skill.description[..35])
        } else {
            skill.description.clone()
        };
        println!("{:<20} {:<10} {}", skill.name, skill.version, desc);
    }

    println!();
    println!("{} result(s).", results.len());
    Ok(())
}

/// Install a skill from the registry or a local path.
pub async fn install_skill(
    name: &str,
    version: Option<&str>,
    from_path: Option<PathBuf>,
    cache_dir: Option<PathBuf>,
) -> Result<()> {
    let client = build_client(cache_dir);

    let installed = if let Some(path) = from_path {
        println!("Installing skill '{name}' from local path: {}", path.display());
        client
            .install_local(name, &path)
            .context("failed to install skill from local path")?
    } else {
        let version_str = version.unwrap_or("latest");
        println!("Installing skill '{name}' version {version_str} from registry...");
        client
            .install(name, version)
            .await
            .context("failed to install skill from registry")?
    };

    println!("Installed {} v{} to {}", installed.name, installed.version, installed.path.display());
    Ok(())
}

/// Update a skill (or all skills) to the latest version.
pub async fn update_skills(
    name: Option<&str>,
    cache_dir: Option<PathBuf>,
) -> Result<()> {
    let client = build_client(cache_dir);

    if let Some(name) = name {
        println!("Updating skill '{name}'...");
        let installed = client
            .update(name)
            .await
            .context("failed to update skill")?;
        println!("Updated {} to v{}", installed.name, installed.version);
    } else {
        println!("Checking for updates...");
        let updates = client.sync().await?;

        if updates.is_empty() {
            println!("All skills are up to date.");
            return Ok(());
        }

        println!("{} update(s) available:", updates.len());
        for update in &updates {
            println!(
                "  {} {} -> {}",
                update.name, update.current_version, update.latest_version
            );
        }

        for update in &updates {
            println!("Updating {}...", update.name);
            match client.update(&update.name).await {
                Ok(installed) => {
                    println!("  Updated to v{}", installed.version);
                }
                Err(e) => {
                    eprintln!("  Failed to update {}: {e}", update.name);
                }
            }
        }
    }

    Ok(())
}

/// Uninstall a skill.
pub async fn uninstall_skill(name: &str, cache_dir: Option<PathBuf>) -> Result<()> {
    let client = build_client(cache_dir);

    println!("Uninstalling skill '{name}'...");
    client.uninstall(name)?;
    println!("Skill '{name}' has been removed.");
    Ok(())
}

/// Show detailed info about an installed skill.
pub async fn skill_info(name: &str, cache_dir: Option<PathBuf>) -> Result<()> {
    let client = build_client(cache_dir);
    let cache = client.cache_dir();
    let skill_dir = cache.join(name);

    if !skill_dir.exists() {
        // Also check bundled skills
        let project_skills = std::path::Path::new("skills").join(name);
        if project_skills.exists() {
            return show_skill_info(&project_skills);
        }
        anyhow::bail!("skill '{}' is not installed. Use 'aegis skills install {}' to install it.", name, name);
    }

    show_skill_info(&skill_dir)
}

fn show_skill_info(skill_dir: &std::path::Path) -> Result<()> {
    let installed = validate_installation(skill_dir)?;
    let manifest = &installed.manifest;

    println!("Name:        {}", manifest.name);
    println!("Version:     {}", manifest.version);
    println!("Description: {}", manifest.description);
    if let Some(ref author) = manifest.author {
        println!("Author:      {}", author);
    }
    println!("Entry Point: {}", manifest.entry_point);
    println!("Path:        {}", installed.path.display());
    println!("Source:      {}", installed.source);
    println!(
        "Installed:   {}",
        installed
            .installed_at
            .with_timezone(&Local)
            .format(DATETIME_SHORT_FMT)
    );

    if !manifest.permissions.is_empty() {
        println!("Permissions: {}", manifest.permissions.join(", "));
    }
    if !manifest.dependencies.is_empty() {
        println!("Dependencies: {}", manifest.dependencies.join(", "));
    }
    if let Some(ref min_version) = manifest.min_aegis_version {
        println!("Min Aegis:   {}", min_version);
    }

    Ok(())
}

fn build_client(cache_dir: Option<PathBuf>) -> RegistryClient {
    match cache_dir {
        Some(dir) => RegistryClient::with_config(RegistryConfig {
            cache_dir: dir,
            ..Default::default()
        }),
        None => RegistryClient::new(),
    }
}
