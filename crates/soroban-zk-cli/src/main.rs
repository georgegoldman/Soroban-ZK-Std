use clap::{Parser, Subcommand, ValueEnum};
use std::fs;
use std::path::Path;

#[derive(Parser)]
#[command(name = "soroban-zk")]
#[command(about = "Scaffold ZK dApps for Soroban")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init {
        name: String,
        #[arg(short, long, value_enum, default_value_t = Template::ShieldedToken)]
        template: Template,
    },
}

#[derive(ValueEnum, Clone, Debug)]
enum Template {
    ShieldedToken,
    ZkVoting,
    Groth16,
}

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Init { name, template } => {
            if let Err(e) = scaffold_project(name, template) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
            println!("Successfully created project '{}'", name);
        }
    }
}

fn scaffold_project(project_name: &str, template: &Template) -> Result<(), Box<dyn std::error::Error>> {
    let project_dir = Path::new(project_name);
    if project_dir.exists() {
        return Err(format!("Directory '{}' already exists", project_name).into());
    }
    fs::create_dir_all(project_dir)?;
    
    if let Template::ShieldedToken = template {
        let cargo_toml = include_str!("../templates/shielded-token/Cargo.toml.template");
        let lib_rs = include_str!("../templates/shielded-token/src/lib.rs.template");
        let test_rs = include_str!("../templates/shielded-token/src/test.rs.template");
        let deploy_sh = include_str!("../templates/shielded-token/scripts/deploy_testnet.sh.template");

        // env!("CARGO_MANIFEST_DIR") gives the absolute path to crates/soroban-zk-cli
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
        
        let zk_std_path = workspace_root.join("crates/soroban-zk-std");
        let zk_std_path_str = zk_std_path.to_string_lossy().to_string();

        let cargo_toml = cargo_toml.replace("{{PROJECT_NAME}}", project_name);
        let cargo_toml = cargo_toml.replace("{{ZK_STD_PATH}}", &zk_std_path_str);
        let deploy_sh = deploy_sh.replace("{{PROJECT_NAME}}", project_name);

        fs::write(project_dir.join("Cargo.toml"), cargo_toml)?;
        
        fs::create_dir_all(project_dir.join("src"))?;
        fs::write(project_dir.join("src/lib.rs"), lib_rs)?;
        fs::write(project_dir.join("src/test.rs"), test_rs)?;
        
        fs::create_dir_all(project_dir.join("scripts"))?;
        fs::write(project_dir.join("scripts/deploy_testnet.sh"), deploy_sh)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(project_dir.join("scripts/deploy_testnet.sh"))?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(project_dir.join("scripts/deploy_testnet.sh"), perms)?;
        }
    } else {
        return Err(format!("Template {:?} is not implemented.", template).into());
    }
    Ok(())
}
