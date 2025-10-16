mod app;
mod audit_log;
mod backups;
mod cli;
mod crypto;
mod health_check;
mod rotation;
mod terminal_ui;
mod types;

use app::SecretApp;
use colored::*;

#[tokio::main]
async fn main() {
    // Initialize colored output
    colored::control::set_override(true);

    match run().await {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            std::process::exit(1);
        }
    }
}

async fn run() -> anyhow::Result<()> {
    let mut app = SecretApp::new()?;
    app.run().await?;
    Ok(())
}

