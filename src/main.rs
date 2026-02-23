// Copyright (c) 2026 Adrian Lorenz <a.lorenz@noa-x.de>
// SPDX-License-Identifier: MIT

use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use std::path::PathBuf;
use std::time::Instant;

mod cli;
mod config;
mod output;
mod rules;
mod scanner;

use cli::{Cli, Commands, OutputFormat};
use config::{Config, default_config_toml};
use output::{print_json, print_markdown, print_pretty, print_sarif, write_github_summary};
use rules::builtin_rules;
use scanner::Scanner;

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::InitConfig => {
            let path = PathBuf::from("pyl.toml");
            if path.exists() { eprintln!("{} pyl.toml already exists", "Error:".red()); std::process::exit(1); }
            std::fs::write(&path, default_config_toml())?;
            println!("{} Created pyl.toml", "✅".green());
        }

        Commands::Rules => {
            println!("{}", "📋 pyl — Built-in Detection Rules\n".bold());
            println!("{:<35} {:<10} {:<46} {}", "ID".underline(), "SEVERITY".underline(), "DESCRIPTION".underline(), "TAGS".underline());
            for rule in builtin_rules() {
                println!("{:<35} {:<10} {:<46} {}", rule.id.cyan(), rule.severity.to_string(), rule.description, rule.tags.join(", ").dimmed());
            }
            println!("\n{} rules total", builtin_rules().len().to_string().yellow());
        }

        Commands::Check { source, format, verbose, max_size, config, github_summary, warnings } => {
            let cfg = Config::load_auto(config.as_ref());
            let rules = builtin_rules();
            let rule_count = rules.len();
            let disabled = cfg.rules.disable.len();
            let scanner = Scanner::new(rules, max_size, &cfg)?;
            let ext_display = if cfg.scan.extensions.is_empty() { "all (except .env)".to_string() } else { cfg.scan.extensions.join(", ") };
            println!("{}", format!("🔍 pyl v0.2.0 — scanning '{}' | {} rules ({} disabled) | files: [{}]",
                                   source.display(), rule_count, disabled, ext_display).bold());

            let start = Instant::now();
            let (mut findings, stats) = if source.is_dir() {
                scanner.scan_directory(&source, verbose)?
            } else {
                scanner.scan_file(&source)?
            };
            let elapsed = start.elapsed();

            findings.sort_by(|a, b| {
                fn sev_order(s: &str) -> u8 { match s { "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2, "LOW" => 3, _ => 4 } }
                sev_order(&a.severity).cmp(&sev_order(&b.severity))
                    .then(a.file.cmp(&b.file))
                    .then(a.line_number.cmp(&b.line_number))
            });

            let visible: Vec<_> = findings.iter()
                .filter(|f| warnings || f.severity != "WARNING")
                .collect();

            match format {
                OutputFormat::Pretty   => print_pretty(&findings, warnings),
                OutputFormat::Json     => print_json(&visible)?,
                OutputFormat::Sarif    => print_sarif(&visible)?,
                OutputFormat::Markdown => print_markdown(&visible),
            }

            if matches!(format, OutputFormat::Pretty | OutputFormat::Markdown) {
                let ms = elapsed.as_millis();
                let time_str = if ms < 1000 { format!("{}ms", ms) } else { format!("{:.2}s", elapsed.as_secs_f64()) };
                eprintln!("\n{}", format!(
                    "Scanned {} file(s), {} line(s) in {}",
                    stats.files, stats.lines, time_str
                ).dimmed());
            }

            if github_summary {
                write_github_summary(&findings, &source)?;
                eprintln!("{} GitHub Job Summary written", "✅".green());
            }

            if findings.iter().any(|f| matches!(f.severity.as_str(), "CRITICAL"|"HIGH"|"MEDIUM")) {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}
