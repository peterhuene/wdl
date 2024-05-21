#![allow(dead_code)]

use std::borrow::Cow;
use std::fs;
use std::io::IsTerminal;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use clap::Args;
use clap::Parser;
use colored::Colorize;
use miette::GraphicalReportHandler;
use miette::GraphicalTheme;
use miette::NamedSource;
use miette::Report;

use crate::experimental::tree::SyntaxTree;

/// Gets the CLI version.
fn version() -> &'static str {
    option_env!("CARGO_VERSION_INFO").unwrap_or(env!("CARGO_PKG_VERSION"))
}

/// Create a report handler for displaying any parse errors.
fn reporter() -> GraphicalReportHandler {
    let mut theme = if std::io::stderr().is_terminal() {
        GraphicalTheme::unicode()
    } else {
        GraphicalTheme::unicode_nocolor()
    };

    theme.characters.error = if std::io::stderr().is_terminal() {
        format!("{}:", "error".red().bold())
    } else {
        "error:".to_string()
    };

    theme.characters.warning = if std::io::stderr().is_terminal() {
        format!("{}:", "warning".yellow().bold())
    } else {
        "warning:".to_string()
    };

    GraphicalReportHandler::new()
        .with_cause_chain()
        .with_theme(theme)
}

/// Parses a WDL source file into a syntax tree.
#[derive(Args)]
#[clap(disable_version_flag = true)]
pub struct ParseCommand {
    /// The path to the source WDL file.
    #[clap(value_name = "PATH")]
    pub path: PathBuf,
}

impl ParseCommand {
    /// Executes the command.
    pub async fn exec(self) -> Result<()> {
        log::debug!("executing `parse` command");

        let source = if self.path.as_os_str() == "-" {
            let mut source = String::new();
            std::io::stdin()
                .read_to_string(&mut source)
                .context("failed to read source from stdin")?;
            Arc::new(source)
        } else {
            Arc::new(fs::read_to_string(&self.path).with_context(|| {
                format!(
                    "failed to read source file `{path}`",
                    path = self.path.display()
                )
            })?)
        };

        let (tree, errors) = SyntaxTree::parse(&source);
        if !errors.is_empty() {
            let reporter = reporter();

            let mut s = String::new();
            for e in errors {
                s.clear();
                reporter
                    .render_report(
                        &mut s,
                        Report::from(e)
                            .with_source_code(NamedSource::new(
                                if self.path.as_os_str() == "-" {
                                    Cow::Borrowed("<stdin>")
                                } else {
                                    self.path.to_string_lossy()
                                },
                                source.clone(),
                            ))
                            .as_ref(),
                    )
                    .expect("failed to render diagnostic");
                eprintln!("{s}");
            }
        }

        print!("{:#?}", tree);
        Ok(())
    }
}

/// Parser for Workflow Description Language (WDL) files.
#[derive(Parser)]
#[clap(
    bin_name = "wdl-grammar",
    version,
    propagate_version = true,
    arg_required_else_help = true
)]
#[command(version = version())]
enum App {
    Parse(ParseCommand),
}

/// The main entry point for the CLI.
///
/// In the future, this will go in a `main.rs` once
/// the experimental feature is removed.
pub async fn main() {
    env_logger::init();

    if let Err(e) = match App::parse() {
        App::Parse(cmd) => cmd.exec().await,
    } {
        if std::io::stderr().is_terminal() {
            eprintln!("{}: {e:?}", "error".red().bold())
        } else {
            eprintln!("error: {e:?}");
        }

        std::process::exit(1);
    }
}
