use std::fs;
use std::io::IsTerminal;
use std::path::Path;
use std::path::PathBuf;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Args;
use clap::Parser;
use codespan_reporting::files::SimpleFile;
use codespan_reporting::term::emit;
use codespan_reporting::term::termcolor::ColorChoice;
use codespan_reporting::term::termcolor::StandardStream;
use codespan_reporting::term::Config;
use colored::Colorize;
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use wdl_analysis::AnalysisEngine;
use wdl_ast::Diagnostic;
use wdl_ast::Validator;
use wdl_lint::LintVisitor;

/// Emits the given diagnostics to the output stream.
///
/// The use of color is determined by the presence of a terminal.
///
/// In the future, we might want the color choice to be a CLI argument.
fn emit_diagnostics(path: &Path, source: &str, diagnostics: &[Diagnostic]) -> Result<()> {
    let file = SimpleFile::new(path.to_str().context("path should be UTF-8")?, source);
    let mut stream = StandardStream::stdout(ColorChoice::Auto);
    for diagnostic in diagnostics.iter() {
        emit(
            &mut stream,
            &Config::default(),
            &file,
            &diagnostic.to_codespan(),
        )
        .context("failed to emit diagnostic")?;
    }

    Ok(())
}

/// Analyzes the given path and reports all diagnostics.
#[derive(Args)]
#[clap(disable_version_flag = true)]
pub struct AnalyzeCommand {
    /// Whether or not to run analysis with lint rules enabled.
    #[clap(long)]
    pub lint: bool,
    /// The path to analyze.
    #[clap(value_name = "PATH")]
    pub path: PathBuf,
}

impl AnalyzeCommand {
    async fn exec(self) -> Result<()> {
        let bar = ProgressBar::new(0);
        bar.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] {bar:40.cyan/blue} {msg} {pos}/{len}",
            )
            .unwrap(),
        );

        let lint = self.lint;
        let engine = AnalysisEngine::new_with_validator(move || {
            let mut validator = Validator::default();
            if lint {
                validator.add_visitor(LintVisitor::default());
            }
            validator
        })?;

        let results = engine
            .analyze_with_progress(&self.path, move |kind, completed, total| {
                if completed == 0 {
                    bar.set_length(total.try_into().unwrap());
                    bar.set_message(format!("{kind}"));
                }
                bar.set_position(completed.try_into().unwrap());
            })
            .await;

        let mut count = 0;
        for result in results {
            let source = fs::read_to_string(result.path()).with_context(|| {
                format!("failed to read `{path}`", path = result.path().display())
            })?;
            emit_diagnostics(result.path(), &source, result.diagnostics())?;
            count += result.diagnostics().len();
        }

        engine.shutdown().await;

        if count > 0 {
            bail!(
                "aborting due to previous {count} diagnostic{s}",
                s = if count == 1 { "" } else { "s" }
            );
        }

        Ok(())
    }
}

/// A tool for analyzing WDL documents.
#[derive(Parser)]
#[clap(
    bin_name = "analyzer",
    version,
    propagate_version = true,
    arg_required_else_help = true
)]
enum App {
    Analyze(AnalyzeCommand),
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder()
        .format_module_path(false)
        .format_target(false)
        .init();

    if let Err(e) = match App::parse() {
        App::Analyze(cmd) => cmd.exec().await,
    } {
        eprintln!(
            "{error}: {e:?}",
            error = if std::io::stderr().is_terminal() {
                "error".red().bold()
            } else {
                "error".normal()
            }
        );

        std::process::exit(1);
    }

    Ok(())
}
