//! Subcommands for the `wdl-grammar` command-line tool.

use clap::Parser;
use clap::Subcommand;
use log::debug;
use log::LevelFilter;

pub mod create_test;
pub mod parse;

/// Subcommands for the `wdl-grammar` command-line tool.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Creates a test for a given input and grammar rule.
    CreateTest(create_test::Args),

    /// Parses an input according to the specified grammar rule.
    Parse(parse::Args),
}

/// Parse and testing Workflow Description Language (WDL) grammar.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about)]
struct Args {
    /// The subcommand to execute.
    #[command(subcommand)]
    command: Command,

    /// Detailed information, including debug information, is logged in the
    /// console.
    #[arg(short, long, global = true)]
    debug: bool,

    /// Enables logging for all modules (not just `wdl-grammar`).
    #[arg(short, long, global = true)]
    log_all_modules: bool,

    /// Only errors are logged to the console.
    #[arg(short, long, global = true)]
    quiet: bool,

    /// All available information, including trace information, is logged in
    /// the console.
    #[arg(short, long, global = true)]
    trace: bool,

    /// Additional information is logged in the console.
    #[arg(short, long, global = true)]
    verbose: bool,
}

/// The inner function for the binary.
pub async fn inner() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let level = if args.trace {
        LevelFilter::max()
    } else if args.debug {
        LevelFilter::Debug
    } else if args.verbose {
        LevelFilter::Info
    } else if args.quiet {
        LevelFilter::Error
    } else {
        LevelFilter::Warn
    };

    let module = match args.log_all_modules {
        true => None,
        false => Some("wdl_grammar"),
    };

    env_logger::builder().filter(module, level).init();

    match args.command {
        Command::CreateTest(args) => create_test::create_test(args)?,
        Command::Parse(args) => parse::parse(args)?,
    };

    Ok(())
}

/// An error common to any subcommand.
#[derive(Debug)]
pub enum Error {
    /// An input/output error.
    InputOutput(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InputOutput(err) => write!(f, "i/o error: {err}"),
        }
    }
}

impl std::error::Error for Error {}

/// A [`Result`](std::result::Result) with an [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Gets lines of input from STDIN.
pub fn get_contents_stdin() -> Result<String> {
    debug!("Reading from STDIN...");

    Ok(std::io::stdin()
        .lines()
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Error::InputOutput)?
        .join("\n"))
}
