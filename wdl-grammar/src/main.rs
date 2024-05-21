//! A command-line tool for parsing Workflow Description Language (WDL)
//! documents.
//!
//! **Note:** this tool is intended to be used as a utility to test and develop
//! the [`wdl-grammar`](https://crates.io/crates/wdl-grammar) crate. It is not
//! intended to be used by a general audience.

#[cfg(feature = "experimental")]
#[allow(dead_code)]
mod experimental;

#[cfg(not(feature = "experimental"))]
mod commands;

#[tokio::main]
async fn main() {
    #[cfg(feature = "experimental")]
    experimental::cli::main().await;

    #[cfg(not(feature = "experimental"))]
    match commands::inner().await {
        Ok(_) => {}
        Err(err) => eprintln!("error: {}", err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_arguments() {
        use clap::CommandFactory;
        Args::command().debug_assert()
    }
}
