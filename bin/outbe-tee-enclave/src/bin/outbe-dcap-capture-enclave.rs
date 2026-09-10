//! Capture-only Gramine SGX entrypoint for real intent-bound DCAP fixtures.
//!
//! This required-feature binary is deliberately separate from the production
//! `outbe-tee-enclave` ELF and is never included in release packaging.

fn main() {
    let arguments = std::env::args().collect::<Vec<_>>();
    let Some(intent_path) = argument(&arguments, "--intent") else {
        usage();
        std::process::exit(2);
    };
    let Some(quote_path) = argument(&arguments, "--quote-output") else {
        usage();
        std::process::exit(2);
    };

    match outbe_tee_enclave::gramine::capture_dcap_quote_to_file(intent_path, quote_path) {
        Ok(()) => {
            eprintln!("outbe-dcap-capture-enclave: captured intent-bound quote at {quote_path}");
        }
        Err(error) => {
            eprintln!("outbe-dcap-capture-enclave: capture failed: {error}");
            std::process::exit(1);
        }
    }
}

fn argument<'a>(arguments: &'a [String], name: &str) -> Option<&'a str> {
    let index = arguments.iter().position(|argument| argument == name)?;
    arguments.get(index + 1).map(String::as_str)
}

fn usage() {
    eprintln!(
        "usage: outbe-dcap-capture-enclave --intent <canonical-intent> \
         --quote-output <new-quote-file>"
    );
}
