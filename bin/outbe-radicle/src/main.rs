use std::sync::mpsc;

fn main() {
    let _ = log::set_boxed_logger(Box::new(radicle_log::Logger::new()));
    log::set_max_level(log::LevelFilter::Info);
    if let Err(error) = run() {
        eprintln!("outbe-radicle: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), heartwood_outbe_radicle::Error> {
    let options = heartwood_outbe_radicle::Options::from_env()?;
    let (sender, receiver) = mpsc::sync_channel(1);
    radicle_signals::install(sender)?;
    heartwood_outbe_radicle::PreparedSidecar::prepare(options, receiver)?.run()
}
