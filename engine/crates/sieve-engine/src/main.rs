//! sieve-engine: no behaviour in slice 1 (the service lands in slice 2).
fn main() {
    eprintln!("sieve-engine {}: not a service yet", env!("CARGO_PKG_VERSION"));
    std::process::exit(2);
}
