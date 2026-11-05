//! The real system behind the CA's seams: the only code that names a CNG key
//! write, a root-store write or the Firefox policy's registry write (law 13).
//! Compiled and linted, never run by a test: `service::runner` and
//! `service::scm` alone build these types. Their proof is the user's live
//! check (`docs/live/engine-slice-5.md`).

pub mod cng;
pub mod firefox;
pub mod store;

pub use cng::CngKeyStore;
pub use firefox::RegistryFirefoxPolicy;
pub use store::WindowsRootStore;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
