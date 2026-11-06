//! Proves COM and WMI load under the service's DLL rule: with the search
//! limited to System32, as `service::runner` sets it, one plain query must
//! still answer. Read only, needs no elevation. Exit 0 means it did.

#[cfg(windows)]
fn main() {
    use windows::Win32::System::LibraryLoader::{LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories};
    // SAFETY: a process-wide setting with a valid flag, the runner's first act.
    unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) }.expect("SetDefaultDllDirectories");
    match sieve_engine::flow::nat::os::operating_system_caption() {
        Ok(caption) => println!("WMI answered under the System32-only search: {caption}"),
        Err(why) => {
            eprintln!("WMI failed under the System32-only search: {why}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(windows))]
fn main() {}
