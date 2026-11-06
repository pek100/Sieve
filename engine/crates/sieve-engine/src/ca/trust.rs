//! The system's trust behind seams (plan 2.3): the machine root store and the
//! Firefox policy value. `win::store` and `win::firefox` are the real ones;
//! tests use the fakes below, so no test can write to either.

/// The DER of an `extKeyUsage` of Server Authentication only: a SEQUENCE of
/// the one OID 1.3.6.1.5.5.7.3.1. It is the certificate's EKU extension value
/// and the store's `CERT_ENHKEY_USAGE_PROP_ID` (a test compares the two).
pub const SERVER_AUTH_EKU_DER: &[u8] = &[0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

/// The policy value that makes Firefox read the Windows store.
pub const FIREFOX_POLICY_ON: u32 = 1;

/// `LocalMachine\Root`, by thumbprint only: nothing here can name a
/// certificate by its subject, so a foreign root cannot be touched.
pub trait RootStore: Send + Sync {
    /// Adds the root with its Server Authentication property.
    fn add(&self, der: &[u8]) -> Result<(), String>;
    /// The DER of the root with this thumbprint, if it is in the store.
    fn read(&self, thumbprint: &str) -> Result<Option<Vec<u8>>, String>;
    /// Removes it; a root that is not there is success.
    fn remove(&self, thumbprint: &str) -> Result<(), String>;
}

/// The store's three writes for one add.
pub trait StoreWrites {
    type Context;
    fn context(&self, der: &[u8]) -> Result<Self::Context, String>;
    fn set_server_auth(&self, context: &Self::Context) -> Result<(), String>;
    fn add_new(&self, context: &Self::Context) -> Result<(), String>;
}

/// The property goes on the context first, so a root is never in the store
/// without it.
pub fn add_with_property<W: StoreWrites>(writes: &W, der: &[u8]) -> Result<(), String> {
    let context = writes.context(der)?;
    writes.set_server_auth(&context)?;
    writes.add_new(&context)
}

/// `ImportEnterpriseRoots` in the machine's Firefox policy.
pub trait FirefoxPolicy: Send + Sync {
    fn installed(&self) -> Result<bool, String>;
    fn read(&self) -> Result<Option<u32>, String>;
    fn set(&self) -> Result<(), String>;
    fn delete(&self) -> Result<(), String>;
}

#[cfg(test)]
pub use fakes::{Faults, FakeFirefox, FakeRootStore};

#[cfg(test)]
mod fakes {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, Mutex};

    use super::{FIREFOX_POLICY_ON, FirefoxPolicy, RootStore};
    use crate::ca::root::thumbprint;

    /// Numbers every fake operation, so a test can fail any one of them:
    /// before it happens (a refused call), after it happened (a crash right
    /// behind the write), or every call by name.
    #[derive(Default)]
    pub struct Faults {
        pub count: Mutex<usize>,
        pub fail_before: Mutex<Option<usize>>,
        pub fail_after: Mutex<Option<usize>>,
        pub fail_named: Mutex<BTreeSet<&'static str>>,
        pub log: Mutex<Vec<&'static str>>,
    }

    impl Faults {
        pub fn step<T>(&self, name: &'static str, work: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
            let n = {
                let mut count = self.count.lock().unwrap();
                *count += 1;
                *count - 1
            };
            self.log.lock().unwrap().push(name);
            if self.fail_named.lock().unwrap().contains(name) {
                return Err(format!("{name}: refused"));
            }
            if *self.fail_before.lock().unwrap() == Some(n) {
                return Err(format!("{name}: refused (step {n})"));
            }
            let done = work()?;
            if *self.fail_after.lock().unwrap() == Some(n) {
                return Err(format!("{name}: crashed behind the write (step {n})"));
            }
            Ok(done)
        }

        pub fn clear(&self) {
            *self.fail_before.lock().unwrap() = None;
            *self.fail_after.lock().unwrap() = None;
            self.fail_named.lock().unwrap().clear();
            self.log.lock().unwrap().clear();
            *self.count.lock().unwrap() = 0;
        }
    }

    #[derive(Default)]
    pub struct FakeRootStore {
        pub faults: Arc<Faults>,
        pub roots: Mutex<BTreeMap<String, Vec<u8>>>,
    }

    impl FakeRootStore {
        pub fn thumbprints(&self) -> Vec<String> {
            self.roots.lock().unwrap().keys().cloned().collect()
        }
    }

    impl RootStore for FakeRootStore {
        fn add(&self, der: &[u8]) -> Result<(), String> {
            self.faults.step("store add", || {
                self.roots.lock().unwrap().insert(thumbprint(der), der.to_vec());
                Ok(())
            })
        }

        fn read(&self, thumb: &str) -> Result<Option<Vec<u8>>, String> {
            self.faults.step("store read", || Ok(self.roots.lock().unwrap().get(thumb).cloned()))
        }

        fn remove(&self, thumb: &str) -> Result<(), String> {
            self.faults.step("store remove", || {
                self.roots.lock().unwrap().remove(thumb);
                Ok(())
            })
        }
    }

    #[derive(Default)]
    pub struct FakeFirefox {
        pub faults: Arc<Faults>,
        pub installed: Mutex<bool>,
        pub value: Mutex<Option<u32>>,
    }

    impl FirefoxPolicy for FakeFirefox {
        fn installed(&self) -> Result<bool, String> {
            self.faults.step("firefox installed", || Ok(*self.installed.lock().unwrap()))
        }

        fn read(&self) -> Result<Option<u32>, String> {
            self.faults.step("firefox read", || Ok(*self.value.lock().unwrap()))
        }

        fn set(&self) -> Result<(), String> {
            self.faults.step("firefox set", || {
                *self.value.lock().unwrap() = Some(FIREFOX_POLICY_ON);
                Ok(())
            })
        }

        fn delete(&self) -> Result<(), String> {
            self.faults.step("firefox delete", || {
                *self.value.lock().unwrap() = None;
                Ok(())
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    #[derive(Default)]
    struct Recording {
        calls: RefCell<Vec<&'static str>>,
        fail: Option<&'static str>,
    }

    impl Recording {
        fn call(&self, name: &'static str) -> Result<(), String> {
            self.calls.borrow_mut().push(name);
            if self.fail == Some(name) { Err(name.to_string()) } else { Ok(()) }
        }
    }

    impl StoreWrites for Recording {
        type Context = ();
        fn context(&self, _: &[u8]) -> Result<(), String> {
            self.call("context")
        }
        fn set_server_auth(&self, _: &()) -> Result<(), String> {
            self.call("property")
        }
        fn add_new(&self, _: &()) -> Result<(), String> {
            self.call("add")
        }
    }

    #[test]
    fn the_server_auth_property_is_set_with_the_add() {
        let writes = Recording::default();
        add_with_property(&writes, b"der").unwrap();
        assert_eq!(*writes.calls.borrow(), ["context", "property", "add"]);

        let writes = Recording { fail: Some("property"), ..Recording::default() };
        assert!(add_with_property(&writes, b"der").is_err());
        assert_eq!(*writes.calls.borrow(), ["context", "property"], "no root in the store without its property");
    }
}
