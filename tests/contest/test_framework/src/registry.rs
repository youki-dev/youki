//! Test groups registered with `register_test_group!` are collected here at
//! link time, so `main.rs` does not need to list every group by hand.
use crate::test_manager::TestableGroupType;

#[doc(hidden)]
pub struct TestGroupFactory(pub fn() -> Box<TestableGroupType>);

inventory::collect!(TestGroupFactory);

pub(crate) fn registered() -> impl Iterator<Item = Box<TestableGroupType>> {
    inventory::iter::<TestGroupFactory>
        .into_iter()
        .map(|f| (f.0)())
}

/// Register a test group so that `TestManager::add_registered_test_groups` picks it up.
///
/// `register_test_group!(get_pidfile_test);`
#[macro_export]
macro_rules! register_test_group {
    ($ctor:path) => {
        $crate::inventory::submit! {
            $crate::registry::TestGroupFactory(|| ::std::boxed::Box::new($ctor()))
        }
    };
}
