//! Contains structure for a test group
use std::collections::BTreeMap;

use crossbeam::thread;

use crate::testable::{TestResult, Testable, TestableGroup};

/// Stores tests belonging to a group
pub struct TestGroup {
    /// name of the test group
    name: &'static str,
    /// can the test group be executed in parallel (both the tests
    /// within it, and alongside other test groups)
    parallel: bool,
    /// tests belonging to this group
    tests: BTreeMap<&'static str, Box<dyn Testable + Sync + Send>>,
}

impl TestGroup {
    /// create a new test group
    pub fn new(name: &'static str) -> Self {
        TestGroup {
            name,
            parallel: true,
            tests: BTreeMap::new(),
        }
    }

    /// mark the test group as unsuitable for parallel execution
    pub fn set_nonparallel(&mut self) {
        self.parallel = false
    }

    /// add a test to the group
    pub fn add(&mut self, tests: Vec<Box<impl Testable + Sync + Send + 'static>>) {
        tests.into_iter().for_each(|t| {
            self.tests.insert(t.get_name(), t);
        });
    }
}

impl TestableGroup for TestGroup {
    /// get name of the test group
    fn get_name(&self) -> &'static str {
        self.name
    }

    /// can this test group be executed (within itself, and alongside other groups)
    fn parallel(&self) -> bool {
        self.parallel
    }

    /// run all the test from the test group
    fn run_all(&self) -> Vec<(&'static str, TestResult)> {
        let mut ret = Vec::with_capacity(self.tests.len());
        if self.parallel {
            thread::scope(|s| {
                let mut collector = Vec::with_capacity(self.tests.len());
                for (_, t) in self.tests.iter() {
                    let _t = s.spawn(move |_| {
                        if t.can_run() {
                            (t.get_name(), t.run())
                        } else {
                            (t.get_name(), TestResult::Skipped)
                        }
                    });
                    collector.push(_t);
                }
                for handle in collector {
                    ret.push(handle.join().unwrap());
                }
            })
            .unwrap();
        } else {
            for (_, t) in self.tests.iter() {
                ret.push(if t.can_run() {
                    (t.get_name(), t.run())
                } else {
                    (t.get_name(), TestResult::Skipped)
                });
            }
        }
        ret
    }

    /// run selected test from the group
    fn run_selected(&self, selected: &[&str]) -> Vec<(&'static str, TestResult)> {
        let selected_tests = self
            .tests
            .iter()
            .filter(|(name, _)| selected.contains(name));
        let mut ret = Vec::with_capacity(selected.len());
        if self.parallel {
            thread::scope(|s| {
                let mut collector = Vec::with_capacity(selected.len());
                for (_, t) in selected_tests {
                    let _t = s.spawn(move |_| {
                        if t.can_run() {
                            (t.get_name(), t.run())
                        } else {
                            (t.get_name(), TestResult::Skipped)
                        }
                    });
                    collector.push(_t);
                }
                for handle in collector {
                    ret.push(handle.join().unwrap());
                }
            })
            .unwrap();
        } else {
            for (_, t) in selected_tests {
                ret.push(if t.can_run() {
                    (t.get_name(), t.run())
                } else {
                    (t.get_name(), TestResult::Skipped)
                });
            }
        }
        ret
    }
}
