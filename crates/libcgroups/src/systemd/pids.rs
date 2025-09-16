use std::collections::HashMap;
use std::convert::Infallible;

use oci_spec::runtime::LinuxPids;

use super::controller::Controller;
use super::dbus_native::serialize::Variant;
use crate::common::ControllerOpt;

pub const TASKS_MAX: &str = "TasksMax";

pub struct Pids {}

impl Controller for Pids {
    type Error = Infallible;

    fn apply(
        options: &ControllerOpt,
        _: u32,
        properties: &mut HashMap<&str, Variant>,
    ) -> Result<(), Self::Error> {
        if let Some(pids) = options.resources.pids() {
            tracing::debug!("Applying pids resource restrictions");
            Self::apply(pids, properties);
        }

        Ok(())
    }
}

impl Pids {
    fn apply(pids: &LinuxPids, properties: &mut HashMap<&str, Variant>) {
        let limit = if pids.limit() > 0 {
            pids.limit() as u64
        } else {
            u64::MAX
        };

        properties.insert(TASKS_MAX, Variant::U64(limit));
    }
}

#[cfg(test)]
mod tests {

    use anyhow::{Context, Result, anyhow};
    use oci_spec::runtime::{LinuxPidsBuilder, LinuxResources, LinuxResourcesBuilder};

    use super::super::dbus_native::serialize::DbusSerialize;
    use super::*;
    use crate::recast;

    fn setup(resources: &LinuxResources) -> (ControllerOpt<'_>, HashMap<&str, Variant>) {
        let properties = HashMap::new();
        let options = ControllerOpt {
            resources,
            disable_oom_killer: false,
            oom_score_adj: None,
            freezer_state: None,
        };

        (options, properties)
    }

    #[test]
    fn test_pids_positive_limit() -> Result<()> {
        let resources = LinuxResourcesBuilder::default()
            .pids(LinuxPidsBuilder::default().limit(10).build()?)
            .build()?;
        let (options, mut properties) = setup(&resources);

        <Pids as Controller>::apply(&options, 245, &mut properties)
            .map_err(|err| anyhow!(err))
            .context("apply pids")?;

        assert_eq!(properties.len(), 1);
        assert!(properties.contains_key(TASKS_MAX));

        let task_max = properties.get(TASKS_MAX).unwrap();
        let val = recast!(task_max, Variant)?;
        assert_eq!(val, Variant::U64(10));

        Ok(())
    }

    #[test]
    fn test_pids_zero_limit() -> Result<()> {
        let resources = LinuxResourcesBuilder::default()
            .pids(LinuxPidsBuilder::default().limit(0).build()?)
            .build()?;
        let (options, mut properties) = setup(&resources);

        <Pids as Controller>::apply(&options, 245, &mut properties)
            .map_err(|err| anyhow!(err))
            .context("apply pids")?;

        assert_eq!(properties.len(), 1);
        assert!(properties.contains_key(TASKS_MAX));

        let task_max = properties.get(TASKS_MAX).unwrap();
        let val = recast!(task_max, Variant)?;
        assert_eq!(val, Variant::U64(u64::MAX));

        Ok(())
    }

    #[test]
    fn test_pids_negative_limit() -> Result<()> {
        let resources = LinuxResourcesBuilder::default()
            .pids(LinuxPidsBuilder::default().limit(-500).build()?)
            .build()?;
        let (options, mut properties) = setup(&resources);

        <Pids as Controller>::apply(&options, 245, &mut properties)
            .map_err(|err| anyhow!(err))
            .context("apply pids")?;

        assert_eq!(properties.len(), 1);
        assert!(properties.contains_key(TASKS_MAX));

        let task_max = properties.get(TASKS_MAX).unwrap();
        let val = recast!(task_max, Variant)?;
        assert_eq!(val, Variant::U64(u64::MAX));

        Ok(())
    }
}
