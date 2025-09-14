use std::borrow::Cow;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use tracing::Level;
use tracing_subscriber::prelude::*;

const LOG_FORMAT_TEXT: &str = "text";
const LOG_FORMAT_JSON: &str = "json";
enum LogFormat {
    Text,
    Json,
}

/// If in debug mode, default level is debug to get maximum logging
#[cfg(debug_assertions)]
const DEFAULT_LOG_LEVEL: &str = "debug";

/// If not in debug mode, default level is error to get important logs
#[cfg(not(debug_assertions))]
const DEFAULT_LOG_LEVEL: &str = "error";

fn detect_log_format(log_format: Option<&str>) -> Result<LogFormat> {
    match log_format {
        None | Some(LOG_FORMAT_TEXT) => Ok(LogFormat::Text),
        Some(LOG_FORMAT_JSON) => Ok(LogFormat::Json),
        Some(unknown) => bail!("unknown log format: {}", unknown),
    }
}

fn detect_log_level(input: Option<String>, is_debug: bool) -> Result<Level> {
    // We keep the `debug` flag for backward compatibility, but use `log-level`
    // as the main way to set the log level due to the flexibility. If both are
    // specified, `log-level` takes precedence.
    let log_level: Cow<str> = match input {
        None if is_debug => "debug".into(),
        None => DEFAULT_LOG_LEVEL.into(),
        Some(level) => level.into(),
    };

    Ok(Level::from_str(log_level.as_ref())?)
}

#[derive(Debug, Default)]
pub struct ObservabilityConfig {
    pub log_debug_flag: bool,
    pub log_level: Option<String>,
    pub log_file: Option<PathBuf>,
    pub log_format: Option<String>,
    #[allow(dead_code)]
    pub systemd_log: bool,
}

impl From<&crate::Opts> for ObservabilityConfig {
    fn from(opts: &crate::Opts) -> Self {
        Self {
            log_debug_flag: opts.global.debug,
            log_level: opts.youki_extend.log_level.to_owned(),
            log_file: opts.global.log.to_owned(),
            log_format: opts.global.log_format.to_owned(),
            systemd_log: opts.youki_extend.systemd_log,
        }
    }
}

pub fn init<T>(config: T) -> Result<()>
where
    T: Into<ObservabilityConfig>,
{
    let config = config.into();
    let level = detect_log_level(config.log_level, config.log_debug_flag)
        .with_context(|| "failed to parse log level")?;
    let log_level_filter = tracing_subscriber::filter::LevelFilter::from(level);
    let log_format = detect_log_format(config.log_format.as_deref())
        .with_context(|| "failed to detect log format")?;

    #[cfg(debug_assertions)]
    let journald = true;
    #[cfg(not(debug_assertions))]
    let journald = config.systemd_log;

    let systemd_journald = if journald {
        match tracing_journald::layer() {
            Ok(layer) => Some(layer.with_syslog_identifier("youki".to_string())),
            Err(err) => {
                // Do not fail if we can't open syslog, just print a warning.
                // This is the case in, e.g., docker-in-docker.
                eprintln!("failed to initialize syslog logging: {:?}", err);
                None
            }
        }
    } else {
        None
    };
    let subscriber = tracing_subscriber::registry()
        .with(log_level_filter)
        .with(systemd_journald);

    // I really dislike how we have to specify individual branch for each
    // combination, but I can't find any better way to do this. The tracing
    // crate makes it hard to build a single format layer with different
    // conditions.
    match (config.log_file.as_ref(), log_format) {
        (None, LogFormat::Text) => {
            // Text to stderr
            subscriber
                .with(
                    tracing_subscriber::fmt::layer()
                        .without_time()
                        .with_writer(std::io::stderr),
                )
                .try_init()
                .map_err(|e| anyhow::anyhow!("failed to init logger: {}", e))?;
        }
        (None, LogFormat::Json) => {
            // JSON to stderr
            subscriber
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .flatten_event(true)
                        .with_span_list(false)
                        .with_writer(std::io::stderr),
                )
                .try_init()
                .map_err(|e| anyhow::anyhow!("failed to init logger: {}", e))?;
        }
        (Some(path), LogFormat::Text) => {
            // Log file with text format
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(path)
                .with_context(|| "failed to open log file")?;
            subscriber
                .with(tracing_subscriber::fmt::layer().with_writer(file))
                .try_init()
                .map_err(|e| anyhow::anyhow!("failed to init logger: {}", e))?;
        }
        (Some(path), LogFormat::Json) => {
            // Log file with JSON format
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(path)
                .with_context(|| "failed to open log file")?;
            subscriber
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .flatten_event(true)
                        .with_span_list(false)
                        .with_writer(file),
                )
                .try_init()
                .map_err(|e| anyhow::anyhow!("failed to init logger: {}", e))?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use libcontainer::test_utils::TestCallbackError;

    use super::*;

    #[test]
    fn test_detect_log_level() {
        let test = vec![
            ("error", tracing::Level::ERROR),
            ("warn", tracing::Level::WARN),
            ("info", tracing::Level::INFO),
            ("debug", tracing::Level::DEBUG),
            ("trace", tracing::Level::TRACE),
        ];
        for (input, expected) in test {
            assert_eq!(
                detect_log_level(Some(input.to_string()), false)
                    .expect("failed to parse log level"),
                expected
            )
        }
        assert_eq!(
            detect_log_level(None, true).expect("failed to parse log level"),
            tracing::Level::DEBUG
        );
        // Invalid log level should fail the parse
        assert!(detect_log_level(Some("invalid".to_string()), false).is_err());
    }

    #[test]
    fn test_detect_log_level_default() {
        if cfg!(debug_assertions) {
            assert_eq!(
                detect_log_level(None, false).unwrap(),
                tracing::Level::DEBUG
            )
        } else {
            assert_eq!(
                detect_log_level(None, false).unwrap(),
                tracing::Level::ERROR
            )
        }
    }

    #[test]
    fn test_init_many_times() -> Result<()> {
        let cb = || {
            let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
            let log_file = Path::join(temp_dir.path(), "test.log");
            let config = ObservabilityConfig {
                log_file: Some(log_file),
                ..Default::default()
            };
            init(config).map_err(|err| TestCallbackError::Other(err.into()))?;
            Ok(())
        };
        libcontainer::test_utils::test_in_child_process(cb)
            .with_context(|| "failed the first init tracing")?;
        libcontainer::test_utils::test_in_child_process(cb)
            .with_context(|| "failed the second init tracing")?;
        Ok(())
    }

    #[test]
    fn test_higher_loglevel_no_log() -> Result<()> {
        libcontainer::test_utils::test_in_child_process(|| {
            let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
            let log_file = Path::join(temp_dir.path(), "test.log");
            // Note, we can only init the tracing once, so we have to test in a
            // single unit test. The orders are important here.
            let config = ObservabilityConfig {
                log_file: Some(log_file.clone()),
                log_level: Some("error".to_string()),
                ..Default::default()
            };
            init(config).map_err(|err| TestCallbackError::Other(err.into()))?;
            assert!(
                log_file
                    .as_path()
                    .metadata()
                    .expect("failed to get logfile metadata")
                    .len()
                    == 0,
                "a new logfile should be empty"
            );
            // Test that info level is not logged into the logfile because we set the log level to error.
            tracing::info!("testing this");
            if log_file
                .as_path()
                .metadata()
                .map_err(|err| format!("failed to get logfile metadata: {err:?}"))?
                .len()
                != 0
            {
                let data = std::fs::read_to_string(&log_file)
                    .map_err(|err| format!("failed to read the logfile: {err:?}"))?;
                Err(TestCallbackError::Custom(format!(
                    "info level should not be logged into the logfile, but got: {data}"
                )))?;
            }

            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn test_json_logfile() -> Result<()> {
        libcontainer::test_utils::test_in_child_process(|| {
            let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
            let log_file = Path::join(temp_dir.path(), "test.log");
            // Note, we can only init the tracing once, so we have to test in a
            // single unit test. The orders are important here.
            let config = ObservabilityConfig {
                log_file: Some(log_file.clone()),
                log_format: Some(LOG_FORMAT_JSON.to_owned()),
                ..Default::default()
            };
            init(config).map_err(|err| TestCallbackError::Other(err.into()))?;
            assert!(
                log_file
                    .as_path()
                    .metadata()
                    .expect("failed to get logfile metadata")
                    .len()
                    == 0,
                "a new logfile should be empty"
            );
            // Test that the message logged is actually JSON format.
            tracing::error!("testing json log");
            let data = std::fs::read_to_string(&log_file)
                .map_err(|err| format!("failed to read the logfile: {err:?}"))?;
            if data.is_empty() {
                Err("logfile should not be empty")?;
            }
            serde_json::from_str::<serde_json::Value>(&data)
                .map_err(|err| format!("failed to parse {data}: {err:?}"))?;
            Ok(())
        })?;

        Ok(())
    }
}
