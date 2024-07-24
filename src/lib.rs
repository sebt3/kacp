pub mod config;
pub mod controller;
pub mod kacp;
pub use crate::config::Configuration;
pub use crate::controller::{error_policy, reconcile, update_config};
pub use crate::kacp::*;
use kube::client::Client;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("SerializationError: {0}")]
    SerializationError(#[source] serde_json::Error),

    #[error("K8s error: {0}")]
    KubeError(#[source] kube::Error),

    #[error("Watcher error: {0}")]
    WatcherError(#[source] kube::runtime::watcher::Error),

    #[error("IO error: {0}")]
    StdIo(#[source] std::io::Error),

    #[error("Finalizer error: {0}")]
    // NB: awkward type because finalizer::Error embeds the reconciler error (which is this)
    // so boxing this error to break cycles
    FinalizerError(#[source] Box<kube::runtime::finalizer::Error<Error>>),

    #[error("Json decoding error: {0}")]
    JsonError(#[source] serde_json::Error),

    #[error("Yaml decoding error: {0}")]
    YamlError(#[source] serde_yaml::Error),
}
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub fn metric_label(&self) -> String {
        format!("{self:?}").to_lowercase()
    }
}

#[derive(Clone)]
pub struct Context {
    /// Kubernetes client
    pub client: Client,
    /// Controller configuration
    pub config: Configuration,
    /// File to update
    pub target: PathBuf,
    /// Current node name
    pub node: String,
}
impl Context {
    #[must_use]
    pub fn new(client: Client, config: Configuration, target: PathBuf, node: &str) -> Context {
        Context {
            client,
            config,
            target,
            node: node.into(),
        }
    }
}
