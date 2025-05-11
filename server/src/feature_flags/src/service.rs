use std::{collections::HashMap, sync::Arc};

use launchdarkly_server_sdk::Client;

use crate::config::Mode;

#[derive(Clone)]
pub struct Service {
    pub(crate) client: Arc<Client>,
    pub(crate) mode: Mode,
    pub(crate) override_flags: HashMap<String, String>,
}

impl Service {
    /// Public test stub constructor for local/offline mode
    pub fn test_stub(overrides: HashMap<String, String>) -> Self {
        let config = launchdarkly_server_sdk::ConfigBuilder::new("dummy").offline(true).build().unwrap();
        let client = launchdarkly_server_sdk::Client::build(config).unwrap();
        Self {
            client: Arc::new(client),
            mode: Mode::Test,
            override_flags: overrides,
        }
    }
    pub(crate) fn new(client: Client, mode: Mode, override_flags: HashMap<String, String>) -> Self {
        Self {
            client: Arc::new(client),
            mode,
            override_flags,
        }
    }
}
