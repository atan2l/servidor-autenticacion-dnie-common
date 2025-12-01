use crate::oauth::client_cert_data::ClientCertData;
use oxide_auth::code_grant::authorization::Request;
use oxide_auth::frontends::simple::extensions::{AddonResult, AuthorizationAddon};
use oxide_auth::primitives::grant::{GrantExtension, Value};

pub struct MtlsExtension {
    client_cert_data: ClientCertData,
}

impl MtlsExtension {
    pub fn new(client_cert_data: ClientCertData) -> Self {
        Self { client_cert_data }
    }
}

impl GrantExtension for MtlsExtension {
    fn identifier(&self) -> &'static str {
        "mtls"
    }
}

impl AuthorizationAddon for MtlsExtension {
    fn execute(&self, _: &dyn Request) -> AddonResult {
        match serde_json::to_string(&self.client_cert_data) {
            Ok(json) => AddonResult::Data(Value::Public(Some(json))),
            Err(_) => AddonResult::Err,
        }
    }
}
