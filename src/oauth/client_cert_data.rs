use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ClientCertData {
    pub given_name: String,
    pub surname: String,
    pub serial_number: String,
    pub country: String,
}
