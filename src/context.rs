use jwt_simple::prelude::*;

use crate::config::acl::Action;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct Access {
    #[serde(rename = "type")]
    pub type_: String,
    pub name: String,
    pub actions: Vec<Action>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct AdditionalClaims {
    pub access: Vec<Access>,
}
