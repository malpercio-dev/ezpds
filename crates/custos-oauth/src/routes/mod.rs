//! The OAuth route handlers, one file per endpoint (the token endpoint one directory, a file per
//! grant). Only the handler functions leave this module; shared support lives outside it
//! (`crate::oauth_errors`, `crate::oauth_dpop`, `crate::oauth_templates`).

mod oauth_authorize;
mod oauth_client_metadata;
mod oauth_consent;
mod oauth_jwks;
mod oauth_par;
mod oauth_protected_resource;
mod oauth_revoke;
mod oauth_server_metadata;
mod oauth_token;

pub(crate) use oauth_authorize::{get_authorization, post_authorization};
pub(crate) use oauth_client_metadata::oauth_client_metadata;
pub(crate) use oauth_consent::{
    get_authorization_status, get_consent_request, post_authorization_approve,
    post_authorization_complete,
};
pub(crate) use oauth_jwks::oauth_jwks;
pub(crate) use oauth_par::post_par;
pub(crate) use oauth_protected_resource::oauth_protected_resource_metadata;
pub(crate) use oauth_revoke::post_revoke;
pub(crate) use oauth_server_metadata::oauth_server_metadata;
pub(crate) use oauth_token::post_token;
