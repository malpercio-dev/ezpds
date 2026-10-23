//! The Spaces route handlers, one file per endpoint. Only the handler functions leave this
//! module; shared support lives outside it (`crate::views`, `crate::auth`, `crate::db`).

mod admin_spaces;
mod get_delegation_token;
mod get_space_credential;
mod simplespace_create_space;
mod simplespace_delete_space;
mod simplespace_get_space;
mod simplespace_list_members;
mod simplespace_put_member;
mod simplespace_remove_member;
mod simplespace_update_space;
mod space_apply_writes;
mod space_create_record;
mod space_delete_record;
mod space_get_blob;
mod space_get_latest_commit;
mod space_get_record;
mod space_get_repo;
mod space_import_repo;
mod space_list_blobs;
mod space_list_records;
mod space_list_repo_ops;
mod space_list_repos;
mod space_list_spaces;
mod space_notify_credential_revoked;
mod space_notify_write;
mod space_put_record;
mod space_register_notify;
mod space_unregister_notify;

#[cfg(test)]
mod simplespace_routes_test;
#[cfg(test)]
mod space_lifecycle_test;
#[cfg(test)]
mod space_notify_routes_test;
#[cfg(test)]
mod space_routes_test;
#[cfg(test)]
mod space_sync_routes_test;
#[cfg(test)]
mod space_takedown_test;

pub(crate) use admin_spaces::{list_hosted_spaces, set_space_takedown};
pub(crate) use get_delegation_token::get_delegation_token;
pub(crate) use get_space_credential::get_space_credential;
pub(crate) use simplespace_create_space::simplespace_create_space;
pub(crate) use simplespace_delete_space::simplespace_delete_space;
pub(crate) use simplespace_get_space::simplespace_get_space;
pub(crate) use simplespace_list_members::simplespace_list_members;
pub(crate) use simplespace_put_member::simplespace_put_member;
pub(crate) use simplespace_remove_member::simplespace_remove_member;
pub(crate) use simplespace_update_space::simplespace_update_space;
pub(crate) use space_apply_writes::space_apply_writes;
pub(crate) use space_create_record::space_create_record;
pub(crate) use space_delete_record::space_delete_record;
pub(crate) use space_get_blob::space_get_blob;
pub(crate) use space_get_latest_commit::space_get_latest_commit;
pub(crate) use space_get_record::space_get_record;
pub(crate) use space_get_repo::space_get_repo;
pub(crate) use space_import_repo::space_import_repo;
pub(crate) use space_list_blobs::space_list_blobs;
pub(crate) use space_list_records::space_list_records;
pub(crate) use space_list_repo_ops::space_list_repo_ops;
pub(crate) use space_list_repos::space_list_repos;
pub(crate) use space_list_spaces::space_list_spaces;
pub(crate) use space_notify_credential_revoked::space_notify_credential_revoked;
pub(crate) use space_notify_write::space_notify_write;
pub(crate) use space_put_record::space_put_record;
pub(crate) use space_register_notify::space_register_notify;
pub(crate) use space_unregister_notify::space_unregister_notify;
