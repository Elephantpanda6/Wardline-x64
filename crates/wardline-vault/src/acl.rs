use std::path::Path;

use crate::VaultError;

pub fn current_user_sid_string() -> Result<String, VaultError> {
    wardline_platform::acl::current_user_sid_string().map_err(Into::into)
}

pub fn protect_path_owner_only(path: &Path) -> Result<(), VaultError> {
    wardline_platform::acl::protect_path_owner_only(path).map_err(Into::into)
}

pub fn verify_owner_only_file(path: &Path) -> Result<(), VaultError> {
    wardline_platform::acl::verify_owner_only_file(path).map_err(Into::into)
}
