// pattern: Imperative Shell

//! Queries over every KEK-wrapped column in the schema.
//!
//! The signing-key master key (`EZPDS_SIGNING_KEY_MASTER_KEY`) is an AES-256-GCM
//! key-encryption key (KEK) that wraps every at-rest secret. This module is the
//! single inventory of where that ciphertext lives — one [`SecretFamily`] per
//! wrapped column — plus generic fetch/update functions over the inventory, so
//! the `rewrap` maintenance path can re-encrypt everything without a per-table
//! query function scattered across five sibling modules. Adding a new
//! KEK-wrapped column means adding a variant here; the re-wrap tool then covers
//! it automatically.
//!
//! Like every `db/` module this file only moves opaque ciphertext; decryption
//! and re-encryption live in the caller (`crate::rewrap`).

use sqlx::Sqlite;

/// One KEK-wrapped column: the table, its primary-key column, and the
/// ciphertext column. `ALL` is the exhaustive inventory the re-wrap sweep
/// iterates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretFamily {
    /// Per-account repo signing keys for promoted DIDs (`signing_keys`, V002).
    SigningKeys,
    /// Standard-migration signing-key reservations (`reserved_signing_keys`, V032).
    ReservedSigningKeys,
    /// Mobile DID-ceremony repo keys still on the pending account
    /// (`pending_accounts.repo_signing_private_key_encrypted`, V019; nullable).
    PendingAccounts,
    /// Operator-level relay signing keys (`relay_signing_keys`, V003).
    RelaySigningKeys,
    /// The server's persistent ES256 OAuth signing key (`oauth_signing_key`, V012).
    OauthSigningKey,
    /// The persistent HS256 JWT signing secret (`jwt_signing_secret`, V015).
    JwtSigningSecret,
    /// The persistent Iroh node Ed25519 secret key (`iroh_identity`, V022).
    IrohIdentity,
}

impl SecretFamily {
    /// Every KEK-wrapped column in the schema, in sweep order.
    pub const ALL: [SecretFamily; 7] = [
        SecretFamily::SigningKeys,
        SecretFamily::ReservedSigningKeys,
        SecretFamily::PendingAccounts,
        SecretFamily::RelaySigningKeys,
        SecretFamily::OauthSigningKey,
        SecretFamily::JwtSigningSecret,
        SecretFamily::IrohIdentity,
    ];

    /// The owning table name, for reporting and error messages.
    pub fn table(self) -> &'static str {
        match self {
            SecretFamily::SigningKeys => "signing_keys",
            SecretFamily::ReservedSigningKeys => "reserved_signing_keys",
            SecretFamily::PendingAccounts => "pending_accounts",
            SecretFamily::RelaySigningKeys => "relay_signing_keys",
            SecretFamily::OauthSigningKey => "oauth_signing_key",
            SecretFamily::JwtSigningSecret => "jwt_signing_secret",
            SecretFamily::IrohIdentity => "iroh_identity",
        }
    }

    /// SELECT for `(id, ciphertext)` over every wrapped row of this family.
    /// `pending_accounts`' key columns are nullable (the key is generated
    /// mid-ceremony), so that query skips NULL rows — there is nothing to
    /// re-wrap on them.
    fn select_sql(self) -> &'static str {
        match self {
            SecretFamily::SigningKeys => "SELECT id, private_key_encrypted FROM signing_keys",
            SecretFamily::ReservedSigningKeys => {
                "SELECT id, private_key_encrypted FROM reserved_signing_keys"
            }
            SecretFamily::PendingAccounts => {
                "SELECT id, repo_signing_private_key_encrypted FROM pending_accounts \
                 WHERE repo_signing_private_key_encrypted IS NOT NULL"
            }
            SecretFamily::RelaySigningKeys => {
                "SELECT id, private_key_encrypted FROM relay_signing_keys"
            }
            SecretFamily::OauthSigningKey => {
                "SELECT id, private_key_encrypted FROM oauth_signing_key"
            }
            SecretFamily::JwtSigningSecret => "SELECT id, secret_encrypted FROM jwt_signing_secret",
            SecretFamily::IrohIdentity => "SELECT id, secret_key_encrypted FROM iroh_identity",
        }
    }

    /// UPDATE writing a re-wrapped ciphertext back to one row by primary key.
    fn update_sql(self) -> &'static str {
        match self {
            SecretFamily::SigningKeys => {
                "UPDATE signing_keys SET private_key_encrypted = ? WHERE id = ?"
            }
            SecretFamily::ReservedSigningKeys => {
                "UPDATE reserved_signing_keys SET private_key_encrypted = ? WHERE id = ?"
            }
            SecretFamily::PendingAccounts => {
                "UPDATE pending_accounts SET repo_signing_private_key_encrypted = ? WHERE id = ?"
            }
            SecretFamily::RelaySigningKeys => {
                "UPDATE relay_signing_keys SET private_key_encrypted = ? WHERE id = ?"
            }
            SecretFamily::OauthSigningKey => {
                "UPDATE oauth_signing_key SET private_key_encrypted = ? WHERE id = ?"
            }
            SecretFamily::JwtSigningSecret => {
                "UPDATE jwt_signing_secret SET secret_encrypted = ? WHERE id = ?"
            }
            SecretFamily::IrohIdentity => {
                "UPDATE iroh_identity SET secret_key_encrypted = ? WHERE id = ?"
            }
        }
    }
}

/// One KEK-wrapped row: its primary key and the stored ciphertext
/// (80-char base64 per `crypto::encrypt_private_key`).
#[derive(Debug, Clone)]
pub struct WrappedSecretRow {
    pub id: String,
    pub ciphertext: String,
}

/// Fetch every wrapped row of one family. Generic over the executor so the
/// re-wrap transaction can read and write on the same connection.
pub async fn list_wrapped_secrets<'e, E>(
    executor: E,
    family: SecretFamily,
) -> Result<Vec<WrappedSecretRow>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let rows: Vec<(String, String)> = sqlx::query_as(family.select_sql())
        .fetch_all(executor)
        .await?;
    Ok(rows
        .into_iter()
        .map(|(id, ciphertext)| WrappedSecretRow { id, ciphertext })
        .collect())
}

/// Write one re-wrapped ciphertext back by primary key. Errors if the row
/// vanished (`RowNotFound`) — inside the re-wrap transaction that can only
/// mean a logic bug, and a silent zero-row update would leave the secret
/// stranded under the old key.
pub async fn update_wrapped_secret<'e, E>(
    executor: E,
    family: SecretFamily,
    id: &str,
    ciphertext: &str,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let result = sqlx::query(family.update_sql())
        .bind(ciphertext)
        .bind(id)
        .execute(executor)
        .await?;
    if result.rows_affected() != 1 {
        return Err(sqlx::Error::RowNotFound);
    }
    Ok(())
}

/// The `server_metadata` key tracking how many KEK rotations have been applied.
/// Absent = 0 (the DB has only ever seen its initial key).
const KEK_GENERATION_KEY: &str = "kek_generation";

/// Read the current KEK generation (0 when the marker has never been written).
pub async fn get_kek_generation<'e, E>(executor: E) -> Result<i64, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let row: Option<(String,)> = sqlx::query_as("SELECT value FROM server_metadata WHERE key = ?")
        .bind(KEK_GENERATION_KEY)
        .fetch_optional(executor)
        .await?;
    Ok(row.and_then(|(v,)| v.parse::<i64>().ok()).unwrap_or(0))
}

/// Upsert the KEK generation marker. Written inside the re-wrap transaction so
/// the marker and the re-encrypted ciphertext commit (or roll back) together.
pub async fn set_kek_generation<'e, E>(executor: E, generation: i64) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT INTO server_metadata (key, value) VALUES (?, ?) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(KEK_GENERATION_KEY)
    .bind(generation.to_string())
    .execute(executor)
    .await?;
    Ok(())
}
