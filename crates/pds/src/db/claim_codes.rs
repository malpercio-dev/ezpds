// pattern: Imperative Shell

use sqlx::SqlitePool;

use crate::code_gen::generate_code;

#[derive(Debug, thiserror::Error)]
pub enum MintClaimCodesError {
    #[error("failed to store claim codes: {0}")]
    Store(sqlx::Error),
    #[error("failed to generate unique claim codes after retries")]
    Exhausted,
}

/// Mint and persist a batch of single-use claim codes.
///
/// Retries on rare code-collision unique violations; any other storage failure is returned
/// immediately so the route can map it to its wire error shape.
pub async fn mint_claim_codes(
    db: &SqlitePool,
    count: u32,
    expires_in_hours: u32,
) -> Result<Vec<String>, MintClaimCodesError> {
    for attempt in 0..3_usize {
        let codes = generate_unique_codes(count as usize);
        match insert_claim_codes(db, &codes, expires_in_hours).await {
            Ok(()) => return Ok(codes),
            Err(e) if super::is_unique_violation(&e) => {
                tracing::warn!(attempt, "claim code uniqueness conflict; retrying");
            }
            Err(e) => return Err(MintClaimCodesError::Store(e)),
        }
    }

    Err(MintClaimCodesError::Exhausted)
}

fn generate_unique_codes(count: usize) -> Vec<String> {
    let mut codes = std::collections::HashSet::with_capacity(count);
    while codes.len() < count {
        codes.insert(generate_code());
    }
    codes.into_iter().collect()
}

async fn insert_claim_codes(
    db: &SqlitePool,
    codes: &[String],
    expires_in_hours: u32,
) -> Result<(), sqlx::Error> {
    let offset = format!("+{expires_in_hours} hours");
    let mut tx = db.begin().await?;
    for code in codes {
        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES (?, datetime('now', ?), datetime('now'))",
        )
        .bind(code)
        .bind(&offset)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}
