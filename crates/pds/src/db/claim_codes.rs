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
    mint_claim_codes_with_generator(db, count, expires_in_hours, generate_code).await
}

async fn mint_claim_codes_with_generator(
    db: &SqlitePool,
    count: u32,
    expires_in_hours: u32,
    mut generate: impl FnMut() -> String,
) -> Result<Vec<String>, MintClaimCodesError> {
    for attempt in 0..3_usize {
        let codes = generate_unique_codes(count as usize, &mut generate);
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

fn generate_unique_codes(count: usize, generate: &mut impl FnMut() -> String) -> Vec<String> {
    let mut codes = std::collections::HashSet::with_capacity(count);
    while codes.len() < count {
        codes.insert(generate());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_pool, run_migrations};

    async fn test_db() -> SqlitePool {
        let db = open_pool("sqlite::memory:").await.expect("test pool");
        run_migrations(&db).await.expect("test migrations");
        db
    }

    #[tokio::test]
    async fn mint_claim_codes_persists_generated_code() {
        let db = test_db().await;

        let codes = mint_claim_codes_with_generator(&db, 1, 24, || "OKCODE".to_string())
            .await
            .expect("mint succeeds");

        assert_eq!(codes, vec!["OKCODE".to_string()]);
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM claim_codes WHERE code = 'OKCODE'")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn mint_claim_codes_retries_unique_conflicts_then_exhausts() {
        let db = test_db().await;
        insert_claim_codes(&db, &["DUP123".to_string()], 24)
            .await
            .expect("seed duplicate code");

        let err = mint_claim_codes_with_generator(&db, 1, 24, || "DUP123".to_string())
            .await
            .expect_err("constant duplicate generator exhausts retries");

        assert!(matches!(err, MintClaimCodesError::Exhausted));
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM claim_codes WHERE code = 'DUP123'")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(
            count, 1,
            "failed retry attempts must not add duplicate rows"
        );
    }

    #[tokio::test]
    async fn mint_claim_codes_returns_store_error() {
        let db = test_db().await;
        db.close().await;

        let err = mint_claim_codes_with_generator(&db, 1, 24, || "ERR123".to_string())
            .await
            .expect_err("closed pool returns storage error");

        assert!(matches!(err, MintClaimCodesError::Store(_)));
    }
}
