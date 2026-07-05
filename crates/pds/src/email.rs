// pattern: Imperative Shell
//
// Outbound email delivery.
//
// A small pluggable abstraction behind the password-reset, email-confirmation, and email-update
// flows. `AppState.email` holds an `Arc<dyn EmailSender>`, mirroring the `dns_provider` /
// `txt_resolver` / `well_known_resolver` trait-object pattern:
//   - LogEmailSender  — the default. Logs the message instead of sending it, so a fresh install
//     and the test suite need no mail server (this is the pre-outbound-email stub behaviour, now
//     behind a real interface). The plaintext token in the body is exactly what a developer reads
//     out of the logs to complete a flow locally.
//   - SmtpEmailSender — real delivery over SMTP via `lettre`, selected by `email.provider = "smtp"`.
//
// Message *content* (subjects, bodies, the reset/confirmation links) is built by the route
// handlers; this module only knows how to deliver an already-rendered `EmailMessage`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use common::{EmailConfig, EmailProvider, SmtpTls};
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

/// Connect/send timeout for the SMTP transport. `send()` is awaited on the request path, so an
/// unresponsive relay must not stall a handler (and tie up request capacity) indefinitely.
const SMTP_TIMEOUT: Duration = Duration::from_secs(15);

/// A fully-rendered outbound message. Plaintext body only — the flows this serves (token
/// delivery) have no need for HTML.
pub struct EmailMessage {
    /// Recipient address (a bare `user@host`).
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// Error returned by an [`EmailSender`] delivery.
#[derive(Debug, thiserror::Error)]
#[error("email delivery error: {0}")]
pub struct EmailError(pub String);

/// Abstraction over outbound email delivery.
///
/// Object-safe: uses `Pin<Box<dyn Future>>` so `dyn EmailSender` works with `Arc`, matching the
/// other resolver/provider traits in this crate.
pub trait EmailSender: Send + Sync {
    fn send<'a>(
        &'a self,
        message: EmailMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), EmailError>> + Send + 'a>>;
}

/// Default [`EmailSender`]: logs the message rather than sending it.
///
/// Keeps a fresh install and the test suite fully offline. In local development the logged body
/// (which carries the plaintext token) is the delivery channel — read the token out of the logs.
pub struct LogEmailSender;

impl EmailSender for LogEmailSender {
    fn send<'a>(
        &'a self,
        message: EmailMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), EmailError>> + Send + 'a>> {
        Box::pin(async move {
            tracing::info!(
                to = %message.to,
                subject = %message.subject,
                body = %message.body,
                "email delivery (log provider): message not actually sent"
            );
            Ok(())
        })
    }
}

/// Real [`EmailSender`] delivering over SMTP via `lettre`.
pub struct SmtpEmailSender {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl SmtpEmailSender {
    /// Build an SMTP sender from the resolved [`EmailConfig`]. Expects `provider = Smtp` with
    /// `from` and `smtp_host` present (config validation guarantees this).
    fn from_config(config: &EmailConfig) -> Result<Self, EmailError> {
        let from_addr = config
            .from
            .as_deref()
            .ok_or_else(|| EmailError("email.from is required for SMTP delivery".to_string()))?;
        let from = build_from_mailbox(from_addr, config.from_name.as_deref())?;

        let host = config.smtp_host.as_deref().ok_or_else(|| {
            EmailError("email.smtp_host is required for SMTP delivery".to_string())
        })?;

        // Select the transport builder by TLS mode. `relay`/`starttls_relay` fail only if the
        // rustls config can't be built; `builder_dangerous` is the plaintext (test-sink) path.
        let mut builder = match config.smtp_tls {
            SmtpTls::Implicit => AsyncSmtpTransport::<Tokio1Executor>::relay(host)
                .map_err(|e| EmailError(format!("failed to build implicit-TLS SMTP relay: {e}")))?,
            SmtpTls::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
                .map_err(|e| EmailError(format!("failed to build STARTTLS SMTP relay: {e}")))?,
            SmtpTls::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host),
        }
        .port(config.smtp_port)
        .timeout(Some(SMTP_TIMEOUT));

        // Authenticate only when both a username and password are configured.
        if let (Some(user), Some(pass)) = (
            config.smtp_username.as_deref(),
            config.smtp_password.as_ref(),
        ) {
            builder = builder.credentials(Credentials::new(user.to_string(), pass.0.clone()));
        }

        Ok(Self {
            transport: builder.build(),
            from,
        })
    }
}

impl EmailSender for SmtpEmailSender {
    fn send<'a>(
        &'a self,
        message: EmailMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), EmailError>> + Send + 'a>> {
        Box::pin(async move {
            let email = build_message(&self.from, &message)?;
            self.transport
                .send(email)
                .await
                .map_err(|e| EmailError(format!("SMTP send failed: {e}")))?;
            Ok(())
        })
    }
}

/// Parse the configured from address (with an optional display name) into a [`Mailbox`].
fn build_from_mailbox(address: &str, name: Option<&str>) -> Result<Mailbox, EmailError> {
    let addr = address
        .parse()
        .map_err(|e| EmailError(format!("invalid email.from address {address:?}: {e}")))?;
    Ok(Mailbox::new(name.map(str::to_string), addr))
}

/// Build a `lettre::Message` from a rendered [`EmailMessage`]. Pure aside from the `to`-address
/// parse, so it is unit-testable without a transport.
fn build_message(from: &Mailbox, message: &EmailMessage) -> Result<Message, EmailError> {
    let to: Mailbox = message
        .to
        .parse()
        .map_err(|e| EmailError(format!("invalid recipient address {:?}: {e}", message.to)))?;
    Message::builder()
        .from(from.clone())
        .to(to)
        .subject(message.subject.clone())
        .body(message.body.clone())
        .map_err(|e| EmailError(format!("failed to build email message: {e}")))
}

/// Construct the configured [`EmailSender`] for the running server.
///
/// `provider = "log"` → [`LogEmailSender`] (no network); `provider = "smtp"` → [`SmtpEmailSender`].
/// A misconfigured SMTP setup fails here at startup rather than on the first send.
pub fn build_email_sender(config: &EmailConfig) -> Result<Arc<dyn EmailSender>, EmailError> {
    match config.provider {
        EmailProvider::Log => Ok(Arc::new(LogEmailSender)),
        EmailProvider::Smtp => Ok(Arc::new(SmtpEmailSender::from_config(config)?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn log_sender_succeeds() {
        let sender = LogEmailSender;
        let result = sender
            .send(EmailMessage {
                to: "alice@example.com".to_string(),
                subject: "Test".to_string(),
                body: "hello".to_string(),
            })
            .await;
        assert!(result.is_ok());
    }

    #[test]
    fn build_from_mailbox_parses_plain_address() {
        let mb = build_from_mailbox("noreply@pds.example.com", None).unwrap();
        assert_eq!(mb.email.to_string(), "noreply@pds.example.com");
        assert!(mb.name.is_none());
    }

    #[test]
    fn build_from_mailbox_includes_display_name() {
        let mb = build_from_mailbox("noreply@pds.example.com", Some("Custos PDS")).unwrap();
        assert_eq!(mb.name.as_deref(), Some("Custos PDS"));
    }

    #[test]
    fn build_from_mailbox_rejects_garbage() {
        assert!(build_from_mailbox("not-an-email", None).is_err());
    }

    #[test]
    fn build_message_sets_headers_and_body() {
        let from = build_from_mailbox("noreply@pds.example.com", Some("Custos")).unwrap();
        let msg = build_message(
            &from,
            &EmailMessage {
                to: "alice@example.com".to_string(),
                subject: "Reset your password".to_string(),
                body: "token: abc123".to_string(),
            },
        )
        .unwrap();
        let formatted = String::from_utf8(msg.formatted()).unwrap();
        assert!(formatted.contains("Subject: Reset your password"));
        assert!(formatted.contains("alice@example.com"));
        assert!(formatted.contains("token: abc123"));
    }

    #[test]
    fn build_message_rejects_bad_recipient() {
        let from = build_from_mailbox("noreply@pds.example.com", None).unwrap();
        let err = build_message(
            &from,
            &EmailMessage {
                to: "definitely not an address".to_string(),
                subject: "x".to_string(),
                body: "y".to_string(),
            },
        );
        assert!(err.is_err());
    }

    #[test]
    fn smtp_sender_builds_from_valid_config() {
        let config = EmailConfig {
            provider: EmailProvider::Smtp,
            from: Some("noreply@pds.example.com".to_string()),
            from_name: Some("Custos".to_string()),
            smtp_host: Some("smtp.example.com".to_string()),
            smtp_port: 587,
            smtp_username: Some("user".to_string()),
            smtp_password: Some(common::Sensitive("pass".to_string())),
            smtp_tls: SmtpTls::Starttls,
        };
        assert!(SmtpEmailSender::from_config(&config).is_ok());
    }

    #[test]
    fn build_email_sender_selects_log_by_default() {
        let sender = build_email_sender(&EmailConfig::default()).unwrap();
        // A Log sender delivers without a transport; just confirm construction succeeds and the
        // returned object is usable.
        let _ = sender;
    }
}
