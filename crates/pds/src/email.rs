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
//   - HttpEmailSender — real delivery over Mailtrap's transactional HTTPS Send API via `reqwest`,
//     selected by `email.provider = "mailtrap"`. Needs only outbound HTTPS, so it delivers on
//     hosts (e.g. Railway's non-Pro plans) that block every outbound SMTP port — the reason it
//     exists.
//
// Message *content* (subjects, bodies, the reset/confirmation links) is built by the route
// handlers; this module only knows how to deliver an already-rendered `EmailMessage`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use common::{EmailConfig, EmailProvider, SmtpTls, MAILTRAP_SEND_API_URL};
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

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
        // `send()` is awaited on the request path, so bound how long a slow or unresponsive relay
        // can stall a handler (configurable via `email.smtp_timeout_secs`, default 15s).
        .port(config.smtp_port)
        .timeout(Some(Duration::from_secs(config.smtp_timeout_secs)));

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

/// Real [`EmailSender`] delivering over Mailtrap's transactional HTTPS Send API via `reqwest`.
///
/// Selected by `email.provider = "mailtrap"`. The only I/O is an outbound HTTPS POST, so this
/// works where `SmtpEmailSender` cannot: hosts that block outbound SMTP ports entirely (Railway
/// on non-Pro plans blocks 25/465/587/2525).
pub struct HttpEmailSender {
    client: reqwest::Client,
    /// The Send API endpoint (defaults to [`MAILTRAP_SEND_API_URL`]; overridable for tests).
    api_url: String,
    /// Bearer API token. Held as a bare `String`; never logged.
    token: String,
    /// `from.email` on every message.
    from_email: String,
    /// Optional `from.name` paired with `from_email`.
    from_name: Option<String>,
}

impl HttpEmailSender {
    /// Build a Mailtrap HTTP sender from the resolved [`EmailConfig`]. Expects `provider = Mailtrap`
    /// with `from` and `http_token` present (config validation guarantees this).
    ///
    /// Builds a dedicated `reqwest::Client` with a bounded request timeout (`http_timeout_secs`),
    /// mirroring `SmtpEmailSender`'s self-owned transport, so a stalled API can never hang a request
    /// task for minutes.
    fn from_config(config: &EmailConfig) -> Result<Self, EmailError> {
        let from_email = config.from.clone().ok_or_else(|| {
            EmailError("email.from is required for Mailtrap delivery".to_string())
        })?;
        let token = config
            .http_token
            .as_ref()
            .map(|s| s.0.clone())
            .ok_or_else(|| {
                EmailError("email.http_token is required for Mailtrap delivery".to_string())
            })?;
        let api_url = config
            .http_api_url
            .clone()
            .unwrap_or_else(|| MAILTRAP_SEND_API_URL.to_string());

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.http_timeout_secs))
            .build()
            .map_err(|e| EmailError(format!("failed to build HTTP email client: {e}")))?;

        Ok(Self {
            client,
            api_url,
            token,
            from_email,
            from_name: config.from_name.clone(),
        })
    }
}

impl EmailSender for HttpEmailSender {
    fn send<'a>(
        &'a self,
        message: EmailMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), EmailError>> + Send + 'a>> {
        Box::pin(async move {
            let body = build_mailtrap_body(&self.from_email, self.from_name.as_deref(), &message);
            let response = self
                .client
                .post(&self.api_url)
                .bearer_auth(&self.token)
                .json(&body)
                .send()
                .await
                .map_err(|e| EmailError(format!("Mailtrap API request failed: {e}")))?;

            let status = response.status();
            if !status.is_success() {
                // Surface the API's error body (bounded by the client timeout) so a misconfigured
                // token or rejected recipient is diagnosable from the logs, not a bare status code.
                let detail = response.text().await.unwrap_or_default();
                return Err(EmailError(format!(
                    "Mailtrap API returned {status}: {detail}"
                )));
            }
            Ok(())
        })
    }
}

/// Build the Mailtrap Send API JSON body from a rendered [`EmailMessage`]. Pure, so the request
/// shape is unit-testable without an HTTP client. Mirrors the `EmailMessage` fields 1:1 onto
/// Mailtrap's `{from, to, subject, text}` schema; `from.name` is omitted when unset.
fn build_mailtrap_body(
    from_email: &str,
    from_name: Option<&str>,
    message: &EmailMessage,
) -> serde_json::Value {
    let mut from = serde_json::json!({ "email": from_email });
    if let Some(name) = from_name {
        from["name"] = serde_json::Value::String(name.to_string());
    }
    serde_json::json!({
        "from": from,
        "to": [{ "email": message.to }],
        "subject": message.subject,
        "text": message.body,
    })
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
/// `provider = "log"` → [`LogEmailSender`] (no network); `provider = "smtp"` → [`SmtpEmailSender`];
/// `provider = "mailtrap"` → [`HttpEmailSender`]. A misconfigured SMTP/HTTP setup fails here at
/// startup rather than on the first send.
pub fn build_email_sender(config: &EmailConfig) -> Result<Arc<dyn EmailSender>, EmailError> {
    match config.provider {
        EmailProvider::Log => Ok(Arc::new(LogEmailSender)),
        EmailProvider::Smtp => Ok(Arc::new(SmtpEmailSender::from_config(config)?)),
        EmailProvider::Mailtrap => Ok(Arc::new(HttpEmailSender::from_config(config)?)),
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
            smtp_timeout_secs: 15,
            ..EmailConfig::default()
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

    /// A minimal `provider = "mailtrap"` config pointed at `api_url`.
    fn mailtrap_config(api_url: &str) -> EmailConfig {
        EmailConfig {
            provider: EmailProvider::Mailtrap,
            from: Some("noreply@pds.example.com".to_string()),
            from_name: Some("Custos".to_string()),
            http_token: Some(common::Sensitive("test-token".to_string())),
            http_api_url: Some(api_url.to_string()),
            http_timeout_secs: 15,
            ..EmailConfig::default()
        }
    }

    #[test]
    fn http_sender_builds_from_valid_config() {
        let config = mailtrap_config("https://send.api.mailtrap.io/api/send");
        assert!(HttpEmailSender::from_config(&config).is_ok());
    }

    #[test]
    fn build_email_sender_selects_http_for_mailtrap() {
        let config = mailtrap_config("https://send.api.mailtrap.io/api/send");
        // Construction succeeds and yields a usable `dyn EmailSender`.
        let sender = build_email_sender(&config).unwrap();
        let _ = sender;
    }

    #[test]
    fn mailtrap_body_maps_message_fields() {
        let body = build_mailtrap_body(
            "noreply@pds.example.com",
            Some("Custos"),
            &EmailMessage {
                to: "alice@example.com".to_string(),
                subject: "Reset your password".to_string(),
                body: "token: abc123".to_string(),
            },
        );
        assert_eq!(body["from"]["email"], "noreply@pds.example.com");
        assert_eq!(body["from"]["name"], "Custos");
        assert_eq!(body["to"][0]["email"], "alice@example.com");
        assert_eq!(body["subject"], "Reset your password");
        assert_eq!(body["text"], "token: abc123");
    }

    #[test]
    fn mailtrap_body_omits_from_name_when_unset() {
        let body = build_mailtrap_body(
            "noreply@pds.example.com",
            None,
            &EmailMessage {
                to: "alice@example.com".to_string(),
                subject: "x".to_string(),
                body: "y".to_string(),
            },
        );
        assert_eq!(body["from"]["email"], "noreply@pds.example.com");
        assert!(
            body["from"].get("name").is_none(),
            "from.name must be absent when no display name is configured"
        );
    }

    #[tokio::test]
    async fn http_sender_posts_to_mailtrap_api() {
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/send"))
            .and(header("authorization", "Bearer test-token"))
            .and(body_json(serde_json::json!({
                "from": { "email": "noreply@pds.example.com", "name": "Custos" },
                "to": [{ "email": "alice@example.com" }],
                "subject": "Reset your password",
                "text": "token: abc123",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "message_ids": ["abc"],
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sender =
            HttpEmailSender::from_config(&mailtrap_config(&format!("{}/api/send", server.uri())))
                .unwrap();
        let result = sender
            .send(EmailMessage {
                to: "alice@example.com".to_string(),
                subject: "Reset your password".to_string(),
                body: "token: abc123".to_string(),
            })
            .await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        // `expect(1)` is verified on drop.
    }

    #[tokio::test]
    async fn http_sender_reports_error_on_non_2xx() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/send"))
            .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
            .mount(&server)
            .await;

        let sender =
            HttpEmailSender::from_config(&mailtrap_config(&format!("{}/api/send", server.uri())))
                .unwrap();
        let err = sender
            .send(EmailMessage {
                to: "alice@example.com".to_string(),
                subject: "x".to_string(),
                body: "y".to_string(),
            })
            .await
            .expect_err("a 401 must surface as a delivery error");
        // The status and the API's error body are both surfaced for diagnosability.
        let msg = err.to_string();
        assert!(msg.contains("401"), "error should name the status: {msg}");
        assert!(
            msg.contains("unauthorized"),
            "error should include the API body: {msg}"
        );
    }
}
