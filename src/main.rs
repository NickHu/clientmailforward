use anyhow::Result;
use async_imap::{
    Session,
    extensions::idle::{Handle, IdleResponse::*},
};
use async_native_tls::TlsStream;
use async_std::{
    net::TcpStream,
    sync::{Arc, Mutex},
};
use clap::Parser;
use futures::TryStreamExt;
use itertools::Itertools;
use std::time::Duration;

mod oauth2;
use oauth2::OAuth2;

// RFC says to restart IDLE every 29 minutes
// Gmail will disconnect you after 10 minutes
const TIMEOUT: Duration = Duration::from_secs(9 * 60);

#[derive(Parser, Debug)]
#[command(author, version, about)]
#[command(group = clap::ArgGroup::new("source_auth").required(true))]
#[command(group = clap::ArgGroup::new("target_auth").required(true))]
/// Application configuration
struct Args {
    /// source IMAP server address
    #[arg(long)]
    source_address: String,
    /// source IMAP server port
    #[arg(long, default_value_t = 993)]
    source_port: u16,
    /// source IMAP server username
    #[arg(long)]
    source_username: String,
    /// source IMAP mailbox
    #[arg(long, default_value = "INBOX")]
    source_mailbox: String,

    /// source IMAP server password
    #[arg(long, group = "source_auth")]
    source_password: Option<String>,
    /// source IMAP server password command
    #[arg(long, group = "source_auth")]
    source_password_cmd: Option<String>,
    /// source IMAP server OAuth2 token command
    #[arg(long, group = "source_auth")]
    source_token_cmd: Option<String>,

    /// target IMAP server address
    #[arg(long)]
    target_address: String,
    /// target IMAP server port
    #[arg(long, default_value_t = 993)]
    target_port: u16,
    /// target IMAP server username
    #[arg(long)]
    target_username: String,
    /// target IMAP mailbox
    #[arg(long, default_value = "INBOX")]
    target_mailbox: String,

    /// target IMAP server password
    #[arg(long, group = "target_auth")]
    target_password: Option<String>,
    /// target IMAP server password command
    #[arg(long, group = "target_auth")]
    target_password_cmd: Option<String>,
    /// target IMAP server OAuth2 token command
    #[arg(long, group = "target_auth")]
    target_token_cmd: Option<String>,
}

struct ImapClientConfig {
    address: String,
    port: u16,
    username: String,
    password: Password,
    mailbox: String,
}

enum Password {
    Plain(String),
    Command(String),
    OAuth2Command(String),
}

#[async_std::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let source_client_config = ImapClientConfig {
        address: args.source_address,
        port: args.source_port,
        username: args.source_username,
        password: match (
            args.source_password,
            args.source_password_cmd,
            args.source_token_cmd,
        ) {
            (Some(password), None, None) => Password::Plain(password),
            (None, Some(password_cmd), None) => Password::Command(password_cmd),
            (None, None, Some(token_cmd)) => Password::OAuth2Command(token_cmd),
            _ => unreachable!(),
        },
        mailbox: args.source_mailbox,
    };
    let target_client_config = ImapClientConfig {
        address: args.target_address,
        port: args.target_port,
        username: args.target_username,
        password: match (
            args.target_password,
            args.target_password_cmd,
            args.target_token_cmd,
        ) {
            (Some(password), None, None) => Password::Plain(password),
            (None, Some(password_cmd), None) => Password::Command(password_cmd),
            (None, None, Some(token_cmd)) => Password::OAuth2Command(token_cmd),
            _ => unreachable!(),
        },
        mailbox: args.target_mailbox,
    };
    idle_and_fetch(&source_client_config, &target_client_config).await?;
    Ok(())
}

async fn idle_and_fetch(
    source_client_config: &ImapClientConfig,
    target_client_config: &ImapClientConfig,
) -> Result<()> {
    loop {
        let mut session = new_session(source_client_config).await?;
        session.select(&source_client_config.mailbox).await?;
        tracing::info!("{} selected", source_client_config.mailbox);

        // init IDLE session
        tracing::debug!("initializing IDLE");
        let mut idle = session.idle();
        idle.init().await?;

        // wait for messages
        tracing::debug!("IDLE async wait");
        let (idle_wait, _interrupt) = idle.wait_with_timeout(TIMEOUT);

        let idle_result = idle_wait.await?;
        match idle_result {
            ManualInterrupt => {
                tracing::info!("IDLE manually interrupted");
                idle_interrupt(idle, async |_| Ok(())).await?;
                break;
            }
            Timeout => {
                idle_interrupt(idle, async |_| Ok(())).await?;
                continue;
            }
            NewData(data) => {
                let s = String::from_utf8(data.borrow_owner().to_vec()).unwrap();
                tracing::debug!("IDLE data:\n{}", s);
                idle_interrupt(idle, async |session| {
                    tracing::info!("IDLE interrupted, fetching");
                    let uids = session.uid_search("NEW").await?;
                    let target_session =
                        Arc::new(Mutex::new(new_session(target_client_config).await?));
                    let borrowed = &target_session;
                    let fetched = session
                        .uid_fetch(uids.iter().join(","), "(FLAGS INTERNALDATE BODY.PEEK[])")
                        .await?;
                    let _ = fetched
                        .try_for_each(|msg| async move {
                            tracing::debug!("processing message: {:?}", msg.message);
                            if let Some(message) = msg.body() {
                                tracing::debug!(
                                    "message body:\n{}",
                                    String::from_utf8_lossy(message)
                                );
                                let flags = None;
                                let internaldate = msg
                                    .internal_date()
                                    .map(|d| format!("\"{}\"", d.to_rfc2822()));
                                match borrowed
                                    .lock_arc()
                                    .await
                                    .append(
                                        &target_client_config.mailbox,
                                        flags,
                                        internaldate.as_deref(),
                                        message,
                                    )
                                    .await
                                {
                                    Ok(_) => {
                                        tracing::info!("appended message to target server");
                                    }
                                    Err(e) => {
                                        tracing::error!("failed to append message: {}", e);
                                        return Err(e);
                                    }
                                }
                            } else {
                                tracing::warn!("got message without body");
                            }
                            Ok(())
                        })
                        .await;
                    Ok(())
                })
                .await?;
            }
        }
    }

    Ok(())
}

async fn idle_interrupt(
    idle: Handle<TlsStream<TcpStream>>,
    f: impl AsyncFn(&mut Session<TlsStream<TcpStream>>) -> Result<()>,
) -> Result<()> {
    tracing::debug!("sending DONE");
    let mut session = idle.done().await?;
    f(&mut session).await?;
    tracing::info!("logging out");
    session.logout().await?;

    Ok(())
}

async fn new_session(config: &ImapClientConfig) -> Result<Session<TlsStream<TcpStream>>> {
    let tcp_stream = TcpStream::connect((config.address.as_str(), config.port)).await?;
    let tls = async_native_tls::TlsConnector::new();
    let tls_stream = tls.connect(config.address.as_str(), tcp_stream).await?;

    let mut client = async_imap::Client::new(tls_stream);
    tracing::info!("connected to {}:{}", config.address, config.port);

    // most IMAP servers will greet you with a message
    let greeting = client.read_response().await.unwrap();
    tracing::debug!("greeting: {:?}", greeting);

    // authenticate
    tracing::debug!("authenticating as {}", config.username);
    let session = match config.password {
        Password::Plain(ref password) => client
            .login(config.username.as_str(), password.as_str())
            .await
            .map_err(|e| e.0)?,
        Password::Command(ref cmd) => {
            let mut parts = cmd.split_whitespace();
            let prog = parts
                .next()
                .ok_or_else(|| anyhow::anyhow!("no command provided"))?;
            let output = std::process::Command::new(prog).args(parts).output()?;
            let password = String::from_utf8_lossy(&output.stdout);
            client
                .login(config.username.as_str(), &password)
                .await
                .map_err(|e| e.0)?
        }
        Password::OAuth2Command(ref token_cmd) => {
            let mut parts = token_cmd.split_whitespace();
            let prog = parts
                .next()
                .ok_or_else(|| anyhow::anyhow!("no command provided"))?;
            let output = std::process::Command::new(prog).args(parts).output()?;
            let token = String::from_utf8_lossy(&output.stdout);
            client
                .authenticate(
                    "XOAUTH2",
                    &OAuth2 {
                        user: config.username.clone(),
                        access_token: token.into_owned(),
                    },
                )
                .await
                .map_err(|e| e.0)?
        }
    };
    tracing::info!("logged in as {}", config.username);

    Ok(session)
}
