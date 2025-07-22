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
use mail_parser::MessageParser;
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
    let dirs = directories::ProjectDirs::from("", "", "clientmailforward")
        .expect("Failed to get project directories");
    let cachedir = dirs.cache_dir();
    std::fs::create_dir_all(cachedir).expect("Failed to create cache directory");
    let db = sled::open(cachedir.join("source_uids")).expect("Failed to open sled database");
    let app = App::new(source_client_config, target_client_config, db);

    let mut session = App::new_session(&app.source_client_config).await?;
    session.select(&app.source_client_config.mailbox).await?;
    tracing::info!("{} selected", app.source_client_config.mailbox);

    tracing::info!("first run, fetching all messages");
    app.upload_from_query("ALL", &mut session).await.unwrap();
    tracing::info!("processed all old messages");
    app.idle_and_fetch().await?;

    Ok(())
}

struct App {
    source_client_config: ImapClientConfig,
    target_client_config: ImapClientConfig,
    db: sled::Db,
}

impl App {
    fn new(
        source_client_config: ImapClientConfig,
        target_client_config: ImapClientConfig,
        db: sled::Db,
    ) -> Self {
        Self {
            source_client_config,
            target_client_config,
            db,
        }
    }

    async fn idle_and_fetch(&self) -> Result<()> {
        loop {
            let mut session = Self::new_session(&self.source_client_config).await?;
            session.select(&self.source_client_config.mailbox).await?;
            tracing::info!("{} selected", self.source_client_config.mailbox);

            // init IDLE session
            tracing::info!("initializing IDLE");
            let mut idle = session.idle();
            idle.init().await?;

            // wait for messages
            tracing::debug!("IDLE async wait");
            let (idle_wait, _interrupt) = idle.wait_with_timeout(TIMEOUT);

            let idle_result = idle_wait.await?;
            match idle_result {
                ManualInterrupt => {
                    tracing::info!("IDLE manually interrupted");
                    self.idle_interrupt(idle, async |_| Ok(())).await?;
                    break;
                }
                Timeout => {
                    self.idle_interrupt(idle, async |_| Ok(())).await?;
                    continue;
                }
                NewData(data) => {
                    let s = String::from_utf8(data.borrow_owner().to_vec()).unwrap();
                    tracing::debug!("IDLE data:\n{}", s);
                    self.idle_interrupt(idle, async |session| {
                        tracing::info!("IDLE interrupted, fetching");
                        self.upload_from_query("NEW", session).await
                    })
                    .await?;
                }
            }
        }

        Ok(())
    }

    async fn upload_from_query<S: AsRef<str>>(
        &self,
        query: S,
        session: &mut Session<TlsStream<TcpStream>>,
    ) -> Result<()> {
        let mut uids = session.uid_search(query.as_ref()).await?;
        tracing::info!(
            "found {} messages matching query '{}'",
            uids.len(),
            query.as_ref()
        );
        uids.retain(|uid| {
            !self
                .db
                .contains_key(uid.to_string())
                .expect("Failed to check UID in db")
        });
        tracing::info!("{} to process", uids.len());
        let target_session = Arc::new(Mutex::new(
            Self::new_session(&self.target_client_config).await?,
        ));
        target_session
            .lock_arc()
            .await
            .select(&self.target_client_config.mailbox)
            .await?;
        let borrowed = &target_session;
        let fetched = session
            .uid_fetch(uids.iter().join(","), "(FLAGS INTERNALDATE BODY.PEEK[])")
            .await?;
        let res = fetched
            .try_for_each(|msg| async move {
                tracing::debug!("processing message: {:?}", msg.message);
                let Some(raw) = msg.body() else {
                    tracing::warn!("got message without body");
                    return Ok(());
                };
                tracing::debug!("message body:\n{}", String::from_utf8_lossy(raw));
                let Some(message) = MessageParser::default().parse(raw) else {
                    tracing::warn!("failed to parse message");
                    return Ok(());
                };

                // check if this message is already in the target mailbox
                let Some(id) = message.message_id() else {
                    tracing::warn!("message has no Message-ID, skipping");
                    return Ok(());
                };
                tracing::info!("processing message with Message-ID: {}", id);
                let mut target = borrowed.lock_arc().await;
                if !(target
                    .uid_search(format!("HEADER Message-ID {}", id))
                    .await?
                    .is_empty()
                    && target
                    .uid_search(format!("HEADER x-ms-exchange-parent-message-id {}", id))
                    .await?
                    .is_empty())
                {
                    tracing::info!(
                        "message {} already exists in target mailbox, skipping",
                        id
                    );
                    if let Some(uid) = msg.uid {
                        self.db
                            .insert(uid.to_string(), id)
                            .expect("Failed to insert UID into db");
                    }
                    return Ok(());
                };

                tracing::warn!("message (subject: {:?} ; date: {:?} ; from: {:?}) not found in target mailbox, appending",
                    message.subject(),
                    message.date(),
                    message.from()
                );
                let flags = None;
                let internaldate = msg
                    .internal_date()
                    .map(|d| format!("\"{}\"", d.format("%d-%b-%Y %T %z")));
                match target
                    .append(
                        &self.target_client_config.mailbox,
                        flags,
                        internaldate.as_deref(),
                        raw,
                    )
                    .await
                {
                    Ok(()) => {
                        tracing::info!("appended message to target server");
                        if let Some(uid) = msg.uid {
                            self.db
                                .insert(uid.to_string(), id)
                                .expect("Failed to insert UID into db");
                        }
                    }
                    Err(e) => {
                        tracing::error!("failed to append message: {}", e);
                        return Err(e);
                    }
                }
                Ok(())
            })
            .await
            .map_err(anyhow::Error::new);
        self.db.flush_async().await.expect("Failed to flush db");
        res
    }

    async fn idle_interrupt(
        &self,
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
}
