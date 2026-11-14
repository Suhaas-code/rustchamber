use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

use crate::client::{ApiError, Client, ClientConfig};
use crate::models::ServerInfo;
use crate::process::{ServerHandle, free_port, random_password, spawn_log_reader};

const SSH_READY_TIMEOUT: Duration = Duration::from_secs(45);
const SSH_ATTEMPTS: u32 = 3;
const STDERR_TAIL_LINES: usize = 24;

const DENIED_FLAGS: &[char] = &['N', 'L', 'R', 'D', 'W', 'f', 'O', 'S', 'M'];
const VALUE_FLAGS: &[char] = &['p', 'i', 'J', 'o', 'F', 'l'];
const BOOL_FLAGS: &[char] = &['4', '6', 'a', 'C', 'T', 'v', 'q'];
const SAFE_OPTIONS: &[&str] = &[
    "addressfamily",
    "ciphers",
    "compression",
    "connecttimeout",
    "hostkeyalgorithms",
    "identityfile",
    "identitiesonly",
    "ipqos",
    "port",
    "preferredauthentications",
    "pubkeyauthentication",
    "serveralivecountmax",
    "serveraliveinterval",
    "tcpkeepalive",
    "user",
];

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SshError {
    #[error("Enter a host or an SSH command.")]
    Empty,
    #[error("The SSH command is not valid: {0}.")]
    Shell(String),
    #[error("The SSH option {0} changes how the tunnel works and is not supported.")]
    TransportFlag(String),
    #[error("The SSH option {0} is not supported.")]
    UnknownFlag(String),
    #[error("The SSH option {0} needs a value.")]
    MissingValue(String),
    #[error("Use exactly one host after the SSH options.")]
    MultipleHosts,
    #[error("Add a host such as user@example.com.")]
    MissingHost,
    #[error("The host contains characters that are not allowed.")]
    InvalidHost,
    #[error(
        "The SSH option `{0}` can run local commands or change the tunnel and is not supported."
    )]
    UnsafeOption(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshTarget {
    /// User supplied options, without the leading `ssh` and without the host.
    pub args: Vec<String>,
    pub destination: String,
}

impl SshTarget {
    pub fn summary(&self) -> String {
        let mut parts = vec!["ssh".to_string()];
        parts.extend(self.args.iter().cloned());
        parts.push(self.destination.clone());
        parts.join(" ")
    }
}

/// Parse a bare host, `user@host`, or a full `ssh` command into argv parts.
///
/// The input is tokenized with shell quoting rules but never executed by a shell.
/// Options that would replace the tunnel or detach the child are rejected.
pub fn parse_target(input: &str) -> Result<SshTarget, SshError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(SshError::Empty);
    }
    if trimmed
        .chars()
        .any(|character| character == '\0' || character == '\n' || character == '\r')
    {
        return Err(SshError::InvalidHost);
    }
    let tokens = shell_words::split(trimmed).map_err(|error| SshError::Shell(error.to_string()))?;
    let mut tokens = tokens.into_iter().peekable();
    if tokens.peek().is_some_and(|token| token == "ssh") {
        tokens.next();
    }

    let mut args = Vec::new();
    let mut destination: Option<String> = None;
    while let Some(token) = tokens.next() {
        if token == "--" {
            for positional in tokens.by_ref() {
                remember_destination(&mut destination, &positional)?;
            }
            break;
        }
        if token.starts_with('-') && token != "-" {
            parse_flag(&token, &mut tokens, &mut args)?;
            continue;
        }
        remember_destination(&mut destination, &token)?;
    }

    let destination = destination.ok_or(SshError::MissingHost)?;
    validate_destination(&destination)?;
    Ok(SshTarget { args, destination })
}

fn remember_destination(destination: &mut Option<String>, token: &str) -> Result<(), SshError> {
    if destination.is_some() {
        return Err(SshError::MultipleHosts);
    }
    *destination = Some(token.to_string());
    Ok(())
}

fn parse_flag(
    token: &str,
    tokens: &mut impl Iterator<Item = String>,
    args: &mut Vec<String>,
) -> Result<(), SshError> {
    if token.starts_with("--") {
        return Err(SshError::UnknownFlag(token.to_string()));
    }
    let mut characters = token[1..].chars().peekable();
    while let Some(flag) = characters.next() {
        let short = format!("-{flag}");
        if DENIED_FLAGS.contains(&flag) {
            return Err(SshError::TransportFlag(short));
        }
        if VALUE_FLAGS.contains(&flag) {
            let attached: String = characters.by_ref().collect();
            let value = if attached.is_empty() {
                tokens.next().ok_or(SshError::MissingValue(short.clone()))?
            } else {
                attached
            };
            if value.is_empty() || value.starts_with('-') {
                return Err(SshError::MissingValue(short.clone()));
            }
            if flag == 'o' {
                validate_option(&value)?;
            }
            args.push(short);
            args.push(value);
            return Ok(());
        }
        if !BOOL_FLAGS.contains(&flag) {
            return Err(SshError::UnknownFlag(short));
        }
        args.push(short);
    }
    Ok(())
}

fn validate_option(value: &str) -> Result<(), SshError> {
    let key = value
        .split_once('=')
        .map(|(key, _)| key)
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase();
    if SAFE_OPTIONS.contains(&key.as_str()) {
        Ok(())
    } else {
        Err(SshError::UnsafeOption(value.to_string()))
    }
}

fn validate_destination(destination: &str) -> Result<(), SshError> {
    if destination.is_empty() || destination.starts_with('-') {
        return Err(SshError::InvalidHost);
    }
    if destination.chars().any(|character| {
        character.is_whitespace()
            || matches!(
                character,
                ';' | '|' | '&' | '<' | '>' | '`' | '$' | '\\' | '\'' | '"'
            )
    }) {
        return Err(SshError::InvalidHost);
    }
    if let Some((user, host)) = destination.split_once('@')
        && (user.is_empty() || host.is_empty() || host.contains('@'))
    {
        return Err(SshError::InvalidHost);
    }
    Ok(())
}

/// Build the complete local argv for the ssh child.
pub fn serve_args(target: &SshTarget, local_port: u16, remote_port: u16) -> Vec<String> {
    let mut args = vec![
        "-T".to_string(),
        "-o".to_string(),
        "ExitOnForwardFailure=yes".to_string(),
        "-o".to_string(),
        "ServerAliveInterval=15".to_string(),
        "-o".to_string(),
        "ServerAliveCountMax=3".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
    ];
    args.extend(target.args.iter().cloned());
    args.push("-L".to_string());
    args.push(format!("127.0.0.1:{local_port}:127.0.0.1:{remote_port}"));
    args.push(target.destination.clone());
    args.push(remote_command(remote_port));
    args
}

fn remote_command(remote_port: u16) -> String {
    // The password arrives on stdin so it never appears in a local process list.
    // The background reader makes the remote server follow the ssh channel: when
    // the channel closes, stdin reaches EOF and the child is killed.
    format!(
        "sh -c 'read -r pw || exit 1; \
         export OPENCODE_PASSWORD=\"$pw\" OPENCODE_SERVER_PASSWORD=\"$pw\" OPENCODE_SERVER_USERNAME=opencode; \
         command -v opencode >/dev/null 2>&1 || {{ echo \"RustChamber: OpenCode 2.x is required on the remote host.\" >&2; exit 127; }}; \
         major=$(opencode --version 2>/dev/null | sed -n \"s/^[^0-9]*\\([0-9][0-9]*\\)\\..*/\\1/p\" | head -n 1); \
         [ \"$major\" -ge 2 ] 2>/dev/null || {{ echo \"RustChamber: OpenCode 2.x is required on the remote host.\" >&2; exit 128; }}; \
         opencode serve --hostname 127.0.0.1 --port {remote_port} & child=$!; \
         trap \"kill $child 2>/dev/null\" HUP TERM INT; \
         ( cat >/dev/null; kill $child 2>/dev/null ) & \
         wait $child'"
    )
}

#[derive(Clone, Debug, Default)]
pub struct SshLaunchOptions {
    pub target: String,
    pub directory: Option<String>,
}

/// Start a remote OpenCode server and its loopback tunnel over one ssh child.
pub async fn launch(options: SshLaunchOptions) -> Result<ServerHandle, ApiError> {
    let target =
        parse_target(&options.target).map_err(|error| ApiError::Config(error.to_string()))?;
    for attempt in 0..SSH_ATTEMPTS {
        let local_port =
            free_port().map_err(|error| ApiError::Other(format!("no free port: {error}")))?;
        let remote_port = random_remote_port();
        let password = random_password();
        let endpoint = format!("http://127.0.0.1:{local_port}");

        let mut config = ClientConfig::new(&endpoint)?;
        config.password = Some(password.clone());
        config.directory = options
            .directory
            .as_ref()
            .map(|directory| directory.trim())
            .filter(|directory| !directory.is_empty())
            .map(str::to_string);
        let client = Client::new(config)?;

        let mut command = ssh_command();
        command
            .args(serve_args(&target, local_port, remote_port))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        tracing::debug!(
            destination = %target.destination,
            remote_port,
            local_port,
            password_len = password.len(),
            "starting SSH OpenCode server"
        );
        let mut child = command.spawn().map_err(|error| {
            ApiError::Other(format!(
                "Could not start ssh. Install OpenSSH and check that `ssh` is on PATH: {error}"
            ))
        })?;

        let mut stdin = child.stdin.take();
        let payload = format!("{password}\n");
        let written = match stdin.as_mut() {
            Some(writer) => writer.write_all(payload.as_bytes()).await,
            None => Ok(()),
        };
        if let Err(error) = written {
            stdin.take();
            let _ = child.start_kill();
            return Err(ApiError::Other(format!(
                "Could not pass the server password over SSH: {error}"
            )));
        }
        if let Some(stdout) = child.stdout.take() {
            spawn_log_reader(stdout, "ssh stdout");
        }
        let tail = Arc::new(Mutex::new(VecDeque::new()));
        if let Some(stderr) = child.stderr.take() {
            spawn_stderr_reader(stderr, Arc::clone(&tail));
        }

        match wait_ready(&client, &mut child, Arc::clone(&tail)).await {
            Ok(info) => {
                return Ok(ServerHandle {
                    client,
                    info,
                    password: Some(password),
                    endpoint,
                    child: None,
                    ssh: Some(child),
                    ssh_stdin: stdin,
                });
            }
            Err(failure) => {
                let text = failure.describe(&target.destination);
                let retry = failure.is_port_collision() && attempt + 1 < SSH_ATTEMPTS;
                stdin.take();
                let _ = child.start_kill();
                if !retry {
                    return Err(ApiError::Other(text));
                }
            }
        }
    }
    Err(ApiError::Other("Could not start the SSH tunnel.".into()))
}

enum WaitFailure {
    Exited {
        status: String,
        health: Option<String>,
    },
    Timeout {
        tail: String,
        health: Option<String>,
    },
    Health(String),
}

impl WaitFailure {
    fn tail_text(&self) -> String {
        match self {
            WaitFailure::Exited { status, .. } => status.clone(),
            WaitFailure::Timeout { tail, .. } => tail.clone(),
            WaitFailure::Health(_) => String::new(),
        }
    }

    fn is_port_collision(&self) -> bool {
        let tail = self.tail_text().to_lowercase();
        tail.contains("remote port forwarding failed") || tail.contains("address already in use")
    }

    fn describe(&self, destination: &str) -> String {
        let health = match self {
            WaitFailure::Exited { health, .. } | WaitFailure::Timeout { health, .. } => {
                health.as_deref()
            }
            WaitFailure::Health(message) => Some(message.as_str()),
        };
        let detail = health
            .map(|health| format!(" Last health check: {health}"))
            .unwrap_or_default();
        match self {
            WaitFailure::Exited { status, .. } => format!(
                "The SSH connection to {destination} closed before OpenCode was ready: {status}.{detail}"
            ),
            WaitFailure::Timeout { tail, .. } if !tail.is_empty() => format!(
                "The SSH connection to {destination} did not become ready within {} seconds: {tail}.{detail}",
                SSH_READY_TIMEOUT.as_secs()
            ),
            WaitFailure::Timeout { .. } => format!(
                "The SSH connection to {destination} did not become ready within {} seconds.{detail}",
                SSH_READY_TIMEOUT.as_secs()
            ),
            WaitFailure::Health(message) => format!(
                "The SSH connection to {destination} reached a server but the health check failed: {message}"
            ),
        }
    }
}

async fn wait_ready(
    client: &Client,
    child: &mut Child,
    tail: Arc<Mutex<VecDeque<String>>>,
) -> Result<ServerInfo, WaitFailure> {
    let started = tokio::time::Instant::now();
    let mut health: Option<String> = None;
    while started.elapsed() < SSH_READY_TIMEOUT {
        match tokio::time::timeout(Duration::from_secs(2), client.info()).await {
            Ok(Ok(info)) => return Ok(info),
            Ok(Err(error)) => {
                let message = error.to_string();
                if error.is_unauthorized() {
                    return Err(WaitFailure::Health(message));
                }
                health = Some(message);
            }
            Err(_) => health = Some("health request timed out".into()),
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let tail = tail_text(&tail);
                let mut status = status.to_string();
                if !tail.is_empty() {
                    status.push_str(": ");
                    status.push_str(&tail);
                }
                return Err(WaitFailure::Exited { status, health });
            }
            Ok(None) => {}
            Err(error) => {
                return Err(WaitFailure::Exited {
                    status: error.to_string(),
                    health,
                });
            }
        }
        tokio::time::sleep(Duration::from_millis(180)).await;
    }
    Err(WaitFailure::Timeout {
        tail: tail_text(&tail),
        health,
    })
}

fn spawn_stderr_reader<R>(reader: R, tail: Arc<Mutex<VecDeque<String>>>)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            tracing::debug!(target: "ssh", "stderr: {line}");
            let mut tail = tail.lock().unwrap_or_else(|error| error.into_inner());
            if tail.len() == STDERR_TAIL_LINES {
                tail.pop_front();
            }
            tail.push_back(line);
        }
    });
}

fn tail_text(tail: &Arc<Mutex<VecDeque<String>>>) -> String {
    let tail = tail.lock().unwrap_or_else(|error| error.into_inner());
    tail.iter().cloned().collect::<Vec<_>>().join("\n")
}

fn ssh_command() -> Command {
    if std::env::var_os("FLATPAK_ID").is_some() {
        // The sandbox cannot see the user's agent socket or host keys, so run
        // the host ssh binary through the portal.
        let mut command = Command::new("flatpak-spawn");
        command.arg("--host").arg("ssh");
        command
    } else {
        Command::new("ssh")
    }
}

fn random_remote_port() -> u16 {
    use rand::Rng;
    rand::rng().random_range(30_000..=59_999)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_bare_and_user_host_forms() {
        assert_eq!(
            parse_target("example.com").unwrap(),
            SshTarget {
                args: Vec::new(),
                destination: "example.com".into()
            }
        );
        let target = parse_target("user@example.com").unwrap();
        assert_eq!(target.destination, "user@example.com");
        assert_eq!(target.summary(), "ssh user@example.com");
        assert_eq!(
            parse_target("ssh -p 2222 me@example.com")
                .unwrap()
                .summary(),
            "ssh -p 2222 me@example.com"
        );
    }

    #[test]
    fn strips_a_leading_ssh_and_keeps_supported_options() {
        let target = parse_target("ssh -p 2222 -i ~/.ssh/key -4 user@example.com").unwrap();
        assert_eq!(target.args, vec!["-p", "2222", "-i", "~/.ssh/key", "-4"]);
        assert_eq!(target.destination, "user@example.com");
    }

    #[test]
    fn supports_jump_hosts_and_forwarded_options() {
        let target = parse_target(
            "ssh -J bastion.example.com -o ServerAliveInterval=5 -F ~/.ssh/config host",
        )
        .unwrap();
        assert_eq!(
            target.args,
            vec![
                "-J",
                "bastion.example.com",
                "-o",
                "ServerAliveInterval=5",
                "-F",
                "~/.ssh/config"
            ]
        );
    }

    #[test]
    fn supports_attached_values() {
        let target = parse_target("ssh -p2222 -i/tmp/key host").unwrap();
        assert_eq!(target.args, vec!["-p", "2222", "-i", "/tmp/key"]);
    }

    #[test]
    fn rejects_transport_flags_and_unknown_flags() {
        for command in [
            "ssh -N host",
            "ssh -L 1:2 host",
            "ssh -R 1:2 host",
            "ssh -D 8080 host",
            "ssh -W host:22 host",
            "ssh -f host",
            "ssh -O check host",
            "ssh -S socket host",
            "ssh -M host",
            "ssh -Z host",
            "ssh -A host",
        ] {
            assert!(parse_target(command).is_err(), "{command}");
        }
    }

    #[test]
    fn rejects_options_that_can_run_commands_or_change_the_tunnel() {
        for command in [
            "ssh -o ProxyCommand=sh host",
            "ssh -o LocalCommand=sh host",
            "ssh -o RequestTTY=yes host",
            "ssh -o ForkAfterAuthentication=yes host",
            "ssh -o ControlMaster=auto host",
            "ssh -o ClearAllForwardings=yes host",
            "ssh -o UserKnownHostsFile=/dev/null host",
        ] {
            assert!(
                matches!(parse_target(command), Err(SshError::UnsafeOption(_))),
                "{command}"
            );
        }
        assert!(parse_target("ssh -o ServerAliveInterval=5 host").is_ok());
        assert!(parse_target("ssh -o Ciphers=aes128-ctr host").is_ok());
    }

    #[test]
    fn rejects_missing_values_two_hosts_and_metacharacters() {
        assert_eq!(
            parse_target("ssh -p"),
            Err(SshError::MissingValue("-p".into()))
        );
        assert_eq!(
            parse_target("ssh -p -v host"),
            Err(SshError::MissingValue("-p".into()))
        );
        assert_eq!(
            parse_target("a.example b.example"),
            Err(SshError::MultipleHosts)
        );
        assert_eq!(parse_target(""), Err(SshError::Empty));
        assert_eq!(parse_target("   "), Err(SshError::Empty));
        assert!(parse_target("host;rm -rf /").is_err());
        assert!(parse_target("user@").is_err());
        assert!(parse_target("@host").is_err());
        assert!(parse_target("a|b").is_err());
        assert!(parse_target("a\nb").is_err());
    }

    #[test]
    fn rejects_shell_expansion_through_shell_words() {
        let error = parse_target("'host' 'second'").unwrap_err();
        assert_eq!(error, SshError::MultipleHosts);
        assert!(parse_target("$(whoami)").is_err());
    }

    #[test]
    fn builds_one_ssh_invocation_with_tunnel_and_remote_command() {
        let target = parse_target("ssh -p 2222 user@example.com").unwrap();
        let args = serve_args(&target, 41000, 42000);
        assert_eq!(args[0], "-T");
        assert_eq!(args[1], "-o");
        assert_eq!(args[2], "ExitOnForwardFailure=yes");
        assert!(
            args.iter()
                .any(|arg| arg == "StrictHostKeyChecking=accept-new")
        );
        assert!(args.iter().any(|arg| arg == "-p"));
        assert!(args.iter().any(|arg| arg == "2222"));
        let forward = args
            .iter()
            .position(|arg| arg == "-L")
            .expect("tunnel flag");
        assert_eq!(args[forward + 1], "127.0.0.1:41000:127.0.0.1:42000");
        assert!(
            args[forward + 2..]
                .iter()
                .any(|arg| arg == "user@example.com")
        );
        let remote = args.last().unwrap();
        assert!(remote.contains("opencode serve --hostname 127.0.0.1 --port 42000"));
        assert!(remote.contains("read -r pw"));
        assert!(remote.contains("OPENCODE_SERVER_PASSWORD"));
        assert!(!args.iter().any(|arg| arg.contains("--port 41000")));
    }
}
