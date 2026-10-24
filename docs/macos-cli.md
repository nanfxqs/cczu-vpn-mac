# macOS CLI

The macOS entrypoint controls a system VPN service. Windows and Linux retain the existing interactive CLI.

Build with `cargo build --release --locked`, then install once:

```sh
sudo ./target/release/cczu-vpn-proto service install
cczu-vpn-proto --json status
```

Installation copies the executable into `/usr/local/libexec/cczu-vpn-proto`, creates a launchd definition, and installs a CLI link in `/usr/local/bin`. Repeating installation updates only this service. It does not start a VPN connection. Service management follows Apple's [launchd lifecycle](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html).

The background service is independent of SSH sessions. Its local Unix socket accepts this tool's commands without per-user authorization configuration. There is no network listener or arbitrary privileged-command interface. As requested for this personal machine, any local user can control VPN operations. The daemon owns privileged network configuration; daily status and VPN commands do not need sudo.

```sh
sudo cczu-vpn-proto service stop
sudo cczu-vpn-proto service install  # start again
sudo cczu-vpn-proto service uninstall
```

`service stop` unloads the service, so launchd will not immediately restart it. The next machine boot loads the installed service again. Uninstall removes only this tool's service definition, binary and CLI link; stored credentials are handled separately.

## Campus credentials over SSH

Credentials belong to the background service, not the user who ran `sudo` during installation. Production stores one shared plaintext account/password file in `/var/db/cczu-vpn/credentials.json`, owned by root with mode `0600` inside a `0700` directory. Daily management goes through the local service and needs no sudo. It does not use the login keychain or require a graphical session.

For interactive initialization, run `cczu-vpn-proto credentials set` in a terminal. The password input is hidden. The command asks whether to save; answering no keeps the credentials only in daemon memory. `--save` explicitly chooses persistence. The CLI does not claim to have authenticated the credentials; the connection command validates them against the school service.

Agents should send a JSON object with `user` and `password` through standard input, rather than supplying passwords as command arguments:

```sh
your-secret-source | cczu-vpn-proto --json credentials set --stdin --save
cczu-vpn-proto --json credentials status
cczu-vpn-proto --json credentials status --ignore-saved
cczu-vpn-proto --json credentials delete
```

Omit `--save` to use temporary credentials until the background service restarts or they are replaced/deleted. Temporary credentials take priority over the saved file; saving a new account clears the temporary override. Ignoring saved credentials does not remove them and still permits temporary credentials. Status reports only presence (`configured`, `saved`, `temporary`), never the stored account or password. Delete clears both temporary and persisted credentials and is safe to repeat.

JSON-mode and non-terminal initialization never prompt. Missing input returns `credentials_required`, malformed or empty JSON credentials return `invalid_credentials`, and storage failures return `credential_store_error`; each uses operation-failed exit code `5`. Initialization does not save unless explicitly selected. Secrets must come from a source controlled by the caller; do not embed real passwords in shell history, logs or example commands.

## Machine output

Use global `--json` to emit one JSON response on standard output. Diagnostics go to standard error. Responses contain `ok`, `code`, `message`, and `data`. Status data separately identifies the service and VPN connection state. A running service does not imply a connected VPN.

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Operation succeeded |
| 2 | Invalid command or arguments |
| 3 | Background service unavailable or local protocol failure |
| 4 | Required administrator privileges missing |
| 5 | Operation failed |

## Offline development

The integration tests use the actual executable and Unix socket without launchd or VPN access. An unprivileged developer can launch an isolated daemon with `daemon --test-socket /absolute/private/directory/control.sock`, then query it using `--socket /absolute/private/directory/control.sock --json status`. The test daemon refuses root execution and never installs a service. Production daemon mode uses fixed system paths and requires root.

`service install --staging-dir /absolute/private/directory` and matching uninstall stage or remove the owned installation beneath that directory without loading launchd. Staging is restricted to unprivileged execution. These modes do not modify the active mihomo service, routes or DNS. Staging verifies the installation artifacts, not a real system-domain launchd bootstrap.
