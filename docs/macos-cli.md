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
