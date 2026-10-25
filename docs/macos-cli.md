# macOS CLI

```sh
cczu-vpn on          # Connect using saved credentials
cczu-vpn off         # Disconnect and clean owned routes
cczu-vpn status      # Query service and connection state
cczu-vpn doctor      # Diagnose routing, DNS and campus HTTP access
cczu-vpn help        # List commands
cczu-vpn on --help   # Show connection options
```

The short entrypoint emits compact JSON by default, so agents need no output-format flag. `help`, `--help`, `-h` and subcommand help print readable usage. The `connect`/`disconnect` aliases and `cczu-vpn-proto --json` calls remain compatible.

## Connect and disconnect

After installation and credential initialization, daily operations do not require sudo:

```sh
cczu-vpn on
cczu-vpn status
cczu-vpn off
```

`on` returns success only after authentication, tunnel creation, campus routes and packet forwarding are ready. It does not treat a started process as a connected VPN. Status includes a `connection_info` snapshot with the allocated utun interface, tunnel address/mask/gateway, advertised DNS, actual tunnel peer and campus prefixes; it never includes the password. Website availability is a separate diagnostic from tunnel readiness.

Concurrent `on` calls share the current attempt; status `generation` increments only when a new attempt starts. Repeating connect for an already connected VPN succeeds without re-reading credentials. `off` cancels startup, waits for owned-resource cleanup, and prevents late startup success. While disconnecting, a new connect returns `operation_in_progress` so the caller can retry after cleanup. Duplicate disconnects are safe.

Startup has a 60-second deadline, followed by at most 30 seconds of cleanup per attempt. Cancellation reports `connection_cancelled`; startup expiry reports `connection_timeout`. If cleanup cannot establish ownership or finish, status remains failed with a retryable reason and the journal is retained; do not treat an error response as proof that all network resources were removed. Control requests have bounded client waits; query status before retrying after `operation_timeout`.

The background service monitors packet-forwarding completion and cleans failed connections without requiring a status query. It preserves the last failure across status queries and explicit disconnect, clears it after a successful connection, and never automatically reconnects. Idle traffic alone is not a failure signal: the upstream protocol sends heartbeats but does not define a verified acknowledgement deadline.

For a one-off account, pass a JSON object containing `user` and `password` to `on --stdin --ignore-saved` on standard input. This does not save that account. Avoid putting secrets in command arguments or shell history. Missing credentials produce `credentials_required` rather than an interactive prompt.

The native runtime allocates a new utun without selecting another process's interface. It forwards raw IP packets in both directions, preserves TLS verification, and installs only checked campus IPv4 routes plus exact school endpoint protections. The physical gateway/interface are discovered at connection time. Default/broad takeover routes, overlapping local networks, malformed masks and conflicting exact routes fail explicitly. Gateway Fake IP responses also fail with an instruction to check DNS/Fake IP configuration. Existing matching routes are not adopted for cleanup. Successful adds are removed in reverse order only while their prefix/interface/gateway still match.

Some school rules also advertise the authentication and tunnel endpoints as campus hosts. Exact `/32` rules for protected bootstrap endpoints and the actual peer are omitted from the campus plan, including duplicate DNS host routes. Their physical host routes stay in place; broader campus prefixes remain available. This prevents the client from conflicting with its own endpoint protection.

The runtime does not modify system DNS, default routes, IPv6 configuration or active mihomo configuration. DNS policy preparation and diagnostics are separate from daily VPN connection control. It uses macOS [point-to-point interface routes](https://github.com/apple-oss-distributions/network_cmds/blob/main/route.tproj/route.8) and the existing tun-rs 2.8.3 device API.

Offline connection tests can start an unprivileged isolated daemon with `daemon --test-socket PATH --test-scenario ready`. The explicit `setup-failure`, `unsafe-default`, `local-overlap` and `invalid-mask` scenarios verify failure behavior without touching host networking. The default test scenario is `disabled`, which refuses connection attempts; all test scenario selection requires an isolated test socket and test daemon mode refuses root. Production daemon mode always uses the native backend.

The native path was verified on the SSH-operated Apple Silicon Mac mini on 2026-10-25: authenticated connection, HTTP 200 from `http://172.22.226.31/`, repeated connection control and owned-route cleanup. Public connectivity, the default route, original IPv6 routes and the running mihomo process/configuration remained intact. Domain-specific mihomo policy has not been applied because the current acceptance resource uses an IP address.

The macOS entrypoint controls a system VPN service. Windows and Linux retain the existing interactive CLI.

Build with `cargo build --release --locked`, then install once:

```sh
sudo ./target/release/cczu-vpn service install
cczu-vpn status
```

Installation copies the executable into `/usr/local/libexec/cczu-vpn-proto`, creates a launchd definition, and installs both `cczu-vpn` and the legacy `cczu-vpn-proto` links in `/usr/local/bin`. Repeating installation updates only this service. It does not start a VPN connection. Service management follows Apple's [launchd lifecycle](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html).

If the background service is already installed, the short client can also be installed for the current user without updating the privileged service:

```sh
mkdir -p "$HOME/.local/bin"
install -m 755 target/release/cczu-vpn "$HOME/.local/bin/cczu-vpn"
```

Use this location when `$HOME/.local/bin` is in the user's `PATH`. The client communicates with the existing local service and reuses its saved credentials.

The background service is independent of SSH sessions. Its local Unix socket accepts this tool's commands without per-user authorization configuration. There is no network listener or arbitrary privileged-command interface. As requested for this personal machine, any local user can control VPN operations. The daemon owns privileged network configuration; daily status and VPN commands do not need sudo.

```sh
sudo cczu-vpn service stop
sudo cczu-vpn service install  # start again
sudo cczu-vpn service uninstall
```

`service stop` unloads the service, so launchd will not immediately restart it. The next machine boot loads the installed service again. Uninstall removes only this tool's service definition, binary and CLI link; stored credentials are handled separately.

## Campus credentials over SSH

Credentials belong to the background service, not the user who ran `sudo` during installation. Production stores one shared plaintext account/password file in `/var/db/cczu-vpn/credentials.json`, owned by root with mode `0600` inside a `0700` directory. Daily management goes through the local service and needs no sudo. It does not use the login keychain or require a graphical session.

For interactive initialization, run `cczu-vpn credentials set` in a terminal. The password input is hidden. The command asks whether to save; answering no keeps the credentials only in daemon memory. `--save` explicitly chooses persistence. The CLI does not claim to have authenticated the credentials; the connection command validates them against the school service.

Agents should send a JSON object with `user` and `password` through standard input, rather than supplying passwords as command arguments:

```sh
your-secret-source | cczu-vpn credentials set --stdin --save
cczu-vpn credentials status
cczu-vpn credentials status --ignore-saved
cczu-vpn credentials delete
```

Omit `--save` to use temporary credentials until the background service restarts or they are replaced/deleted. Temporary credentials take priority over the saved file; saving a new account clears the temporary override. Ignoring saved credentials does not remove them and still permits temporary credentials. Status reports only presence (`configured`, `saved`, `temporary`), never the stored account or password. Delete clears both temporary and persisted credentials and is safe to repeat.

Explicit `--json` and non-terminal initialization never prompt. Missing input returns `credentials_required`, malformed or empty JSON credentials return `invalid_credentials`, and storage failures return `credential_store_error`; each uses operation-failed exit code `5`. Initialization does not save unless explicitly selected. Secrets must come from a source controlled by the caller; do not embed real passwords in shell history, logs or example commands.

## Read-only diagnosis and campus DNS preparation

```sh
cczu-vpn doctor
cczu-vpn doctor --domain YOUR-INTERNAL-HOST.cczu.edu.cn
```

Replace the example with an actual lowercase campus hostname. The current acceptance resource is an IP address, so domain-specific DNS preparation is optional until a domain that needs internal resolution is identified. `doctor` does not change routes, DNS settings, mihomo configuration or school business data. It reports service availability, whether credentials are configured, connection state, the route to `172.22.226.31`, public VPN authentication hostname resolution, and a bounded direct TCP HTTP `HEAD /` probe to the known resource. It does not send credentials to the website, read its body, follow redirects or perform login operations. Its HTTP probe bypasses HTTP proxy environment settings; application/mihomo proxy rules need separate verification.

Each result keeps transport and HTTP response status separate: any valid HTTP response demonstrates HTTP transport reachability, including redirects, authentication errors and `405 Method Not Allowed`. A `503` response is reported as a non-success business response, not automatically a tunnel failure. Doctor exit `0` means the requested live checks passed, `5` means checks need attention (including a deliberately disconnected VPN), and `3` means the control service is unavailable. JSON results preserve details even for nonzero exits. Human output also includes check details.

When exact campus hostnames are supplied, native diagnostics compare system resolution with an explicit query to the DNS advertised by the current VPN session. Public authentication resolution is checked even while disconnected. The report always identifies active mihomo policy as `not_verified`: neither a real resolved address nor the repository's override fragment proves the running mihomo has loaded the intended policy.

After a native VPN connection is active, obtain a one-time **merge fragment** using the actual DNS address from authorization:

```sh
cczu-vpn doctor --dns-override --domain actual-internal-host.cczu.edu.cn \
  | jq -r '.data.yaml // empty' > campus-dns-override.yaml
```

The command returns YAML in `data.yaml` with `applied: false`; it does not write or reload mihomo. It refuses disconnected sessions, offline fixture DNS, unsupported DNS addresses, the root school suffix and the VPN authentication hostname. Merge the fragment's entries into the existing override during environment preparation, keeping existing configuration. Subsequent `on`/`off` operations never reconfigure mihomo.

The fragment retains `+.cczu.edu.cn` in the Fake IP exclusion list and maps only the explicitly selected exact hostnames to the advertised DNS using `#DIRECT`. It does not change the public authentication hostname's resolver, so adding an internal-only DNS does not create a VPN bootstrap dependency. Selected internal hostnames may stop resolving while VPN is disconnected; that is preferable to silently sending them to a public resolver. The address is a session snapshot: if later authorization advertises a different DNS, regenerate the fragment as a separate environment update.

Check existing merge semantics and mihomo modes before applying: the list form assumes blacklist Fake IP filtering; rule/whitelist configurations need their corresponding syntax. If `direct-nameserver` is configured, verify `direct-nameserver-follow-policy`; otherwise direct re-resolution may ignore the intended policy. Preserve ordinary DNS defaults and validate existing school-domain/IP `DIRECT` routing rules independently. These settings are described in the [official mihomo DNS reference](https://wiki.metacubex.one/en/config/dns/); the generator never adjusts global behavior to force a match.

Offline test daemons never perform DNS, route or HTTP probes. Their reports explicitly say `offline_test`/`simulated` and cannot generate production DNS overrides. Use a native connection for real diagnosis.

## Machine output

`cczu-vpn` emits one compact JSON response on standard output by default. The legacy entrypoint also accepts global `--json`. Help remains readable text; interactive credential setup uses the terminal. Diagnostics go to standard error. Responses contain `ok`, `code`, `message`, and `data`. Status data separately identifies the service and VPN connection state. A running service does not imply a connected VPN.

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

## Restart recovery and removal

The daemon persists a private route intent journal at `/var/db/cczu-vpn/network-journal.json` before each mutation. It verifies the current prefix, interface, gateway and ownership marker before deletion. Normal disconnect and service shutdown remove owned routes; SIGHUP from an SSH hangup leaves an effective connection running. A daemon restart reconciles the journal and starts disconnected. It never automatically reconnects.

Existing routes are never adopted. Changed routes are retained and reported as an incomplete recovery; new connections remain blocked until cleanup can finish. Interrupted physical endpoint host-route additions can be reconciled from the same-boot write-ahead record when the current prefix, interface, gateway and ownership marker match. Routes attributed to another boot and a surviving recovered utun whose ownership cannot be proven remain untouched. An old utun name alone is insufficient because macOS can reuse it. Missing routes are reconciled without deleting another prefix. The offline backend exercises this same journal and cleanup algorithm using an isolated persisted route table; its owner token models provable resource identity and does not claim a native macOS interface has that token.

Installation records the identity of its executable in `/var/db/cczu-vpn/install.json`; install/uninstall refuse to overwrite or delete a replaced executable or changed service definition. Stop, reinstall and uninstall also reconcile owned network resources after the service exits. Uninstall retains saved campus credentials by default. To remove them, run `cczu-vpn credentials delete` while the service is running before uninstalling. Neither cleanup nor removal changes mihomo configuration.

Startup failures expose a stable category in the response `code` and in status
`last_error_code`, alongside the sanitized human-readable `last_error`. Categories
include `credentials_required`, `authentication_rejected`,
`authentication_transport`, `authentication_response`, `tls_failed`,
`tunnel_transport_failed`, `tunnel_negotiation_failed`,
`network_configuration_failed`, and `connection_timeout`. These failures use exit
code `5`. `authentication_rejected` means the login endpoint returned HTTP 401 or
403; it does not establish that the password was wrong. Other unusable login
responses are `authentication_response`. Upstream bodies and error chains are not
included in startup diagnostics. Successful connect clears the previous failure.

Route recovery reconciles the write-ahead journal even if the process died after
kernel add but before its confirmation write. A physical endpoint host route can
be cleaned when the journal recorded its prior absence in the same boot and the
current exact prefix, interface, gateway and PROTO2 marker match. Changed or
unmarked routes are preserved. Recovered native utun names cannot prove ownership
because macOS may reuse them; matching routes on such interfaces remain untouched
until they disappear. Retrying disconnect then completes cleanup. Offline tests
exercise this same decision with native-shaped snapshots without an owner token;
the offline backend also has a durable token for its simulated tunnel identity.
