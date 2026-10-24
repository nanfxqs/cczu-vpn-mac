//! Read-only diagnostics and one-time DNS configuration artifacts.
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use anyhow::{Result, ensure};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

use super::{
    Response,
    connection::ConnectionInfo,
    network,
    service::{ConnectionPhase, Status},
};

const AUTH_HOST: &str = "zmvpn.cczu.edu.cn";
const TARGET_IP: &str = "172.22.226.31";
const TARGET_URL: &str = "http://172.22.226.31/";
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

pub fn validate_domains(domains: &[String]) -> Result<()> {
    ensure!(domains.len() <= 4, "Specify at most four campus hostnames");
    for domain in domains {
        ensure!(
            domain.len() <= 253
                && domain.ends_with(".cczu.edu.cn")
                && domain != AUTH_HOST
                && domain.split('.').all(|label| !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')),
            "Use exact lowercase campus hostnames, excluding the public VPN authentication entrypoint"
        );
    }
    Ok(())
}

/// Produce a merge fragment from an authorized native session, never a complete mihomo config.
pub fn dns_override(info: &ConnectionInfo, domains: &[String]) -> Result<String> {
    ensure!(
        info.backend == "native",
        "DNS source must be an authorized native VPN session"
    );
    validate_domains(domains)?;
    ensure!(
        !domains.is_empty(),
        "Specify the exact campus hostnames that need internal DNS"
    );
    let server: Ipv4Addr = info.dns.parse()?;
    ensure!(
        !server.is_unspecified()
            && !server.is_loopback()
            && !server.is_multicast()
            && !server.is_broadcast()
            && !fake_ip(IpAddr::V4(server)),
        "Unsupported advertised DNS address"
    );
    let mut domains = domains.to_vec();
    domains.sort();
    domains.dedup();
    let mut artifact = String::from(
        "# DNS address snapshot from the current authorized VPN session.\n# Merge entries into your override; this fragment is NOT automatically applied.\ndns:\n  fake-ip-filter:\n    - '+.cczu.edu.cn'\n  nameserver-policy:\n",
    );
    for domain in domains {
        artifact.push_str(&format!("    '{domain}': '{server}#DIRECT'\n"));
    }
    Ok(artifact)
}

pub fn override_response(status: &Status, domains: &[String]) -> Response {
    if domains.is_empty() || validate_domains(domains).is_err() {
        return Response::error(
            "invalid_arguments",
            "Specify one to four exact campus hostnames with --domain; exclude the public VPN authentication hostname",
        );
    }
    let Some(info) = status
        .connection_info
        .as_ref()
        .filter(|_| status.connection == ConnectionPhase::Connected)
    else {
        return Response::error(
            "connection_required",
            "Connect a native VPN before obtaining the advertised campus DNS address",
        );
    };
    if info.backend != "native" {
        return Response::error(
            "unverified_dns_source",
            "Offline fixtures cannot supply production DNS configuration",
        );
    }
    match dns_override(info, domains) {
        Ok(yaml) => Response::success(
            json!({"source": "authorization_response", "dns": info.dns, "domains": domains,
            "yaml": yaml, "applied": false,
            "requirements": ["Merge entries without replacing existing override configuration", "Verify blacklist fake-ip-filter semantics and direct-nameserver policy behavior", "Verify existing mihomo DIRECT rules separately", "Campus-only domains can fail to resolve while VPN is disconnected"]}),
        ),
        Err(_) => Response::error(
            "unsupported_dns_source",
            "Advertised campus DNS cannot produce a supported IPv4 override",
        ),
    }
}

pub fn unavailable(mut response: Response) -> Response {
    response.data = json!({"healthy": false, "environment": "unknown",
        "service": {"status": "failed", "reason": response.code},
        "connection": {"state": "unknown"}, "credentials": {"status": "unknown"},
        "routes": {"status": "skipped"},
        "dns": {"authentication": {"status": "not_probed"}, "campus": {"status": "not_requested"}, "active_mihomo_policy": "not_verified"},
        "http": {"url": TARGET_URL, "transport": "skipped", "status_code": null, "business": "not_checked"}});
    response
}

fn fake_ip(address: IpAddr) -> bool {
    matches!(address, IpAddr::V4(ip) if ip.octets()[0] == 198 && (ip.octets()[1] == 18 || ip.octets()[1] == 19))
}

async fn resolve(domain: &str) -> Value {
    match tokio::time::timeout(PROBE_TIMEOUT, tokio::net::lookup_host((domain, 443))).await {
        Ok(Ok(addresses)) => {
            let mut addresses: Vec<IpAddr> = addresses.map(|address| address.ip()).collect();
            addresses.sort();
            addresses.dedup();
            let valid = !addresses.is_empty() && addresses.iter().all(|address| !fake_ip(*address));
            json!({"status": if valid {"passed"} else {"failed"}, "addresses": addresses, "fake_ip_detected": addresses.iter().any(|address| fake_ip(*address))})
        }
        _ => {
            json!({"status": "failed", "reason": "resolution_failed_or_timed_out", "addresses": []})
        }
    }
}

fn http_response(status: u16, simulated: bool) -> Value {
    json!({"url": TARGET_URL, "method": "HEAD", "transport": if simulated {"simulated"} else {"passed"}, "status_code": status,
        "business": if status >= 400 {"non_success_response"} else {"response_received"}})
}

async fn http_probe() -> Value {
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = TcpStream::connect((TARGET_IP, 80)).await?;
        stream
            .write_all(b"HEAD / HTTP/1.1\r\nHost: 172.22.226.31\r\nConnection: close\r\n\r\n")
            .await?;
        let mut line = Vec::new();
        BufReader::new(stream)
            .take(1025)
            .read_until(b'\n', &mut line)
            .await?;
        ensure!(
            line.len() <= 1024 && line.ends_with(b"\r\n"),
            "Invalid HTTP status line"
        );
        let line = std::str::from_utf8(&line)?;
        let mut fields = line.split_whitespace();
        ensure!(
            matches!(fields.next(), Some("HTTP/1.0" | "HTTP/1.1")),
            "Invalid HTTP protocol"
        );
        let status: u16 = fields
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing HTTP status"))?
            .parse()?;
        ensure!((100..=599).contains(&status), "Invalid HTTP status");
        Ok::<_, anyhow::Error>(status)
    })
    .await;
    match result {
        Ok(Ok(status)) => http_response(status, false),
        _ => {
            json!({"url": TARGET_URL, "method": "HEAD", "transport": "failed", "status_code": null, "business": "not_checked", "reason": "connection_or_http_protocol_failed_or_timed_out"})
        }
    }
}

async fn route_check(target: &str, expected: Option<&str>) -> Value {
    match network::lookup(target).await {
        Ok(Some(route)) => {
            json!({"status": if expected.is_none_or(|interface| route.interface == interface) {"passed"} else {"failed"}, "interface": route.interface, "expected_interface": expected})
        }
        _ => json!({"status": "failed", "reason": "route_unavailable_or_lookup_failed"}),
    }
}

async fn advertised_dns(info: &ConnectionInfo) -> Value {
    match info.dns.parse::<Ipv4Addr>() {
        Ok(server) => {
            let route = route_check(
                &info.dns,
                server.is_private().then_some(info.interface.as_str()),
            )
            .await;
            json!({"address": server, "source": "authorization_response", "route": route})
        }
        Err(_) => json!({"status": "unsupported", "reason": "advertised_dns_is_not_ipv4"}),
    }
}

async fn campus_domains(info: &ConnectionInfo, domains: &[String]) -> Value {
    if domains.is_empty() {
        return json!({"status": "not_requested", "domains": []});
    }
    let Ok(server) = info.dns.parse::<Ipv4Addr>() else {
        return json!({"status": "failed", "reason": "advertised_dns_is_not_ipv4"});
    };
    let mut results = Vec::new();
    for domain in domains {
        let server_arg = format!("@{server}");
        let direct = async {
            match tokio::time::timeout(
                PROBE_TIMEOUT,
                tokio::process::Command::new("/usr/bin/dig")
                    .args(["+time=2", "+tries=1", "+short", &server_arg, domain, "A"])
                    .kill_on_drop(true)
                    .output(),
            )
            .await
            {
                Ok(Ok(output)) if output.status.success() => {
                    let addresses: Vec<IpAddr> = String::from_utf8_lossy(&output.stdout)
                        .lines()
                        .filter_map(|line| line.parse().ok())
                        .collect();
                    let valid =
                        !addresses.is_empty() && addresses.iter().all(|address| !fake_ip(*address));
                    json!({"status": if valid {"passed"} else {"failed"}, "addresses": addresses})
                }
                _ => {
                    json!({"status": "failed", "reason": "advertised_dns_query_failed_or_timed_out"})
                }
            }
        };
        let (system, advertised) = tokio::join!(resolve(domain), direct);
        results.push(json!({"domain": domain, "system": system, "advertised_server": advertised}));
    }
    let valid = results.iter().all(|result| {
        result["system"]["status"] == "passed" && result["advertised_server"]["status"] == "passed"
    });
    json!({"status": if valid {"passed"} else {"failed"}, "domains": results})
}

pub async fn run(
    status: Status,
    credentials: Response,
    test_mode: bool,
    domains: Vec<String>,
) -> Response {
    if validate_domains(&domains).is_err() {
        return Response::error(
            "invalid_arguments",
            "Specify up to four exact lowercase cczu.edu.cn hostnames; exclude the public VPN authentication hostname",
        );
    }
    let configured = credentials.ok && credentials.data["configured"] == true;
    let mut data = json!({
        "healthy": false,
        "environment": if test_mode { "offline_test" } else { "native" },
        "service": {"status": "passed"},
        "credentials": {"status": if configured { "configured" } else if credentials.ok { "missing" } else { "error" }},
        "connection": {"state": status.connection, "last_error": status.last_error, "last_error_code": status.last_error_code},
        "routes": {"status": "skipped"},
        "dns": {"authentication": {"status": "not_probed"}, "campus": {"status": "not_requested"}, "active_mihomo_policy": "not_verified"},
        "http": {"url": TARGET_URL, "transport": "skipped", "status_code": null, "business": "not_checked"}
    });
    let connected = status.connection == ConnectionPhase::Connected;
    if test_mode {
        data["dns"]["authentication"] = json!({"status": "simulated", "hostname": AUTH_HOST});
        if connected {
            data["routes"] = json!({"status": "simulated"});
            data["dns"]["campus"] = json!({"status": "simulated", "domains": domains});
            data["http"] = http_response(503, true);
        }
    } else {
        let auth = resolve(AUTH_HOST);
        if let Some(info) = status
            .connection_info
            .as_ref()
            .filter(|info| connected && info.backend == "native")
        {
            let (authentication, routes, advertised, campus, http) = tokio::join!(
                auth,
                route_check(TARGET_IP, Some(&info.interface)),
                advertised_dns(info),
                campus_domains(info, &domains),
                http_probe()
            );
            data["dns"]["authentication"] = authentication;
            data["dns"]["advertised_server"] = advertised;
            data["dns"]["campus"] = campus;
            data["routes"] = routes;
            data["http"] = http;
        } else {
            data["dns"]["authentication"] = auth.await;
        }
    }
    let healthy = data["routes"]["status"] == "passed"
        && data["http"]["transport"] == "passed"
        && data["dns"]["authentication"]["status"] == "passed"
        && (domains.is_empty() || data["dns"]["campus"]["status"] == "passed");
    data["healthy"] = json!(healthy);
    if healthy {
        Response::success(data)
    } else {
        let mut response = Response::error(
            "diagnostic_issues",
            "VPN diagnostic checks need attention; inspect individual results",
        );
        response.data = data;
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_override_uses_advertised_dns_only_for_exact_campus_domains() {
        let info = ConnectionInfo {
            interface: "utun7".into(),
            address: "10.0.0.2".into(),
            mask: "255.255.255.0".into(),
            gateway: "10.0.0.1".into(),
            dns: "172.22.0.53".into(),
            peer: "211.65.64.100".into(),
            routes: vec!["172.22.0.0/16".into()],
            backend: "native".into(),
        };
        let artifact = dns_override(&info, &["library.cczu.edu.cn".into()]).unwrap();
        assert!(artifact.contains("- '+.cczu.edu.cn'"));
        assert!(artifact.contains("'library.cczu.edu.cn': '172.22.0.53#DIRECT'"));
        assert!(!artifact.contains("'+.cczu.edu.cn':"));
        assert!(!artifact.contains("zmvpn.cczu.edu.cn:"));
        assert!(!artifact.contains("nameserver:\n"));
        for domain in [
            "cczu.edu.cn",
            "+.cczu.edu.cn",
            "zmvpn.cczu.edu.cn",
            "unrelated.example",
            "evil.cczu.edu.cn\n",
        ] {
            assert!(dns_override(&info, &[domain.into()]).is_err());
        }
        assert!(dns_override(&info, &[]).is_err());
        let mut unsupported = info.clone();
        unsupported.backend = "offline".into();
        assert!(dns_override(&unsupported, &["library.cczu.edu.cn".into()]).is_err());
        unsupported.backend = "native".into();
        unsupported.dns = "198.18.0.53".into();
        assert!(dns_override(&unsupported, &["library.cczu.edu.cn".into()]).is_err());
    }
}
