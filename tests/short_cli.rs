#![cfg(target_os = "macos")]

use std::process::{Command, Stdio};

#[test]
fn help_lists_short_commands_and_their_parameters() {
    for args in [
        ["help"].as_slice(),
        ["--help"].as_slice(),
        ["-h"].as_slice(),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_cczu-vpn"))
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("Usage: cczu-vpn "), "{text}");
        for name in ["on", "off", "status", "doctor", "help"] {
            assert!(
                text.lines()
                    .any(|line| line.split_whitespace().next() == Some(name)),
                "Missing {name}: {text}"
            );
        }
    }
    for args in [["help", "on"], ["on", "--help"], ["on", "-h"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_cczu-vpn"))
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            text.contains("--stdin") && text.contains("--ignore-saved"),
            "{text}"
        );
    }
}
