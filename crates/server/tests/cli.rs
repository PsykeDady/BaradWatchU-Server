use std::process::Command;

#[test]
fn informational_flags_bypass_startup_configuration() {
    for flag in ["--version", "-V", "--help", "-h"] {
        let output = Command::new(env!("CARGO_BIN_EXE_baradwatchu-server"))
            .env("BARADWATCHU_SERVER_ADDR", "invalid-address")
            .arg(flag)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains(concat!("BaradWatchU Server ", env!("CARGO_PKG_VERSION"))));
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn invalid_configuration_is_actionable_and_does_not_panic() {
    let output = Command::new(env!("CARGO_BIN_EXE_baradwatchu-server"))
        .env("BARADWATCHU_SERVER_ADDR", "invalid-address")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("BARADWATCHU_SERVER_ADDR"));
    assert!(!error.contains("panicked"));
}

#[test]
fn invalid_cli_returns_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_baradwatchu-server"))
        .arg("--invalid")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    #[cfg(unix)]
    {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};
        let output = Command::new(env!("CARGO_BIN_EXE_baradwatchu-server"))
            .arg(OsString::from_vec(vec![b'-', b'-', 0xff]))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
    }
}
