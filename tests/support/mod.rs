//! What the integration tests share.

use common::time::{Ts, TICKS_PER_SECOND};

/// The test files: plaso's three, then the one written for these tests.
pub const FILES: [&str; 4] = [
    "plaso/test_pe.exe",
    "plaso/test_driver.sys",
    "plaso/wrc-test-wevt_template.dll",
    "written/sample.dll",
];

/// A file under `tests/`.
pub fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/{path}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// A file's name, without its directory.
pub fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap()
}

/// Seconds since 1970, 0 when not set.
pub fn seconds(time: Option<Ts>) -> i64 {
    time.and_then(|t| t.ticks())
        .map_or(0, |t| t / TICKS_PER_SECOND)
}

/// A section's raw name as plaso and pefile print it: NUL as `\0`.
pub fn raw_name(raw: &[u8]) -> String {
    raw.iter()
        .map(|&b| {
            if b == 0 {
                "\\0".to_owned()
            } else {
                char::from(b).to_string()
            }
        })
        .collect()
}
