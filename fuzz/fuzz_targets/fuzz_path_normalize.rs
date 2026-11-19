#![no_main]

use libfuzzer_sys::fuzz_target;
use wardline_core::path::{normalize_host_lexical_path, validate_safe_host_path};

fuzz_target!(|data: &[u8]| {
    if let Ok(raw) = std::str::from_utf8(data) {
        let _ = validate_safe_host_path(raw);
        let _ = normalize_host_lexical_path(raw);
    }
});
