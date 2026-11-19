#![no_main]

use libfuzzer_sys::fuzz_target;
use wardline_core::capability::parse_canonical_destination;
use wardline_policy::{method_is_token, request_target_is_clean};

fuzz_target!(|data: &[u8]| {
    if let Ok(raw) = std::str::from_utf8(data) {
        let _ = parse_canonical_destination(raw);
        let _ = method_is_token(raw);
        let _ = request_target_is_clean(raw);
    }
});
