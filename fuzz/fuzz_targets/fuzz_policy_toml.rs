#![no_main]

use libfuzzer_sys::fuzz_target;
use wardline_policy::CompiledPolicy;

fuzz_target!(|data: &[u8]| {
    if let Ok(raw) = std::str::from_utf8(data) {
        let _ = CompiledPolicy::from_toml_str(raw);
    }
});
