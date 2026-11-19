#![no_main]

use libfuzzer_sys::fuzz_target;
use wardline_policy::argv_shield::{inspect_argv, unwrap_command};

fuzz_target!(|data: &[u8]| {
    if let Ok(raw) = std::str::from_utf8(data) {
        let mut parts = raw.split('\0');
        let exe = parts.next().unwrap_or("");
        let args: Vec<String> = parts.map(ToOwned::to_owned).collect();
        let _ = unwrap_command(exe, &args);
        let _ = inspect_argv(exe, &args, false, false);
    }
});
