#![no_main]

use libfuzzer_sys::fuzz_target;
use wardline_log::AuditFrame;

fuzz_target!(|data: &[u8]| {
    let mut cur = std::io::Cursor::new(data);
    while let Ok(_frame) = ciborium::from_reader::<AuditFrame, _>(&mut cur) {}
});
