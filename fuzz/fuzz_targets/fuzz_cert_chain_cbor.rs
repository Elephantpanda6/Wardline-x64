#![no_main]

use libfuzzer_sys::fuzz_target;
use wardline_cert::{verify_cert_chain_with_revocations, WardCertChain};

fuzz_target!(|data: &[u8]| {
    if let Ok(chain) = ciborium::from_reader::<WardCertChain, _>(data) {
        let root_pk = [0x11u8; 32];
        let _ = verify_cert_chain_with_revocations(&root_pk, &chain, None, None, 1_750_000_000);
    }
});
