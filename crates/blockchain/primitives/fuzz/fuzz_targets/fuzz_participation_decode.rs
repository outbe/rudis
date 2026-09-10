#![no_main]

use alloy_primitives::Address;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz with various validator set sizes.
    for n in [1, 4, 16, 64, 128] {
        let validators: Vec<Address> = (0..n)
            .map(|i| Address::with_last_byte(i as u8))
            .collect();

        // Must not panic regardless of input.
        let _ = outbe_primitives::participation::decode_participation(data, &validators);
        let _ = outbe_primitives::participation::decode_participation_extended(data, &validators);
    }
});
