//! Arbitrary bytes, the test files cut anywhere, and the test files with
//! bytes changed, read or are refused: never a panic.

use proptest::prelude::*;

const FILES: [&[u8]; 4] = [
    include_bytes!("fixtures/plaso/test_pe.exe"),
    include_bytes!("fixtures/plaso/test_driver.sys"),
    include_bytes!("fixtures/plaso/wrc-test-wevt_template.dll"),
    include_bytes!("fixtures/written/sample.dll"),
];

fn read(data: &[u8]) {
    let _ = pe::detect(data);
    if let Ok(pe) = pe::read(data) {
        let _ = pe.imphash;
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        read(&data);
    }

    #[test]
    fn arbitrary_bytes_after_real_headers(
        file in 0..FILES.len(),
        keep in 0usize..1024,
        tail in proptest::collection::vec(any::<u8>(), 0..8192),
    ) {
        let mut data = FILES[file][..keep.min(FILES[file].len())].to_vec();
        data.extend(tail);
        read(&data);
    }

    #[test]
    fn cut_anywhere(file in 0..FILES.len(), at in 0usize..10_000) {
        let data = FILES[file];
        read(&data[..at.min(data.len())]);
    }

    #[test]
    fn bytes_changed(
        file in 0..FILES.len(),
        changes in proptest::collection::vec((0usize..10_000, any::<u8>()), 1..16),
    ) {
        let mut data = FILES[file].to_vec();
        let length = data.len();
        for (at, value) in changes {
            data[at % length] = value;
        }
        read(&data);
    }
}
