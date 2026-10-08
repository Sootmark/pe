//! plaso's `pe` parser on its three test files (Apache-2.0,
//! `tests/fixtures/plaso/`) and on `sample.dll` (written for these tests,
//! `tests/fixtures/written/`): every event psort shows, read the same
//! (`tests/oracle/plaso.tsv`, written from plaso's output): the time
//! stamps of the COFF header, the export table, the load configuration
//! table and each import and delay-load import, with the PE type, import
//! hash, raw section names, export DLL name, DLL names and delay flags.
//!
//! One difference: plaso means to give each resource type's directory
//! time stamp an event (`pe_coff:resource`) but never does, as it looks
//! the time stamp up on pefile's directory object instead of its
//! structure. This crate reads them (`sample.dll` has two); they are
//! checked against pefile in `tests/pefile.rs`.

mod support;

use support::{file_name, fixture, raw_name, seconds, FILES};

const CREATION: &str = "Creation Time";
const MODIFICATION: &str = "Content Modification Time";

fn events(path: &str) -> Vec<String> {
    let pe = pe::read(&fixture(&format!("fixtures/{path}"))).unwrap();
    assert_eq!(pe.problems, Vec::<String>::new(), "{path}");
    let name = file_name(path);
    let sections: Vec<String> = pe.sections.iter().map(|s| raw_name(&s.raw_name)).collect();
    let file_columns = [
        pe.kind.label().to_owned(),
        pe.imphash.clone().unwrap_or_default(),
        sections.join("|"),
        pe.exports
            .as_ref()
            .map(|e| e.dll_name.clone())
            .unwrap_or_default(),
    ]
    .join("\t");
    let file_times = [
        (pe.compiled, CREATION),
        (pe.exports.as_ref().and_then(|e| e.timestamp), MODIFICATION),
        (pe.load_config_time, MODIFICATION),
    ];
    let mut lines: Vec<String> = file_times
        .iter()
        .filter(|(time, _)| time.is_some())
        .map(|&(time, description)| {
            format!(
                "{name}\tpe_coff:file\t{description}\t{}\t{file_columns}",
                seconds(time)
            )
        })
        .collect();
    lines.extend(
        pe.imports
            .iter()
            .filter(|import| import.timestamp.is_some())
            .map(|import| {
                format!(
                    "{name}\tpe_coff:dll_import\t{MODIFICATION}\t{}\t{}\t{}",
                    seconds(import.timestamp),
                    import.dll,
                    import.delayed
                )
            }),
    );
    lines
}

#[test]
fn every_event_as_plaso_reads_it() {
    let mut got: Vec<String> = FILES.iter().flat_map(|path| events(path)).collect();
    got.sort();
    let oracle = String::from_utf8(fixture("oracle/plaso.tsv")).unwrap();
    let expected: Vec<&str> = oracle.lines().collect();
    assert_eq!(got.len(), 8);
    assert_eq!(got, expected);
}

#[test]
fn plaso_test_counts() {
    // plaso's own tests expect 3, 1 and 1 event data: the file, and for
    // test_pe.exe its bound import and its delay-load import.
    let counts: Vec<usize> = FILES[..3]
        .iter()
        .map(|path| {
            let pe = pe::read(&fixture(&format!("fixtures/{path}"))).unwrap();
            1 + pe.imports.iter().filter(|i| i.timestamp.is_some()).count()
        })
        .collect();
    assert_eq!(counts, [3, 1, 1]);
}
