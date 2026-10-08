//! Everything pefile 2024.8.26 (an independent reader) reads from the four
//! test files, read the same (`tests/oracle/pefile.tsv`, written from
//! pefile's output): the COFF and optional headers, sections, imports and
//! delay-load imports function by function, exports with forwarders, the
//! debug directory, CodeView records, the resource tree with its time
//! stamps, version information, the load configuration time stamp and the
//! import hash.

mod support;

/// A record's columns as text.
macro_rules! row {
    ($($column:expr),* $(,)?) => {
        vec![$($column.to_string()),*]
    };
}

use pe::image::directory;
use pe::{Pe, ResourceId, Symbol};
use support::{file_name, fixture, raw_name, seconds, FILES};

fn records(pe: &Pe) -> Vec<Vec<String>> {
    let mut records = vec![header(pe)];
    for (index, section) in pe.sections.iter().enumerate() {
        records.push(row![
            "section",
            index,
            raw_name(&section.raw_name),
            section.virtual_address,
            section.virtual_size,
            section.raw_offset,
            section.raw_size,
            section.characteristics
        ]);
    }
    records.push(row!["imphash", pe.imphash.clone().unwrap_or_default()]);
    for import in &pe.imports {
        for (index, function) in import.functions.iter().enumerate() {
            let symbol = match function {
                Symbol::Name { hint, name } => format!("{name}@{hint}"),
                Symbol::Ordinal(ordinal) => format!("#{ordinal}"),
            };
            records.push(row![
                "import",
                import.dll,
                import.delayed,
                seconds(import.timestamp),
                index,
                symbol
            ]);
        }
    }
    if let Some(exports) = &pe.exports {
        records.push(row![
            "exports",
            exports.dll_name,
            seconds(exports.timestamp),
            exports.ordinal_base
        ]);
        for export in &exports.functions {
            records.push(row![
                "export",
                export.ordinal,
                export.name.clone().unwrap_or_default(),
                export.rva,
                export.forwarder.clone().unwrap_or_default()
            ]);
        }
    }
    for (index, entry) in pe.debug.iter().enumerate() {
        records.push(row![
            "debug",
            index,
            entry.kind,
            seconds(entry.timestamp),
            entry.size,
            entry.rva,
            entry.file_offset
        ]);
    }
    if let Some(codeview) = &pe.codeview {
        let id = codeview
            .guid
            .clone()
            .or(codeview.signature.map(|s| s.to_string()));
        records.push(row![
            "codeview",
            codeview.format,
            id.unwrap_or_default(),
            codeview.age,
            codeview.path
        ]);
    }
    records.extend(resources(pe));
    records.extend(version(pe));
    if pe
        .optional
        .as_ref()
        .and_then(|o| o.directory(directory::LOAD_CONFIG))
        .is_some()
    {
        records.push(row!["load-config", seconds(pe.load_config_time)]);
    }
    records
}

fn header(pe: &Pe) -> Vec<String> {
    let (file, optional) = (&pe.file_header, pe.optional.as_ref().unwrap());
    let dotted = |(major, minor): (u16, u16)| format!("{major}.{minor}");
    row![
        "header",
        file.machine,
        file.time_date_stamp,
        file.characteristics,
        optional.magic,
        format!(
            "{}.{}",
            optional.linker_version.0, optional.linker_version.1
        ),
        optional.entry_point,
        optional.image_base,
        optional.subsystem,
        dotted(optional.os_version),
        dotted(optional.subsystem_version),
        optional.size_of_image,
        optional.checksum,
        optional.dll_characteristics,
        optional.data_directories.len()
    ]
}

fn id(id: &ResourceId) -> String {
    match id {
        ResourceId::Id(number) => number.to_string(),
        ResourceId::Name(name) => name.clone(),
    }
}

fn resources(pe: &Pe) -> Vec<Vec<String>> {
    let Some(resources) = &pe.resources else {
        return Vec::new();
    };
    let mut records = vec![row!["resource-root", seconds(resources.timestamp)]];
    for kind in &resources.types {
        records.push(row!["resource-type", id(&kind.id), seconds(kind.timestamp)]);
        for resource in &kind.resources {
            records.push(row![
                "resource",
                id(&kind.id),
                id(&resource.name),
                resource.language,
                resource.rva,
                resource.size,
                resource.code_page
            ]);
        }
    }
    records
}

fn version(pe: &Pe) -> Vec<Vec<String>> {
    let Some(info) = &pe.version_info else {
        return Vec::new();
    };
    let dotted = |v: [u16; 4]| format!("{}.{}.{}.{}", v[0], v[1], v[2], v[3]);
    let mut records = Vec::new();
    if let Some(fixed) = &info.fixed {
        records.push(row![
            "version-fixed",
            dotted(fixed.file_version),
            dotted(fixed.product_version),
            fixed.flags_mask,
            fixed.flags,
            fixed.os,
            fixed.file_type,
            fixed.file_subtype
        ]);
    }
    for table in &info.string_tables {
        for (key, value) in &table.strings {
            records.push(row!["version-string", table.key, key, value]);
        }
    }
    if !info.translations.is_empty() {
        let pairs: Vec<String> = info
            .translations
            .iter()
            .map(|(language, code_page)| format!("0x{language:04x} 0x{code_page:04x}"))
            .collect();
        records.push(row!["version-var", "Translation", pairs.join(" ")]);
    }
    records
}

#[test]
fn everything_as_pefile_reads_it() {
    let mut got = Vec::new();
    for path in FILES {
        let pe = pe::read(&fixture(&format!("fixtures/{path}"))).unwrap();
        for record in records(&pe) {
            got.push(format!("{}\t{}", file_name(path), record.join("\t")));
        }
    }
    got.sort();
    let oracle = String::from_utf8(fixture("oracle/pefile.tsv")).unwrap();
    let expected: Vec<&str> = oracle.lines().collect();
    assert_eq!(got.len(), 107);
    for (got, expected) in got.iter().zip(&expected) {
        assert_eq!(got, expected);
    }
    assert_eq!(got, expected);
}
