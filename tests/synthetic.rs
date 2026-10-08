//! Format details on small images built here: the RVA mapping, long
//! section names, `NB10` records, old delay-load descriptors, driver
//! detection, the import hash's rules, and damage (a resource loop, an
//! unknown optional header, files that aren't PE).

use pe::{imphash, Import, Kind, Symbol};

const PE_AT: usize = 0x40;
const COFF_AT: usize = PE_AT + 4;
const OPTIONAL_AT: usize = COFF_AT + 20;
const PE32_OPTIONAL_SIZE: usize = 224;
const SECTIONS_AT: usize = OPTIONAL_AT + PE32_OPTIONAL_SIZE;
const HEADERS_SIZE: usize = 0x200;
const SECTION_RVA: u32 = 0x1000;
const IMAGE_BASE: u32 = 0x40_0000;
const EXECUTABLE: u16 = 0x0002;
const NATIVE: u16 = 1;

fn put16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// A PE32 executable whose sections hold `sections` (at RVAs 0x1000,
/// 0x2000, …), with `directories` as (index, RVA, size).
fn build(sections: &[(&[u8; 8], &[u8])], directories: &[(usize, u32, u32)]) -> Vec<u8> {
    let mut data = vec![0u8; HEADERS_SIZE];
    data[..2].copy_from_slice(b"MZ");
    put32(&mut data, 0x3c, PE_AT as u32);
    data[PE_AT..PE_AT + 4].copy_from_slice(b"PE\0\0");
    put16(&mut data, COFF_AT, 0x14c);
    put16(&mut data, COFF_AT + 2, sections.len() as u16);
    put32(&mut data, COFF_AT + 4, 1_000_000_000);
    put16(&mut data, COFF_AT + 16, PE32_OPTIONAL_SIZE as u16);
    put16(&mut data, COFF_AT + 18, EXECUTABLE);
    put16(&mut data, OPTIONAL_AT, 0x10b);
    put32(&mut data, OPTIONAL_AT + 28, IMAGE_BASE);
    put32(&mut data, OPTIONAL_AT + 60, HEADERS_SIZE as u32);
    put16(&mut data, OPTIONAL_AT + 68, 2);
    put32(&mut data, OPTIONAL_AT + 92, 16);
    for &(index, rva, size) in directories {
        put32(&mut data, OPTIONAL_AT + 96 + index * 8, rva);
        put32(&mut data, OPTIONAL_AT + 100 + index * 8, size);
    }
    for (index, (name, contents)) in sections.iter().enumerate() {
        let header = SECTIONS_AT + index * 40;
        let raw_offset = data.len() as u32;
        let raw_size = contents.len().div_ceil(0x200) * 0x200;
        data[header..header + 8].copy_from_slice(*name);
        put32(&mut data, header + 8, contents.len() as u32);
        put32(&mut data, header + 12, SECTION_RVA * (index as u32 + 1));
        put32(&mut data, header + 16, raw_size as u32);
        put32(&mut data, header + 20, raw_offset);
        data.extend_from_slice(contents);
        data.resize(raw_offset as usize + raw_size, 0);
    }
    data
}

#[test]
fn not_pe() {
    assert!(pe::read(b"").is_err());
    assert!(pe::read(b"ELF").is_err());
    let mut dos_only = vec![0u8; 0x80];
    dos_only[..2].copy_from_slice(b"MZ");
    put32(&mut dos_only, 0x3c, 0x40);
    assert!(!pe::detect(&dos_only));
    assert_eq!(pe::read(&dos_only).unwrap_err().offset, 0x40);
    let truncated = &build(&[], &[])[..COFF_AT + 10];
    assert!(pe::detect(truncated));
    assert!(pe::read(truncated).is_err());
}

#[test]
fn rva_mapping_and_headers() {
    let text = [0x90u8; 0x10];
    let image = build(&[(b".text\0\0\0", &text)], &[]);
    let pe = pe::read(&image).unwrap();
    assert_eq!(pe.problems, Vec::<String>::new());
    assert_eq!(pe.kind, Kind::Executable);
    assert_eq!(pe.sections[0].name, ".text");
    assert_eq!(pe.sections[0].raw_offset, 0x200);
    assert_eq!(
        pe.compiled.unwrap().to_string(),
        "2001-09-09T01:46:40.0000000Z"
    );
    assert!(pe.imphash.is_none());
}

#[test]
fn long_section_name_from_the_string_table() {
    let mut image = build(&[(b"/4\0\0\0\0\0\0", b"data")], &[]);
    let symbols = image.len() as u32;
    put32(&mut image, COFF_AT + 8, symbols);
    put32(&mut image, COFF_AT + 12, 0);
    // The string table: its 4-byte size, then the names.
    image.extend_from_slice(&[23, 0, 0, 0]);
    image.extend_from_slice(b".debug_line_str\0");
    let pe = pe::read(&image).unwrap();
    assert_eq!(pe.sections[0].name, ".debug_line_str");
    assert_eq!(&pe.sections[0].raw_name, b"/4\0\0\0\0\0\0");
}

#[test]
fn nb10_codeview() {
    let mut section = vec![0u8; 0x60];
    // One debug entry, type 2, its data at RVA 0x1020 (file offset 0x220).
    put32(&mut section, 4, 1_100_000_000);
    put32(&mut section, 12, 2);
    put32(&mut section, 16, 24);
    put32(&mut section, 20, SECTION_RVA + 0x20);
    put32(&mut section, 24, 0x220);
    section[0x20..0x24].copy_from_slice(b"NB10");
    put32(&mut section, 0x28, 0x3b9a_ca00);
    put32(&mut section, 0x2c, 3);
    section[0x30..0x37].copy_from_slice(b"old.pdb");
    let image = build(&[(b".rdata\0\0", &section)], &[(6, SECTION_RVA, 28)]);
    let pe = pe::read(&image).unwrap();
    assert_eq!(pe.problems, Vec::<String>::new());
    let codeview = pe.codeview.unwrap();
    assert_eq!(codeview.format, "NB10");
    assert_eq!(codeview.signature, Some(0x3b9a_ca00));
    assert_eq!(codeview.guid, None);
    assert_eq!((codeview.age, codeview.path.as_str()), (3, "old.pdb"));
}

#[test]
fn old_delay_import_descriptor_holds_addresses() {
    let mut section = vec![0u8; 0x80];
    let va = |offset: u32| IMAGE_BASE + SECTION_RVA + offset;
    // Attributes 0: names and tables are addresses, not RVAs.
    put32(&mut section, 4, va(0x40));
    put32(&mut section, 16, va(0x50));
    section[0x40..0x4a].copy_from_slice(b"OLDDLL.dll");
    put32(&mut section, 0x50, 0x8000_0004);
    let image = build(&[(b".data\0\0\0", &section)], &[(13, SECTION_RVA, 64)]);
    let pe = pe::read(&image).unwrap();
    assert_eq!(pe.problems, Vec::<String>::new());
    assert_eq!(pe.imports.len(), 1);
    assert_eq!(pe.imports[0].dll, "OLDDLL.dll");
    assert!(pe.imports[0].delayed);
    assert_eq!(pe.imports[0].functions, [Symbol::Ordinal(4)]);
    // Delay-loaded imports are not in the import hash.
    assert_eq!(pe.imphash, None);
}

#[test]
fn driver_by_pageable_section_under_the_native_subsystem() {
    let mut image = build(&[(b"PAGE\0\0\0\0", b"code")], &[]);
    assert_eq!(pe::read(&image).unwrap().kind, Kind::Executable);
    put16(&mut image, OPTIONAL_AT + 68, NATIVE);
    assert_eq!(pe::read(&image).unwrap().kind, Kind::Driver);
    put16(&mut image, COFF_AT + 18, 0x2000 | EXECUTABLE);
    assert_eq!(pe::read(&image).unwrap().kind, Kind::Dll);
}

#[test]
fn resource_loop_ends() {
    let mut tree = vec![0u8; 0x40];
    // The root has one numbered entry whose subdirectory is the root.
    put16(&mut tree, 14, 1);
    put32(&mut tree, 16, 3);
    put32(&mut tree, 20, 0x8000_0000);
    let image = build(&[(b".rsrc\0\0\0", &tree)], &[(2, SECTION_RVA, 0x40)]);
    let pe = pe::read(&image).unwrap();
    assert!(pe.problems.iter().any(|p| p.contains("reached twice")));
    assert_eq!(pe.resources.unwrap().types, []);
}

#[test]
fn unknown_optional_header() {
    let mut image = build(&[(b".text\0\0\0", b"code")], &[]);
    put16(&mut image, OPTIONAL_AT, 0x107);
    let pe = pe::read(&image).unwrap();
    assert!(pe.optional.is_none());
    assert_eq!(pe.problems, ["optional header: unknown magic 0x107"]);
    assert_eq!(pe.sections.len(), 1);
}

#[test]
fn imphash_rules() {
    let import = |dll: &str, functions: Vec<Symbol>, delayed: bool| Import {
        dll: dll.to_owned(),
        delayed,
        timestamp: None,
        functions,
    };
    let named = |name: &str| Symbol::Name {
        hint: 0,
        name: name.to_owned(),
    };
    let imports = [
        import("KERNEL32.dll", vec![named("GetProcAddress")], false),
        import("helper.OCX", vec![Symbol::Ordinal(3)], false),
        import("foo.exe", vec![named("Bar")], false),
        import("USER32.dll", vec![named("MessageBoxA")], true),
    ];
    // md5("kernel32.getprocaddress,helper.ord3,foo.exe.bar")
    assert_eq!(
        imphash(&imports).as_deref(),
        Some("fec491983b5ea3aa7f3a1dcc92884cc2")
    );
}
