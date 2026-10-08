# pe

Windows Portable Executable files for forensics: what an `.exe`, `.dll` or `.sys` says about itself, read from Microsoft's "PE Format" specification. When it was linked, whether it is a program, a DLL or a driver, what it imports and exports, its import hash (imphash), the version information its publisher wrote, the PDB path its linker left, and the time stamps in its export, import, resource, debug and load configuration tables. One dependency, its sibling `sootmark-common` (times, MD5).

```toml
[dependencies]
sootmark-pe = "0.1"
```

```rust
let pe = pe::read(&std::fs::read("sample.dll")?)?;
println!("{} linked {:?}, imphash {:?}", pe.kind.label(), pe.compiled, pe.imphash);
for import in &pe.imports {
    println!("{} delayed: {} ({} functions)", import.dll, import.delayed, import.functions.len());
}
if let Some(info) = &pe.version_info {
    println!("{:?} {:?}", info.get("CompanyName"), info.get("OriginalFilename"));
}
if let Some(pdb) = &pe.codeview {
    println!("built with {} ({:?}, age {})", pdb.path, pdb.guid, pdb.age);
}
```

## What you get

- `read(bytes)`: the kind (executable, DLL, driver, as plaso names them), the COFF header (machine, time stamp, characteristics), the optional header (PE32 or PE32+: linker, OS, image and subsystem versions, entry point, image base, sizes, checksum, subsystem, DLL characteristics, data directories), the sections (raw and trimmed names, long names from the string table, addresses, sizes, flags), the imports and delay-load imports (DLL, time stamp, each function by name and hint or by ordinal), the import hash, the exports (the DLL's linked name, time stamp, functions by ordinal with names and forwarders), the resource tree (types, names, languages, data, directory time stamps), the version information (fixed file and product versions, every string table, translations), the debug directory (types, time stamps), the CodeView record (`RSDS` GUID, age and PDB path, or `NB10`) and the load configuration time stamp.
- `detect(bytes)`: whether a file is a PE image.
- `machine_name`, `subsystem_name`: names for the common values.
- Each table is read on its own: damage goes to `problems`, the rest is still read, never a panic. Every count and loop is bounded by the file; the resource tree is walked once per directory, so a loop ends.

## How it's checked

- plaso's three PE test files (Apache-2.0, `tests/fixtures/plaso/`) and a DLL written for these tests (`tests/fixtures/written/`, built with mingw-w64): all 8 events plaso's `pe` parser gives, identical (compile, export, load configuration and import time stamps, PE type, imphash, raw section names, export DLL name, DLL names, delay flags), and the 3, 1 and 1 event data plaso's own tests expect. plaso means to give each resource type's directory time stamp an event but never does (it looks the time stamp up on the wrong pefile object); this crate reads them.
- pefile 2024.8.26, an independent reader, on the same four files: all 107 records identical (headers, sections, every imported and exported function, debug entries, CodeView records, resources with their time stamps, version information, load configuration time stamp, imphash).
- Synthetic images for the RVA mapping, long section names, `NB10` records, old address-based delay-load descriptors, driver detection, the imphash rules, a resource loop and an unknown optional header. Property tests: arbitrary bytes, the test files cut anywhere or with bytes changed never panic.

## Not yet

- pefile names some ordinal imports from `ws2_32.dll`, `wsock32.dll` and `oleaut32.dll` from its own tables before hashing; here they stay `ord<n>`, so the imphash of an image importing those by ordinal differs from pefile's (and VirusTotal's).
- Not read: the certificate table (Authenticode), the Rich header, .NET metadata, relocations, exception data, TLS callbacks, and message tables or event templates inside resources.

## Licence

MIT or Apache-2.0, at your option. plaso's test files are under the Apache licence 2.0.
