//! The import table, the delay-load import table and the import hash.
//!
//! The import table (data directory 1) is a run of 20-byte descriptors
//! ended by an all-zero one: the import lookup table's RVA, a time stamp
//! (non-zero when the imports were bound), the forwarder chain, the DLL
//! name's RVA and the import address table's RVA. The delay-load table
//! (data directory 13) is a run of 32-byte descriptors: attributes, the
//! DLL name, module handle, address table, name table, bound and unload
//! tables, and a time stamp. In both, a lookup table entry (4 bytes in
//! PE32, 8 in PE32+) either has its top bit set and carries an ordinal, or
//! is the RVA of a 2-byte hint and the function's name.

use common::bytes::Reader;
use common::time::Ts;

use crate::image::{directory, time_stamp, until_nul, Image};

const DESCRIPTOR_SIZE: usize = 20;
const DELAY_DESCRIPTOR_SIZE: usize = 32;
/// The most DLLs read from one table.
const MAX_DLLS: usize = 4096;
/// The most functions read from the file's import tables.
const MAX_FUNCTIONS: usize = 65_536;
/// The longest DLL or function name read.
const MAX_NAME: usize = 512;
/// Delay-load attribute: the descriptor holds RVAs, not addresses.
const DELAY_RVA_BASED: u32 = 1;
/// Low 31 bits of a lookup entry: the hint/name RVA.
const NAME_RVA_MASK: u64 = 0x7fff_ffff;
const ORDINAL_FLAG_32: u64 = 1 << 31;
const ORDINAL_FLAG_64: u64 = 1 << 63;
/// Extensions the import hash drops from DLL names, as pefile does.
const IMPHASH_EXTENSIONS: [&str; 3] = ["ocx", "sys", "dll"];

/// A DLL the image imports from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Import {
    /// The DLL's name as stored (`KERNEL32.dll`).
    pub dll: String,
    /// Whether it is delay-loaded: loaded on first call, not at start.
    pub delayed: bool,
    /// The descriptor's time stamp: for a bound import, the bound DLL's;
    /// for a delay-loaded one, its bound DLL's. Usually not set.
    pub timestamp: Option<Ts>,
    /// The functions imported, in table order.
    pub functions: Vec<Symbol>,
}

/// An imported function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Symbol {
    /// By name, with the hint (an index into the DLL's export name table).
    Name {
        /// The hint.
        hint: u16,
        /// The name.
        name: String,
    },
    /// By ordinal.
    Ordinal(u16),
}

/// Both tables: the regular imports, then the delay-loaded ones.
pub(crate) fn read(image: &Image<'_>, problems: &mut Vec<String>) -> Vec<Import> {
    let mut tables = Tables {
        image,
        problems,
        functions_left: MAX_FUNCTIONS,
    };
    let mut imports = tables.regular();
    imports.extend(tables.delayed());
    imports
}

/// Reads the import tables, within one budget of functions for the file
/// (DLLs can share a lookup table).
struct Tables<'i, 'a, 'p> {
    image: &'i Image<'a>,
    problems: &'p mut Vec<String>,
    functions_left: usize,
}

impl<'a> Tables<'_, 'a, '_> {
    fn regular(&mut self) -> Vec<Import> {
        let Some(descriptors) = self.descriptors(directory::IMPORT, "import table") else {
            return Vec::new();
        };
        let mut imports = Vec::new();
        for (index, descriptor) in descriptors.chunks_exact(DESCRIPTOR_SIZE).enumerate() {
            if is_terminator(descriptor) {
                return imports;
            }
            if index == MAX_DLLS {
                self.problems
                    .push(format!("import table: only {MAX_DLLS} DLLs read"));
                return imports;
            }
            let field = |at: usize| u32_at(descriptor, at);
            let (lookup, stamp, name, address_table) = (field(0), field(4), field(12), field(16));
            let place = format!("import {index}");
            let Some(dll) = self.dll_name(name, &place) else {
                continue;
            };
            let names = if lookup == 0 { address_table } else { lookup };
            imports.push(Import {
                functions: self.functions(names, &format!("{place} ({dll})")),
                dll,
                delayed: false,
                timestamp: time_stamp(stamp),
            });
        }
        self.problems
            .push("import table: no terminating descriptor".to_owned());
        imports
    }

    fn delayed(&mut self) -> Vec<Import> {
        let Some(descriptors) = self.descriptors(directory::DELAY_IMPORT, "delay import table")
        else {
            return Vec::new();
        };
        let image_base = self.image.image_base();
        let mut imports = Vec::new();
        for (index, descriptor) in descriptors.chunks_exact(DELAY_DESCRIPTOR_SIZE).enumerate() {
            if is_terminator(descriptor) {
                return imports;
            }
            if index == MAX_DLLS {
                self.problems
                    .push(format!("delay import table: only {MAX_DLLS} DLLs read"));
                return imports;
            }
            let field = |at: usize| u32_at(descriptor, at);
            let attributes = field(0);
            // Old (Visual C++ 6) descriptors hold addresses, not RVAs.
            let rva = |value: u32| {
                if attributes & DELAY_RVA_BASED == 0 && value != 0 {
                    u64::from(value)
                        .checked_sub(image_base)
                        .and_then(|r| u32::try_from(r).ok())
                        .unwrap_or(0)
                } else {
                    value
                }
            };
            let place = format!("delay import {index}");
            let Some(dll) = self.dll_name(rva(field(4)), &place) else {
                continue;
            };
            imports.push(Import {
                functions: self.functions(rva(field(16)), &format!("{place} ({dll})")),
                dll,
                delayed: true,
                timestamp: time_stamp(field(28)),
            });
        }
        self.problems
            .push("delay import table: no terminating descriptor".to_owned());
        imports
    }

    /// The bytes from a table's start to the end of its section.
    fn descriptors(&mut self, index: usize, what: &str) -> Option<&'a [u8]> {
        let table = self.image.directory(index)?;
        let bytes = self.image.bytes_at(table.rva);
        if bytes.is_none() {
            self.problems
                .push(format!("{what}: RVA {:#x} not in the file", table.rva));
        }
        bytes
    }

    fn dll_name(&mut self, rva: u32, place: &str) -> Option<String> {
        let name = self.image.string_at(rva, MAX_NAME);
        if name.is_none() {
            self.problems
                .push(format!("{place}: DLL name at RVA {rva:#x} not in the file"));
        }
        name
    }

    /// The functions a lookup table at `rva` lists, up to its zero entry.
    fn functions(&mut self, rva: u32, place: &str) -> Vec<Symbol> {
        if rva == 0 {
            return Vec::new();
        }
        let Some(bytes) = self.image.bytes_at(rva) else {
            self.problems.push(format!(
                "{place}: lookup table at RVA {rva:#x} not in the file"
            ));
            return Vec::new();
        };
        let pe32_plus = self.image.is_pe32_plus();
        let ordinal_flag = if pe32_plus {
            ORDINAL_FLAG_64
        } else {
            ORDINAL_FLAG_32
        };
        let mut reader = Reader::new(bytes);
        let mut symbols = Vec::new();
        loop {
            let entry = if pe32_plus {
                reader.u64_le()
            } else {
                reader.u32_le().map(u64::from)
            };
            let Ok(entry) = entry else {
                self.problems
                    .push(format!("{place}: lookup table not terminated"));
                break;
            };
            if entry == 0 {
                break;
            }
            if self.functions_left == 0 {
                self.problems.push(format!(
                    "{place}: only {MAX_FUNCTIONS} functions read in all"
                ));
                break;
            }
            self.functions_left -= 1;
            let name_rva = (entry & NAME_RVA_MASK) as u32;
            if entry & ordinal_flag != 0 {
                symbols.push(Symbol::Ordinal(entry as u16));
            } else if let Some(symbol) = hint_name(self.image, name_rva) {
                symbols.push(symbol);
            } else {
                self.problems.push(format!(
                    "{place}: function name at RVA {name_rva:#x} not in the file"
                ));
            }
        }
        symbols
    }
}

fn is_terminator(descriptor: &[u8]) -> bool {
    descriptor.iter().all(|&b| b == 0)
}

fn hint_name(image: &Image<'_>, rva: u32) -> Option<Symbol> {
    let bytes = image.bytes_at(rva)?;
    let hint = u16::from_le_bytes([*bytes.first()?, *bytes.get(1)?]);
    let name = bytes.get(2..)?;
    let name = until_nul(&name[..name.len().min(MAX_NAME)]);
    Some(Symbol::Name {
        hint,
        name: String::from_utf8_lossy(name).into_owned(),
    })
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    bytes
        .get(at..at + 4)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

/// The import hash (Mandiant's "imphash"), as pefile computes it: for each
/// regular (not delay-loaded) import, `dll.function` in lower case, the
/// DLL name without an `.ocx`, `.sys` or `.dll` extension and an ordinal
/// written `ord<n>`, joined by commas, MD5 in lower-case hex. `None`
/// without regular imports.
///
/// pefile names some ordinals of `ws2_32.dll`, `wsock32.dll` and
/// `oleaut32.dll` from its own tables; here they stay `ord<n>`, so the
/// hash of an image importing those by ordinal differs from pefile's.
#[must_use]
pub fn imphash(imports: &[Import]) -> Option<String> {
    let regular: Vec<&Import> = imports.iter().filter(|i| !i.delayed).collect();
    if regular.is_empty() {
        return None;
    }
    let mut entries = Vec::new();
    for import in regular {
        let dll = import.dll.to_lowercase();
        let library = match dll.rsplit_once('.') {
            Some((stem, extension)) if IMPHASH_EXTENSIONS.contains(&extension) => stem,
            _ => dll.as_str(),
        };
        for function in &import.functions {
            let function = match function {
                Symbol::Name { name, .. } => name.to_lowercase(),
                Symbol::Ordinal(ordinal) => format!("ord{ordinal}"),
            };
            entries.push(format!("{library}.{function}"));
        }
    }
    Some(common::hex::encode(&common::md5::Md5::digest(
        entries.join(",").as_bytes(),
    )))
}
