//! The export table (data directory 0).
//!
//! A 40-byte directory: flags, a time stamp, a version, the RVA of the
//! DLL's own name, the ordinal base, the number of functions and of names,
//! and the RVAs of three tables: the export address table (one RVA per
//! ordinal, from the base), the name pointer table (sorted name RVAs) and
//! the ordinal table (for each name, its index in the address table). An
//! address inside the export directory itself is a forwarder: the text
//! `DLL.function` (or `DLL.#ordinal`) the loader resolves instead.

use std::collections::HashMap;

use common::bytes::Reader;
use common::time::Ts;

use crate::image::{directory, time_stamp, Image};

const DIRECTORY_SIZE: usize = 40;
/// The most functions or names read (ordinals are 16-bit).
const MAX_EXPORTS: usize = 65_536;
/// The longest name or forwarder read.
const MAX_NAME: usize = 512;

/// What a DLL exports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Exports {
    /// The DLL's name as it was linked (`sample.dll`): the name it was
    /// built as, which a renamed file keeps.
    pub dll_name: String,
    /// The directory's time stamp (usually the link time).
    pub timestamp: Option<Ts>,
    /// The first ordinal.
    pub ordinal_base: u32,
    /// The functions, by ordinal.
    pub functions: Vec<Export>,
}

/// An exported function.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Export {
    /// Its ordinal.
    pub ordinal: u32,
    /// Its name, unless it is exported by ordinal only.
    pub name: Option<String>,
    /// Its RVA (for a forwarder, the forwarder text's).
    pub rva: u32,
    /// Where it is forwarded to (`KERNEL32.GetTickCount`).
    pub forwarder: Option<String>,
}

/// The export table, when there is one.
pub(crate) fn read(image: &Image<'_>, problems: &mut Vec<String>) -> Option<Exports> {
    let table = image.directory(directory::EXPORT)?;
    let Some(bytes) = image.at_rva(table.rva, DIRECTORY_SIZE) else {
        problems.push(format!(
            "export table: RVA {:#x} not in the file",
            table.rva
        ));
        return None;
    };
    let field = |at: usize| {
        bytes
            .get(at..at + 4)
            .and_then(|b| b.try_into().ok())
            .map_or(0, u32::from_le_bytes)
    };
    let (stamp, name, base) = (field(4), field(12), field(16));
    let (function_count, name_count) = (field(20) as usize, field(24) as usize);
    let (addresses, names, ordinals) = (field(28), field(32), field(36));
    let dll_name = image.string_at(name, MAX_NAME).unwrap_or_else(|| {
        problems.push(format!(
            "export table: name at RVA {name:#x} not in the file"
        ));
        String::new()
    });
    let names = names_by_index(image, names, ordinals, name_count, problems);
    let forwarders = table.rva..table.rva.saturating_add(table.size);
    let mut functions = Vec::new();
    for (index, rva) in table_of(image, addresses, function_count, "address", problems)
        .into_iter()
        .enumerate()
    {
        if rva == 0 {
            continue; // an unused ordinal
        }
        functions.push(Export {
            ordinal: base.wrapping_add(index as u32),
            name: names.get(&index).cloned(),
            rva,
            forwarder: forwarders
                .contains(&rva)
                .then(|| image.string_at(rva, MAX_NAME))
                .flatten(),
        });
    }
    Some(Exports {
        dll_name,
        timestamp: time_stamp(stamp),
        ordinal_base: base,
        functions,
    })
}

/// Each name, by the address table index the ordinal table gives it.
fn names_by_index(
    image: &Image<'_>,
    names: u32,
    ordinals: u32,
    count: usize,
    problems: &mut Vec<String>,
) -> HashMap<usize, String> {
    let name_rvas = table_of(image, names, count, "name pointer", problems);
    let indexes = ordinal_table(image, ordinals, name_rvas.len(), problems);
    let mut by_index = HashMap::new();
    for (rva, index) in name_rvas.into_iter().zip(indexes) {
        match image.string_at(rva, MAX_NAME) {
            Some(name) => {
                by_index.entry(usize::from(index)).or_insert(name);
            }
            None => problems.push(format!(
                "export table: name at RVA {rva:#x} not in the file"
            )),
        }
    }
    by_index
}

/// `count` 32-bit values at `rva`, as many as the file holds.
fn table_of(
    image: &Image<'_>,
    rva: u32,
    count: usize,
    what: &str,
    problems: &mut Vec<String>,
) -> Vec<u32> {
    let wanted = count.min(MAX_EXPORTS);
    if count > MAX_EXPORTS {
        problems.push(format!(
            "export {what} table: {count} entries, only {MAX_EXPORTS} read"
        ));
    }
    if wanted == 0 {
        return Vec::new();
    }
    let mut reader = Reader::new(image.bytes_at(rva).unwrap_or_default());
    let values: Vec<u32> = (0..wanted).map_while(|_| reader.u32_le().ok()).collect();
    if values.len() < wanted {
        problems.push(format!(
            "export {what} table: {wanted} entries, {} in the file",
            values.len()
        ));
    }
    values
}

/// `count` 16-bit address table indexes at `rva`.
fn ordinal_table(
    image: &Image<'_>,
    rva: u32,
    count: usize,
    problems: &mut Vec<String>,
) -> Vec<u16> {
    if count == 0 {
        return Vec::new();
    }
    let mut reader = Reader::new(image.bytes_at(rva).unwrap_or_default());
    let values: Vec<u16> = (0..count).map_while(|_| reader.u16_le().ok()).collect();
    if values.len() < count {
        problems.push(format!(
            "export ordinal table: {count} entries, {} in the file",
            values.len()
        ));
    }
    values
}
