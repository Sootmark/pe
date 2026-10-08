//! The debug directory (data directory 6), the CodeView record that names
//! the program database (PDB), and the load configuration table's time
//! stamp (data directory 10).
//!
//! The debug directory is a run of 28-byte entries: flags, a time stamp, a
//! version, a type (2 CodeView, 12 Visual C++ features, 13 POGO, 14
//! iLTCG, 16 reproducible build, …), and the data's size, RVA and file
//! offset. A CodeView record is `RSDS` (a GUID, an age and the PDB's path,
//! UTF-8) or, from older linkers, `NB10` (an offset, a signature that is
//! a time stamp, an age and the path). The PDB's GUID and age match an
//! image to its symbols; the path shows where it was built.

use common::bytes::Reader;
use common::time::Ts;
use common::win::guid_to_string;

use crate::image::{directory, time_stamp, until_nul, Image};

const ENTRY_SIZE: usize = 28;
/// The most debug entries read.
const MAX_ENTRIES: usize = 256;
/// `IMAGE_DEBUG_TYPE_CODEVIEW`.
pub const CODEVIEW_TYPE: u32 = 2;
const RSDS: &[u8; 4] = b"RSDS";
const NB10: &[u8; 4] = b"NB10";
/// The longest PDB path read.
const MAX_PATH: usize = 4096;
/// Where the load configuration table keeps its time stamp (after its size).
const LOAD_CONFIG_TIME_AT: usize = 4;

/// A debug directory entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DebugEntry {
    /// `IMAGE_DEBUG_TYPE_*`: 2 CodeView, 12 Visual C++ features, 13 POGO,
    /// 14 iLTCG, 16 reproducible build, 20 extended DLL characteristics, …
    pub kind: u32,
    /// Its time stamp (the link time, or a hash in reproducible builds).
    pub timestamp: Option<Ts>,
    /// Its version: major, minor.
    pub version: (u16, u16),
    /// The size of its data.
    pub size: u32,
    /// The RVA of its data (0 when not loaded).
    pub rva: u32,
    /// The file offset of its data.
    pub file_offset: u32,
}

/// A CodeView record: the program database (PDB) the image was built with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CodeView {
    /// `RSDS` or `NB10`.
    pub format: String,
    /// The PDB's GUID (`RSDS`).
    pub guid: Option<String>,
    /// The PDB's signature (`NB10`: a time stamp, seconds since 1970).
    pub signature: Option<u32>,
    /// The PDB's age: how many times it was written.
    pub age: u32,
    /// The PDB's path as the linker wrote it.
    pub path: String,
}

/// The debug directory's entries.
pub(crate) fn entries(image: &Image<'_>, problems: &mut Vec<String>) -> Vec<DebugEntry> {
    let Some(table) = image.directory(directory::DEBUG) else {
        return Vec::new();
    };
    let declared = table.size as usize / ENTRY_SIZE;
    if declared > MAX_ENTRIES {
        problems.push(format!(
            "debug directory: {declared} entries, only {MAX_ENTRIES} read"
        ));
    }
    let wanted = declared.min(MAX_ENTRIES);
    let Some(bytes) = image.bytes_at(table.rva) else {
        problems.push(format!(
            "debug directory: RVA {:#x} not in the file",
            table.rva
        ));
        return Vec::new();
    };
    let mut reader = Reader::new(bytes);
    let entries: Vec<DebugEntry> = (0..wanted).map_while(|_| entry(&mut reader).ok()).collect();
    if entries.len() < wanted {
        problems.push(format!(
            "debug directory: {wanted} entries, {} in the file",
            entries.len()
        ));
    }
    entries
}

fn entry(reader: &mut Reader<'_>) -> Result<DebugEntry, common::bytes::Error> {
    reader.skip(4)?; // characteristics, reserved
    let timestamp = time_stamp(reader.u32_le()?);
    let version = (reader.u16_le()?, reader.u16_le()?);
    Ok(DebugEntry {
        timestamp,
        version,
        kind: reader.u32_le()?,
        size: reader.u32_le()?,
        rva: reader.u32_le()?,
        file_offset: reader.u32_le()?,
    })
}

/// The first CodeView record that reads.
pub(crate) fn codeview(
    image: &Image<'_>,
    entries: &[DebugEntry],
    problems: &mut Vec<String>,
) -> Option<CodeView> {
    let mut found = None;
    for entry in entries.iter().filter(|e| e.kind == CODEVIEW_TYPE) {
        let start = entry.file_offset as usize;
        let record = image
            .data
            .get(start..start.saturating_add(entry.size as usize))
            .or_else(|| image.at_rva(entry.rva, entry.size as usize));
        match record.and_then(codeview_record) {
            Some(record) => {
                found = Some(record);
                break;
            }
            None => problems.push(format!(
                "debug directory: CodeView record at {start:#x} unreadable"
            )),
        }
    }
    found
}

fn codeview_record(record: &[u8]) -> Option<CodeView> {
    let mut reader = Reader::new(record);
    let format = reader.array::<4>().ok()?;
    let (guid, signature) = if &format == RSDS {
        (Some(guid_to_string(&reader.array::<16>().ok()?)), None)
    } else if &format == NB10 {
        reader.skip(4).ok()?; // offset, always 0
        (None, Some(reader.u32_le().ok()?))
    } else {
        return None;
    };
    let age = reader.u32_le().ok()?;
    let rest = reader.bytes(reader.remaining()).ok()?;
    let path = until_nul(&rest[..rest.len().min(MAX_PATH)]);
    Some(CodeView {
        format: String::from_utf8_lossy(&format).into_owned(),
        guid,
        signature,
        age,
        path: String::from_utf8_lossy(path).into_owned(),
    })
}

/// The load configuration table's time stamp.
pub(crate) fn load_config_time(image: &Image<'_>, problems: &mut Vec<String>) -> Option<Ts> {
    let table = image.directory(directory::LOAD_CONFIG)?;
    let Some(bytes) = image.at_rva(table.rva, LOAD_CONFIG_TIME_AT + 4) else {
        problems.push(format!(
            "load configuration table: RVA {:#x} not in the file",
            table.rva
        ));
        return None;
    };
    let mut reader = Reader::new(bytes);
    reader.skip(LOAD_CONFIG_TIME_AT).ok()?;
    time_stamp(reader.u32_le().ok()?)
}
