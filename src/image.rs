//! The headers and the section table, and how an RVA (an address relative
//! to where the image is loaded) maps to a place in the file.
//!
//! An image starts with the MS-DOS header (`MZ`), whose `e_lfanew` at 0x3c
//! points to the `PE\0\0` signature. The 20-byte COFF file header follows
//! (machine, number of sections, time stamp, size of the optional header,
//! characteristics), then the optional header (PE32 or PE32+, with the data
//! directories at its end), then the section table, 40 bytes a section.

use common::bytes::Reader;
use common::time::Ts;

use crate::{error, Error};

/// `MZ`.
const DOS_SIGNATURE: &[u8; 2] = b"MZ";
/// Where the MS-DOS header keeps the offset of the PE signature.
const PE_OFFSET_AT: usize = 0x3c;
/// `PE\0\0`.
const PE_SIGNATURE: &[u8; 4] = b"PE\0\0";
const COFF_HEADER_SIZE: usize = 20;
const SECTION_HEADER_SIZE: usize = 40;
const SECTION_NAME_SIZE: usize = 8;
/// A COFF symbol table entry, after which the string table starts.
const SYMBOL_SIZE: usize = 18;
/// The longest section name read from the string table.
const MAX_LONG_NAME: usize = 256;
/// The most sections the format allows (`NumberOfSections` is 16-bit, and
/// Windows loads at most 96).
const MAX_SECTIONS: usize = 96;
/// The data directories the format defines.
const MAX_DATA_DIRECTORIES: usize = 16;
/// Optional header magic of a PE32 image.
pub const PE32_MAGIC: u16 = 0x10b;
/// Optional header magic of a PE32+ (64-bit) image.
pub const PE32_PLUS_MAGIC: u16 = 0x20b;
/// Where the data directories start in a PE32 optional header.
const PE32_DIRECTORIES_AT: usize = 96;
/// Where the data directories start in a PE32+ optional header.
const PE32_PLUS_DIRECTORIES_AT: usize = 112;

/// The data directories, by index.
pub mod directory {
    /// The export table.
    pub const EXPORT: usize = 0;
    /// The import table.
    pub const IMPORT: usize = 1;
    /// The resource table.
    pub const RESOURCE: usize = 2;
    /// The debug directory.
    pub const DEBUG: usize = 6;
    /// The load configuration table.
    pub const LOAD_CONFIG: usize = 10;
    /// The delay-load import table.
    pub const DELAY_IMPORT: usize = 13;
}

/// The COFF file header.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileHeader {
    /// The target machine (`IMAGE_FILE_MACHINE_*`: 0x14c i386, 0x8664
    /// AMD64, 0xaa64 ARM64, …; see [`crate::machine_name`]).
    pub machine: u16,
    /// How many sections the section table says there are.
    pub number_of_sections: u16,
    /// `TimeDateStamp`: seconds since 1970, when the linker made the file
    /// (or, in reproducible builds, a hash of it).
    pub time_date_stamp: u32,
    /// Offset of the COFF symbol table, usually 0 in images.
    pub pointer_to_symbol_table: u32,
    /// Its number of entries.
    pub number_of_symbols: u32,
    /// Size of the optional header.
    pub size_of_optional_header: u16,
    /// `IMAGE_FILE_*` flags (see [`crate::characteristics`]).
    pub characteristics: u16,
}

/// Where a data directory is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DataDirectory {
    /// Its RVA (for the certificate table, a file offset).
    pub rva: u32,
    /// Its size in bytes.
    pub size: u32,
}

/// The optional header (PE32 or PE32+), which images always have.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OptionalHeader {
    /// [`PE32_MAGIC`] or [`PE32_PLUS_MAGIC`].
    pub magic: u16,
    /// The linker's major and minor version.
    pub linker_version: (u8, u8),
    /// Size of the code sections.
    pub size_of_code: u32,
    /// Size of the initialized data sections.
    pub size_of_initialized_data: u32,
    /// Size of the uninitialized data sections.
    pub size_of_uninitialized_data: u32,
    /// RVA of the entry point (0 when there is none, as in many DLLs).
    pub entry_point: u32,
    /// RVA of the start of the code.
    pub base_of_code: u32,
    /// The preferred load address.
    pub image_base: u64,
    /// Alignment of sections in memory.
    pub section_alignment: u32,
    /// Alignment of section data in the file.
    pub file_alignment: u32,
    /// The required operating system version.
    pub os_version: (u16, u16),
    /// The image's own version.
    pub image_version: (u16, u16),
    /// The required subsystem version.
    pub subsystem_version: (u16, u16),
    /// Size of the image in memory.
    pub size_of_image: u32,
    /// Size of the headers in the file.
    pub size_of_headers: u32,
    /// The image checksum (0 in most user-mode files; drivers must have
    /// one).
    pub checksum: u32,
    /// `IMAGE_SUBSYSTEM_*`: 1 native, 2 Windows GUI, 3 Windows console, …
    /// (see [`crate::subsystem_name`]).
    pub subsystem: u16,
    /// `IMAGE_DLLCHARACTERISTICS_*` flags.
    pub dll_characteristics: u16,
    /// The data directories, as many as `NumberOfRvaAndSizes` says and the
    /// header holds (at most 16).
    pub data_directories: Vec<DataDirectory>,
}

impl OptionalHeader {
    /// Whether it is PE32+ (64-bit).
    #[must_use]
    pub fn is_pe32_plus(&self) -> bool {
        self.magic == PE32_PLUS_MAGIC
    }

    /// A data directory, when present and not empty.
    #[must_use]
    pub fn directory(&self, index: usize) -> Option<DataDirectory> {
        self.data_directories
            .get(index)
            .copied()
            .filter(|d| d.rva != 0 && d.size != 0)
    }
}

/// A section header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Section {
    /// The name as stored: 8 bytes, NUL-padded.
    pub raw_name: [u8; SECTION_NAME_SIZE],
    /// The name: up to the first NUL, or the long name a `/123` refers to
    /// in the COFF string table.
    pub name: String,
    /// Its size in memory.
    pub virtual_size: u32,
    /// Its RVA.
    pub virtual_address: u32,
    /// Size of its data in the file.
    pub raw_size: u32,
    /// Offset of its data in the file.
    pub raw_offset: u32,
    /// `IMAGE_SCN_*` flags (`0x20` code, `0x2000_0000` executable,
    /// `0x4000_0000` readable, `0x8000_0000` writable, …).
    pub characteristics: u32,
}

/// The headers read, and the file they map into.
pub(crate) struct Image<'a> {
    pub data: &'a [u8],
    pub file_header: FileHeader,
    pub optional: Option<OptionalHeader>,
    pub sections: Vec<Section>,
}

/// Whether `data` starts like a PE image: `MZ`, and `PE\0\0` where
/// `e_lfanew` points.
pub(crate) fn has_signatures(data: &[u8]) -> bool {
    pe_offset(data).is_ok()
}

/// The offset of `PE\0\0`.
fn pe_offset(data: &[u8]) -> Result<usize, Error> {
    if !data.starts_with(DOS_SIGNATURE) {
        return Err(error(0, "no MZ signature"));
    }
    let mut reader = Reader::new(data);
    reader
        .seek(PE_OFFSET_AT)
        .map_err(|_| error(PE_OFFSET_AT, "MS-DOS header truncated"))?;
    let offset = reader
        .u32_le()
        .map_err(|_| error(PE_OFFSET_AT, "MS-DOS header truncated"))? as usize;
    match data
        .get(offset..)
        .map(|rest| rest.starts_with(PE_SIGNATURE))
    {
        Some(true) => Ok(offset),
        _ => Err(error(offset, "no PE signature where e_lfanew points")),
    }
}

impl<'a> Image<'a> {
    /// Read the headers and the section table.
    pub fn read(data: &'a [u8], problems: &mut Vec<String>) -> Result<Self, Error> {
        let signature_at = pe_offset(data)?;
        let file_header_at = signature_at + PE_SIGNATURE.len();
        let mut reader = Reader::new(data);
        reader
            .seek(file_header_at)
            .map_err(|_| error(file_header_at, "COFF file header truncated"))?;
        let file_header = file_header(&mut reader)
            .map_err(|_| error(file_header_at, "COFF file header truncated"))?;
        let optional_at = file_header_at + COFF_HEADER_SIZE;
        let optional_size = usize::from(file_header.size_of_optional_header);
        let optional = data
            .get(optional_at..)
            .map(|rest| &rest[..optional_size.min(rest.len())])
            .and_then(|bytes| optional_header(bytes, problems));
        let mut image = Image {
            data,
            file_header,
            optional,
            sections: Vec::new(),
        };
        image.sections = image.section_table(optional_at + optional_size, problems);
        Ok(image)
    }

    fn section_table(&self, at: usize, problems: &mut Vec<String>) -> Vec<Section> {
        let declared = usize::from(self.file_header.number_of_sections);
        if declared > MAX_SECTIONS {
            problems.push(format!(
                "section table: {declared} sections, only {MAX_SECTIONS} read"
            ));
        }
        let mut sections = Vec::new();
        for index in 0..declared.min(MAX_SECTIONS) {
            let header = at
                .checked_add(index * SECTION_HEADER_SIZE)
                .and_then(|start| {
                    self.data
                        .get(start..start.checked_add(SECTION_HEADER_SIZE)?)
                });
            let Some(header) = header else {
                problems.push(format!(
                    "section table: truncated after {index} of {declared} sections"
                ));
                break;
            };
            if let Ok(section) = self.section(header) {
                sections.push(section);
            }
        }
        sections
    }

    fn section(&self, header: &[u8]) -> Result<Section, common::bytes::Error> {
        let mut reader = Reader::new(header);
        let raw_name = reader.array::<SECTION_NAME_SIZE>()?;
        let virtual_size = reader.u32_le()?;
        let virtual_address = reader.u32_le()?;
        let raw_size = reader.u32_le()?;
        let raw_offset = reader.u32_le()?;
        reader.skip(12)?; // relocations, line numbers and their counts
        let characteristics = reader.u32_le()?;
        Ok(Section {
            name: self.section_name(raw_name),
            raw_name,
            virtual_size,
            virtual_address,
            raw_size,
            raw_offset,
            characteristics,
        })
    }

    /// The name up to its first NUL, or the long name `/123` points to in
    /// the COFF string table (which images built by MinGW keep).
    fn section_name(&self, raw: [u8; SECTION_NAME_SIZE]) -> String {
        let short = until_nul(&raw);
        let long = short
            .strip_prefix(b"/")
            .and_then(|digits| std::str::from_utf8(digits).ok())
            .and_then(|digits| digits.parse::<usize>().ok())
            .and_then(|offset| self.string_table_entry(offset));
        long.unwrap_or_else(|| String::from_utf8_lossy(short).into_owned())
    }

    fn string_table_entry(&self, offset: usize) -> Option<String> {
        let symbols = usize::try_from(self.file_header.number_of_symbols).ok()?;
        if self.file_header.pointer_to_symbol_table == 0 {
            return None;
        }
        let table = (self.file_header.pointer_to_symbol_table as usize)
            .checked_add(symbols.checked_mul(SYMBOL_SIZE)?)?;
        let bytes = self.data.get(table.checked_add(offset)?..)?;
        let bytes = &bytes[..bytes.len().min(MAX_LONG_NAME)];
        Some(String::from_utf8_lossy(until_nul(bytes)).into_owned())
    }

    /// The file bytes from `rva` to the end of what the file holds of its
    /// section (or of the headers).
    pub fn bytes_at(&self, rva: u32) -> Option<&'a [u8]> {
        let (offset, available) = self.locate(rva)?;
        let end = offset.checked_add(available)?.min(self.data.len());
        self.data.get(offset..end)
    }

    /// `length` file bytes at `rva`, when the file holds them all.
    pub fn at_rva(&self, rva: u32, length: usize) -> Option<&'a [u8]> {
        self.bytes_at(rva)?.get(..length)
    }

    /// A NUL-terminated string at `rva` of at most `max` bytes, decoded as
    /// UTF-8 (invalid bytes replaced); `None` when it isn't in the file.
    pub fn string_at(&self, rva: u32, max: usize) -> Option<String> {
        let bytes = self.bytes_at(rva)?;
        let bytes = &bytes[..bytes.len().min(max)];
        Some(String::from_utf8_lossy(until_nul(bytes)).into_owned())
    }

    /// The file offset of `rva` and how many bytes of its section follow:
    /// the section it falls in maps it; outside every section, an RVA
    /// below `SizeOfHeaders` is in the headers, where RVA and offset are
    /// equal.
    pub fn locate(&self, rva: u32) -> Option<(usize, usize)> {
        for section in &self.sections {
            let span = if section.virtual_size == 0 {
                section.raw_size
            } else {
                section.virtual_size
            };
            let Some(into) = rva.checked_sub(section.virtual_address) else {
                continue;
            };
            if into < span {
                // Past its raw data, a section is zeros the file doesn't hold.
                let available = section.raw_size.checked_sub(into)?;
                let offset = section.raw_offset.checked_add(into)?;
                return Some((offset as usize, available as usize));
            }
        }
        let headers = self.optional.as_ref().map_or(0, |o| o.size_of_headers);
        (rva < headers).then(|| (rva as usize, (headers - rva) as usize))
    }

    /// Whether the image is PE32+.
    pub fn is_pe32_plus(&self) -> bool {
        self.optional
            .as_ref()
            .is_some_and(OptionalHeader::is_pe32_plus)
    }

    /// The image base, 0 without an optional header.
    pub fn image_base(&self) -> u64 {
        self.optional.as_ref().map_or(0, |o| o.image_base)
    }

    /// A data directory, when present and not empty.
    pub fn directory(&self, index: usize) -> Option<DataDirectory> {
        self.optional.as_ref()?.directory(index)
    }
}

fn file_header(reader: &mut Reader<'_>) -> Result<FileHeader, common::bytes::Error> {
    Ok(FileHeader {
        machine: reader.u16_le()?,
        number_of_sections: reader.u16_le()?,
        time_date_stamp: reader.u32_le()?,
        pointer_to_symbol_table: reader.u32_le()?,
        number_of_symbols: reader.u32_le()?,
        size_of_optional_header: reader.u16_le()?,
        characteristics: reader.u16_le()?,
    })
}

/// The optional header in `bytes` (`SizeOfOptionalHeader` long), or a
/// problem when it is missing, truncated or of an unknown kind.
fn optional_header(bytes: &[u8], problems: &mut Vec<String>) -> Option<OptionalHeader> {
    let mut reader = Reader::new(bytes);
    let Ok(magic) = reader.u16_le() else {
        problems.push("optional header: missing".to_owned());
        return None;
    };
    if magic != PE32_MAGIC && magic != PE32_PLUS_MAGIC {
        problems.push(format!("optional header: unknown magic {magic:#x}"));
        return None;
    }
    let Ok(mut header) = optional_fields(&mut reader, magic) else {
        problems.push("optional header: truncated".to_owned());
        return None;
    };
    let directories_at = if magic == PE32_PLUS_MAGIC {
        PE32_PLUS_DIRECTORIES_AT
    } else {
        PE32_DIRECTORIES_AT
    };
    header.data_directories = data_directories(bytes, directories_at, problems);
    Some(header)
}

fn optional_fields(
    reader: &mut Reader<'_>,
    magic: u16,
) -> Result<OptionalHeader, common::bytes::Error> {
    let pe32_plus = magic == PE32_PLUS_MAGIC;
    let linker_version = (reader.u8()?, reader.u8()?);
    let size_of_code = reader.u32_le()?;
    let size_of_initialized_data = reader.u32_le()?;
    let size_of_uninitialized_data = reader.u32_le()?;
    let entry_point = reader.u32_le()?;
    let base_of_code = reader.u32_le()?;
    let image_base = if pe32_plus {
        reader.u64_le()?
    } else {
        reader.skip(4)?; // BaseOfData, PE32 only
        u64::from(reader.u32_le()?)
    };
    let section_alignment = reader.u32_le()?;
    let file_alignment = reader.u32_le()?;
    let os_version = (reader.u16_le()?, reader.u16_le()?);
    let image_version = (reader.u16_le()?, reader.u16_le()?);
    let subsystem_version = (reader.u16_le()?, reader.u16_le()?);
    reader.skip(4)?; // Win32VersionValue, reserved
    let size_of_image = reader.u32_le()?;
    let size_of_headers = reader.u32_le()?;
    let checksum = reader.u32_le()?;
    let subsystem = reader.u16_le()?;
    let dll_characteristics = reader.u16_le()?;
    Ok(OptionalHeader {
        magic,
        linker_version,
        size_of_code,
        size_of_initialized_data,
        size_of_uninitialized_data,
        entry_point,
        base_of_code,
        image_base,
        section_alignment,
        file_alignment,
        os_version,
        image_version,
        subsystem_version,
        size_of_image,
        size_of_headers,
        checksum,
        subsystem,
        dll_characteristics,
        data_directories: Vec::new(),
    })
}

/// The data directories: `NumberOfRvaAndSizes` (just before them) of
/// them, bounded by 16 and by the header's size.
fn data_directories(bytes: &[u8], at: usize, problems: &mut Vec<String>) -> Vec<DataDirectory> {
    let mut reader = Reader::new(bytes);
    let count_at = at - 4;
    let Ok(declared) = reader.seek(count_at).and_then(|()| reader.u32_le()) else {
        problems.push("optional header: no data directories".to_owned());
        return Vec::new();
    };
    let declared = declared as usize;
    if declared > MAX_DATA_DIRECTORIES {
        problems.push(format!(
            "optional header: {declared} data directories, only {MAX_DATA_DIRECTORIES} read"
        ));
    }
    let mut directories = Vec::new();
    for _ in 0..declared.min(MAX_DATA_DIRECTORIES) {
        if let (Ok(rva), Ok(size)) = (reader.u32_le(), reader.u32_le()) {
            directories.push(DataDirectory { rva, size });
        } else {
            problems.push(format!(
                "optional header: {declared} data directories, {} fit",
                directories.len()
            ));
            break;
        }
    }
    directories
}

/// `bytes` up to the first NUL.
pub(crate) fn until_nul(bytes: &[u8]) -> &[u8] {
    bytes
        .iter()
        .position(|&b| b == 0)
        .map_or(bytes, |end| &bytes[..end])
}

/// A `TimeDateStamp` (seconds since 1970) as a time; `None` when 0.
pub(crate) fn time_stamp(value: u32) -> Option<Ts> {
    (value != 0).then(|| Ts::from_unix_seconds(i64::from(value)))
}
