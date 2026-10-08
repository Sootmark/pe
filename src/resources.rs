//! The resource tree (data directory 2) and the version information in it.
//!
//! Resources are a three-level tree of directories: type (icon, version,
//! manifest, …), then name, then language. A directory is 16 bytes (flags,
//! a time stamp, a version, and how many named and numbered entries
//! follow), then its 8-byte entries: a number, or (top bit set) the offset
//! of a length-prefixed UTF-16 name; and the offset of a subdirectory (top
//! bit set) or of a 16-byte data entry (the data's RVA, size and code
//! page). Offsets count from the start of the tree.
//!
//! The version resource (type 16) is `VS_VERSIONINFO`: nested blocks, each
//! a length, a value length, a type, a UTF-16 key and a value, aligned to
//! 4 bytes. Its value is `VS_FIXEDFILEINFO` (binary file and product
//! versions); its children are `StringFileInfo` (one string table per
//! language and code page, `040904b0`, of `CompanyName`, `FileVersion`,
//! `OriginalFilename`, …) and `VarFileInfo` (the translations).

use std::collections::HashSet;

use common::bytes::Reader;
use common::text::{utf16le, utf16le_until_nul};
use common::time::Ts;

use crate::image::{directory, time_stamp, Image};

const DIRECTORY_SIZE: usize = 16;
const ENTRY_SIZE: usize = 8;
const DATA_ENTRY_SIZE: usize = 16;
/// Top bit of an entry's fields: a name (not a number), a subdirectory (not
/// data).
const HIGH_BIT: u32 = 0x8000_0000;
/// The most entries read from the whole tree.
const MAX_ENTRIES: usize = 65_536;
/// `RT_VERSION`.
pub const VERSION_TYPE: u32 = 16;
/// `VS_FIXEDFILEINFO`'s signature.
const FIXED_SIGNATURE: u32 = 0xfeef_04bd;
const FIXED_SIZE: usize = 52;
/// A version block's length, value length and type.
const BLOCK_HEADER_SIZE: usize = 6;
/// Version blocks with a text value count its length in UTF-16 units.
const TEXT_VALUE: u16 = 1;
const ALIGNMENT: usize = 4;

/// A resource type or name: a number or a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceId {
    /// A number (`16` is the version resource, `24` the manifest).
    Id(u32),
    /// A name (`WEVT_TEMPLATE`).
    Name(String),
}

/// The resource tree.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resources {
    /// The root directory's time stamp.
    pub timestamp: Option<Ts>,
    /// The types, in directory order.
    pub types: Vec<ResourceType>,
}

/// The resources of one type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceType {
    /// The type.
    pub id: ResourceId,
    /// Its directory's time stamp.
    pub timestamp: Option<Ts>,
    /// Its resources, one per name and language.
    pub resources: Vec<Resource>,
}

/// One resource: a name in a language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource {
    /// Its name.
    pub name: ResourceId,
    /// Its language identifier (`1033` is English, United States).
    pub language: u32,
    /// The RVA of its data.
    pub rva: u32,
    /// The size of its data.
    pub size: u32,
    /// The code page of its data.
    pub code_page: u32,
}

/// The version resource's contents.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VersionInfo {
    /// The binary versions and flags.
    pub fixed: Option<FixedFileInfo>,
    /// The string tables, one per language and code page.
    pub string_tables: Vec<StringTable>,
    /// The translations `VarFileInfo` lists: (language, code page).
    pub translations: Vec<(u16, u16)>,
}

impl VersionInfo {
    /// A string by key (`CompanyName`, `FileDescription`, `FileVersion`,
    /// `InternalName`, `OriginalFilename`, `ProductName`,
    /// `ProductVersion`, …), from the first table that has it.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.string_tables.iter().find_map(|table| table.get(key))
    }
}

/// `VS_FIXEDFILEINFO`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FixedFileInfo {
    /// The file version: major, minor, build, revision.
    pub file_version: [u16; 4],
    /// The product version.
    pub product_version: [u16; 4],
    /// Which `flags` are valid.
    pub flags_mask: u32,
    /// `VS_FF_*`: debug, pre-release, patched, private build, …
    pub flags: u32,
    /// `VOS_*`: the operating system it was made for.
    pub os: u32,
    /// `VFT_*`: 1 application, 2 DLL, 3 driver, …
    pub file_type: u32,
    /// The driver or font kind, for those.
    pub file_subtype: u32,
    /// The file date (two 32-bit halves), almost always 0.
    pub date: u64,
}

/// One `StringFileInfo` string table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StringTable {
    /// Its language and code page in hex (`040904b0`).
    pub key: String,
    /// Its strings, in order.
    pub strings: Vec<(String, String)>,
}

impl StringTable {
    /// A string by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.strings
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// The resource tree, when there is one.
pub(crate) fn read(image: &Image<'_>, problems: &mut Vec<String>) -> Option<Resources> {
    let table = image.directory(directory::RESOURCE)?;
    let Some(tree) = image.bytes_at(table.rva) else {
        problems.push(format!(
            "resource table: RVA {:#x} not in the file",
            table.rva
        ));
        return None;
    };
    let mut walker = Walker {
        tree,
        visited: HashSet::new(),
        entries: 0,
        problems,
    };
    let root = walker.directory(0)?;
    let types = root
        .entries
        .into_iter()
        .filter_map(|(id, target)| walker.resource_type(id, target))
        .collect();
    Some(Resources {
        timestamp: root.timestamp,
        types,
    })
}

/// Where an entry leads.
#[derive(Clone, Copy)]
enum Target {
    Directory(usize),
    Data(usize),
}

/// A directory's time stamp and entries.
struct Directory {
    timestamp: Option<Ts>,
    entries: Vec<(ResourceId, Target)>,
}

/// Walks the tree; every directory is read once, so a loop ends.
struct Walker<'a, 'p> {
    tree: &'a [u8],
    visited: HashSet<usize>,
    entries: usize,
    problems: &'p mut Vec<String>,
}

impl Walker<'_, '_> {
    fn resource_type(&mut self, id: ResourceId, target: Target) -> Option<ResourceType> {
        let Target::Directory(offset) = target else {
            self.problems
                .push(format!("resources: type {id:?} is data, not a directory"));
            return None;
        };
        let names = self.directory(offset)?;
        let mut resources = Vec::new();
        for (name, target) in names.entries {
            match target {
                Target::Data(offset) => resources.extend(self.data(name, 0, offset)),
                Target::Directory(offset) => {
                    let Some(languages) = self.directory(offset) else {
                        continue;
                    };
                    for (language, target) in languages.entries {
                        let ResourceId::Id(language) = language else {
                            self.problems
                                .push(format!("resources: language {language:?} is a name"));
                            continue;
                        };
                        match target {
                            Target::Data(offset) => {
                                resources.extend(self.data(name.clone(), language, offset));
                            }
                            Target::Directory(_) => self
                                .problems
                                .push("resources: deeper than three levels".to_owned()),
                        }
                    }
                }
            }
        }
        Some(ResourceType {
            id,
            timestamp: names.timestamp,
            resources,
        })
    }

    /// The directory at `offset`: its time stamp and entries.
    fn directory(&mut self, offset: usize) -> Option<Directory> {
        if !self.visited.insert(offset) {
            self.problems
                .push(format!("resources: directory at {offset:#x} reached twice"));
            return None;
        }
        let Some(header) = self.tree.get(offset..offset.saturating_add(DIRECTORY_SIZE)) else {
            self.problems.push(format!(
                "resources: directory at {offset:#x} not in the file"
            ));
            return None;
        };
        let mut reader = Reader::new(header);
        let (_, stamp, _, named, numbered) = (
            reader.u32_le().ok()?,
            reader.u32_le().ok()?,
            reader.u32_le().ok()?,
            reader.u16_le().ok()?,
            reader.u16_le().ok()?,
        );
        let count = usize::from(named) + usize::from(numbered);
        let mut entries = Vec::new();
        for index in 0..count {
            if self.entries == MAX_ENTRIES {
                self.problems
                    .push(format!("resources: only {MAX_ENTRIES} entries read"));
                break;
            }
            let at = offset + DIRECTORY_SIZE + index * ENTRY_SIZE;
            let Some(entry) = self.entry(at) else {
                self.problems
                    .push(format!("resources: directory at {offset:#x} truncated"));
                break;
            };
            self.entries += 1;
            entries.push(entry);
        }
        Some(Directory {
            timestamp: time_stamp(stamp),
            entries,
        })
    }

    fn entry(&mut self, at: usize) -> Option<(ResourceId, Target)> {
        let mut reader = Reader::new(self.tree.get(at..)?);
        let name = reader.u32_le().ok()?;
        let target = reader.u32_le().ok()?;
        let id = if name & HIGH_BIT == 0 {
            ResourceId::Id(name)
        } else {
            ResourceId::Name(self.name((name & !HIGH_BIT) as usize))
        };
        let offset = (target & !HIGH_BIT) as usize;
        let target = if target & HIGH_BIT == 0 {
            Target::Data(offset)
        } else {
            Target::Directory(offset)
        };
        Some((id, target))
    }

    /// A name: a 16-bit length, then that many UTF-16 units.
    fn name(&mut self, offset: usize) -> String {
        let mut reader = Reader::new(self.tree.get(offset..).unwrap_or_default());
        let text = reader
            .u16_le()
            .and_then(|units| reader.bytes(usize::from(units) * 2));
        if let Ok(text) = text {
            utf16le(text).text
        } else {
            self.problems
                .push(format!("resources: name at {offset:#x} not in the file"));
            String::new()
        }
    }

    fn data(&mut self, name: ResourceId, language: u32, offset: usize) -> Option<Resource> {
        let Some(entry) = self
            .tree
            .get(offset..offset.saturating_add(DATA_ENTRY_SIZE))
        else {
            self.problems.push(format!(
                "resources: data entry at {offset:#x} not in the file"
            ));
            return None;
        };
        let mut reader = Reader::new(entry);
        Some(Resource {
            name,
            language,
            rva: reader.u32_le().ok()?,
            size: reader.u32_le().ok()?,
            code_page: reader.u32_le().ok()?,
        })
    }
}

/// The first version resource's contents.
pub(crate) fn version_info(
    image: &Image<'_>,
    resources: &Resources,
    problems: &mut Vec<String>,
) -> Option<VersionInfo> {
    let resource = resources
        .types
        .iter()
        .filter(|t| t.id == ResourceId::Id(VERSION_TYPE))
        .find_map(|t| t.resources.first())?;
    let Some(data) = image.at_rva(resource.rva, resource.size as usize) else {
        problems.push(format!(
            "version resource: {} bytes at RVA {:#x} not in the file",
            resource.size, resource.rva
        ));
        return None;
    };
    let Some(root) = Block::read(data) else {
        problems.push("version resource: not a VS_VERSIONINFO block".to_owned());
        return None;
    };
    let mut info = VersionInfo {
        fixed: fixed_file_info(root.value),
        ..VersionInfo::default()
    };
    for child in root.children() {
        match child.key.as_str() {
            "StringFileInfo" => info
                .string_tables
                .extend(child.children().map(|table| string_table(&table))),
            "VarFileInfo" => info.translations.extend(
                child
                    .children()
                    .filter(|var| var.key == "Translation")
                    .flat_map(|var| translations(var.value)),
            ),
            _ => {}
        }
    }
    Some(info)
}

fn fixed_file_info(value: &[u8]) -> Option<FixedFileInfo> {
    let mut reader = Reader::new(value.get(..FIXED_SIZE)?);
    if reader.u32_le().ok()? != FIXED_SIGNATURE {
        return None;
    }
    reader.skip(4).ok()?; // the structure's version
    let mut version = || -> Option<[u16; 4]> {
        let (high, low) = (reader.u32_le().ok()?, reader.u32_le().ok()?);
        Some([
            (high >> 16) as u16,
            high as u16,
            (low >> 16) as u16,
            low as u16,
        ])
    };
    let file_version = version()?;
    let product_version = version()?;
    Some(FixedFileInfo {
        file_version,
        product_version,
        flags_mask: reader.u32_le().ok()?,
        flags: reader.u32_le().ok()?,
        os: reader.u32_le().ok()?,
        file_type: reader.u32_le().ok()?,
        file_subtype: reader.u32_le().ok()?,
        date: (u64::from(reader.u32_le().ok()?) << 32) | u64::from(reader.u32_le().ok()?),
    })
}

fn string_table(table: &Block<'_>) -> StringTable {
    StringTable {
        key: table.key.clone(),
        strings: table
            .children()
            .map(|string| (string.key, utf16le_until_nul(string.rest).text))
            .collect(),
    }
}

fn translations(value: &[u8]) -> Vec<(u16, u16)> {
    value
        .chunks_exact(4)
        .map(|pair| {
            (
                u16::from_le_bytes([pair[0], pair[1]]),
                u16::from_le_bytes([pair[2], pair[3]]),
            )
        })
        .collect()
}

/// A version information block.
struct Block<'a> {
    /// The block's length, children included.
    length: usize,
    key: String,
    /// The value, as long as the value length says.
    value: &'a [u8],
    /// Everything after the key: the value (whatever its stated length),
    /// then the children.
    rest: &'a [u8],
    /// The children.
    children: &'a [u8],
}

impl<'a> Block<'a> {
    /// The block at the start of `bytes`.
    fn read(bytes: &'a [u8]) -> Option<Self> {
        let mut reader = Reader::new(bytes);
        let length = usize::from(reader.u16_le().ok()?);
        let value_length = usize::from(reader.u16_le().ok()?);
        let value_type = reader.u16_le().ok()?;
        let block = bytes.get(..length)?;
        let key_bytes = block.get(BLOCK_HEADER_SIZE..)?;
        let key_end = key_bytes
            .chunks_exact(2)
            .position(|unit| unit == [0, 0])
            .map_or(key_bytes.len(), |units| units * 2);
        let key = utf16le(&key_bytes[..key_end]).text;
        let value_at = align(BLOCK_HEADER_SIZE + key_end + 2);
        let rest = block.get(value_at..).unwrap_or_default();
        let value_size = if value_type == TEXT_VALUE {
            value_length * 2
        } else {
            value_length
        };
        let value = rest.get(..value_size).unwrap_or(rest);
        let children = block
            .get(align(value_at + value.len())..)
            .unwrap_or_default();
        Some(Block {
            length,
            key,
            value,
            rest,
            children,
        })
    }

    /// The child blocks, each aligned to 4 bytes.
    fn children(&self) -> impl Iterator<Item = Block<'a>> {
        let mut remaining = self.children;
        std::iter::from_fn(move || {
            // A block shorter than its header fails to read, so this ends.
            let child = Block::read(remaining)?;
            remaining = remaining.get(align(child.length)..).unwrap_or_default();
            Some(child)
        })
    }
}

/// `offset` rounded up to the 4-byte alignment of version blocks.
fn align(offset: usize) -> usize {
    offset.div_ceil(ALIGNMENT) * ALIGNMENT
}
