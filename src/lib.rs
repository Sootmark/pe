//! Windows Portable Executable (PE) files (`.exe`, `.dll`, `.sys`, …):
//! what an executable says about itself, read from Microsoft's "PE Format"
//! specification. When it was linked, what kind of file it is, what it
//! imports and exports, its import hash, the version information its
//! publisher wrote, the program database (PDB) path its linker left, and the
//! time stamps in its resource, debug, export, import and load
//! configuration tables.
//!
//! The file starts with an MS-DOS header (`MZ`) whose `e_lfanew` points to
//! `PE\0\0`, followed by the COFF file header (machine, sections, time
//! stamp, characteristics), the optional header (PE32 or PE32+: linker
//! version, entry point, image base, versions, subsystem, checksum, and the
//! data directories) and the section table. The data directories locate
//! the tables, by RVA: an address once loaded, which the section table maps
//! back to the file ([`image`]). Then [`imports`], [`exports`],
//! [`resources`] and [`debug`] read the tables.
//!
//! Every table is optional and read on its own: a damaged one goes to
//! [`Pe::problems`] and the others are still read. Only a file that isn't
//! a PE image (no `MZ`, no `PE\0\0`, no COFF header) is an error.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let pe = pe::read(&std::fs::read("sample.dll")?)?;
//! println!("{} linked {:?}, imphash {:?}", pe.kind.label(), pe.compiled, pe.imphash);
//! for import in &pe.imports {
//!     println!("{} ({} functions)", import.dll, import.functions.len());
//! }
//! if let Some(info) = &pe.version_info {
//!     println!("{:?} {:?}", info.get("CompanyName"), info.get("OriginalFilename"));
//! }
//! # Ok(())
//! # }
//! ```

pub mod debug;
pub mod exports;
pub mod image;
pub mod imports;
pub mod resources;

use core::fmt;

use common::time::Ts;

pub use debug::{CodeView, DebugEntry};
pub use exports::{Export, Exports};
pub use image::{DataDirectory, FileHeader, OptionalHeader, Section};
pub use imports::{imphash, Import, Symbol};
pub use resources::{
    FixedFileInfo, Resource, ResourceId, ResourceType, Resources, StringTable, VersionInfo,
};

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The COFF header's `IMAGE_FILE_*` characteristics.
pub mod characteristics {
    /// Relocations were removed: the image must load at its base.
    pub const RELOCS_STRIPPED: u16 = 0x0001;
    /// The image is valid and can be run.
    pub const EXECUTABLE_IMAGE: u16 = 0x0002;
    /// It can handle addresses above 2 GB.
    pub const LARGE_ADDRESS_AWARE: u16 = 0x0020;
    /// A 32-bit machine.
    pub const MACHINE_32BIT: u16 = 0x0100;
    /// Debug information was removed.
    pub const DEBUG_STRIPPED: u16 = 0x0200;
    /// A system file, not a user program.
    pub const SYSTEM: u16 = 0x1000;
    /// A dynamic-link library.
    pub const DLL: u16 = 0x2000;
}

/// `IMAGE_SUBSYSTEM_NATIVE`: drivers and native processes.
const SUBSYSTEM_NATIVE: u16 = 1;
/// `IMAGE_SUBSYSTEM_NATIVE_WINDOWS`.
const SUBSYSTEM_NATIVE_WINDOWS: u16 = 8;
/// Kernel components whose import makes an image a driver, as pefile
/// (and so plaso) decides.
const KERNEL_COMPONENTS: [&str; 5] = [
    "ntoskrnl.exe",
    "hal.dll",
    "ndis.sys",
    "bootvid.dll",
    "kdcom.dll",
];
/// Pageable kernel code section names that, under the native subsystem,
/// make an image a driver.
const DRIVER_SECTIONS: [&str; 2] = ["page", "paged"];

/// Why a file couldn't be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// Byte offset where it went wrong.
    pub offset: usize,
    /// What went wrong.
    pub reason: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (at byte {})", self.reason, self.offset)
    }
}

impl std::error::Error for Error {}

fn error(offset: usize, reason: impl Into<String>) -> Error {
    Error {
        offset,
        reason: reason.into(),
    }
}

/// What kind of image it is, as plaso (through pefile) tells them apart.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Kind {
    /// A program: executable, not a DLL, not a driver.
    Executable,
    /// A dynamic-link library (the DLL flag).
    Dll,
    /// A driver: it imports a kernel component (`ntoskrnl.exe`, `hal.dll`,
    /// `ndis.sys`, `bootvid.dll`, `kdcom.dll`), or has a `PAGE` section
    /// under the native subsystem.
    Driver,
    /// None of these.
    #[default]
    Unknown,
}

impl Kind {
    /// plaso's name for it: `Executable (EXE)`, `Dynamic Link Library
    /// (DLL)`, `Driver (SYS)`, `Unknown PE type`.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Kind::Executable => "Executable (EXE)",
            Kind::Dll => "Dynamic Link Library (DLL)",
            Kind::Driver => "Driver (SYS)",
            Kind::Unknown => "Unknown PE type",
        }
    }
}

/// A PE image's metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pe {
    /// What kind of image it is.
    pub kind: Kind,
    /// The COFF file header.
    pub file_header: FileHeader,
    /// When it was linked: the COFF header's time stamp (in reproducible
    /// builds, a hash that looks like a time).
    pub compiled: Option<Ts>,
    /// The optional header; `None` (with a problem) when missing or of an
    /// unknown kind, and then no table is read.
    pub optional: Option<OptionalHeader>,
    /// The sections, in table order.
    pub sections: Vec<Section>,
    /// The DLLs it imports from: the regular imports, then the
    /// delay-loaded ones.
    pub imports: Vec<Import>,
    /// The import hash (see [`imphash`]).
    pub imphash: Option<String>,
    /// What it exports.
    pub exports: Option<Exports>,
    /// Its resources.
    pub resources: Option<Resources>,
    /// Its version resource.
    pub version_info: Option<VersionInfo>,
    /// Its debug directory.
    pub debug: Vec<DebugEntry>,
    /// The program database it was built with.
    pub codeview: Option<CodeView>,
    /// The load configuration table's time stamp.
    pub load_config_time: Option<Ts>,
    /// Damage met.
    pub problems: Vec<String>,
}

/// Whether `data` is a PE image: `MZ`, and `PE\0\0` where `e_lfanew`
/// points.
#[must_use]
pub fn detect(data: &[u8]) -> bool {
    image::has_signatures(data)
}

/// Read a PE image.
///
/// # Errors
/// When it isn't one: no `MZ`, no `PE\0\0` where `e_lfanew` points, or a
/// truncated COFF file header.
pub fn read(data: &[u8]) -> Result<Pe, Error> {
    let mut problems = Vec::new();
    let image = image::Image::read(data, &mut problems)?;
    let imports = imports::read(&image, &mut problems);
    let resources = resources::read(&image, &mut problems);
    let version_info = resources
        .as_ref()
        .and_then(|r| resources::version_info(&image, r, &mut problems));
    let debug = debug::entries(&image, &mut problems);
    let mut pe = Pe {
        kind: Kind::Unknown,
        file_header: image.file_header,
        compiled: image::time_stamp(image.file_header.time_date_stamp),
        imphash: imphash(&imports),
        exports: exports::read(&image, &mut problems),
        codeview: debug::codeview(&image, &debug, &mut problems),
        load_config_time: debug::load_config_time(&image, &mut problems),
        imports,
        resources,
        version_info,
        debug,
        optional: image.optional,
        sections: image.sections,
        problems,
    };
    pe.kind = kind(&pe);
    Ok(pe)
}

/// The kind, in pefile's order: the DLL flag, then a driver's signs, then
/// the executable flag.
fn kind(pe: &Pe) -> Kind {
    let flags = pe.file_header.characteristics;
    if flags & characteristics::DLL != 0 {
        Kind::Dll
    } else if is_driver(pe) {
        Kind::Driver
    } else if flags & characteristics::EXECUTABLE_IMAGE != 0 {
        Kind::Executable
    } else {
        Kind::Unknown
    }
}

fn is_driver(pe: &Pe) -> bool {
    let imports_kernel = pe
        .imports
        .iter()
        .filter(|i| !i.delayed)
        .any(|i| KERNEL_COMPONENTS.contains(&i.dll.to_lowercase().as_str()));
    let native = pe.optional.as_ref().is_some_and(|o| {
        o.subsystem == SUBSYSTEM_NATIVE || o.subsystem == SUBSYSTEM_NATIVE_WINDOWS
    });
    let pageable = pe.sections.iter().any(|s| {
        let name = String::from_utf8_lossy(image::until_nul(&s.raw_name)).to_lowercase();
        DRIVER_SECTIONS.contains(&name.as_str())
    });
    imports_kernel || (native && pageable)
}

/// The name of a machine type (`IMAGE_FILE_MACHINE_*`), for the common ones.
#[must_use]
pub fn machine_name(machine: u16) -> Option<&'static str> {
    Some(match machine {
        0x014c => "i386",
        0x0166 => "R4000",
        0x01c0 => "ARM",
        0x01c4 => "ARMv7 Thumb-2",
        0x0200 => "IA-64",
        0x8664 => "AMD64",
        0xa641 => "ARM64EC",
        0xa64e => "ARM64X",
        0xaa64 => "ARM64",
        _ => return None,
    })
}

/// The name of a subsystem (`IMAGE_SUBSYSTEM_*`).
#[must_use]
pub fn subsystem_name(subsystem: u16) -> Option<&'static str> {
    Some(match subsystem {
        1 => "Native",
        2 => "Windows GUI",
        3 => "Windows console",
        5 => "OS/2 console",
        7 => "POSIX console",
        8 => "Native Windows 9x driver",
        9 => "Windows CE GUI",
        10 => "EFI application",
        11 => "EFI boot service driver",
        12 => "EFI runtime driver",
        13 => "EFI ROM",
        14 => "Xbox",
        16 => "Windows boot application",
        _ => return None,
    })
}
