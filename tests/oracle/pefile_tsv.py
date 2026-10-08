"""What pefile reads from each PE file, as TSV, sorted: an independent
reader to check this crate's headers, sections, imports, exports, debug
directory, CodeView record, resources, version information, load
configuration time stamp and import hash against.

    python3 -P pefile_tsv.py test_pe.exe test_driver.sys \
        wrc-test-wevt_template.dll sample.dll > pefile.tsv

Run with pefile 2024.8.26. Each line starts with the file name and a
record kind; times are seconds since 1970 (0 when not set).
"""

import os
import sys

import pefile


def text(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8", "backslashreplace")
    return str(value).replace("\0", "\\0")


def records(pe):
    header, optional = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    yield ["header", header.Machine, header.TimeDateStamp, header.Characteristics,
           optional.Magic, f"{optional.MajorLinkerVersion}.{optional.MinorLinkerVersion}",
           optional.AddressOfEntryPoint, optional.ImageBase, optional.Subsystem,
           f"{optional.MajorOperatingSystemVersion}.{optional.MinorOperatingSystemVersion}",
           f"{optional.MajorSubsystemVersion}.{optional.MinorSubsystemVersion}",
           optional.SizeOfImage, optional.CheckSum, optional.DllCharacteristics,
           optional.NumberOfRvaAndSizes]
    for index, section in enumerate(pe.sections):
        yield ["section", index, text(section.Name), section.VirtualAddress,
               section.Misc_VirtualSize, section.PointerToRawData,
               section.SizeOfRawData, section.Characteristics]
    yield ["imphash", pe.get_imphash()]
    imports = [(entry, "false", entry.struct.TimeDateStamp)
               for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])]
    imports += [(entry, "true", entry.struct.dwTimeStamp)
                for entry in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", [])]
    for entry, delayed, stamp in imports:
        for index, function in enumerate(entry.imports):
            symbol = (f"{text(function.name)}@{function.hint}" if function.name
                      else f"#{function.ordinal}")
            yield ["import", text(entry.dll), delayed, stamp, index, symbol]
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        exports = pe.DIRECTORY_ENTRY_EXPORT
        yield ["exports", text(exports.name), exports.struct.TimeDateStamp,
               exports.struct.Base]
        for symbol in exports.symbols:
            yield ["export", symbol.ordinal, text(symbol.name or ""), symbol.address,
                   text(symbol.forwarder or "")]
    for index, entry in enumerate(getattr(pe, "DIRECTORY_ENTRY_DEBUG", [])):
        debug = entry.struct
        yield ["debug", index, debug.Type, debug.TimeDateStamp, debug.SizeOfData,
               debug.AddressOfRawData, debug.PointerToRawData]
        if entry.entry is not None and hasattr(entry.entry, "CvSignature"):
            record = entry.entry
            if record.CvSignature == b"RSDS":
                guid = (f"{record.Signature_Data1:08x}-{record.Signature_Data2:04x}-"
                        f"{record.Signature_Data3:04x}-{record.Signature_Data4:02x}"
                        f"{record.Signature_Data5:02x}-{record.Signature_Data6.hex()}")
                yield ["codeview", "RSDS", guid, record.Age,
                       text(record.PdbFileName.rstrip(b"\0"))]
            elif record.CvSignature == b"NB10":
                yield ["codeview", "NB10", record.Signature, record.Age,
                       text(record.PdbFileName.rstrip(b"\0"))]
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        root = pe.DIRECTORY_ENTRY_RESOURCE
        yield ["resource-root", root.struct.TimeDateStamp]
        for kind in root.entries:
            kind_id = text(kind.name) if kind.name is not None else kind.id
            yield ["resource-type", kind_id, kind.directory.struct.TimeDateStamp]
            for name in kind.directory.entries:
                name_id = text(name.name) if name.name is not None else name.id
                for language in name.directory.entries:
                    data = language.data.struct
                    yield ["resource", kind_id, name_id, language.id, data.OffsetToData,
                           data.Size, data.CodePage]
    for fixed in getattr(pe, "VS_FIXEDFILEINFO", []):
        yield ["version-fixed", version(fixed.FileVersionMS, fixed.FileVersionLS),
               version(fixed.ProductVersionMS, fixed.ProductVersionLS),
               fixed.FileFlagsMask, fixed.FileFlags, fixed.FileOS, fixed.FileType,
               fixed.FileSubtype]
    for info in getattr(pe, "FileInfo", []):
        for block in info:
            for table in getattr(block, "StringTable", []):
                for key, value in table.entries.items():
                    yield ["version-string", text(table.LangID), text(key), text(value)]
            for var in getattr(block, "Var", []):
                for key, value in var.entry.items():
                    yield ["version-var", text(key), text(value)]
    if hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG"):
        yield ["load-config", pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.TimeDateStamp]


def version(high, low):
    return f"{high >> 16}.{high & 0xFFFF}.{low >> 16}.{low & 0xFFFF}"


lines = []
for path in sys.argv[1:]:
    name = os.path.basename(path)
    lines.extend("\t".join([name] + [str(c) for c in record])
                 for record in records(pefile.PE(path)))
for line in sorted(lines):
    print(line)
