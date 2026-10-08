"""Fills in what GNU ld leaves out of sample.dll, in place.

GNU ld 2.44 links a delay-load descriptor (dlltool --output-delaylib) and
`_load_config_used` but leaves their data directories empty, and windres
writes zero resource directory time stamps. This points the delay import
(13) and load configuration (10) directories at them, gives the resource
directories time stamps, and recomputes the checksum.

    python3 -I finish.py sample.dll <delay descriptor VA> <load config VA>
"""

import struct
import sys

DELAY_DESCRIPTOR_SIZE = 32
ROOT_RESOURCE_TIME = 1_550_000_000  # 2019-02-12T19:33:20Z
TYPE_RESOURCE_TIME = 1_650_000_000  # 2022-04-15T05:20:00Z, + the type's index


def main():
    path, delay_va, load_config_va = sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3], 16)
    data = bytearray(open(path, "rb").read())
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    optional = pe + 24
    if struct.unpack_from("<H", data, optional)[0] != 0x20B:
        raise SystemExit("not PE32+")
    image_base = struct.unpack_from("<Q", data, optional + 24)[0]
    directories = optional + 112

    def set_directory(index, rva, size):
        struct.pack_into("<II", data, directories + index * 8, rva, size)

    set_directory(13, delay_va - image_base, DELAY_DESCRIPTOR_SIZE)
    load_config_rva = load_config_va - image_base
    load_config_size = struct.unpack_from("<I", data, rva_to_offset(data, pe, load_config_rva))[0]
    set_directory(10, load_config_rva, load_config_size)

    resource_rva = struct.unpack_from("<I", data, directories + 2 * 8)[0]
    root = rva_to_offset(data, pe, resource_rva)
    struct.pack_into("<I", data, root + 4, ROOT_RESOURCE_TIME)
    named, ids = struct.unpack_from("<HH", data, root + 12)
    for index in range(named + ids):
        target = struct.unpack_from("<I", data, root + 16 + index * 8 + 4)[0]
        if target & 0x8000_0000:
            struct.pack_into("<I", data, root + (target & 0x7FFF_FFFF) + 4, TYPE_RESOURCE_TIME + index)

    struct.pack_into("<I", data, optional + 64, checksum(data, optional + 64))
    open(path, "wb").write(data)


def rva_to_offset(data, pe, rva):
    sections = struct.unpack_from("<H", data, pe + 6)[0]
    table = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]
    for index in range(sections):
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, table + index * 40 + 8
        )
        if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
            return rva - virtual_address + raw_offset
    raise SystemExit(f"RVA {rva:#x} is in no section")


def checksum(data, checksum_offset):
    """The image checksum: 16-bit one's-complement sum, plus the length."""
    total = 0
    padded = bytes(data) + b"\0" * (len(data) % 2)
    for offset in range(0, len(padded), 2):
        if checksum_offset <= offset < checksum_offset + 4:
            continue
        total += struct.unpack_from("<H", padded, offset)[0]
        total = (total & 0xFFFF) + (total >> 16)
    return (total & 0xFFFF) + len(data)


main()
