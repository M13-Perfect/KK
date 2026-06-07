#!/usr/bin/env python3
"""Small static PE reporter for the recovered Windows executable.

This script intentionally avoids executing the target binary.  It parses the
Portable Executable header directly and prints the facts that are most useful
when deciding whether static source recovery is possible: architecture, entry
point, section layout, entropy, imports, and checksum.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import math
import struct
from pathlib import Path


def _cstring(data: bytes, offset: int) -> str:
    end = data.find(b"\0", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("ascii", "replace")


def _entropy(blob: bytes) -> float:
    if not blob:
        return 0.0
    counts = [0] * 256
    for byte in blob:
        counts[byte] += 1
    total = len(blob)
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def _rva_to_offset(rva: int, sections: list[dict[str, int | str]]) -> int | None:
    for section in sections:
        start = int(section["virtual_address"])
        size = max(int(section["virtual_size"]), int(section["raw_size"]))
        if start <= rva < start + size:
            raw_size = int(section["raw_size"])
            raw_pointer = int(section["raw_pointer"])
            delta = rva - start
            if delta >= raw_size:
                return None
            return raw_pointer + delta
    return None


def _parse_imports(data: bytes, import_rva: int, sections: list[dict[str, int | str]], is_pe32_plus: bool) -> list[dict[str, object]]:
    imports: list[dict[str, object]] = []
    descriptor_offset = _rva_to_offset(import_rva, sections)
    if not import_rva or descriptor_offset is None:
        return imports

    thunk_size = 8 if is_pe32_plus else 4
    ordinal_flag = 0x8000000000000000 if is_pe32_plus else 0x80000000
    thunk_format = "<Q" if is_pe32_plus else "<I"

    cursor = descriptor_offset
    while cursor + 20 <= len(data):
        original_first_thunk, _time_date_stamp, _forwarder_chain, name_rva, first_thunk = struct.unpack_from("<IIIII", data, cursor)
        if not any((original_first_thunk, name_rva, first_thunk)):
            break
        name_offset = _rva_to_offset(name_rva, sections)
        dll_name = _cstring(data, name_offset) if name_offset is not None else f"<unmapped RVA 0x{name_rva:x}>"
        thunk_rva = original_first_thunk or first_thunk
        thunk_offset = _rva_to_offset(thunk_rva, sections)
        functions: list[str] = []
        if thunk_offset is not None:
            tcur = thunk_offset
            while tcur + thunk_size <= len(data):
                thunk_value = struct.unpack_from(thunk_format, data, tcur)[0]
                if thunk_value == 0:
                    break
                if thunk_value & ordinal_flag:
                    functions.append(f"ordinal:{thunk_value & 0xffff}")
                else:
                    hint_name_offset = _rva_to_offset(thunk_value, sections)
                    if hint_name_offset is not None and hint_name_offset + 2 < len(data):
                        functions.append(_cstring(data, hint_name_offset + 2))
                    else:
                        functions.append(f"<unmapped RVA 0x{thunk_value:x}>")
                tcur += thunk_size
        imports.append({"dll": dll_name, "functions": functions})
        cursor += 20
    return imports


def parse_pe(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    if data[:2] != b"MZ":
        raise ValueError("not an MZ/PE executable")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")

    coff_offset = pe_offset + 4
    machine, section_count, timestamp, _sym_ptr, _sym_count, optional_size, characteristics = struct.unpack_from("<HHIIIHH", data, coff_offset)
    optional_offset = coff_offset + 20
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    is_pe32_plus = magic == 0x20B
    if not is_pe32_plus and magic != 0x10B:
        raise ValueError(f"unsupported optional-header magic 0x{magic:x}")

    entry_point = struct.unpack_from("<I", data, optional_offset + 16)[0]
    image_base = struct.unpack_from("<Q" if is_pe32_plus else "<I", data, optional_offset + 24)[0]
    subsystem = struct.unpack_from("<H", data, optional_offset + (68 if is_pe32_plus else 92))[0]
    data_directory_offset = optional_offset + (112 if is_pe32_plus else 96)
    import_rva = struct.unpack_from("<I", data, data_directory_offset + 8)[0]

    sections: list[dict[str, int | str]] = []
    section_offset = optional_offset + optional_size
    for index in range(section_count):
        offset = section_offset + index * 40
        name = data[offset : offset + 8].rstrip(b"\0").decode("latin1", "replace")
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", data, offset + 8)
        flags = struct.unpack_from("<I", data, offset + 36)[0]
        raw = data[raw_pointer : raw_pointer + raw_size]
        sections.append(
            {
                "index": index,
                "name": name,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "raw_size": raw_size,
                "raw_pointer": raw_pointer,
                "entropy": _entropy(raw),
                "flags": flags,
            }
        )

    return {
        "path": str(path),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "machine": machine,
        "timestamp": timestamp,
        "timestamp_utc": _dt.datetime.fromtimestamp(timestamp, tz=_dt.UTC).isoformat(),
        "characteristics": characteristics,
        "format": "PE32+" if is_pe32_plus else "PE32",
        "image_base": image_base,
        "entry_point_rva": entry_point,
        "entry_point_va": image_base + entry_point,
        "subsystem": subsystem,
        "sections": sections,
        "imports": _parse_imports(data, import_rva, sections, is_pe32_plus),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Print static PE facts without executing the binary.")
    parser.add_argument("path", nargs="?", default="Z4B8T2N6.exe", type=Path)
    args = parser.parse_args()

    report = parse_pe(args.path)
    print(f"File: {report['path']}")
    print(f"Size: {report['size']} bytes")
    print(f"SHA-256: {report['sha256']}")
    print(f"Format: {report['format']} machine=0x{report['machine']:04x} subsystem={report['subsystem']}")
    print(f"Build timestamp (UTC): {report['timestamp_utc']}")
    print(f"ImageBase: 0x{report['image_base']:x}")
    print(f"EntryPoint: RVA 0x{report['entry_point_rva']:x} / VA 0x{report['entry_point_va']:x}")
    print("\nSections:")
    print("idx name       vaddr      vsize      raw_ptr    raw_size   entropy flags")
    for section in report["sections"]:
        print(
            f"{section['index']:>3} {section['name']:<10} "
            f"0x{section['virtual_address']:08x} 0x{section['virtual_size']:08x} "
            f"0x{section['raw_pointer']:08x} 0x{section['raw_size']:08x} "
            f"{section['entropy']:.3f}  0x{section['flags']:08x}"
        )
    print("\nImports:")
    for imported in report["imports"]:
        functions = ", ".join(imported["functions"]) or "<none>"
        print(f"- {imported['dll']}: {functions}")


if __name__ == "__main__":
    main()
