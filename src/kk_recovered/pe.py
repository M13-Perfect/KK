"""用于还原工作区的轻量级 PE 解析器。

该模块只依赖 Python 标准库，目标是把当前样本中已经确认的结构解析出来，
为后续脱壳和业务逻辑重建提供稳定基础。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import math
import struct
from typing import Iterable


class PEFormatError(ValueError):
    """输入文件不是当前解析器支持的 PE 文件时抛出。"""


@dataclass(frozen=True)
class DataDirectory:
    """PE 可选头中的数据目录。"""

    index: int
    rva: int
    size: int


@dataclass(frozen=True)
class Section:
    """PE 节区信息。"""

    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_pointer: int
    entropy: float


@dataclass(frozen=True)
class ImportEntry:
    """导入表中的一个函数。"""

    dll: str
    name: str


@dataclass(frozen=True)
class PEImage:
    """解析后的 PE 映像摘要。"""

    path: Path
    size: int
    machine: int
    is_pe32_plus: bool
    subsystem: int
    image_base: int
    entry_point_rva: int
    sections: tuple[Section, ...]
    directories: tuple[DataDirectory, ...]
    imports: tuple[ImportEntry, ...]

    @property
    def architecture(self) -> str:
        """返回人类可读的架构名称。"""

        return {0x8664: "x86-64", 0x14C: "x86"}.get(self.machine, f"未知架构 0x{self.machine:04x}")

    @property
    def subsystem_name(self) -> str:
        """返回人类可读的子系统名称。"""

        return {
            2: "Windows 图形界面程序",
            3: "Windows 控制台程序",
        }.get(self.subsystem, f"未知子系统 {self.subsystem}")

    def directory(self, index: int) -> DataDirectory:
        """按索引读取数据目录。"""

        for directory in self.directories:
            if directory.index == index:
                return directory
        return DataDirectory(index=index, rva=0, size=0)

    def section_for_rva(self, rva: int) -> Section | None:
        """查找包含指定 RVA 的节区。"""

        for section in self.sections:
            size = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= rva < section.virtual_address + size:
                return section
        return None

    def rva_to_offset(self, rva: int) -> int | None:
        """将 RVA 转换为文件偏移。"""

        section = self.section_for_rva(rva)
        if section is None or section.raw_size == 0:
            return None
        return section.raw_pointer + (rva - section.virtual_address)


def parse_pe(path: str | Path) -> PEImage:
    """解析 PE 文件并返回摘要。"""

    pe_path = Path(path)
    data = pe_path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEFormatError("文件缺少 MZ 头，不是有效 PE 文件")

    pe_offset = _u32(data, 0x3C)
    if pe_offset + 24 >= len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise PEFormatError("文件缺少 PE 签名，不是有效 PE 文件")

    coff_offset = pe_offset + 4
    machine = _u16(data, coff_offset)
    section_count = _u16(data, coff_offset + 2)
    optional_header_size = _u16(data, coff_offset + 16)
    optional_offset = coff_offset + 20
    optional_magic = _u16(data, optional_offset)
    is_pe32_plus = optional_magic == 0x20B
    if not is_pe32_plus and optional_magic != 0x10B:
        raise PEFormatError(f"不支持的可选头格式：0x{optional_magic:04x}")

    entry_point_rva = _u32(data, optional_offset + 16)
    image_base = _u64(data, optional_offset + 24) if is_pe32_plus else _u32(data, optional_offset + 28)
    subsystem = _u16(data, optional_offset + 68)
    directory_count = min(_u32(data, optional_offset + 108), 16) if is_pe32_plus else min(_u32(data, optional_offset + 92), 16)
    directory_offset = optional_offset + (112 if is_pe32_plus else 96)
    directories = tuple(
        DataDirectory(index=index, rva=_u32(data, directory_offset + index * 8), size=_u32(data, directory_offset + index * 8 + 4))
        for index in range(directory_count)
    )

    section_offset = optional_offset + optional_header_size
    sections = tuple(_parse_section(data, section_offset + index * 40) for index in range(section_count))
    image = PEImage(
        path=pe_path,
        size=len(data),
        machine=machine,
        is_pe32_plus=is_pe32_plus,
        subsystem=subsystem,
        image_base=image_base,
        entry_point_rva=entry_point_rva,
        sections=sections,
        directories=directories,
        imports=(),
    )
    return PEImage(
        path=image.path,
        size=image.size,
        machine=image.machine,
        is_pe32_plus=image.is_pe32_plus,
        subsystem=image.subsystem,
        image_base=image.image_base,
        entry_point_rva=image.entry_point_rva,
        sections=image.sections,
        directories=image.directories,
        imports=tuple(_parse_imports(data, image)),
    )


def _parse_section(data: bytes, offset: int) -> Section:
    raw_name = data[offset : offset + 8].split(b"\0", 1)[0]
    name = raw_name.decode("ascii", errors="replace")
    virtual_size = _u32(data, offset + 8)
    virtual_address = _u32(data, offset + 12)
    raw_size = _u32(data, offset + 16)
    raw_pointer = _u32(data, offset + 20)
    raw_data = data[raw_pointer : raw_pointer + raw_size] if raw_size else b""
    return Section(
        name=name,
        virtual_size=virtual_size,
        virtual_address=virtual_address,
        raw_size=raw_size,
        raw_pointer=raw_pointer,
        entropy=_entropy(raw_data),
    )


def _parse_imports(data: bytes, image: PEImage) -> Iterable[ImportEntry]:
    import_directory = image.directory(1)
    offset = image.rva_to_offset(import_directory.rva)
    if offset is None or import_directory.size == 0:
        return ()

    entries: list[ImportEntry] = []
    cursor = offset
    while cursor + 20 <= len(data):
        original_first_thunk = _u32(data, cursor)
        name_rva = _u32(data, cursor + 12)
        first_thunk = _u32(data, cursor + 16)
        if original_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
            break
        dll = _read_c_string(data, image.rva_to_offset(name_rva) or -1)
        thunk_rva = original_first_thunk or first_thunk
        thunk_offset = image.rva_to_offset(thunk_rva)
        if dll and thunk_offset is not None:
            entries.extend(_parse_thunks(data, image, dll, thunk_offset))
        cursor += 20
    return entries


def _parse_thunks(data: bytes, image: PEImage, dll: str, thunk_offset: int) -> Iterable[ImportEntry]:
    entries: list[ImportEntry] = []
    cursor = thunk_offset
    ordinal_flag = 0x8000000000000000 if image.is_pe32_plus else 0x80000000
    step = 8 if image.is_pe32_plus else 4
    reader = _u64 if image.is_pe32_plus else _u32
    while cursor + step <= len(data):
        thunk = reader(data, cursor)
        if thunk == 0:
            break
        if thunk & ordinal_flag:
            name = f"序号导入 {thunk & 0xFFFF}"
        else:
            hint_name_offset = image.rva_to_offset(thunk)
            name = _read_c_string(data, (hint_name_offset or 0) + 2) if hint_name_offset is not None else "<无法解析>"
        entries.append(ImportEntry(dll=dll, name=name))
        cursor += step
    return entries


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def _read_c_string(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\0", offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode("ascii", errors="replace")


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]
