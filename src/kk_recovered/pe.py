"""用于还原工作区的轻量级 PE 解析器。

该模块只依赖 Python 标准库，目标是把当前样本中已经确认的结构解析出来，
为后续脱壳和业务逻辑重建提供稳定基础。
"""

from __future__ import annotations

from dataclasses import dataclass
import datetime as _dt
import hashlib
import math
from pathlib import Path
import struct
from typing import Iterable


class PEFormatError(ValueError):
    """输入文件不是当前解析器支持的 PE 文件时抛出。"""


DATA_DIRECTORY_NAMES = {
    0: "导出表",
    1: "导入表",
    2: "资源表",
    3: "异常表",
    4: "证书表",
    5: "重定位表",
    6: "调试表",
    7: "架构表",
    8: "全局指针",
    9: "TLS 表",
    10: "加载配置",
    11: "绑定导入",
    12: "IAT",
    13: "延迟导入",
    14: ".NET 运行时",
    15: "保留目录",
}

RESOURCE_TYPE_NAMES = {
    1: "光标",
    2: "位图",
    3: "图标",
    4: "菜单",
    5: "对话框",
    6: "字符串表",
    10: "自定义数据",
    14: "图标组",
    16: "版本信息",
    24: "应用清单",
}


@dataclass(frozen=True)
class DataDirectory:
    """PE 可选头中的数据目录。"""

    index: int
    rva: int
    size: int

    @property
    def name(self) -> str:
        """返回目录的常用名称。"""

        return DATA_DIRECTORY_NAMES.get(self.index, f"目录 {self.index}")


@dataclass(frozen=True)
class Section:
    """PE 节区信息。"""

    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_pointer: int
    entropy: float
    characteristics: int

    @property
    def end_rva(self) -> int:
        """节区虚拟地址范围结尾。"""

        return self.virtual_address + max(self.virtual_size, self.raw_size)

    @property
    def is_virtual_only(self) -> bool:
        """判断节区是否只有内存大小而没有磁盘原始数据。"""

        return self.virtual_size > 0 and self.raw_size == 0


@dataclass(frozen=True)
class ImportEntry:
    """导入表中的一个函数。"""

    dll: str
    name: str


@dataclass(frozen=True)
class ResourceEntry:
    """资源表叶子节点。"""

    type_id: int | None
    type_name: str
    name_id: int | None
    language_id: int | None
    rva: int
    size: int
    codepage: int
    data: bytes

    @property
    def text(self) -> str | None:
        """尝试把文本型资源解码为字符串。"""

        if not self.data:
            return None
        for encoding in ("utf-8-sig", "utf-16-le", "latin1"):
            try:
                decoded = self.data.rstrip(b"\0").decode(encoding)
            except UnicodeDecodeError:
                continue
            if decoded and sum(ch.isprintable() or ch in "\r\n\t" for ch in decoded) / len(decoded) > 0.9:
                return decoded
        return None


@dataclass(frozen=True)
class PEImage:
    """解析后的 PE 映像摘要。"""

    path: Path
    size: int
    sha256: str
    timestamp: int
    machine: int
    is_pe32_plus: bool
    subsystem: int
    image_base: int
    entry_point_rva: int
    sections: tuple[Section, ...]
    directories: tuple[DataDirectory, ...]
    imports: tuple[ImportEntry, ...]
    resources: tuple[ResourceEntry, ...]

    @property
    def timestamp_utc(self) -> str:
        """返回 COFF 时间戳的 UTC 表示。"""

        return _dt.datetime.fromtimestamp(self.timestamp, tz=_dt.UTC).isoformat()

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

    @property
    def entry_point_section(self) -> Section | None:
        """返回入口点所在节区。"""

        return self.section_for_rva(self.entry_point_rva)

    @property
    def manifest_text(self) -> str | None:
        """返回嵌入式应用清单文本。"""

        for resource in self.resources:
            if resource.type_id == 24:
                return resource.text
        return None

    @property
    def protection_findings(self) -> tuple[str, ...]:
        """基于静态证据生成保护/加壳判断。"""

        findings: list[str] = []
        virtual_sections = [section.name for section in self.sections if section.is_virtual_only]
        if virtual_sections:
            findings.append(f"存在 {len(virtual_sections)} 个 RawSize=0 的虚拟节区：{', '.join(virtual_sections)}")
        high_entropy = [section.name for section in self.sections if section.raw_size and section.entropy >= 7.2]
        if high_entropy:
            findings.append(f"存在高熵原始节区：{', '.join(high_entropy)}")
        entry_section = self.entry_point_section
        if entry_section is not None and entry_section.entropy >= 7.2:
            findings.append(f"入口点落在高熵节区 {entry_section.name}")
        if len(self.imports) <= 16:
            findings.append(f"导入函数数量很少（{len(self.imports)} 个），符合壳加载器特征")
        if self.directory(14).rva == 0:
            findings.append("未发现 .NET 运行时目录，当前样本不像直接可反编译的 .NET 程序")
        return tuple(findings)

    def directory(self, index: int) -> DataDirectory:
        """按索引读取数据目录。"""

        for directory in self.directories:
            if directory.index == index:
                return directory
        return DataDirectory(index=index, rva=0, size=0)

    def section_for_rva(self, rva: int) -> Section | None:
        """查找包含指定 RVA 的节区。"""

        for section in self.sections:
            if section.virtual_address <= rva < section.end_rva:
                return section
        return None

    def rva_to_offset(self, rva: int) -> int | None:
        """将 RVA 转换为文件偏移。"""

        section = self.section_for_rva(rva)
        if section is None or section.raw_size == 0:
            return None
        delta = rva - section.virtual_address
        if delta >= section.raw_size:
            return None
        return section.raw_pointer + delta


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
    timestamp = _u32(data, coff_offset + 4)
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
        sha256=hashlib.sha256(data).hexdigest(),
        timestamp=timestamp,
        machine=machine,
        is_pe32_plus=is_pe32_plus,
        subsystem=subsystem,
        image_base=image_base,
        entry_point_rva=entry_point_rva,
        sections=sections,
        directories=directories,
        imports=(),
        resources=(),
    )
    return PEImage(
        path=image.path,
        size=image.size,
        sha256=image.sha256,
        timestamp=image.timestamp,
        machine=image.machine,
        is_pe32_plus=image.is_pe32_plus,
        subsystem=image.subsystem,
        image_base=image.image_base,
        entry_point_rva=image.entry_point_rva,
        sections=image.sections,
        directories=image.directories,
        imports=tuple(_parse_imports(data, image)),
        resources=tuple(_parse_resources(data, image)),
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
        characteristics=_u32(data, offset + 36),
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


def _parse_resources(data: bytes, image: PEImage) -> Iterable[ResourceEntry]:
    directory = image.directory(2)
    base_offset = image.rva_to_offset(directory.rva)
    if base_offset is None or directory.size == 0:
        return ()

    resources: list[ResourceEntry] = []

    def walk(relative_offset: int, levels: tuple[int | None, ...]) -> None:
        directory_offset = base_offset + relative_offset
        if directory_offset + 16 > len(data):
            return
        named_count = _u16(data, directory_offset + 12)
        id_count = _u16(data, directory_offset + 14)
        entry_count = named_count + id_count
        entries_offset = directory_offset + 16
        for index in range(entry_count):
            entry_offset = entries_offset + index * 8
            if entry_offset + 8 > len(data):
                continue
            name_raw = _u32(data, entry_offset)
            value_raw = _u32(data, entry_offset + 4)
            identifier = None if name_raw & 0x80000000 else name_raw
            child_levels = (*levels, identifier)
            if value_raw & 0x80000000:
                walk(value_raw & 0x7FFFFFFF, child_levels)
            else:
                data_entry_offset = base_offset + value_raw
                if data_entry_offset + 16 > len(data):
                    continue
                data_rva = _u32(data, data_entry_offset)
                size = _u32(data, data_entry_offset + 4)
                codepage = _u32(data, data_entry_offset + 8)
                payload_offset = image.rva_to_offset(data_rva)
                payload = data[payload_offset : payload_offset + size] if payload_offset is not None else b""
                type_id = child_levels[0] if len(child_levels) > 0 else None
                type_name = RESOURCE_TYPE_NAMES.get(type_id, f"资源类型 {type_id}") if type_id is not None else "命名资源"
                name_id = child_levels[1] if len(child_levels) > 1 else None
                language_id = child_levels[2] if len(child_levels) > 2 else None
                resources.append(
                    ResourceEntry(
                        type_id=type_id,
                        type_name=type_name,
                        name_id=name_id,
                        language_id=language_id,
                        rva=data_rva,
                        size=size,
                        codepage=codepage,
                        data=payload,
                    )
                )

    walk(0, ())
    return resources


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
