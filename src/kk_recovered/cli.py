"""中文命令行报告入口。"""

from __future__ import annotations

import argparse
from pathlib import Path

from .pe import PEFormatError, PEImage, parse_pe


def build_report(image: PEImage) -> str:
    """生成中文 PE 分析报告。"""

    entry_section = image.entry_point_section
    lines = [
        "KK 应用源码还原报告",
        "=" * 24,
        f"文件路径：{image.path}",
        f"文件大小：{image.size} 字节",
        f"SHA-256：{image.sha256}",
        f"构建时间戳（UTC）：{image.timestamp_utc}",
        f"文件格式：{'PE32+' if image.is_pe32_plus else 'PE32'}",
        f"目标架构：{image.architecture}",
        f"子系统：{image.subsystem_name}",
        f"映像基址：0x{image.image_base:016x}",
        f"入口点 RVA：0x{image.entry_point_rva:08x}",
        f"入口点节区：{entry_section.name if entry_section else '未映射'}",
        "",
        "节区：",
    ]
    for section in image.sections:
        marker = "（虚拟节区，磁盘无明文数据）" if section.is_virtual_only else ""
        lines.append(
            "- "
            f"{section.name}: "
            f"VA=0x{section.virtual_address:08x}, "
            f"VS=0x{section.virtual_size:08x}, "
            f"RAW_PTR=0x{section.raw_pointer:08x}, "
            f"RAW=0x{section.raw_size:08x}, "
            f"熵={section.entropy:.3f}, "
            f"特征=0x{section.characteristics:08x}{marker}"
        )

    lines.extend(["", "数据目录："])
    for directory in image.directories:
        if directory.rva or directory.size:
            lines.append(f"- {directory.index:02d} {directory.name}: RVA=0x{directory.rva:08x}, 大小=0x{directory.size:08x}")

    lines.extend(["", "导入表："])
    if image.imports:
        for entry in image.imports:
            lines.append(f"- {entry.dll}!{entry.name}")
    else:
        lines.append("- 未解析到导入项")

    lines.extend(["", "资源表："])
    if image.resources:
        for resource in image.resources:
            lines.append(
                "- "
                f"{resource.type_name}: name={resource.name_id}, lang={resource.language_id}, "
                f"RVA=0x{resource.rva:08x}, 大小={resource.size}, codepage={resource.codepage}"
            )
    else:
        lines.append("- 未解析到资源")

    manifest = image.manifest_text
    if manifest:
        one_line_manifest = " ".join(line.strip() for line in manifest.splitlines() if line.strip())
        lines.extend(["", "应用清单：", one_line_manifest])

    lines.extend(["", "保护/加壳证据："])
    for finding in image.protection_findings:
        lines.append(f"- {finding}")

    lines.extend(
        [
            "",
            "源码还原结论：",
            "- 当前磁盘文件能可靠还原 PE 元数据、导入表、资源清单和保护器特征。",
            "- 真实业务代码大概率在运行时解包后才出现在内存中；建议在 Win10 隔离环境获取内存转储后继续迁移源码。",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """执行命令行程序。"""

    parser = argparse.ArgumentParser(description="生成 KK 可执行文件的中文还原分析报告")
    parser.add_argument("pe_file", type=Path, help="需要分析的 Windows PE 可执行文件")
    args = parser.parse_args(argv)

    try:
        image = parse_pe(args.pe_file)
    except (OSError, PEFormatError) as exc:
        parser.error(str(exc))
    print(build_report(image))
    return 0
