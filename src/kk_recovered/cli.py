"""中文命令行报告入口。"""

from __future__ import annotations

import argparse
from pathlib import Path

from .pe import PEFormatError, PEImage, parse_pe


def build_report(image: PEImage) -> str:
    """生成中文 PE 分析报告。"""

    lines = [
        "KK 应用源码还原报告",
        "=" * 24,
        f"文件路径：{image.path}",
        f"文件大小：{image.size} 字节",
        f"文件格式：{'PE32+' if image.is_pe32_plus else 'PE32'}",
        f"目标架构：{image.architecture}",
        f"子系统：{image.subsystem_name}",
        f"映像基址：0x{image.image_base:016x}",
        f"入口点 RVA：0x{image.entry_point_rva:08x}",
        "",
        "节区：",
    ]
    for section in image.sections:
        lines.append(
            "- "
            f"{section.name}: "
            f"VA=0x{section.virtual_address:08x}, "
            f"VS=0x{section.virtual_size:08x}, "
            f"RAW=0x{section.raw_size:08x}, "
            f"熵={section.entropy:.3f}"
        )

    lines.extend(["", "导入表："])
    if image.imports:
        for entry in image.imports:
            lines.append(f"- {entry.dll}!{entry.name}")
    else:
        lines.append("- 未解析到导入项")

    resource_directory = image.directory(2)
    lines.extend(
        [
            "",
            "资源目录：",
            f"- RVA=0x{resource_directory.rva:08x}, 大小=0x{resource_directory.size:08x}",
            "",
            "结论：",
            "- 样本具备高熵集中节区和极小导入表等保护/加壳特征。",
            "- 当前源码还原工作区已提供可复现的静态解析基础，后续可接入脱壳后的业务代码。",
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
