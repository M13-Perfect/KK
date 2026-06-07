from pathlib import Path

from kk_recovered import parse_pe


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "Z4B8T2N6.exe"


def test_parse_sample_core_headers():
    image = parse_pe(SAMPLE)

    assert image.size == 14_818_304
    assert image.is_pe32_plus is True
    assert image.architecture == "x86-64"
    assert image.subsystem_name == "Windows 控制台程序"
    assert image.entry_point_rva == 0x01188B12
    assert image.image_base == 0x0000000140000000


def test_parse_sample_sections_and_imports():
    image = parse_pe(SAMPLE)

    section_names = [section.name for section in image.sections]
    assert ".QZT" in section_names
    assert len(image.sections) == 12

    qzt = next(section for section in image.sections if section.name == ".QZT")
    assert qzt.raw_size == 0x00E21400
    assert qzt.entropy > 7.8

    imports = {(entry.dll, entry.name) for entry in image.imports}
    assert ("KERNEL32.dll", "WaitForSingleObject") in imports
    assert ("USER32.dll", "ShowWindow") in imports
    assert ("IPHLPAPI.DLL", "IcmpCreateFile") in imports
