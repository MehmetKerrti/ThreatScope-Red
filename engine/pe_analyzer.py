import hashlib
import math
from datetime import datetime, timezone

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


def calculate_hashes(data: bytes) -> dict:
    return {
        "MD5": hashlib.md5(data).hexdigest(),
        "SHA-1": hashlib.sha1(data).hexdigest(),
        "SHA-256": hashlib.sha256(data).hexdigest()
    }


def calculate_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def compute_sliding_entropy(data: bytes, chunks: int = 40) -> list:
    """Dosyayı eşit bloklara bölerek bayt bazlı entropi grafiği verisi üretir."""
    total_len = len(data)
    if total_len == 0:
        return []
    if total_len < chunks:
        return [{"offset": "0x0", "entropy": calculate_shannon_entropy(data)}]

    step = total_len // chunks
    series = []
    for i in range(chunks):
        start = i * step
        end = start + step if i < chunks - 1 else total_len
        block = data[start:end]
        series.append({
            "offset": hex(start),
            "entropy": calculate_shannon_entropy(block)
        })
    return series


def format_hex_dump(data: bytes, max_bytes: int = 320) -> str:
    chunk = data[:max_bytes]
    lines = []
    for i in range(0, len(chunk), 16):
        sub = chunk[i:i + 16]
        hex_part = " ".join(f"{b:02X}" for b in sub).ljust(47)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in sub)
        lines.append(f"{i:08X}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


def inspect_pe_binary(data: bytes, suspicious_api_db: dict, lang: str = "TR") -> dict:
    """Windows PE (EXE/DLL/SYS) ikili dosyalarını derinlemesine analiz eder."""
    if not PEFILE_AVAILABLE or not data.startswith(b"MZ"):
        return {"is_pe": False}

    try:
        pe = pefile.PE(data=data)
        imphash = pe.get_imphash() or "N/A"
        
        # Mimari tespiti (x86 / x64)
        machine_type = pe.FILE_HEADER.Machine
        arch = "x64 (64-bit)" if machine_type == 0x8664 else ("x86 (32-bit)" if machine_type == 0x14c else hex(machine_type))

        # Dijital imza (Security Directory) kontrolü
        sec_dir_idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        has_signature = False
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > sec_dir_idx:
            sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_dir_idx]
            has_signature = sec_dir.VirtualAddress != 0 and sec_dir.Size > 0

        # Derleme zaman damgası
        ts = pe.FILE_HEADER.TimeDateStamp
        compile_time = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Bölümler (Sections) ve entropileri
        sections = []
        for sec in pe.sections:
            sec_name = sec.Name.decode("utf-8", errors="ignore").strip("\x00") or ".unnamed"
            sec_ent = round(sec.get_entropy(), 3)
            sections.append({
                "Section": sec_name,
                "Virtual Address": hex(sec.VirtualAddress),
                "Virtual Size": sec.Misc_VirtualSize,
                "Raw Size": sec.SizeOfRawData,
                "Entropy": sec_ent,
                "Flag": "[PACKED / ENCRYPTED]" if sec_ent > 7.2 else "[NORMAL]"
            })

        # Import Address Table (IAT) taraması
        detected_apis = []
        imported_dlls = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore")
                imported_dlls.append(dll_name)
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode("utf-8", errors="ignore")
                        for target_api, meta in suspicious_api_db.items():
                            if target_api.lower() in func_name.lower():
                                desc = meta["desc_tr"] if lang == "TR" else meta["desc_en"]
                                detected_apis.append({
                                    "DLL": dll_name,
                                    "API Function": func_name,
                                    "MITRE ATT&CK": meta["mitre"],
                                    "Risk": meta["risk"],
                                    "Description": desc
                                })

        return {
            "is_pe": True,
            "architecture": arch,
            "imphash": imphash,
            "signed": has_signature,
            "compile_time": compile_time,
            "dll_count": len(imported_dlls),
            "imported_dlls": imported_dlls,
            "sections": sections,
            "detected_apis": detected_apis
        }
    except Exception as e:
        return {"is_pe": False, "error": str(e)}