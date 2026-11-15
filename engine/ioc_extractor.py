import re


def extract_artifacts_and_rules(data: bytes, heuristic_rules: list, min_len: int = 6, lang: str = "TR") -> dict:
    """Ham baytlar içinden ağ göstergeleri, kayıt defteri anahtarları, kripto cüzdanları ve YARA-benzeri kuralları çıkarır."""
    pattern = f"[ -~]{{{min_len},}}".encode()
    ascii_strings = re.findall(pattern, data)
    decoded_strings = [s.decode("utf-8", errors="ignore") for s in ascii_strings]
    full_corpus_lower = "\n".join(decoded_strings).lower()

    urls = set()
    ips = set()
    registry_keys = set()
    crypto_wallets = set()
    shell_cmds = set()

    url_re = re.compile(r"https?://[^\s\"'<>|]+", re.IGNORECASE)
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    reg_re = re.compile(r"(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\[^\s\"']+", re.IGNORECASE)
    btc_re = re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})\b")

    cmd_triggers = ["powershell", "cmd.exe", "vssadmin", "schtasks", "reg add", "certutil", "bitsadmin", "mshta"]

    for s in decoded_strings:
        for u in url_re.findall(s):
            urls.add(u)
        for ip in ip_re.findall(s):
            if not ip.startswith(("0.", "127.", "255.")):
                ips.add(ip)
        for r in reg_re.findall(s):
            registry_keys.add(r)
        for w in btc_re.findall(s):
            crypto_wallets.add(w)

        lower_s = s.lower()
        if any(trig in lower_s for trig in cmd_triggers) and len(s) < 180:
            shell_cmds.add(s)

    # Harici kural eşleştirme
    rule_hits = []
    for rule in heuristic_rules:
        matched_patterns = [p for p in rule["patterns"] if p in full_corpus_lower]
        if matched_patterns:
            rule_hits.append({
                "Rule ID": rule["id"],
                "Signature": rule["name"],
                "MITRE ATT&CK": rule["mitre"],
                "Severity": rule["severity"],
                "Weight": rule["weight"],
                "Matched Artifacts": ", ".join(matched_patterns),
                "Analysis": rule["desc_tr"] if lang == "TR" else rule["desc_en"]
            })

    return {
        "urls": sorted(list(urls))[:40],
        "ips": sorted(list(ips))[:40],
        "registry": sorted(list(registry_keys))[:30],
        "crypto": sorted(list(crypto_wallets))[:20],
        "commands": sorted(list(shell_cmds))[:40],
        "rule_hits": rule_hits,
        "total_strings": len(decoded_strings)
    }