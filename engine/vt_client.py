import time

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


def _parse_vt_payload(results: dict, stats: dict, attributes: dict) -> dict:
    all_engines = []
    flagged_engines = []

    for engine_name, res in results.items():
        category = res.get("category", "undetected")
        signature = res.get("result") or "Undetected"

        if category == "malicious":
            status_tag = "[MALICIOUS]"
            sort_order = 0
        elif category == "suspicious":
            status_tag = "[SUSPICIOUS]"
            sort_order = 1
        else:
            status_tag = "[CLEAN]"
            sort_order = 2

        all_engines.append({
            "AV Vendor": engine_name,
            "Verdict": status_tag,
            "Detection Signature": signature,
            "_sort": sort_order
        })

        if category in ("malicious", "suspicious"):
            flagged_engines.append({
                "AV Vendor": engine_name,
                "Severity": status_tag,
                "Detection Signature": signature,
                "Engine Version": res.get("engine_version", "N/A"),
                "_sort": sort_order
            })

    all_engines.sort(key=lambda x: x["_sort"])
    flagged_engines.sort(key=lambda x: x["_sort"])
    for item in all_engines:
        del item["_sort"]
    for item in flagged_engines:
        del item["_sort"]

    return {
        "status": "ok",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "total": sum(stats.values()),
        "engines": all_engines,
        "flagged": flagged_engines,
        "reputation": attributes.get("reputation", 0),
        "vt_name": attributes.get("meaningful_name", "N/A"),
        "tags": attributes.get("tags", [])
    }


def lookup_hash(file_hash: str, api_key: str) -> dict:
    if not REQUESTS_AVAILABLE or not api_key:
        return {"status": "no_key"}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash.strip()}"
    headers = {"x-apikey": api_key.strip()}

    try:
        resp = requests.get(url, headers=headers, timeout=12)
        if resp.status_code == 200:
            attr = resp.json().get("data", {}).get("attributes", {})
            return _parse_vt_payload(
                attr.get("last_analysis_results", {}),
                attr.get("last_analysis_stats", {}),
                attr
            )
        elif resp.status_code == 404:
            return {"status": "not_found"}
        else:
            return {"status": "error", "code": resp.status_code}
    except Exception as e:
        return {"status": "error", "msg": str(e)}


def upload_sample(file_bytes: bytes, filename: str, api_key: str) -> dict:
    if not REQUESTS_AVAILABLE or not api_key:
        return {"status": "no_key"}

    headers = {"x-apikey": api_key.strip()}
    try:
        files = {"file": (filename, file_bytes)}
        up_resp = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files, timeout=30)
        if up_resp.status_code != 200:
            return {"status": "error", "code": up_resp.status_code, "msg": up_resp.text}

        analysis_id = up_resp.json().get("data", {}).get("id")
        if not analysis_id:
            return {"status": "error", "msg": "Analysis ID missing."}

        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for _ in range(15):
            time.sleep(3)
            an_resp = requests.get(analysis_url, headers=headers, timeout=12)
            if an_resp.status_code == 200:
                attr = an_resp.json().get("data", {}).get("attributes", {})
                if attr.get("status") == "completed":
                    return _parse_vt_payload(
                        attr.get("results", {}),
                        attr.get("stats", {}),
                        {"meaningful_name": filename}
                    )
        return {"status": "queued"}
    except Exception as e:
        return {"status": "error", "msg": str(e)}