import os
import json
import time
import html
from datetime import datetime
import streamlit as st
import pandas as pd
import plotly.graph_objects as go

from engine.pe_analyzer import (
    calculate_hashes,
    calculate_shannon_entropy,
    compute_sliding_entropy,
    format_hex_dump,
    inspect_pe_binary
)
from engine.ioc_extractor import extract_artifacts_and_rules
from engine.vt_client import lookup_hash, upload_sample

DEFAULT_VT_API_KEY = ""
REPORTS_DB_PATH = "reported_files.json"
RULES_PATH = os.path.join("rules", "signatures.json")
CSS_PATH = os.path.join("assets", "style.css")

st.set_page_config(
    page_title="DTH ThreatScope Red",
    page_icon="▪",
    layout="wide",
    initial_sidebar_state="expanded"
)


def load_css(path: str):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


def load_rules(path: str) -> dict:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"suspicious_apis": {}, "heuristic_rules": []}


def load_reports() -> list:
    if os.path.exists(REPORTS_DB_PATH):
        try:
            with open(REPORTS_DB_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_reports(records: list):
    with open(REPORTS_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=4, ensure_ascii=False)


load_css(CSS_PATH)
RULES_DB = load_rules(RULES_PATH)

if "scan_history" not in st.session_state:
    st.session_state.scan_history = []
if "lang" not in st.session_state:
    st.session_state.lang = "TR"
if "vt_cache" not in st.session_state:
    st.session_state.vt_cache = {}

I18N = {
    "TR": {
        "sys_tag": "DTH SYSTEMS // MADE IN GUARBEY",
        "title": "THREATSCOPE RED",
        "subtitle": "Dosya, Hash ve Script Tabanlı Zararlı Yazılım Analiz Platformu",
        "vt_key_lbl": "VirusTotal API Anahtarı",
        "vt_key_tip": "VirusTotal API anahtarınızı girerseniz sonuçlar 70+ antivirüs motoruyla doğrulanacağı için çok daha verimli çıkacaktır.",
        "adv_settings": "Gelişmiş Analiz Ayarları",
        "ent_thresh": "Yüksek Entropi Eşiği",
        "deep_str": "Derin String Taraması (Min 4 Byte)",
        "history_lbl": "Son Taramalar",
        "no_hist": "Henüz tarama yapılmadı.",
        "clear_hist": "Geçmişi Temizle",
        "nav_file": "Dosya Tara",
        "nav_hash": "Hash Sorgula",
        "nav_code": "Kod Analizi",
        "nav_reports": "Raporlanan Dosyalar",
        "upload_prompt": "Analiz edilecek dosyayı seçin veya sürükleyip bırakın",
        "hash_prompt": "MD5, SHA-1 veya SHA-256 değerini girin:",
        "hash_action": "Sorgula",
        "code_prompt": "İncelenecek kodu veya scripti yapıştırın:",
        "code_action": "Analiz Et",
        "v_clean": "TEMİZ / DÜŞÜK RİSK",
        "v_suspicious": "ŞÜPHELİ / İNCELENMELİ",
        "v_malicious": "ZARARLI YAZILIM TESPİT EDİLDİ",
        "tab_main": "Antivirüs & Tespit Özeti",
        "tab_tech": "Teknik Detaylar (PE, Grafik & Hex)",
        "tab_iocs": "Ağ & Sistem İzleri (IOC)",
        "vt_missing": "VirusTotal API anahtarı girilmedi. Canlı antivirüs sonuçları için sol menüden API anahtarınızı girin.",
        "vt_unknown": "Bu dosya VirusTotal veritabanında daha önce taranmamış.",
        "vt_upload": "Dosyayı VirusTotal'a Yükle ve Tarat",
        "no_flagged": "Hiçbir antivirüs motoru bu dosyayı zararlı olarak işaretlemedi.",
        "dl_json": "Raporu İndir (JSON)",
        "rep_btn": "Raporla",
        "rep_placeholder": "Raporlama nedeni (isteğe bağlı)..."
    },
    "EN": {
        "sys_tag": "DTH SYSTEMS // MADE IN GUARBEY",
        "title": "THREATSCOPE RED",
        "subtitle": "File, Hash, and Script Malware Analysis Platform",
        "vt_key_lbl": "VirusTotal API Key",
        "vt_key_tip": "Entering a VirusTotal API key enables verification across 70+ AV engines for much more accurate results.",
        "adv_settings": "Advanced Analysis Settings",
        "ent_thresh": "High Entropy Threshold",
        "deep_str": "Deep String Extraction (Min 4 Bytes)",
        "history_lbl": "Recent Scans",
        "no_hist": "No scans performed yet.",
        "clear_hist": "Clear History",
        "nav_file": "Scan File",
        "nav_hash": "Hash Lookup",
        "nav_code": "Code Analysis",
        "nav_reports": "Reported Files",
        "upload_prompt": "Select or drag and drop a file to analyze",
        "hash_prompt": "Enter MD5, SHA-1, or SHA-256 hash:",
        "hash_action": "Lookup",
        "code_prompt": "Paste code or script snippet to inspect:",
        "code_action": "Analyze",
        "v_clean": "CLEAN / LOW RISK",
        "v_suspicious": "SUSPICIOUS / REVIEW REQUIRED",
        "v_malicious": "MALICIOUS THREAT DETECTED",
        "tab_main": "Antivirus & Detection Summary",
        "tab_tech": "Technical Details (PE, Chart & Hex)",
        "tab_iocs": "Network & System IOCs",
        "vt_missing": "VirusTotal API key not provided. Enter your key in the sidebar for live AV results.",
        "vt_unknown": "This file has not been scanned on VirusTotal before.",
        "vt_upload": "Upload & Scan on VirusTotal",
        "no_flagged": "No antivirus engine flagged this file as malicious.",
        "dl_json": "Download Report (JSON)",
        "rep_btn": "Report",
        "rep_placeholder": "Reason for reporting (optional)..."
    }
}

# --- SADELEŞTİRİLMİŞ SOL MENÜ ---
with st.sidebar:
    lang_choice = st.selectbox("Dil / Language", ["TR", "EN"], index=0 if st.session_state.lang == "TR" else 1)
    st.session_state.lang = lang_choice
    L = I18N[lang_choice]

    st.divider()
    vt_key = st.text_input(L["vt_key_lbl"], value=DEFAULT_VT_API_KEY, type="password")
    st.caption(L["vt_key_tip"])

    with st.expander(L["adv_settings"]):
        ent_limit = st.slider(L["ent_thresh"], 6.0, 7.9, 7.4, 0.1)
        min_str_bytes = 4 if st.checkbox(L["deep_str"], value=False) else 6

    st.divider()
    st.markdown(f"**{L['history_lbl']}**")
    if st.session_state.scan_history:
        for entry in reversed(st.session_state.scan_history[-5:]):
            st.caption(f"• **{entry['name'][:20]}** (`{entry['metric']}`)")
        if st.button(L["clear_hist"], use_container_width=True):
            st.session_state.scan_history = []
            st.rerun()
    else:
        st.caption(L["no_hist"])

# --- KOMPAKT ÜST BAŞLIK ---
st.markdown(f"""
<div class="soc-header">
    <div class="soc-tag">{L['sys_tag']}</div>
    <h1 class="soc-title">{L['title']}</h1>
    <div class="soc-subtitle">{L['subtitle']}</div>
</div>
""", unsafe_allow_html=True)

reports_list = load_reports()
nav_reports_label = f"{L['nav_reports']} ({len(reports_list)})"

active_mode = st.radio(
    "MODE",
    [L["nav_file"], L["nav_hash"], L["nav_code"], nav_reports_label],
    horizontal=True,
    label_visibility="collapsed"
)

st.markdown("<br>", unsafe_allow_html=True)

sample_bytes = None
sample_name = None

# --- RAPORLANAN DOSYALAR SEKMESİ ---
if active_mode == nav_reports_label:
    with st.expander("+ Manuel Rapor Ekle"):
        with st.form("add_report_form", clear_on_submit=True):
            fc1, fc2 = st.columns(2)
            in_name = fc1.text_input("Dosya Adı", placeholder="ornek.exe")
            in_hash = fc2.text_input("SHA-256 Hash", placeholder="Hash değeri...")
            in_note = st.text_input("Açıklama", placeholder="Zararlı aktivite detayı...")
            if st.form_submit_button("Listeye Ekle", type="primary"):
                if in_name.strip():
                    reports_list.append({
                        "id": f"RPT-{int(time.time()*1000)}",
                        "name": in_name.strip(),
                        "sha256": in_hash.strip() or "N/A",
                        "verdict": "REPORTED",
                        "vt_score": "Manuel",
                        "reason": in_note.strip() or "Kullanıcı raporu.",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M")
                    })
                    save_reports(reports_list)
                    st.rerun()

    if not reports_list:
        st.info("Henüz raporlanmış bir dosya bulunmuyor.")
    else:
        for i, item in enumerate(reversed(reports_list)):
            orig_idx = len(reports_list) - 1 - i
            safe_name = html.escape(item.get("name", "unknown"))
            safe_reason = html.escape(item.get("reason", ""))

            rc1, rc2, rc3 = st.columns([3, 3, 1])
            with rc1:
                st.markdown(f"**{safe_name}**")
                st.caption(f"{item.get('timestamp')} • {safe_reason}")
            with rc2:
                st.code(item.get("sha256", "N/A"), language="text")
            with rc3:
                if st.button("Sil", key=f"del_{item.get('id', i)}", use_container_width=True):
                    reports_list.pop(orig_idx)
                    save_reports(reports_list)
                    st.rerun()
            st.divider()

# --- DOSYA YÜKLEME ---
elif active_mode == L["nav_file"]:
    uploaded_obj = st.file_uploader(L["upload_prompt"], type=None)
    if uploaded_obj is not None:
        sample_bytes = uploaded_obj.read()
        sample_name = uploaded_obj.name

# --- KOD ANALİZİ ---
elif active_mode == L["nav_code"]:
    raw_snippet = st.text_area(L["code_prompt"], height=150)
    if st.button(L["code_action"], type="primary") and raw_snippet.strip():
        sample_bytes = raw_snippet.encode("utf-8")
        sample_name = f"script_{datetime.now().strftime('%H%M%S')}.txt"

# --- HASH SORGULAMA ---
elif active_mode == L["nav_hash"]:
    query_digest = st.text_input(L["hash_prompt"], placeholder="44d88612fea8a8f36de82e1278abb02f")
    if st.button(L["hash_action"], type="primary") and query_digest.strip():
        if not vt_key:
            st.warning(L["vt_missing"])
        else:
            with st.spinner("Sorgulanıyor..."):
                vt_resp = lookup_hash(query_digest, vt_key)
                if vt_resp["status"] == "ok":
                    st.metric("AV Tespit Oranı", f"{vt_resp['malicious']} / {vt_resp['total']}")
                    if vt_resp["flagged"]:
                        st.markdown("**Tespit Eden Antivirüsler**")
                        st.dataframe(pd.DataFrame(vt_resp["flagged"]), use_container_width=True)
                    else:
                        st.success(L["no_flagged"])
                    with st.expander("Tüm Antivirüs Motorlarını Göster"):
                        st.dataframe(pd.DataFrame(vt_resp["engines"]), use_container_width=True)
                elif vt_resp["status"] == "not_found":
                    st.info(L["vt_unknown"])
                else:
                    st.error(f"API Hatası: {vt_resp}")

# --- ANALİZ SONUÇ EKRANI (SADELEŞTİRİLMİŞ) ---
if sample_bytes is not None and sample_name is not None:
    size_kb = round(len(sample_bytes) / 1024, 2)
    digests = calculate_hashes(sample_bytes)
    sha256_hex = digests["SHA-256"]
    global_entropy = calculate_shannon_entropy(sample_bytes)
    sliding_series = compute_sliding_entropy(sample_bytes, chunks=40)
    artifacts = extract_artifacts_and_rules(sample_bytes, RULES_DB.get("heuristic_rules", []), min_str_bytes, lang_choice)
    pe_report = inspect_pe_binary(sample_bytes, RULES_DB.get("suspicious_apis", {}), lang_choice)

    heuristic_score = 0
    heuristic_notes = []

    if global_entropy >= ent_limit:
        heuristic_score += 20
        heuristic_notes.append(f"Yüksek entropi ({global_entropy}/8.0): Dosya paketlenmiş veya şifrelenmiş olabilir.")

    for hit in artifacts["rule_hits"]:
        heuristic_score += hit["Weight"]
        heuristic_notes.append(f"{hit['Signature']} ({hit['MITRE ATT&CK']}): {hit['Analysis']}")

    if pe_report.get("is_pe") and pe_report.get("detected_apis"):
        api_hits = len(pe_report["detected_apis"])
        heuristic_score += min(api_hits * 6, 25)
        heuristic_notes.append(f"Import tablosunda {api_hits} adet hassas Windows API çağrısı bulundu.")

    heuristic_score = min(heuristic_score, 100)

    if sha256_hex in st.session_state.vt_cache:
        vt_result = st.session_state.vt_cache[sha256_hex]
    else:
        vt_result = {"status": "no_key"}
        if vt_key:
            with st.spinner("VirusTotal motorları ile doğrulanıyor..."):
                vt_result = lookup_hash(sha256_hex, vt_key)

    if vt_result["status"] == "ok":
        mal_count = vt_result["malicious"]
        tot_count = vt_result["total"]
        vt_metric_str = f"{mal_count} / {tot_count}"
        if mal_count >= 3:
            final_verdict = "malicious"
        elif mal_count >= 1 or vt_result["suspicious"] >= 2:
            final_verdict = "suspicious"
        else:
            final_verdict = "clean"
    else:
        vt_metric_str = "API Yok" if vt_result["status"] == "no_key" else "Bilinmiyor"
        if heuristic_score >= 60:
            final_verdict = "malicious"
        elif heuristic_score >= 35:
            final_verdict = "suspicious"
        else:
            final_verdict = "clean"

    if not st.session_state.scan_history or st.session_state.scan_history[-1]["sha256"] != sha256_hex:
        st.session_state.scan_history.append({
            "name": sample_name,
            "sha256": sha256_hex,
            "verdict": final_verdict,
            "metric": vt_metric_str if vt_result["status"] == "ok" else f"Skor: {heuristic_score}"
        })

    st.divider()

    # Tek Satırlık Temiz Sonuç Özeti
    top_l, top_m, top_r = st.columns([2.5, 1, 1])
    with top_l:
        st.subheader(sample_name)
        if final_verdict == "malicious":
            st.markdown(f'<span class="verdict-malicious">{L["v_malicious"]}</span>', unsafe_allow_html=True)
        elif final_verdict == "suspicious":
            st.markdown(f'<span class="verdict-suspicious">{L["v_suspicious"]}</span>', unsafe_allow_html=True)
        else:
            st.markdown(f'<span class="verdict-clean">{L["v_clean"]}</span>', unsafe_allow_html=True)

    with top_m:
        st.metric("AV Tespit Oranı", vt_metric_str)
    with top_r:
        st.metric("Boyut / Entropi", f"{size_kb} KB • {global_entropy}")

    st.markdown("<br>", unsafe_allow_html=True)

    # 3 SADE SEKME
    t_main, t_tech, t_ioc = st.tabs([L["tab_main"], L["tab_tech"], L["tab_iocs"]])

    with t_main:
        if vt_result["status"] == "ok":
            if vt_result["flagged"]:
                st.markdown(f"**Tespit Eden Antivirüs Motorları ({len(vt_result['flagged'])})**")
                st.dataframe(pd.DataFrame(vt_result["flagged"]), use_container_width=True)
            else:
                st.success(L["no_flagged"])

            with st.expander(f"Tüm Antivirüs Motorlarını Görüntüle ({vt_result['total']})"):
                st.dataframe(pd.DataFrame(vt_result["engines"]), use_container_width=True, height=350)

        elif vt_result["status"] == "not_found":
            st.warning(L["vt_unknown"])
            if len(sample_bytes) < 32 * 1024 * 1024:
                if st.button(L["vt_upload"], type="primary"):
                    with st.spinner("Dosya VirusTotal'a yükleniyor ve taranıyor..."):
                        up_out = upload_sample(sample_bytes, sample_name, vt_key)
                        if up_out["status"] == "ok":
                            st.session_state.vt_cache[sha256_hex] = up_out
                            st.rerun()
                        elif up_out["status"] == "queued":
                            st.info("Dosya sıraya alındı, birkaç saniye sonra tekrar kontrol edin.")
                        else:
                            st.error(f"Hata: {up_out}")
        elif vt_result["status"] == "no_key":
            st.info(L["vt_missing"])

        if heuristic_notes or artifacts["rule_hits"]:
            st.markdown("**Statik Analiz Bulguları**")
            for note in heuristic_notes:
                st.caption(f"• {note}")
            if artifacts["rule_hits"]:
                st.dataframe(pd.DataFrame(artifacts["rule_hits"]), use_container_width=True)

    with t_tech:
        for algo, digest_str in digests.items():
            st.markdown(f'<div class="hash-row"><strong>{algo}:</strong> {digest_str}</div>', unsafe_allow_html=True)

        if pe_report.get("is_pe"):
            st.markdown("**Windows PE Yapısı**")
            st.caption(f"Mimari: `{pe_report['architecture']}` | İmza: `{'SIGNED' if pe_report['signed'] else 'UNSIGNED'}` | IMPHASH: `{pe_report['imphash']}`")
            if pe_report["detected_apis"]:
                st.dataframe(pd.DataFrame(pe_report["detected_apis"]), use_container_width=True)
            st.dataframe(pd.DataFrame(pe_report["sections"]), use_container_width=True)

        with st.expander("Entropi Dağılım Grafiği & Hex Dump"):
            if sliding_series:
                df_ent = pd.DataFrame(sliding_series)
                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=df_ent["offset"], y=df_ent["entropy"],
                    mode="lines", line=dict(color="#ef4444", width=2),
                    fill="tozeroy", fillcolor="rgba(220, 38, 38, 0.15)"
                ))
                fig.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(18, 7, 10, 0.8)",
                    font=dict(color="#cbd5e1"), yaxis=dict(range=[0, 8.2]),
                    height=260, margin=dict(l=10, r=10, t=10, b=10)
                )
                st.plotly_chart(fig, use_container_width=True)
            st.code(format_hex_dump(sample_bytes, 256), language="text")

    with t_ioc:
        ic1, ic2 = st.columns(2)
        with ic1:
            st.markdown("**URL & IP Adresleri**")
            for u in artifacts["urls"] + artifacts["ips"]:
                st.code(u, language="text")
            if not (artifacts["urls"] or artifacts["ips"]):
                st.caption("Bulunamadı.")
        with ic2:
            st.markdown("**Registry & Sistem Komutları**")
            for rk in artifacts["registry"] + artifacts["commands"]:
                st.code(rk, language="text")
            if not (artifacts["registry"] or artifacts["commands"]):
                st.caption("Bulunamadı.")

    # --- SADE ALT ÇUBUK (İNDİR & SAĞ ALTTA RAPORLA) ---
    st.divider()
    b_l, b_r = st.columns([1, 1.5])
    with b_l:
        st.download_button(
            label=L["dl_json"],
            data=json.dumps({"sample": sample_name, "verdict": final_verdict, "digests": digests, "virustotal": vt_result}, indent=4, ensure_ascii=False),
            file_name=f"{sample_name}_report.json",
            mime="application/json"
        )
    with b_r:
        r_in, r_bt = st.columns([2.2, 1])
        with r_in:
            user_note = st.text_input("Not", placeholder=L["rep_placeholder"], label_visibility="collapsed", key=f"note_{sha256_hex}")
        with r_bt:
            if st.button(L["rep_btn"], type="primary", use_container_width=True, key=f"rep_{sha256_hex}"):
                db_records = load_reports()
                if any(r.get("sha256") == sha256_hex for r in db_records):
                    st.warning("Bu dosya zaten raporlanmış.")
                else:
                    db_records.append({
                        "id": f"RPT-{int(time.time()*1000)}",
                        "name": sample_name,
                        "sha256": sha256_hex,
                        "verdict": final_verdict.upper(),
                        "vt_score": vt_metric_str,
                        "reason": user_note.strip() if user_note.strip() else "Kullanıcı raporu.",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M")
                    })
                    save_reports(db_records)
                    st.success("Raporlanan Dosyalar listesine eklendi.")