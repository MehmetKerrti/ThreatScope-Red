# 🛡️ DTH ThreatScope Red

**DTH ThreatScope Red**, şüpheli ikili dosyaları (`EXE`, `DLL`, `SYS`), zararlı betikleri (`PS1`, `BAT`, `VBS`, `PY`) ve kriptografik hash değerlerini kendi bilgisayarınızda (`127.0.0.1`) izole bir ortamda incelemenizi sağlayan, **VirusTotal API v3** destekli modüler bir statik ve hibrit zararlı yazılım analiz platformudur.

> **Developer & Architecture:** Made in **Guarbey** • **DTH Systems**

---

## 🎯 Projenin Amacı ve Yaklaşımı

Bu proje, modern yazılım geliştirme pratiklerinden **Vibe Coding** yaklaşımıyla; fikir aşamasından çalışan, modüler bir siber güvenlik aracına dönüşene kadar hızlı prototipleme, iteratif tasarım ve yapay zeka destekli eşli programlama (AI-assisted pair programming) süreçleriyle geliştirilmiştir.

Klasik tek dosyalık hantal betiklerin aksine; arayüz tasarımı, çekirdek analiz motorları ve tehdit imza kuralları birbirinden tamamen bağımsız katmanlar halinde kurgulanmıştır. Hem siber güvenlik meraklılarının yerel ortamda güvenli dosya incelemesi yapabilmesi hem de tersine mühendislik (reverse engineering) süreçlerinde hızlı triyaj sağlaması hedeflenmiştir.

---

## 🚀 Temel Özellikler

* **Hibrit Tehdit Doğrulaması (VirusTotal API v3):**
  * Yüklenen dosyaların `SHA-256` özetini anlık olarak 70+ antivirüs motoruyla karşılaştırır (dosya gizliliğini korumak için önce yalnızca hash sorgulanır).
  * Veritabanında hiç kaydı bulunmayan (bilinmeyen) dosyaları tek tıkla VirusTotal sunucularına yükleyip canlı tarama sonucu alabilir.
  * **Tespit Eden AV Filtresi:** Temiz sonuç veren motorları gizleyerek yalnızca zararlı veya şüpheli uyarısı veren antivirüsleri ve imza adlarını ayrı bir tabloda listeler.
* **Derin Windows PE (Portable Executable) Analizi:**
  * `IMPHASH` (Import Hash) hesaplaması ile zararlı yazılım ailelerini gruplama.
  * `Authenticode` dijital imza (`SIGNED` / `UNSIGNED`) ve hedef mimari (`x86` / `x64`) kontrolü.
  * Import Address Table (IAT) üzerinden kritik Windows API çağrılarının (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `NtUnmapViewOfSection` vb.) tespiti.
* **Kayan Pencere Entropi Dağılım Grafiği:**
  * Dosyanın bayt ofsetleri boyunca Shannon Entropi değişimini interaktif **Plotly** grafiğiyle görselleştirerek `UPX`, `Themida` gibi araçlarla paketlenmiş (packed) veya şifrelenmiş bölümleri ortaya çıkarır.
* **MITRE ATT&CK & Gelişmiş IOC Çıkarımı:**
  * Harici `rules/signatures.json` kural tabanı üzerinden MITRE ATT&CK teknik eşleştirmesi.
  * Dosya içerisindeki gömülü `URL`, `IP`, `Windows Registry` anahtarları, kabuk komutları ve fidye yazılımı tespiti için `Bitcoin (BTC)` cüzdan adreslerinin ayrıştırılması.
* **Yerel Raporlama Merkezi & Çift Dil Desteği:**
  * Analiz edilen şüpheli dosyaları kalıcı JSON veritabanına (`reported_files.json`) kaydetme, listeleme ve yönetme.
  * Tek tıkla **Türkçe (TR)** ve **İngilizce (EN)** arayüz geçişi.

---

## 📂 Proje Mimarisi

```text
ThreatScope-Red/
├── main.py                  # Ana uygulama giriş noktası ve SOC arayüz akışı
├── baslat.bat               # Tek tıkla otomatik kurulum ve yerel sunucu başlatıcı
├── requirements.txt         # Bağımlı Python kütüphaneleri
├── README.md                # Proje dokümantasyonu
│
├── assets/
│   └── style.css            # Koyu kırmızı (Crimson Dark) SOC tema tasarımı
│
├── engine/
│   ├── __init__.py          # Paket tanımlayıcı
│   ├── pe_analyzer.py       # PE başlık, IMPHASH, imza ve kayan entropi motoru
│   ├── ioc_extractor.py     # Regex tabanlı IOC ve MITRE kural tarayıcı
│   └── vt_client.py         # VirusTotal API v3 sorgu ve yükleme istemcisi
│
└── rules/
    └── signatures.json      # Harici tehdit imzaları ve hassas API veritabanı
