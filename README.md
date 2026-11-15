<p align="center">
  <img src="preview.png" alt="DTH ThreatScope Red Banner" width="100%">
</p>

# 🛡️ DTH ThreatScope Red

**DTH ThreatScope Red**, şüpheli ikili dosyaları (`EXE`, `DLL`, `SYS`), zararlı betikleri (`PS1`, `BAT`, `VBS`, `PY`) ve kriptografik hash değerlerini kendi bilgisayarınızda (`127.0.0.1`) izole bir ortamda incelemenizi sağlayan, **VirusTotal API v3** destekli modüler bir statik ve hibrit zararlı yazılım analiz platformudur.

> **Developer & Architecture:** Made in **Guarbey** • **DTH Systems**

---

## 🎯 Projenin Amacı ve Yaklaşımı (Vibe Coding)

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

## ⚡ Adım Adım Kurulum ve Çalıştırma Rehberi

Uygulamayı kendi bilgisayarınızda (`localhost`) çalıştırmak için aşağıdaki iki yöntemden birini kullanabilirsiniz.

### Ön Gereksinim: Python Kurulumu
Bilgisayarınızda **Python 3.10 veya üzeri** kurulu olmalıdır.
1. [python.org/downloads](https://www.python.org/downloads/) adresinden Python kurulum dosyasını indirin.
2. Kurulum ekranının en altındaki **`"Add Python to PATH"`** kutucuğunu **mutlaka işaretleyin** ve **Install Now** butonuna basın.

---

### Yöntem 1: Tek Tıkla Otomatik Kurulum ve Başlatma (Windows - Önerilen)

Hiçbir terminal komutu yazmadan uygulamayı saniyeler içinde başlatabilirsiniz:

1. **Projeyi İndirin:** Bu sayfanın sağ üstündeki yeşil **`<> Code`** butonuna tıklayın ve **`Download ZIP`** seçeneğini seçin.
2. **Klasöre Çıkartın:** İnen `ThreatScope-Red-main.zip` dosyasına sağ tıklayıp **"Tümünü Ayıkla" (Extract All)** diyerek masaüstüne çıkartın.
3. **Başlatıcıyı Çalıştırın:** Çıkarttığınız klasörün içine girin ve **`baslat.bat`** dosyasına çift tıklayın.
4. **Otomatik Kurulum:** Açılan siyah-kırmızı terminal ekranı gerekli tüm Python kütüphanelerini (`streamlit`, `pefile`, `pandas`, `requests`, `plotly`) otomatik olarak kuracak ve varsayılan tarayıcınızda **`http://localhost:8501`** adresini otomatik olarak açacaktır.

*(Uygulamayı kapatmak istediğinizde terminal penceresini kapatmanız veya klavyeden `CTRL + C` tuşlarına basmanız yeterlidir.)*

---

### Yöntem 2: Terminal / Manuel Kurulum (Windows, Linux, macOS)

Projeyi komut satırı üzerinden klonlayıp manuel kurmak için aşağıdaki adımları sırasıyla uygulayın:

**1. Depoyu bilgisayarınıza klonlayın ve klasöre girin:**
```bash
git clone [https://github.com/MehmetKerrti/ThreatScope-Red.git](https://github.com/MehmetKerrti/ThreatScope-Red.git)
cd ThreatScope-Red
