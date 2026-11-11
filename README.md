# Veritas Scanner

[English](#english) | [Türkçe](#türkçe)

---

<a name="english"></a>
## 🇬🇧 English

Professional forensic analysis and RAM memory scanner designed for Minecraft screenshare anticheat. Veritas Scanner detects both known cheat clients and hidden, subtle cheat modules through advanced memory signature mapping and process analysis.

### ⚠️ Important Notice
This tool reads process memory, which requires specific system permissions. Antivirus software may occasionally flag forensic and memory-scanning tools due to their low-level API usage.
- **False positives may occur on Windows Defender or third-party antiviruses.**
- Ensure you run the application with administrator privileges to allow full memory enumeration across active Java processes.

---

### How It Works

#### Javaw Memory Scanner
Veritas Scanner inspects the RAM of active `java.exe` and `javaw.exe` instances running on your system.
1. **Process Discovery:** Enumerates all active Java/Minecraft processes and establishes secure handles with read permissions (`PROCESS_VM_READ` and `PROCESS_QUERY_INFORMATION`).
2. **Memory Region Filtering:** Scans memory blocks via `VirtualQueryEx`, isolating committed (`MEM_COMMIT`) and readable memory spaces.
3. **Deep Pattern Matching & Hook Detection:** Reads memory buffers dynamically to scan for multi-pattern client signatures, behavioral anomalies, and class hook remnants.
4. **Detailed Classification:** Classifies results into **CLEAN**, **Client Flag** (specific cheat signatures), or **Generic Flag** (suspicious module behaviors).

---

### Detection Capabilities
Veritas Scanner covers a wide range of modern modifications:
- **Combat & Aim Modules:** AimAssist (smoothing/velocity anomalies), TriggerBot (entity tick trigger arrays), Kill Aura, Crystal Aura, Mace Aura, Reach, Hitbox Expansions, Velocity.
- **Movement & Utility:** Fast Place, Fast Break, Auto Clicker, Macros, Inventory Move, Sprint Modifications.

---

### System Requirements
- Windows OS (x64)
- **Administrator Privileges** (Required to read process memory and examine low-level hooks)
- .NET 10.0 Runtime (`--self-contained` package available)

---

<a name="türkçe"></a>
## 🇹🇷 Türkçe

Minecraft ekran paylaşımı (screenshare) ve hile incelemeleri için geliştirilmiş profesyonel adli bilişim analizi ve RAM bellek tarama aracıdır. Veritas Scanner; gelişmiş bellek imza haritalama ve süreç analizi sayesinde hem bilinen hile client'larını hem de gizli/sinsi modülleri tespit eder.

### ⚠️ Önemli Not
Bu araç, düşük seviyeli sistem izinleri gerektiren bellek okuma işlemlerini gerçekleştirir. Antivirüs yazılımları, kullandığı bu API'ler nedeniyle adli bilişim araçlarını şüpheli olarak işaretleyebilir.
- **Windows Defender veya üçüncü taraf antivirüslerde yanlış pozitif (false positive) uyarıları görülebilir.**
- Aktif Java süreçlerinin tamamını tarayabilmesi için uygulamayı mutlaka **Yönetici olarak** çalıştırdığınızdan emin olun.

---

### Nasıl Çalışır?

#### Javaw Bellek Tarayıcısı
Veritas Scanner, sisteminizde çalışan aktif `java.exe` ve `javaw.exe` süreçlerinin RAM'ini inceler.
1. **Süreç Keşfi:** Tüm aktif Java/Minecraft süreçlerini listeler ve okuma izinleriyle (`PROCESS_VM_READ` / `PROCESS_QUERY_INFORMATION`) güvenli bağlantılar kurar.
2. **Bellek Alanı Filtreleme:** `VirtualQueryEx` kullanarak bellek bloklarını tarar, yalnızca erişilebilir ve commit edilmiş alanları inceler.
3. **Derin İmza Eşleme ve Hook Tespiti:** Bellek tamponlarını dinamik olarak okuyarak çoklu imza client'larını, davranışsal anomalileri ve class hook kalıntılarını arar.
4. **Detaylı Sınıflandırma:** Sonuçları **TEMİZ (CLEAN)**, **Client Bayrağı** (özel hile imzaları) veya **Genel Bayrak** (şüpheli modül hareketleri) olarak sınıflandırır.

---

### Tespit Edilen Modüller
Veritas Scanner, güncel hile mimarilerini yakalamak için geniş bir imza havuzu sunar:
- **Savaş ve Nişan Modülleri:** AimAssist (açı ivmesi ve smoothing anomalileri), TriggerBot (entity tick tetikleyicileri), Kill Aura, Crystal Aura, Mace Aura, Reach, Hitbox Genişletme, Velocity.
- **Hareket ve Kolaylık Modülleri:** Fast Place, Fast Break, Auto Clicker, Makrolar, Envanterde Hareket (Inventory Move), Sprint Düzenlemeleri.

---

### Sistem Gereksinimleri
- Windows İşletim Sistemi (x64)
- **Yönetici Yetkileri** (Bellek okuma ve düşük seviyeli hook denetimleri için şarttır)
- .NET 10.0 Çalışma Zamanı (`--self-contained` sürümü mevcuttur)

---

## Security & Privacy / Güvenlik ve Gizlilik
- **100% Local Analysis:** No telemetry or user data is ever sent online. / İnternete hiçbir şekilde veri veya telemetri gönderilmez.
- **Read-Only Operation:** The scanner never modifies, writes to, or injects into target processes. / Tarayıcı, hedef süreçleri asla değiştirmez, yazmaz veya enjekte etmez.

## Contacts / İletişim
Developed and maintained by **Wh1fe** / **Ege**.
