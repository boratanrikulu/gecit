# gecit

DPI bypass aracı. Sahte TLS ClientHello paketleri göndererek Derin Paket İnceleme (DPI) cihazlarını yanıltır. Dahili DoH DNS sunucusu ile DNS zehirlemesini de atlatır.

**Linux**: eBPF sock_ops - doğrudan kernel TCP yığınına bağlanır. Proxy yok, trafik yönlendirme yok.  
**macOS/Windows**: TUN tabanlı şeffaf proxy - sanal ağ arayüzü ile tüm trafiği IP katmanında yakalar.

```
sudo gecit run
```

> **Sorumluluk Reddi**: Bu proje yalnızca eğitim ve araştırma amaçlıdır. IP adresinizi gizlemez, trafiğinizi şifrelemez, anonimlik sağlamaz. Kullanım tamamen kendi sorumluluğunuzdadır. Kullanıcılar kendi yetki alanlarındaki tüm yasalara uymakla yükümlüdür.

## Nasıl çalışır

```
Uygulama hedef:443'e bağlanır
    ↓
gecit bağlantıyı yakalar
  Linux:  eBPF sock_ops tetiklenir (kernel içinde, uygulama veri göndermeden önce)
  macOS/Windows: TUN cihazı paketi yakalar, gVisor netstack TCP'yi sonlandırır
    ↓
Düşük TTL ile sahte ClientHello gönderilir (SNI: "www.google.com")
    ↓
Sahte paket DPI'a ulaşır → DPI "google.com" kaydeder → bağlantıya izin verir
Sahte paket sunucuya ulaşamaz (düşük TTL) → sunucu görmez
    ↓
Gerçek ClientHello geçer → DPI zaten yanıltılmış
```

Bazı ISP'ler TLS ClientHello'daki SNI alanını inceleyerek belirli alan adlarını tespit edip engeller. gecit, gerçek ClientHello'dan önce farklı bir SNI (`www.google.com`) ve düşük TTL ile sahte bir ClientHello gönderir. DPI sahte paketi işler ve bağlantıya izin verir. Sahte paket düşük TTL nedeniyle sunucuya ulaşmadan yok olur.

Bazı ISP'ler DNS yanıtlarını da zehirler. gecit, dahili DoH sunucusu ile DNS sorgularını şifreli HTTPS üzerinden çözer.

## Gereksinimler

| | Linux | macOS | Windows |
|---|---|---|---|
| **İşletim Sistemi** | Kernel 5.10+ | macOS 12+ (Monterey) | Windows 10+ |
| **Yetki** | root / sudo | root / sudo | Yönetici |
| **Bağımlılık** | Yok | Yok | [Npcap](https://npcap.com) |

### Windows notları

- **Npcap**: [npcap.com](https://npcap.com/#download) adresinden indirip kurun. seq/ack çıkarma ve sahte paket enjeksiyonu için gereklidir.
- **Windows Defender**: gecit'i `Win32/Wacapew.A!ml` olarak işaretleyebilir (yanlış pozitif). gecit TUN arayüzü oluşturur, DNS'i değiştirir ve raw socket kullanır - Defender bu davranışları şüpheli bulur. İstisna ekleyin: Windows Güvenlik → Virüs ve tehdit koruması → Dışlamalar → gecit.exe ekleyin.
- **Yönetici olarak çalıştırın**: PowerShell'e sağ tıklayıp "Yönetici olarak çalıştır" seçin, ardından `.\gecit.exe run` çalıştırın.
- **İmzasız kurulum dosyası**: gecit'in kod imzalama sertifikası yok, bu yüzden SmartScreen uyarı gösterir. "Ek bilgi" → "Yine de çalıştır" deyin.

## Kurulum

### Paket yöneticileri

```bash
# macOS
brew install boratanrikulu/tap/gecit
```

Dağıtımınıza uygun paketi
[releases](https://github.com/boratanrikulu/gecit/releases) sayfasından indirin:

```bash
# Debian, Ubuntu
sudo dpkg -i gecit_*_linux_amd64.deb

# Fedora, RHEL
sudo rpm -i gecit_*_linux_amd64.rpm

# Alpine
sudo apk add --allow-untrusted gecit_*_linux_amd64.apk
```

Paketler hem amd64 hem arm64 için var. deb ve rpm, `/usr/bin/gecit` ile
birlikte bir systemd servisi kuruyor ama servisi etkinleştirmiyor. Kurulum
sırasında DNS ayarlarınızın sessizce değişmesi doğru olmaz, paket yöneticisinin
de size soracak bir yolu yok:

```bash
sudo systemctl enable --now gecit
sudo systemctl status gecit
sudo systemctl stop gecit     # DNS'i geri alır
```

Paketi kaldırırken önce servis durduruluyor, DNS ayarlarınız da böyle geri
geliyor. `/etc/gecit/config.yaml` dosyasına dokunulmuyor.

Alpine'da systemd yok, o yüzden apk paketinden sadece binary çıkıyor. `sudo
gecit run` ile kendiniz çalıştırın, ya da OpenRC servisi yazın.

### Hazır binary'ler

[Releases](https://github.com/boratanrikulu/gecit/releases) sayfasından indirin:

```bash
# Linux (amd64)
curl -L https://github.com/boratanrikulu/gecit/releases/latest/download/gecit-linux-amd64 -o gecit
chmod +x gecit
sudo ./gecit run

# Linux (arm64)
curl -L https://github.com/boratanrikulu/gecit/releases/latest/download/gecit-linux-arm64 -o gecit
chmod +x gecit
sudo ./gecit run

# macOS (Apple Silicon)
curl -L https://github.com/boratanrikulu/gecit/releases/latest/download/gecit-darwin-arm64 -o gecit
chmod +x gecit
sudo ./gecit run

# macOS (Intel)
curl -L https://github.com/boratanrikulu/gecit/releases/latest/download/gecit-darwin-amd64 -o gecit
chmod +x gecit
sudo ./gecit run

# Windows (amd64) - Npcap gerekli (npcap.com)
curl -L https://github.com/boratanrikulu/gecit/releases/latest/download/gecit-windows-amd64.exe -o gecit.exe
gecit.exe run
```

### Windows kurulum dosyası

MSI, gecit'i `C:\Program Files\gecit` altına kurar, Windows servisi olarak
kaydeder, `PATH`'e ekler ve varsayılan bir config dosyası yazar.
`gecit-<sürüm>-amd64.msi` dosyasını [releases](https://github.com/boratanrikulu/gecit/releases)
sayfasından indirin.

Önce Npcap'i kurun. Lisansı yeniden dağıtıma izin vermediği için MSI onu
içinde taşıyamaz, Npcap yoksa kurulum başlamaz.

Kurulum sırasında gecit'in açılışta başlayıp başlamayacağı, DoH upstream'i ve
sahte paket TTL'i sorulur. Kutuyu işaretlemezseniz servis kaydedilir ama
çalıştırılmaz.

Sessiz kurulum için:

```powershell
msiexec /i gecit-0.1.4-amd64.msi /qn DOHUPSTREAM=quad9 FAKETTL=12
msiexec /i gecit-0.1.4-amd64.msi /qn AUTOSTART=0
```

Kaldırmak için Program Ekle/Kaldır, ya da
`msiexec /x gecit-0.1.4-amd64.msi /qn`. Kaldırma önce DNS ve route'ları eski
haline döndürür. Config dosyanız ve loglar yerinde kalır.

### Kaynaktan derleme

Go 1.24+ gereklidir. Linux için kernel 5.10+, clang ve llvm-strip gerekir. Windows derlemesi saf Go, her platformdan cross-compile edilir.

```bash
git clone https://github.com/boratanrikulu/gecit.git
cd gecit

make gecit-linux-amd64    # Linux x86_64
make gecit-linux-arm64    # Linux ARM64
make gecit-darwin-arm64   # macOS Apple Silicon
make gecit-darwin-amd64   # macOS Intel
make gecit-windows-amd64  # Windows x86_64

sudo ./bin/gecit-linux-arm64 run
```

gecit her şeyi otomatik ayarlar:
- `127.0.0.1:53` üzerinde **DoH DNS sunucusu**
- **Sistem DNS'i** yerel DoH sunucusuna yönlendirilir
- **Linux**: eBPF programı cgroup'a bağlanır
- **macOS/Windows**: Otomatik yönlendirmeli TUN sanal arayüzü

Durdurmak için `Ctrl+C` - her şey geri yüklenir. Çökme durumunda: `sudo gecit cleanup`

## Kullanım

```bash
# Varsayılan (TTL=8, Cloudflare DoH)
sudo gecit run

# Google DoH kullan
sudo gecit run --doh-upstream google

# Birden fazla upstream (yedekleme sırası)
sudo gecit run --doh-upstream cloudflare,quad9

# Özel DoH URL
sudo gecit run --doh-upstream https://8.8.8.8/dns-query

# Özel TTL
sudo gecit run --fake-ttl 12

# Sistem yeteneklerini kontrol et
sudo gecit status

# Çökme sonrası geri yükleme
sudo gecit cleanup

# Hangi sürüm
gecit version
```

### Windows servisi

```powershell
gecit service install     # Windows'a kaydet, açılışta başlat
gecit service start
gecit service status
gecit service stop
gecit service restart
gecit service set-start --manual   # açılışta başlatma
gecit service uninstall
```

MSI bunları sizin yerinize yapar. Bu komutlar kurulum dosyası olmadan düz
`gecit.exe` kullananlar ve kurulu servisi sonradan değiştirmek isteyenler için.

Servis `C:\ProgramData\gecit\gecit.log` dosyasına yazar, 10 MB'da döner ve 3
dosya saklar. Başlatma, durdurma ve başlatma hataları ayrıca Windows Uygulama
olay günlüğüne `gecit` kaynağı altında düşer.

### Web paneli

`gecit run` aynı zamanda yerel bir panel açar: anlık sayaçlar, log akışı, sahte
paket gönderilen alan adları ve config dosyası bir form olarak.

```bash
sudo gecit run              # panel adresini token'ıyla birlikte yazar
sudo gecit status           # sonradan tekrar görmek için
sudo gecit run --panel=false
sudo gecit run --panel-addr 127.0.0.1:9000   # paneli başka bir porta taşı
```

Paneli `http://gecit.localhost:8088` adresinden açarsınız, gecit de bu adresi
yazar. `.localhost` altındaki her isim RFC 6761 ile ayrılmıştır ve tarayıcı
bunları kendisi loopback'e çözer: ne DNS kaydı ne hosts dosyası gerekir, geriye
temizlenecek bir şey kalmaz. `--doh=false` ile de, kendi DoH'unu kullanan bir
tarayıcıda da aynı şekilde çözülür. `http://127.0.0.1:8088` de aynı işi görür.

Panel `127.0.0.1:8088` adresine bağlanır ve loopback olmayan hiçbir adresi kabul
etmez. Port doluysa bu bir uyarıdır, hata değil: gecit panelsiz çalışmaya devam
eder. Her API isteği `/etc/gecit/panel.token` dosyasındaki token'ı ister
(Windows'ta `%ProgramData%\gecit\panel.token`); dosyayı yalnızca root ya da
Yöneticiler okuyabilir. Adresi bir kez açtığınızda tarayıcı token'ı saklar, sonrasında
adresin kendisi yeter. Panelin artık kabul etmediği bir token atılır ve sayfa
yenisini ister. Başka bir makineden erişmek için adresi değiştirmek yerine portu SSH
üzerinden yönlendirin.

Panelden motoru durdurup başlatabilirsiniz; config'i kaydetmek `config.yaml`
dosyasını baştan yazar. Uygula demek motoru yeniden başlatır, yani sistem DNS'i
önce geri verilir sonra tekrar alınır: bir saniyeliğine ad çözümlemesi durur.
Komut satırında verilen bir parametre yine dosyanın önüne geçer, panel de
hangi alanlar için geçtiğini yanlarında söyler.

Etkinlik listesi yalnızca bellekte durur ve gecit durduğunda kaybolur. İçinde
alan adları olduğu için bunu bilmekte fayda var. Log ayrı bir mesele: Windows'ta
servis logu `C:\ProgramData\gecit\gecit.log` dosyasına yazar, yani seviyenin
ürettiği her şey diskte kalır. DNS sorguları debug seviyesinde loglanır ve bu
seviye varsayılan olarak kapalıdır; panelden açtığınızda çözülen her alan adı o
dosyaya bir satır olarak düşer.

İlk çalıştırmada config dosyasının yanına `panel.token` oluşturulur. Dosyayı
silerseniz o güne kadar verilmiş bütün adresler geçersiz olur, bir sonraki
başlangıçta yenisi yazılır.

### Config dosyası

Windows'un başlattığı bir servisin komut satırı olmadığı için gecit ayarları
dosyadan okur. Elle verdiğiniz parametreler yine de dosyadakinin önüne geçer.

| Platform | Yol |
|---|---|
| Linux, macOS | `/etc/gecit/config.yaml` |
| Windows | `C:\ProgramData\gecit\config.yaml` |

```bash
gecit config path          # kullanılan yolu yazdır
gecit config init          # yorumlu varsayılanı yaz, var olanı ezmez
gecit --config ./my.yaml run
```

Config dosyası yoksa gecit yerleşik varsayılanlarıyla çalışır.

`config init` root ya da Yönetici ister: dosya, root veya LocalSystem olarak
çalışan bir süreci yapılandırdığı için yetkisiz bir kullanıcının
erişemeyeceği bir yere yazılır. Windows'ta dizin aynı sebeple açık bir ACL ile
oluşturulur.

`doh_upstream` ya bir preset adı ya da `https` URL olmalıdır. Şifresiz bir
upstream, makinedeki her sorguyu yoldaki herkese teslim eder, üstelik gecit
sistem çözücüsünü çoktan kendine yönlendirmiştir.

### Parametreler

| Parametre | Varsayılan | Açıklama |
|-----------|-----------|----------|
| `--doh` | `true` | Yerleşik DoH DNS çözücüyü etkinleştir |
| `--doh-upstream` | `cloudflare` | DoH upstream: hazır isim veya URL. Virgülle ayrılarak yedekleme sırası. |
| `--fake-ttl` | `8` | Sahte paket TTL değeri |
| `--mss` | `88` | TCP MSS (Linux) |
| `--restore-after-bytes` | `600` | N bayt sonra normal MSS'e dön (Linux) |
| `--restore-mss` | `0` | Geri dönülen MSS değeri, 0 = otomatik/1460 (Linux) |
| `--cgroup` | `/sys/fs/cgroup` | cgroup v2 yolu (Linux) |
| `--ports` | `443` | Hedef portlar |
| `--interface` | otomatik | Ağ arayüzü |
| `-v` | kapalı | Ayrıntılı loglama |
| `--panel` | `true` | Yerel web panelini aç |
| `--panel-addr` | `127.0.0.1:8088` | Panel adresi, yalnızca loopback |
| `--config` | platforma göre | Config dosyası yolu (Config dosyası bölümüne bakın) |

### DoH hazır ayarları

| İsim | Upstream |
|------|----------|
| `cloudflare` | `https://1.1.1.1/dns-query` |
| `google` | `https://8.8.8.8/dns-query` |
| `quad9` | `https://9.9.9.9:5053/dns-query` |
| `nextdns` | `https://dns.nextdns.io/dns-query` |
| `adguard` | `https://dns.adguard-dns.com/dns-query` |

### Doğru TTL'i bulmak

```bash
traceroute -n hedef.com
```

DPI genellikle ISP'nin ilk birkaç hop'unda bulunur. Varsayılan TTL=8 çoğu ağda çalışır.

## Platform farkları

| | Linux | macOS | Windows |
|---|---|---|---|
| **Motor** | eBPF sock_ops | TUN + gVisor netstack | TUN + gVisor netstack |
| **Sahte enjeksiyon** | Raw socket | Raw socket | Npcap ile raw socket |
| **DNS bypass** | DoH + `/etc/resolv.conf` | DoH + `networksetup` | DoH + `netsh` |
| **Root gerekli** | Evet | Evet | Evet (Yönetici) |

## SSS

**IP adresimi gizler mi?**
Hayır. ISP hangi IP'lere bağlandığınızı görebilir. gecit yalnızca TLS el sıkışmasındaki alan adının (SNI) okunmasını engeller.

**Tüm DPI'lara karşı çalışır mı?**
TCP yeniden birleştirme yapmayan DPI'lara karşı çalışır. Çin'deki gibi gelişmiş sistemler bu tekniği tespit edebilir.

**VPN mi bu?**
Hayır. Tünel yok, şifreleme yok, uzak sunucu yok. gecit tamamen yerel çalışır. macOS/Windows'ta TUN arayüzü kullanır (VPN altyapısına benzer) ama trafik doğrudan internete çıkar.

**Neden Linux'ta eBPF?**
eBPF kernel'in TCP yığınına eşzamanlı bağlanır - sahte paket, uygulama veri göndermeden önce yollanır. Proxy veya paket yakalamaya gerek kalmaz. Yalnızca el sıkışma userspace'e dokunur; veri kernel'de tam hızda akar.

**Neden macOS/Windows'ta TUN?**
Bu platformlar eBPF gibi kernel hook'ları sunmaz. TUN sanal arayüzü tüm trafiği IP katmanında yakalar ve eBPF ile aynı kapsamı sağlar - ancak trafik userspace üzerinden akar.

**Neden WinDivert kullanılmıyor?**
Windows'ta DPI bypass araçlarının çoğu WinDivert kullanır, ancak WinDivert'in kod imzalama sertifikası 2023'te sona erdi. Bu durum Windows Defender uyarılarına ve bazı sistemlerde sürücü yükleme hatalarına neden olur. gecit bunun yerine düzgün imzalanmış sürücülere dayanan TUN tabanlı bir yaklaşım kullanır.

## Mimari

### Linux (eBPF)

```
┌──────────┐   ┌────────────────────┐   ┌────────────┐
│ eBPF     │──>│ Perf Event Buffer  │──>│ Go         │
│ sock_ops │   │ (bağlantı bilgisi) │   │ goroutine  │
│          │   └────────────────────┘   │            │
│ MSS ayar │                            │ Raw socket │
│ per-conn │                            │ ile sahte  │
│          │                            │ gönderir   │
└──────────┘                            └────────────┘
     │                                        │
     ▼                                        ▼
┌────────────────────────────────────────────────────┐
│ Linux Kernel TCP Yığını                            │
│ (düşük MSS ile ClientHello fragmentasyonu)         │
└────────────────────────────────────────────────────┘
```

### macOS/Windows (TUN)

```
┌──────────┐   ┌────────────────────┐   ┌────────────┐
│ Uygulama │──>│ TUN cihazı         │──>│ gVisor     │
│ :443'e   │   │ (macOS'ta utun)    │   │ netstack   │
│ bağlanır │   └────────────────────┘   │ TCP'yi     │
│          │                            │ sonlandırır│
└──────────┘                            └────────────┘
                                              │
                                              ▼
                                        ┌────────────┐
                                        │ gecit      │
                                        │ handler    │
                                        │            │
                                        │ 1. Sunucu  │
                                        │    bağlan  │
                                        │ 2. Sahte   │
                                        │    enjekte │
                                        │ 3. Gerçeği │
                                        │    ilet    │
                                        │ 4. Pipe    │
                                        └────────────┘
```

## Yol Haritası

- [x] Linux - eBPF sock_ops
- [x] macOS - TUN şeffaf proxy
- [x] DoH DNS sunucusu
- [x] Windows - TUN şeffaf proxy
- [x] Yerel web paneli
- [x] Paketler - deb, rpm, apk, Homebrew tap, MSI
- [ ] Otomatik TTL tespiti (DPI hop sayısını bulmak için traceroute)
- [ ] ECH (Encrypted Client Hello) desteği

## Lisans

GPL-3.0. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

Telif Hakkı (c) 2026 Bora Tanrikulu \<me@bora.sh\>
