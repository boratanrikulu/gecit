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
- **Gateway MAC keşfi**: gateway MAC adresi çözülemezse sahte paket enjeksiyonu artık başlamaz. Bu durum ağa yeni bağlandıktan hemen sonra olursa gateway'e bir kez erişip (ör. `ping`) tekrar deneyin.
- **Windows Defender**: gecit'i `Win32/Wacapew.A!ml` olarak işaretleyebilir (yanlış pozitif). gecit TUN arayüzü oluşturur, DNS'i değiştirir ve raw socket kullanır - Defender bu davranışları şüpheli bulur. İstisna ekleyin: Windows Güvenlik → Virüs ve tehdit koruması → Dışlamalar → gecit.exe ekleyin.
- **Yönetici olarak çalıştırın**: PowerShell'e sağ tıklayıp "Yönetici olarak çalıştır" seçin, ardından `.\gecit.exe run` çalıştırın.

## Kurulum

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

### Kaynaktan derleme

Go 1.24+ gereklidir. Linux için kernel 5.10+, clang ve llvm-strip gerekir. Windows için [Npcap SDK](https://npcap.com/guide/npcap-devguide.html) ve CGO gerekir.

```bash
git clone https://github.com/boratanrikulu/gecit.git
cd gecit

make gecit-linux-amd64    # Linux x86_64
make gecit-linux-arm64    # Linux ARM64
make gecit-darwin-arm64   # macOS Apple Silicon
make gecit-darwin-amd64   # macOS Intel
make gecit-windows-amd64  # Windows x86_64 (Npcap SDK gerekli)

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
```

### Parametreler

| Parametre | Varsayılan | Açıklama |
|-----------|-----------|----------|
| `--doh-upstream` | `cloudflare` | DoH upstream: hazır isim veya URL. Virgülle ayrılarak yedekleme sırası. |
| `--allow-plain-doh` | `false` | Düz HTTP DoH upstream kullanımına izin verir. Varsayılan olarak kapalıdır. |
| `--fake-ttl` | `8` | Sahte paket TTL değeri |
| `--mss` | `88` | TCP MSS (Linux) |
| `--ports` | `443` | Hedef portlar |
| `--allow-private-targets` | `false` | Private, loopback ve link-local hedeflere fake injection izni verir. Güvenlik için varsayılan kapalıdır. |
| `--interface` | otomatik | Ağ arayüzü |
| `-v` | kapalı | Ayrıntılı loglama |

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
- [ ] Otomatik TTL tespiti (DPI hop sayısını bulmak için traceroute)
- [ ] ECH (Encrypted Client Hello) desteği

## Lisans

GPL-3.0. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

Telif Hakkı (c) 2026 Bora Tanrikulu \<me@bora.sh\>
