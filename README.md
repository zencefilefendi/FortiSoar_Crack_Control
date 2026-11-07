# FortiSOAR & FortiGate VM Deep Forensic Audit Suite (`fsr-forensic-verdict`)

[![CI](https://github.com/zencefilefendi/FortiSoar_Crack_Control/actions/workflows/ci.yml/badge.svg)](https://github.com/zencefilefendi/FortiSoar_Crack_Control/actions/workflows/ci.yml)
![Language: Rust 2021](https://img.shields.io/badge/Language-Rust_2021-orange.svg)
![Zero External Crates](https://img.shields.io/badge/Dependencies-Zero_External_Crates-brightgreen.svg)
![Forensic Engines: 19 Core + 3 OVA](https://img.shields.io/badge/Forensic_Engines-19_Core_%2B_3_OVA-blue.svg)
![cyops--auth Layers: 11](https://img.shields.io/badge/cyops--auth_Layers-11_Invariants-0284c7.svg)
![False Positive Design: Structural Invariant Based](https://img.shields.io/badge/False_Positive_Design-Structural_Invariant_Based_(Low_FP)-10b981.svg)
![Merkle Evidence: RFC 6962](https://img.shields.io/badge/Evidence_Seal-RFC_6962_Merkle_Tree-purple.svg)
![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-informational.svg)

RHEL/Rocky Linux 8/9 (`x86_64`) üzerinde çalışan FortiSOAR ve FortiGate VM sanal cihazlarında yapılan lisans doğrulama müdahalelerini (cracking), `/opt/cyops-auth/server/csdassrv.py` ve Python başlangıç kancaları üzerinden Cython `.so` (`handlerworkers/license.so`) gölgeleme, Tornado `RequestHandler._execute` baypası, bellek içi yamalama (`libssl.so.3` / `pam_unix.so`), donanım kimliği taklidi (UUID/MAC spoofing), Python `.pyc` bytecode manipülasyonu, sahte FortiGuard (FDN/FDS) emülatörleri, klonlanmış "Golden Image" dağıtımları, tedarik zinciri arka kapıları (connector credential skimmers) ve OVA/VMDK imaj müdahalelerini tespit eden **sıfır harici küfe (zero external crate)** ilkeli, **yapısal değişmez temelli (tasarım gereği düşük yanlış pozitif)** adli bilişim (DFIR) ve tehdit atıf çalışma alanı.

---

## 0. Kurumsal Ekipler İçin 10 Saniyede Anlık Crack Kontrolü ve Görsel Dashboard

Herhangi bir teknik parametre bilmeye gerek kalmadan, teslim alınan bir FortiSOAR/FortiGate cihazının, `/opt/cyops-auth` klasörünün veya `.ova` kurulum dosyasının **orijinal mi yoksa müdahaleli (crackli) mi** olduğunu **Görsel Web Dashboard** veya **Tek Satır Komut** üzerinden doğrulayabilirsiniz:

### Yöntem 1: Sıfır Kurulumlu "Sürükle-Bırak" Görsel Dashboard (`dashboard/index.html`)
Hiçbir derleme veya sunucu kurulumu yapmadan repodaki `dashboard/index.html` dosyasına çift tıklayarak tarayıcınızda (Chrome / Edge / Firefox) açın:
- `/opt/cyops-auth` klasörünü, `.ova` / `.mf` imajını veya şüpheli `.py`, `das.ini`, `das_prod.sql`, `fdnclient.jar`, `.so` dosyalarını doğrudan **tarayıcı ekranına sürükleyip bırakın**.
- **11-Katmanlı Derin Denetim Matrisi** üzerinde hangilerinin temiz (`DOĞRULANDI`), hangilerinin müdahaleli (`CRACK / İHLAL`) olduğunu anında görün ve tek tıkla **Kurumsal Teknik Bütünlük ve Denetim Tutanağı (A4/PDF)** çıktısı alın.

### Yöntem 2: Canlı Sunucu Portalı ve Tek Komutla Otomatik Denetim
```bash
# A) Canlı 19+3 Motorlu Görsel Web Denetim Dashboard'unu Başlat (Tarayıcı: http://127.0.0.1:8090)
./scripts/fortisoar_crack_kontrol.sh --portal 127.0.0.1:8090

# B) SSH Üzerinden Tek Komutla Otomatik Algılamalı Hızlı Kontrol (Canlı Cihaz, /opt/cyops-auth veya .ova İmajı)
./scripts/fortisoar_crack_kontrol.sh /
# veya doğrudan ikili üzerinden:
./target/release/fsr-forensic-verdict --quick-check /opt/cyops-auth
./target/release/fsr-forensic-verdict --quick-check /mnt/FortiSOAR_Appliance.ova

# C) Özel Sürüm Etiketli Baseline Manifest ile Denetim (örn. FortiSOAR 7.4.x veya 7.6.x)
./target/release/fsr-forensic-verdict --root / --baseline baselines/fortisoar-7.6.x.json

# D) Resmi "Kurumsal Teknik Bütünlük ve Denetim Tutanağı" (A4/PDF) Üretimi
./target/release/fsr-forensic-verdict --quick-check / --format denetim-tutanagi -o denetim_tutanagi.html
```

---

## 1. Çalışma Alanı Mimarisi (8 Paket / 19 Çekirdek + 3 OVA/Atıf Motoru)

Standart disk/dizin denetimlerinde (`--root`) **Faz 1–4 kapsamındaki 19 çekirdek motor** çalışır (`bundle.engines.len() == 19`). `--inspect-ova` veya `--attribute-cracker` etkinleştirildiğinde **Faz 8 kapsamındaki 3 OVA/Atıf motoru** devreye girerek toplam **22 adli motor** çalıştırılır. Her faz `std::panic::catch_unwind` hata izolasyon sınırıyla (`execute_isolated_engine_task`) korunur; tek bir bozuk/eksik dosya hiçbir zaman tüm denetimi çökertmez (`LOW_ENGINE_EXECUTION_FAULT_ISOLATED`).

| Faz | Paket Adı | Motor Sayısı | Kapsam ve Tespit Motorları |
| :---: | :--- | :---: | :--- |
| **Faz 1** | `fsr-deep-audit` | 4 Çekirdek | Raw `asm!` Syscall UUID/MAC Hook (`hw_integrity`), ELF64 `.text` Disk vs. VMA Diff (`elf_vma_diff`), PEP 552 `.pyc` & Marshal AST (`pyc_inspector`), SQLite3 B-Tree `rpmdb.sqlite` (`rpm_forensics`) |
| **Faz 2** | `fsr-net-crypto-audit` | 5 Çekirdek | DNS/Netfilter/eBPF Yönlendirme (`net_hijack`), X.509 ASN.1 DER & Rogue CA SPKI (`rogue_ca_audit`), FortiGate VM Config/Bileşen Analizi (`fgt_vm_auditor`), Aktif TLS 1.2/1.3 & DNS Sondajı (`live_fdn_probe`), eBPF/auditd/kprobes Denetimi (`ebpf_socket_probe`) |
| **Faz 3** | `fsr-clone-cluster-audit` | 5 Çekirdek | PostgreSQL `pg_control` & EXT4/XFS/Vault Doğum Lekesi (`birthmark_extractor`), `faketime` / `wtmp` Monotonik Saat Analizi (`time_tamper_audit`), `FGVM` Lisans Grameri (`fgvm_license_analyzer`), Klon Kümeleme (`clone_cluster_engine`), Aktif TLS/HTTP JARM/ETag Parmak İzi (`remote_fingerprinter`) |
| **Faz 4** | `fsr-supplychain-backdoor-audit` | 5 Çekirdek | SOAR Konnektör/Playbook AST Skimmer (`connector_skimmer_audit`), Sürüm-Etiketli `cyops-auth` / Django / Nginx Denetçisi (`web_auth_backdoor`), PostgreSQL Trigger & `COPY TO PROGRAM` (`postgres_persistence`), `authorized_keys`/`systemd`/PAM/cron (`os_persistence_audit`), FortiGate `admin-ssh-grace-time` & TACACS+ (`fortigate_backdoor_audit`) |
| **Faz 5** | `fsr-forensic-verdict` | Komuta Merkezi | `catch_unwind` Hata İzolasyonlu 19+3 Motor Orkestrasyonu, Salt-Okunur Müdahalesizlik Tutanağı (`readonly_attestation`), RFC 6962 İkili Merkle Ağacı (`merkle_evidence`), 3 Nedensel Teknik Sentez (`verdict_classifier`), JSON/NDJSON/Markdown/HTML Raporlayıcı (`report_emitter`) ve Çevrimdışı Doğrulayıcı (`bundle_verifier`) |
| **Faz 6** | `fsr-qa-fixture-harness` | QA / CI | Temiz Fabrika Düğümü (`0/100` risk, `0` bulgu) ile Klonlanmış/Yamalanmış Kurum Kümelerini (`org_alpha_node`, `org_beta_node`) sentezleyen deterministik kıyaslama çatısı |
| **Faz 7** | `fsr-remediation-advisor` | IR & Öz-Zırh | Parola okumadan (`secrets_read_count: 0`) P0–P2 Kasa Rotasyon Envanteri (`compromised_vault_inventory`), Canlı `nftables`/`iptables`/FortiOS Karantina Komutları (`containment_commands`), Temiz Playbook Göç Arındırıcısı (`clean_migration_sanitizer`) ve `/proc/self/exe` Öz-Doğrulama Zırhı (`self_integrity`) |
| **Faz 8** | `fsr-ova-attribution` | +3 OVA/Atıf | Mount Etmeden POSIX `ustar` OVA/OVF & `.mf` Denetçisi (`ova_stream_inspector`), VMDK4 (`KDMV`)/QCOW2 & RFC 1951 DEFLATE İkili Kazıyıcı (`vmdk_carver`), `CKIT-SHA256-...` Kırıcı Kit DNA Atıf Motoru (`cracker_attribution`) |

### 1.1 FortiSOAR (`/opt/cyops-auth`) 11-Katmanlı Yapısal Değişmez Matrisi ve Sürüm-Etiketli Baseline Manifestleri (`baselines/*.json`)

Orijinal FortiSOAR (`cyops-auth`) mimarisinde iş mantığının tamamı Cython ile derlenmiş `.so` (`\x7fELF`) modüllerindedir; düz metin (`.py`) olarak yalnızca giriş betikleri ve yalnızca telif docstring'i içeren `__init__.py` dosyaları bulunur.

**Sürüm Kırılganlığına Karşı Koruma (`baselines/fortisoar-7.6.x.json` & `baselines/fortisoar-7.4.x.json`):**
Fortinet yeni bir yama veya minör sürüm çıkardığında giriş betiği veya `__init__.py` sayılarının değişmesi nedeniyle temiz bir cihazın yanlışlıkla crackli sanılmasını önlemek için:
1. Giriş betikleri, izin verilen `import` listeleri ve `__init__.py` envanteri koda sabit gömülmek yerine sürüm-etiketli **`baselines/fortisoar-7.6.x.json`** ve **`baselines/fortisoar-7.4.x.json`** manifest dosyalarından (veya `--baseline <FILE>` / `FSR_BASELINE_MANIFEST` parametresinden) okunur.
2. Denetçi hedef sistemin sürümünü (`server/das.ini`, `ui_Config.json` veya `.rpm` bilgisinden) otomatik algılar ve rapora hangi baseline profiline karşı denetim yaptığını (`baseline_profile_id`, `detected_target_version`) yazar.
3. Bilinmeyen daha yeni bir FortiSOAR sürümünde `server/` dizinine yabancı bir `.py` dosyası bırakılmamışsa, yeni bir `import` satırı doğrudan `CRITICAL` crack hükmü üretmez; **`MEDIUM_CYOPS_ENTRYPOINT_IMPORT_VERSION_DRIFT`** (sürüm sapması uyarısı) olarak işaretlenir.

| Katman | Hedef Bileşen / Vektör | Tespit Edilen Müdahale / Crack Tekniği | Üretilen Adli Bulgu Kodu (`Rule ID`) |
| :---: | :--- | :--- | :--- |
| **1** | Python Başlangıç Kancası & `sys.modules` / Tornado | `sys.modules['handlerworkers.license']` Cython `.so` gölgelemesi ve Tornado `RequestHandler._execute` lisans baypas yaması | `CRITICAL_PYTHON_SITE_STARTUP_HOOK_BACKDOOR`<br>`CRITICAL_FORTISOAR_DAS_TORNADO_LICENSE_BYPASS` |
| **2** | Düz Metin Giriş Betikleri (`server/csdassrv.py` vb.) | Baseline manifestte tanımlı giriş betiklerine (`csdassrv.py`, `licensemanager.py` vb.) eklenen yetkisiz `import` kancaları, yabancı `.py` dosyaları veya sürüm sapmaları | `CRITICAL_CYOPS_SERVER_UNAUTHORIZED_IMPORT_HOOK`<br>`CRITICAL_CYOPS_SERVER_ROGUE_SCRIPT_DROP`<br>`MEDIUM_CYOPS_ENTRYPOINT_IMPORT_VERSION_DRIFT` |
| **3** | `__init__.py` Paket Başlatıcıları | Fabrika çıkışında yalnızca Fortinet telif docstring'i içeren `__init__.py` dosyalarına gömülen çalıştırılabilir gizli kodlar | `HIGH_CYOPS_INIT_PY_CODE_INJECTION` |
| **4** | `.env/.../site-packages/*.pth` | Yorumlayıcı açılışında otomatik `exec()` çalıştıran `import ...` satırlı `.pth` başlangıç kancaları | `CRITICAL_PYTHON_PTH_STARTUP_HOOK` |
| **5** | Canlı `/auth/license` HTTP Yanıtı | Aynı JSON içinde hem camelCase (`eulaAccepted`) hem snake_case (`is_eula_accepted`) dönen `_SC_LICENSE_PAYLOAD` ve `FSRVMPTM99999999` / `999` kullanıcı imzası | `CRITICAL_LIVE_DAS_TORNADO_LICENSE_INTERCEPT_ACTIVE` |
| **6** | `/opt/cyops-auth/bin/fdnclient.jar` | `fdnclient.jar` arşivinin geçerli `PK\x03\x04` (ZIP/JAR) başlığını kaybetmesi, `#!` betiğiyle değiştirilmesi veya sahte seri numarası içermesi | `CRITICAL_CYOPS_FDNCLIENT_JAR_TAMPERED` |
| **7** | `/opt/cyops-auth/utilities/das.ini` | `hmac_ready = False` yapılarak servisler arası `dashmac/hmacauthorizer.so` doğrulamasının kapatılması veya anahtar yollarının `/tmp` / `/dev/shm` altına yönlendirilmesi | `CRITICAL_CYOPS_DAS_INI_AUTH_BYPASS` |
| **8** | `/opt/cyops-auth/.env/bin/python*` & `activate` | Sanal ortam Python ikilisinin `\x7fELF` yerine `#!` wrapper betiğiyle değiştirilmesi veya `activate` içine `PYTHONSTARTUP` / `LD_PRELOAD` gömülmesi | `CRITICAL_CYOPS_VENV_INTERPRETER_HIJACK` |
| **9** | `licensemanager.py` & `utilities/ha/listener.py` | `validate_license_before_deployment()` çağrısının silinmesi veya HA küme dinleyicisindeki `LIST_OF_SUPPORTED_CMDS` komut beyaz listesinin kaldırılması | `CRITICAL_CYOPS_UTILITY_SCRIPT_TAMPERED` |
| **10** | `sql/das_prod.sql` & `sql/migration/*.sql` | PostgreSQL `SUPERUSER` yetkisiyle çalışan SQL dosyalarına fabrika dışı kullanıcı (`INSERT INTO users`), sahte lisans (`INSERT INTO license`) veya `COPY ... PROGRAM` eklenmesi | `CRITICAL_CYOPS_SQL_SEED_OR_MIGRATION_TAMPER` |
| **11** | Cython `.so` İkilileri (`license.so`, `fdnclient.so` vb.) | Derlenmiş `.so` modüllerinin `\x7fELF` olmayan dosyalarla, `__pyx_` Cython ABI sembolleri taşımayan sahte C kütüphaneleriyle değiştirilmesi veya bellekte (`/proc/<pid>/maps`) gölgelenmesi | `CRITICAL_CYOPS_CYTHON_SO_BINARY_REPLACED`<br>`CRITICAL_LIVE_CYTHON_SO_SYS_MODULES_GHOSTING` |

---

## 2. Saha Dağıtımı İçin Air-Gapped Paketleme ve Mührü Sabitleme

Projede sıfır harici C/Rust bağımlılığı bulunduğu için, sahaya giderken hedef RHEL/Rocky 8/9 cihazdaki `glibc` sürümünden etkilenmeyen taşınabilir `release` ikililerini derleyip salt-okunur (write-protected) bir USB belleğe mühürleyebilirsiniz (`scripts/package_airgapped_usb.sh` veya doğrudan aşağıdaki komutlarla):

```bash
# 1. Hedef Linux x86_64 mimarisi için tüm çalışma alanını derle ve sembolleri temizle
cargo build --workspace --release
strip target/release/fsr-forensic-verdict \
      target/release/fsr-remediation-advisor \
      target/release/fsr-ova-attribution \
      target/release/fsr-qa-fixture-harness

# 2. Saha USB belleğine kopyalanacak ikililerin SHA-256 özet manifestosunu üret (Öz-Doğrulama Zırhı için)
sha256sum target/release/fsr-* > /mnt/ir_usb_ro/fsr-suite-manifest.sha256
```

---

## 3. Uçtan Uca Saha Operasyon Prosedürü (SOP)

Bir kuruma, bankaya veya veri merkezine denetime gidildiğinde uygulanan 4 aşamalı standart akış:

### Aşama 1: Kurulum Öncesi Teslim Edilen `.ova` İmajının Mount Edilmeden Denetimi

Entegratörün kuruma teslim ettiği kurulum arşivini sunucuya hiç yüklemeden ve `root` yetkisi bile kullanmadan doğrudan kullanıcı alanında inceleyin:

```bash
./fsr-forensic-verdict \
  --inspect-ova /mnt/evidence/FortiSOAR_Appliance.ova \
  --attribute-kit \
  --org-label "Kurum_Prod_OVA" \
  --format json --pretty \
  -o /mnt/ir_evidence/01_ova_zero_mount_verdict.json
```

### Aşama 2: Çalışan Cihazın veya Disk İmajının Öz-Doğrulama Zırhıyla Tam Denetimi

Kırık sistemdeki olası `LD_PRELOAD` kancalarına karşı `--expected-self-sha256` bayrağıyla tüm motorları çalıştırın ve diğer kurum telemetrileriyle çapraz kümelemeye sokun:

```bash
./fsr-forensic-verdict \
  --root / \
  --baseline baselines/fortisoar-7.6.x.json \
  --expected-self-sha256 "$(grep 'fsr-forensic-verdict$' /mnt/ir_usb_ro/fsr-suite-manifest.sha256 | awk '{print $1}')" \
  --fgt-config /mnt/evidence/fortigate_backup.conf \
  --fgt-lic /mnt/evidence/fgvm.lic \
  --cluster-input /mnt/ir_usb_ro/known_pirated_clusters.ndjson \
  --attribute-cracker \
  --org-label "Kurum_Canli_SOAR" \
  --format json --pretty \
  -o /mnt/ir_evidence/02_full_forensic_bundle.json
```

### Aşama 3: CISO Sunumu ve Acil Müdahale / Kasa Rotasyon Planı Üretimi

Kanıt zarfından hem Yönetim Kurulu ihlal dosyasını hem de parolalara hiç dokunmadan (`secrets_read_count: 0`) hazırlanan P0–P2 API anahtarı rotasyon ve `nftables` karantina planını üretin:

```bash
# CISO ve Yönetim Kurulu için çevrimdışı (PDF'e hazır) HTML İhlal Raporu
./fsr-forensic-verdict \
  --root / \
  --format html \
  -o /mnt/ir_evidence/03_executive_breach_dossier.html

# Olay Müdahale Ekibi için Karantina, Kasa Rotasyonu ve Temiz Playbook Göç Planı
./fsr-forensic-verdict \
  --generate-remediation-plan /mnt/ir_evidence/02_full_forensic_bundle.json \
  --format html \
  -o /mnt/ir_evidence/04_ciso_remediation_plan.html
```

### Aşama 4: Hukuki Süreç ve Bilirkişi Önünde Bağımsız Kanıt Doğrulaması

Mahkemede veya üçüncü taraf incelemesinde hedef cihaza hiç bağlanmadan RFC 6962 Merkle kök özetini, dahiliyet kanıtlarını ve `target_mutated: false` tutanağını doğrulayın:

```bash
./fsr-forensic-verdict --verify-bundle /mnt/ir_evidence/02_full_forensic_bundle.json
```

---

## 4. Teknik Sentez ve Hukuki / Uyumluluk Konumlandırması (Bilirkişi & Mahkeme Kabul Edilebilirliği)

> **Adli Metodoloji ve Hukuki Sınır İlkesi:** Bu araç yalnızca **deterministik teknik bulgular, kriptografik kanıt özetleri ve çok katmanlı yapısal anomali korelasyonları** üretir. Bulguların hukuki nitelendirilmesi (*kusur*, *kast*, *sözleşme ihlali* veya *suç vasfı*), ilgili kurumların hukuk müşavirlikleri, bağımsız bilirkişi heyetleri ve yargı mercilerinin takdirindedir.

1. **Çok Katmanlı Lisans Doğrulama Müdahalesi Korelasyonu (`VERDICT_WILFUL_LICENSE_CRACK_AND_CLONE`):** Hem ELF64 ikilisinde `endbr64 + xor eax,eax; ret` (veya `mov eax,1; ret`) yaması olması, hem Python `.pyc` sabit havuzunun kısa devre edilmesi, hem de sahte CA gömülmesi rutin bir sistem yönetimi veya yapılandırma hatasıyla teknik olarak açıklanamaz; çok katmanlı sistem dışı müdahaleye işaret eden teknik bulgular bütünüdür.
2. **Tedarik Zinciri ve Veri Güvenliği Riski (`VERDICT_ACTIVE_SUPPLY_CHAIN_IMPLANT`):** Klonlanmış OVA nedeniyle `CRITICAL_SHARED_SOAR_VAULT_MASTER_KEY` veya konnektör skimmer (`CRITICAL_CONNECTOR_CREDENTIAL_SKIMMER`) tespit edilmesi, kurumun SOAR kasasında saklanan Active Directory ve güvenlik duvarı kimlik bilgilerinin dış ortamda çözülebilme riskini teknik olarak ortaya koyar (KVKK m.12, GDPR Art.32 ve sektörel bilgi güvenliği denetimleri kapsamında değerlendirilmek üzere raporlanır).
3. **Ortak Araç Seti / İmaj Köken Korelasyonu (`CRITICAL_SAME_CRACKER_TOOLKIT_ATTRIBUTION`):** Farklı zamanlarda kurulmuş sistemlerin aynı `CKIT-SHA256-...` kriptografik parmak izini taşıması, müdahalelerin aynı araç setinden veya ortak bir "Golden Image" kaynağından türetildiğini teknik olarak belgeler.
