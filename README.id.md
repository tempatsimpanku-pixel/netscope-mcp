# netscope-mcp

[![CI](https://github.com/tempatsimpanku-pixel/netscope-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/tempatsimpanku-pixel/netscope-mcp/actions/workflows/ci.yml)
[![Security](https://github.com/tempatsimpanku-pixel/netscope-mcp/actions/workflows/security.yml/badge.svg)](https://github.com/tempatsimpanku-pixel/netscope-mcp/actions/workflows/security.yml)
[![npm](https://img.shields.io/npm/v/netscope-mcp.svg)](https://www.npmjs.com/package/netscope-mcp)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/tempatsimpanku-pixel/netscope-mcp/badge)](https://securityscorecards.dev/viewer/?uri=github.com/tempatsimpanku-pixel/netscope-mcp)

**Beri LLM "mata" ke jaringan ISP Anda tanpa memberinya "tangan".**

`netscope-mcp` adalah server [MCP](https://modelcontextprotocol.io) **read-only ketat** untuk operator ISP/WISP. Asisten AI dapat memeriksa banyak router dan switch MikroTik RouterOS (v6/v7) sekaligus lewat resep diagnosis satu panggilan. Dukungan VyOS dan GenieACS direncanakan di v0.2.

> **Status:** v0.1; publikasi npm menyusul, sementara itu pasang dari tarball atau dari sumber. Demo 75 detik: [docs/DEMO.md](docs/DEMO.md) (bahasa Inggris).
> Tidak berafiliasi dengan MikroTik. "MikroTik" dan "RouterOS" adalah merek dagang pemiliknya.

## Masalah yang dipecahkan

Engineer NOC di ISP kecil menjawab pertanyaan yang sama sepanjang hari: *router ini sehat? kenapa level optik lemah? pelanggan X ada di router mana? apa yang tercolok di port ini?* Setiap jawaban berarti login ke beberapa router dan menjalankan beberapa perintah.

LLM bisa mengerjakan itu, tetapi memberinya login RouterOS dengan hak tulis berbahaya: satu perintah halusinasi seperti `/system reset-configuration` bisa menjatuhkan pelanggan. Karena itu `netscope-mcp` membuat yang aman menjadi satu-satunya jalan: read-only, secret disamarkan, dan ada panduan membuat user RouterOS read-only sebagai batas pertahanan sebenarnya. Teruji lewat 1.270+ tes otomatis (termasuk korpus keamanan 770 kasus allowlist) dan CI keamanan (gitleaks, CodeQL, Scorecard).

## Kenapa berbeda

- **Read-only, deny-by-default:** hanya `print`, `monitor … once`, `/<menu> export hide-sensitive`, `ping`, `traceroute` yang lolos; perintah tulis ditolak sebelum kredensial dimuat atau router dihubungi.
- **Secret disamarkan** di setiap keluaran (nama kunci, pola, dan nilai kredensial yang dikenal); isi skrip disamarkan penuh.
- **Resep diagnosis:** `health`, `neighbors-map`, `pppoe-lookup`.
- **Batch multi-router** (maks 30 perintah) tahan galat: satu router gagal tidak menggagalkan yang lain.
- **Snapshot opsional:** cari interface, neighbor, IP/MAC (dan nama PPP bila diaktifkan) di semua router dalam milidetik, dengan umur data selalu disebut.

## Mulai cepat

Butuh Node.js 24+.

1. Buat user RouterOS read-only: [docs/ROUTEROS-READONLY-USER.md](docs/ROUTEROS-READONLY-USER.md) (bahasa Inggris).
2. Pasang (dari tarball hasil `npm ci && npm run build && npm pack`):

```bash
npm install -g ./netscope-mcp-0.1.0.tgz
netscope-mcp --version
```

   Dari sumber tanpa memasang: `npm ci && npm run build`, lalu ganti `netscope-mcp` dengan `node dist/cli.js`.

3. Buat `routers.yaml` (contoh lengkap: [routers.example.yaml](routers.example.yaml)):

```yaml
routers:
  - id: core-1
    host: 192.0.2.10
    port: 8729
    family: routeros
    tls_fingerprint256: "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"   # ganti dengan pin SHA-256 router Anda (atau tls_ca_file: /path/ca.pem)
    credentials: { user_env: ROS_CORE1_USER, pass_env: ROS_CORE1_PASS }
```

4. Periksa konfigurasi lalu jalankan:

```bash
export ROS_CORE1_USER=netscope-ro
export ROS_CORE1_PASS='<password panjang acak>'
netscope-mcp --config ./routers.yaml --check   # "configuration OK: 1 router(s)."
netscope-mcp --config ./routers.yaml           # transport stdio
```

5. Sambungkan klien, contoh Claude Code:

```bash
claude mcp add netscope \
  --env ROS_CORE1_USER=netscope-ro --env ROS_CORE1_PASS='<password>' \
  -- netscope-mcp --config /path/to/routers.yaml
```

   Contoh Claude Desktop, Codex CLI, Cursor, dan mode HTTP ada di [README.md](README.md).

6. Coba tanya: *"Jalankan resep health di core-1, ada yang tidak wajar?"* atau *"Pelanggan alice@example.net tersambung di router mana?"*

## Diuji pada

Diuji hanya-baca pada perangkat nyata, 2026-10-22 (RouterOS API dengan runner SSH bawaan; SNMP v2c bila terjangkau).

| Perangkat | RouterOS / SwOS | Alat API, resep | `export` via SSH | SNMP |
|---|---|---|---|---|
| hEX RB750Gr3 (mmips) | 6.48.6 (long-term) | ya | belum diuji | tidak terjangkau di jaringan uji |
| RB450Gx4 (arm) | 7.12.1 (stable) | ya | belum diuji | tidak terjangkau di jaringan uji |
| hEX RB750Gr3 (mmips) | 7.24.4 (stable) | ya | belum diuji | ya |
| x86 (bare metal) | 7.23.8 (long-term) | ya (tanpa `/system routerboard`; `/system health` hanya `state=disabled`) | ya | ya |
| CRS310-1G-5S-4S+ (arm) | 7.23.5 (long-term) | ya (`switch_read`, kesehatan SFP) | ya | ya |
| CRS326-24S+2Q+ (mipsbe) | 7.23.5 dan 7.23.8 (long-term) | ya (`switch_read`, SFP, PSU/kipas) | ya | ya |
| CSS326-24G-2S+ | SwOS 2.16 | n/a (hanya SNMP) | n/a | ya (`switch_read` sysinfo, interfaces) |

- **RouterOS 6.x:** alat API berfungsi. **`export` lewat SSH di v6 dan RouterOS 6.49.x belum diuji** (belum ada perangkat dengan akses SSH); anggap belum terverifikasi.
- SNMP dan SSH butuh keterjangkauan jaringan dari host MCP: port-forward NAT yang hanya meneruskan port API membuat SNMP/SSH timeout. Kegagalan ini dilaporkan bersih dan tidak memengaruhi alat API.
- Fixture regresi format v6 dan v7 ada di `test/unit/compat.test.ts`.

## Keamanan singkat

- Penjaga di sisi alat hanyalah satu lapisan, **bukan sandbox**. Selalu pakai akun RouterOS ber-policy read-only; itulah batas pertahanan sebenarnya.
- API biasa (port 8728) dan TLS tanpa verifikasi hanya jalan dengan `settings.allow_insecure: true`. Bawaan: API-SSL (8729).
- Mode HTTP menolak start tanpa token (`NETSCOPE_MCP_TOKEN`, minimal 32 karakter), terikat ke loopback, memvalidasi `Host`/`Origin`, hanya menerima `POST /mcp`.
- Kredensial tidak pernah di YAML polos: hanya nama variabel lingkungan atau berkas mode 0600.
- Data pelanggan yang tampil di keluaran dikirim ke penyedia model Anda: biarkan `redact_pii` aktif dan perhatikan UU PDP.
- `redact_pii` (aktif bawaan) menyamarkan separuh perangkat dari MAC pelanggan dan kolom teks bebas. **Nama login PPP tidak disamarkan secara bawaan** (dibutuhkan `pppoe-lookup`); aktifkan `redact_ppp_names: true` untuk menyamarkannya juga. Lihat [docs/CONFIG.md](docs/CONFIG.md).

Rincian: [SECURITY.md](SECURITY.md) (bahasa Inggris).

## Dokumentasi

[Demo](docs/DEMO.md) · [Resep](docs/RECIPES.md) · [Konfigurasi](docs/CONFIG.md) · [Snapshot](docs/SNAPSHOT.md) · [FAQ](docs/FAQ.md) (bahasa Inggris)

## Dipakai di produksi

Dibangun dan dipakai harian oleh ISP kecil di Indonesia agar asisten NOC-nya bisa membaca puluhan router MikroTik (backbone, agregasi, edge). Nama dan alamat sengaja tidak disebut. Kalau Anda memakainya, buka issue/diskusi dan ceritakan skalanya (anonim boleh).

## Peta jalan

- **v0.1:** RouterOS v6/v7, resep, batch, snapshot, SNMP v2c, switch CRS/SwOS, stdio + HTTP.
- **v0.2:** VyOS, GenieACS, SNMPv3, transport REST RouterOS v7.
- **v0.3:** deteksi perubahan antar-snapshot, ACL per token, runbook MCP.

## Berkontribusi

Issue dan pull request dipersilakan: keanehan versi RouterOS, resep read-only baru, terjemahan dokumen, kasus uji keamanan allowlist. Baca [CONTRIBUTING.md](CONTRIBUTING.md) dulu (read-only itu syarat mutlak; fixture hanya memakai alamat dokumentasi). Laporkan kerentanan secara privat sesuai [SECURITY.md](SECURITY.md).

## Lisensi

Apache-2.0. Lihat `LICENSE` dan `NOTICE`.
