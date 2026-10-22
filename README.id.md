# netscope-mcp

**Beri LLM "mata" ke jaringan ISP Anda tanpa memberinya "tangan".**

`netscope-mcp` adalah server [MCP](https://modelcontextprotocol.io) **read-only ketat** untuk operator ISP/WISP. Asisten AI dapat memeriksa banyak router dan switch MikroTik RouterOS (v6/v7) sekaligus lewat resep diagnosis satu panggilan. Dukungan VyOS dan GenieACS direncanakan di v0.2.

> **Status:** v0.1, belum dipublikasikan ke npm. Pasang dari tarball atau dari sumber.
> Tidak berafiliasi dengan MikroTik. "MikroTik" dan "RouterOS" adalah merek dagang pemiliknya.

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
    tls_ca_file: /etc/netscope-mcp/ca.pem   # atau tls_fingerprint256 untuk sertifikat self-signed
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

## Keamanan singkat

- Penjaga di sisi alat hanyalah satu lapisan, **bukan sandbox**. Selalu pakai akun RouterOS ber-policy read-only; itulah batas pertahanan sebenarnya.
- API biasa (port 8728) dan TLS tanpa verifikasi hanya jalan dengan `settings.allow_insecure: true`. Bawaan: API-SSL (8729).
- Mode HTTP menolak start tanpa token (`NETSCOPE_MCP_TOKEN`, minimal 32 karakter), terikat ke loopback, memvalidasi `Host`/`Origin`, hanya menerima `POST /mcp`.
- Kredensial tidak pernah di YAML polos: hanya nama variabel lingkungan atau berkas mode 0600.
- Data pelanggan yang tampil di keluaran dikirim ke penyedia model Anda: biarkan `redact_pii` aktif dan perhatikan UU PDP.

Rincian: [SECURITY.md](SECURITY.md) (bahasa Inggris).

## Dokumentasi

[Resep](docs/RECIPES.md) · [Konfigurasi](docs/CONFIG.md) · [Snapshot](docs/SNAPSHOT.md) · [FAQ](docs/FAQ.md) (bahasa Inggris)

## Peta jalan

- **v0.1:** RouterOS v6/v7, resep, batch, snapshot, SNMP v2c, switch CRS/SwOS, stdio + HTTP.
- **v0.2:** VyOS, GenieACS, SNMPv3, transport REST RouterOS v7.
- **v0.3:** deteksi perubahan antar-snapshot, ACL per token, runbook MCP.

## Lisensi

Apache-2.0. Lihat `LICENSE` dan `NOTICE`.
