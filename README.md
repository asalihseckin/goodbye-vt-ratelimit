# 🛡️ vt-domain-scanner

![Python](https://img.shields.io/badge/python-3.8%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)

A multi-threaded **VirusTotal** domain reputation scanner built for bulk-auditing large domain lists (1000+) without manual IP/key management.

> Originally built to scan ~2000 Turkish news domains for malware/phishing indicators — works with any domain list. 🌐

---

## ✨ Features

| | Feature | Description |
|---|---|---|
| 🔑 | **Multi-key rotation** | Load unlimited VirusTotal API keys from `api_keys.env`. Rate-limited keys go on cooldown instead of stopping the scan. |
| 🌍 | **Two connection modes** | `DIRECT` (fast, single IP) or `OPEN_PROXY` (auto-fetches + validates live proxies before scanning). |
| ✅ | **Live proxy validation** | Every proxy is tested against VirusTotal **before** use — no more wasting time on dead proxies. |
| 🔄 | **Auto-replenish pool** | If live proxies run low mid-scan, a background job fetches more without interrupting the scan. |
| 💾 | **Checkpoint / resume** | Kill anytime with `Ctrl+C` — rerun to continue exactly where you left off. |
| 🔁 | **Automatic retry pass** | Domains that errored out get up to 2 extra retry rounds via direct connection. |
| ⏸️ | **Smart rate-limit handling** | On HTTP 429, scanning pauses with clear IP-refresh instructions, then resumes on your command. |
| 🎨 | **Color-coded output** | Instant visual feedback — see the palette below. |
| 📊 | **CSV + JSON export** | Full results plus a dedicated failed-domains log. |

---

## 🎨 Color Legend

| Color | Status | Meaning |
|---|---|---|
| 🟢 **Green** | `CLEAN` | No detections |
| 🟡 **Yellow** | `SUSPICIOUS` | Flagged by some engines, not confirmed malicious |
| 🔴 **Red** | `MALICIOUS` | Confirmed malicious (intensity increases with detection count) |
| 🟣 **Magenta** | `ERROR` | Scan failed (will be retried automatically) |
| 🟠 **Orange/Yellow** | `WARNING` / `PROXY DEAD` / `RATE LIMIT` | Needs attention but scan continues |

```
  [CLEAN] example.com                          🟢
  [SUSPICIOUS] example.com (2 detections)       🟡
  [MALICIOUS] example.com (4 detections)        🔴
  [MALICIOUS] example.com (15 detections)       🔴🔥 (bright/bold)
  [ERROR] example.com                           🟣
```

---

## 📦 Requirements

```bash
pip install colorama requests PySocks
```

> `requests` / `PySocks` are optional leftovers from proxy experimentation — the core scanner only needs `colorama`. 🎨

---

## ⚙️ Setup

**1. Add your API keys** — one VirusTotal key per line in `api_keys.env`:
```
<key_1>
<key_2>
...
```

**2. Add your domain list** — one domain per line in `domains.txt` (protocol / `www.` stripped automatically):
```
example.com
another-domain.com
```

---

## 🚀 Usage

```powershell
python vt_domain_scanner.py
```

You'll be prompted to pick a mode:

```
[1] 🟢 DIRECT       - fastest, single IP, may rate-limit after ~1000 requests
[2] 🔵 OPEN_PROXY   - slower start (proxies validated first), rotates live proxies
```

Then sit back and watch the color-coded live feed:

```
  [CLEAN] example.com
  [SUSPICIOUS] example.com (2 detections)
  [MALICIOUS] example.com (4 detections)

[THREAD-2] Progress: 800/1909 | Rate: 4.39 domain/s | ETA: 253s
```

⏹️ Press `Ctrl+C` anytime — progress saves automatically and resumes on next run.

---

## 📁 Output Files

| File | 📄 Description |
|---|---|
| `vt_resume.json` | Checkpoint state — processed domains, results, key/proxy stats |
| `vt_scan_results_<timestamp>.csv` | Full results, sorted by malicious/suspicious count |
| `vt_scan_results_<timestamp>.json` | Same results in JSON |
| `vt_failed_domains_<timestamp>.json` | Domains that failed even after retry passes |

---



<p align="center"Made in Absence 🥀</p>
