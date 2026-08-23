# FireGod-ESP 🔥📡

**FireGod-ESP** is a custom ESP32 firmware built from scratch for authorized WiFi and BLE security research, auditing, and learning on your own networks and devices. 

It operates completely headless: control it via a sleek, self-hosted WebUI (served in AP mode) or fall back to a robust serial shell. Built with the Arduino-ESP32 core via PlatformIO.

> ⚠️ **Authorized Use Only:** This firmware is strictly for testing networks and devices that the operator owns or is explicitly authorized to assess. Offensive modules (deauth, beacon spam, karma, evil portal, BLE spam) must only be used in this legal context.

---

## ✨ Features

- **Headless WebUI Dashboard:** A modern, dark-themed "hacker" dashboard served over HTTP. Features live event streaming (via WebSockets), responsive module control cards, and real-time status bars (heap, uptime, active module).
- **Serial Shell Fallback:** Full UART line editor and command parser (`scan arp`, `beacon`, `deauth`, etc.).
- **Modular Architecture:** Strictly isolated modules. Core 0 handles the web stack and WebSocket broadcasts, while Core 1 executes the active scan/attack task.
- **WiFi Reconnaissance:**
  - AP Scanner (with built-in OUI vendor lookups)
  - ARP Scanner (subnet sweeps via lwIP)
  - Client Scanner
- **Offensive WiFi (Phase 2 & 3):**
  - Raw 802.11 Sniffer
  - Beacon Spam & SSID Cloning
  - Deauthentication Attacks
  - Karma Attacks
  - Evil Portal (Captive portal with HTTP route wiring for credential capture)
  - ARP-spoof MITM with full L2 relay
- **BLE Auditing (NimBLE-Arduino):**
  - BLE Passive Scanning & Detection (Flags spam signatures)
  - BLE Advert Spam (Apple/Fast Pair)
  - Bad-BLE (HID keyboard/Ducky-script injection)

---

## 🛠 Hardware & Tech Stack

- **Target Board:** ESP32-D0WD rev 1.0 (dual-core LX6 @240MHz, 4MB flash, 520KB RAM, no PSRAM).
- **Framework:** Arduino-ESP32 (PlatformIO).
- **Key Libraries:** `AsyncTCP`, `ESPAsyncWebServer`, `ArduinoJson 7`, `NimBLE-Arduino 2`.
- **Web Stack:** HTML/CSS/JS assets are gzipped pre-build and embedded into `PROGMEM` to save flash and RAM.

---

## 📂 Repository Structure

```text
firegod-esp/
├── platformio.ini         # PlatformIO configuration (board, flags, deps)
├── scripts/               # Pre-build Python scripts (e.g., embed_web.py for WebUI gzipping)
├── web/                   # Uncompressed HTML, CSS, and JS files for the dashboard
├── src/
│   ├── core/              # WiFi manager, Web server, Serial shell
│   ├── data/              # Auto-generated web_assets.h (from scripts/embed_web.py)
│   ├── modules/           # Isolated attack/scan modules (wifi, ble)
│   ├── config.h           # AP credentials, pins, queue sizes, stack sizes
│   ├── fg_globals.*       # State management, OUI tables, mutices
│   └── main.cpp           # Entrypoint: task spawning, AP boot, web start
└── context/               # Development logs, phase planning, and architecture notes
```

---

## 🚀 Getting Started

### 1. Build and Flash
Ensure you have [PlatformIO](https://platformio.org/) installed.

```bash
# Clone the repository
git clone https://github.com/yourusername/firegod-esp.git
cd firegod-esp

# Build the firmware (this will automatically run the web-asset minifier)
pio run

# Upload to your ESP32 (adjust the port if necessary, default is /dev/ttyUSB0)
pio run -t upload

# Open the serial monitor
pio device monitor -b 115200
```

### 2. Connect to the Dashboard
1. On boot, the ESP32 will host an Access Point named **`ESP32-Shell`** (Password: `hacker1234`, Channel 6).
2. Connect your device to this WiFi network.
3. Open your browser and navigate to **`http://192.168.4.1`**.

---

## 🗺 Roadmap & Future Phases

- **Phase 4 (Dashboard Resilience & Module Chaining):** Implementing "channel-lock" policies so the dashboard never drops during attacks, and a playbook engine to chain sequential attacks automatically (e.g., scan → deauth → clone → portal).
- **Phase 5 (ESP8266 Coprocessor):** Offloading raw RF TX (deauth, beacon floods) to a secondary ESP8266 connected via UART. This solves the single-radio limitation, keeping the ESP32 dashboard always up on the AP channel while the ESP8266 hops channels for parallel attacks.
