# FireGod-ESP — Implementation Plan

Custom ESP32 firmware (from scratch — not Bruce/Marauder) for authorized WiFi/BLE
security research and learning on **own network/devices**. Headless: controlled via a
self-hosted WebUI in AP mode, with a serial shell as fallback. Arduino-ESP32 via PlatformIO.

> The `context/firmware/` directory is the Bruce firmware, kept **only as reference**.
> No code is copied from it; this project targets our specific ESP32-D0WD board.

## 1. Target & Boot Behavior
- Chip: ESP32-D0WD rev 1.0, dual-core LX6 @240MHz, 4MB flash, 520KB RAM, no PSRAM.
- On power-on:
  1. Start SoftAP `ESP32-Shell` / `hacker1234`, channel 6, IP `192.168.4.1`.
  2. Serve WebUI (HTTP :80) + WebSocket control channel at `/ws`.
  3. Start serial shell on UART0 @115200 as fallback.
- All scans/attacks triggered from the browser — no USB required after flashing.

## 2. Architecture (already established in existing code)
- **Web stack**: `AsyncWebServer` on port 80 serving **gzipped PROGMEM** assets via
  `beginResponse_P`; `AsyncWebSocket` at `/ws` for commands + live result streaming.
- **Concurrency model**:
  - Core 0: Arduino/AsyncTCP web stack + `fg_ws_sender_task` (drains result queue → `ws.textAll`).
  - Core 1: one `fg_module` task at a time (the active scan/attack) + `fg_serial_shell_task`.
  - Modules push JSON lines into `g_resultQueue` (FreeRTOS queue, 32 × 512B). The sender
    task broadcasts them — decoupling capture from network TX.
  - Single-module concurrency enforced by `g_moduleMutex` + `g_moduleState`.
  - Cooperative cancellation via the `g_stopRequested` flag.
- **Command protocol** (WebSocket, JSON):
  - In: `{"cmd":"wifi_scan"}`, `{"cmd":"client_scan","ssid":"..","pass":".."}`,
    `{"cmd":"arp_scan","ssid":"..","pass":".."}`, `{"cmd":"stop"}`, `{"cmd":"status"}`.
  - Out (events): `{"event":"ap"|"log"|"error"|"status"|"scan_complete", ...}`.

## 3. Current State (from code review)
### Done
- `platformio.ini` — espressif32 ~6.9.0, `esp32dev`, arduino, `no_ota.csv` partitions;
  deps: AsyncTCP, ESPAsyncWebServer, ArduinoJson 7, NimBLE-Arduino 2. `src_dir`/`include_dir` = `src`.
- `src/config.h` — AP creds/IP, pins, web port, scan limits, task stacks/priorities, queue sizes.
- `src/fg_globals.h/.cpp` — module enum (WiFi **and** BLE slots reserved), lifecycle state,
  result queue/mutex, helpers (`fg_send_result[_fmt]`, `fg_mac_to_str`, `fg_auth_to_str`, uptime).
- `src/core/wifi_manager.h/.cpp` — AP/STA/AP+STA, promiscuous enter/exit, channel set,
  raw-802.11 TX sanity-check bypass (`ieee80211_raw_frame_sanity_check`).
- `src/core/web_server.h/.cpp` — server + WebSocket, JSON command dispatch, module launcher
  task (`module_task_wrapper`), sender task. **Depends on missing `data/web_assets.h`.**
- `src/core/serial_shell.h/.cpp` — UART line editor + command parser.
- `src/modules/wifi/ap_scanner.h/.cpp` — full AP scan with OUI vendor lookup table.

### Missing / blocking compile & boot
1. **`src/main.cpp`** — no entrypoint: no `setup()`/`loop()`, no queue/mutex creation,
   no `fg_wifi_*` init, no AP start, no web-server start, no task spawning.
2. **`src/data/web_assets.h`** — `web_server.cpp` references `index_html_gz`/`_len`,
   `style_css_gz`/`_len`, `app_js_gz`/`_len`; file does not exist.
3. **`web/index.html`, `web/style.css`, `web/app.js`** — WebUI source files.
4. **`src/modules/wifi/client_scanner.cpp`** — `fg_client_scan()` declared, not implemented.
5. **`src/modules/wifi/arp_scanner.cpp`** — `fg_arp_scan()` declared, not implemented.

### Known caveats to resolve during implementation
- `onWsEvent` does `data[len] = '\0';` — can write one byte past the frame buffer.
  Copy into a sized local buffer (or bound-check) instead.
- `serial_shell` help advertises `scan arp` / `scan clients`, but `processCommand` only
  handles `scan wifi`. Wire the remaining commands (and they need an STA connection).
- `no_ota.csv` is an Arduino-ESP32 **built-in** partition table (no local file needed) —
  confirm it resolves at build time.
- `client_scan` vs `arp_scan` overlap: decide whether `client_scan` is passive station
  discovery on a target BSSID via promiscuous (no creds) or join-then-enumerate. Current
  WS dispatch passes `ssid`/`pass`, implying join-based. See Phase 1 / T4.

## 4. Phased Roadmap
Build and verify one module at a time; each phase ends with a working flash.
- **Phase 1 — Boot AP + WebUI skeleton + scanners (CURRENT FOCUS).**
  Make it compile, boot the AP, serve the WebUI, stream live results, and run the three
  read-only scanners (AP, client, ARP). Foundation + core are mostly done; finish the gaps.
- **Phase 2 — Offensive WiFi.** Enum slots already reserved:
  `MOD_WIFI_SNIFFER`, `MOD_WIFI_DEAUTH`, `MOD_WIFI_BEACON_SPAM`, `MOD_WIFI_SSID_CLONE`,
  `MOD_WIFI_KARMA`, `MOD_WIFI_EVIL_PORTAL`. Build in this order (simplest → most complex):
  sniffer → beacon spam → SSID clone → deauth → karma → evil portal.
- **Phase 3 — BLE (NimBLE-Arduino).** `MOD_BLE_SCAN` → `MOD_BLE_SPAM` → `MOD_BLE_BAD_BLE`
  (HID keyboard / Ducky-script injection).

## 5. Phase 1 — Detailed Tasks
**T1 — `src/main.cpp` (unblocks everything).**
- `setup()`: `Serial.begin(FG_SERIAL_BAUD)`; record `g_bootTime`; create `g_resultQueue`
  (`FG_RESULT_QUEUE_SIZE` × `FGResultMsg`) and `g_moduleMutex`; `fg_wifi_init()` →
  `fg_wifi_start_ap()`; `fg_web_server_start()`; `fg_serial_shell_init()`; spawn
  `fg_ws_sender_task` (Core 0, `FG_WS_SENDER_*`) and `fg_serial_shell_task` (Core 1, `FG_SERIAL_TASK_*`).
- `loop()`: lightweight — heartbeat/log + `vTaskDelay`; all real work runs in tasks.

**T2 — WebUI (`web/index.html`, `web/style.css`, `web/app.js`).**
- Dark "hacker" dashboard: status bar (heap/uptime/version/active module), buttons for
  AP scan / client scan / ARP scan / stop, an SSID+password input for the join-based scans,
  and a live, auto-scrolling results log/table fed by WebSocket events.
- `app.js`: open `ws://<host>/ws`, send command JSON on button click, render incoming
  `event` messages (append `ap` rows, show `log`/`error`, update on `status`/`scan_complete`),
  auto-reconnect on close.

**T3 — Asset embedding pipeline (`scripts/embed_web.py` + `data/web_assets.h`).**
- PlatformIO pre-build `extra_scripts = pre:scripts/embed_web.py`: read `web/*`, gzip each,
  emit `src/data/web_assets.h` with `const uint8_t <name>_gz[] PROGMEM = {...};` and
  `const unsigned <name>_gz_len = ...;` for `index_html`, `style_css`, `app_js`.
- Keeps WebUI editable as normal files and regenerated on every build (matches the existing
  `beginResponse_P(... , "Content-Encoding: gzip")` usage in `web_server.cpp`).

**T4 — `src/modules/wifi/client_scanner.cpp`.**
- Implement `fg_client_scan(ssid, pass)`: `fg_wifi_connect_sta()` (keeps AP up via AP+STA),
  then enumerate hosts on the joined subnet (ping/ARP sweep) and stream a `client` event per
  device (IP + MAC + vendor). Restore AP on exit; honor `g_stopRequested`.
- (Alt to discuss: credential-free variant = promiscuous capture on a target BSSID/channel,
  collecting associated station MACs from data frames.)

**T5 — `src/modules/wifi/arp_scanner.cpp`.**
- Implement `fg_arp_scan(ssid, pass)`: join via STA, sweep the subnet (1..254) issuing ARP/
  ICMP, resolve IP↔MAC from the lwIP ARP cache, stream `host` events. Bounded by
  `FG_MAX_ARP_HOSTS`; honor stop; restore AP afterward.

**T6 — Wire serial shell.**
- Add `scan arp` / `scan clients` handling (prompt for or accept SSID/pass), keeping the
  single-active-module rule (`g_moduleState`/`g_moduleMutex`) consistent with the WS path.

**T7 — Build, flash, verify.**
- `pio run` (compile clean) → `pio run -t upload` (port `/dev/ttyUSB0`) → `pio device monitor`.
- Acceptance: AP `ESP32-Shell` appears; `http://192.168.4.1` loads UI; WS connects and shows a
  `status` event; AP scan streams `ap` rows in browser + serial table; `stop`/`status` work;
  serial `help`/`scan wifi` work.

## 6. Module Integration Convention (for Phases 2–3)
1. Reuse the reserved `FGModule` enum value.
2. Add `modules/<group>/<name>.h/.cpp` exposing one `fg_<name>(...)` entry function.
3. Register it in: `web_server.cpp` command dispatch + `module_task_wrapper` switch, and
   `serial_shell.cpp`.
4. Stream progress/results as JSON `event`s via `fg_send_result[_fmt]`.
5. Always check `g_stopRequested` in loops and fully restore WiFi/BLE state on exit.

## 7. Authorized-Use Note
This firmware is for testing networks and devices the operator owns or is explicitly
authorized to assess. Offensive modules (deauth, beacon spam, karma, evil portal, BLE spam)
must only be used in that context.
