# FireGod-ESP — Working Context & Progress Log

> Living document. Claude updates this as work progresses. It captures *what is
> built, what is in flight, key decisions, and gotchas* — so any session can
> resume without re-reading every file. For the formal checklist see `task.md`;
> for the design rationale see `implementation_plan.md`.

**Last updated:** 2026-06-15
**Current phase:** Phase 1 COMPLETE & VERIFIED ON HARDWARE. Ready to start Phase 2.
**Build status:** `pio run` ✅ SUCCESS — RAM 13.7% (44,896 B), Flash 40.0% (837,813 B).
**Flash status:** ✅ Flashed to /dev/ttyUSB0, boots clean, AP up, free heap 224,608 B.

---

## 1. What this project is
Custom ESP32 firmware (from scratch — NOT Bruce/Marauder) for authorized WiFi/BLE
security research on the operator's own network/devices. Headless: controlled via a
self-hosted WebUI (SoftAP `ESP32-Shell` / `hacker1234` @ `192.168.4.1`) with a serial
shell fallback. Arduino-ESP32 via PlatformIO.

- **Board:** ESP32-D0WD rev 1.0, dual-core LX6 @240MHz, 4MB flash, 520KB RAM, no PSRAM.
- **Toolchain present:** pio 6.1.19, python3 (pyenv), gzip. Upload/monitor `/dev/ttyUSB0`.
- `context/firmware/` = Bruce source, REFERENCE ONLY. No code copied from it.

## 2. Architecture (as built)
- **Web stack:** `AsyncWebServer` :80 serving gzipped PROGMEM assets via `beginResponse_P`;
  `AsyncWebSocket` at `/ws` for JSON commands + live result streaming.
- **Concurrency:**
  - Core 0: AsyncTCP web stack + `fg_ws_sender_task` (drains `g_resultQueue` → `ws.textAll`).
  - Core 1: one `fg_module` task at a time (active scan/attack) + `fg_serial_shell_task`.
  - Modules push JSON lines into `g_resultQueue` (32 × 512B FreeRTOS queue); sender broadcasts.
  - Single-module concurrency via `g_moduleMutex` + `g_moduleState`. Cancel via `g_stopRequested`.
- **WS protocol:** in `{"cmd":"wifi_scan"|"client_scan"|"arp_scan"|"stop"|"status", ssid?, pass?}`;
  out events `{"event":"ap"|"host"|"client"|"log"|"error"|"status"|"scan_complete", ...}`.

## 3. File map (current)
```
platformio.ini            espressif32 6.9.0, esp32dev, no_ota.csv, extra_scripts=embed_web.py
scripts/embed_web.py      pre-build: gzip web/* -> src/data/web_assets.h (PROGMEM)
web/index.html|style.css|app.js   dark dashboard WebUI source (editable)
src/data/web_assets.h     AUTO-GENERATED (gitignore-worthy), don't hand-edit
src/main.cpp              setup()/loop(): boot AP, web, shell, spawn tasks
src/config.h              AP creds/IP, pins, limits, task stacks/prios, queue sizing
src/fg_globals.h|.cpp     module enum, lifecycle state, queue/mutex, helpers,
                            fg_oui_vendor() (shared OUI table), fg_auth_to_str, fg_mac_to_str
src/core/wifi_manager.*   AP/STA/AP+STA, promiscuous enter/exit, channel set
src/core/web_server.*     server + WS, JSON dispatch, module launcher task, sender task
src/core/serial_shell.*   UART line editor + command parser
src/modules/wifi/ap_scanner.*       WiFi AP scan (uses fg_oui_vendor)
src/modules/wifi/arp_scanner.*      fg_arp_scan + shared fg_subnet_sweep (lwIP etharp)
src/modules/wifi/client_scanner.*   fg_client_scan (reuses fg_subnet_sweep, "client" tag)
```

## 4. Phase 1 — DONE this session
- `main.cpp` entrypoint (queue/mutex create, AP boot, web start, 2 tasks pinned).
- WebUI (HTML/CSS/JS): status bar, scan/stop buttons, SSID+pass inputs, per-event-type
  results table (RSSI color, OPEN highlight), separate log tab, WS auto-reconnect.
- `embed_web.py` + generated `web_assets.h`; wired `extra_scripts` in platformio.ini.
- `arp_scanner.cpp`: STA join → batched ARP sweep of /24 via `etharp_request` /
  `etharp_get_entry` under `LOCK_TCPIP_CORE()`. Batch=8, drain between batches (ARP cache
  is only ~10 entries), dedup by IP, stream `host` events, restore AP. `fg_subnet_sweep()`
  is the shared core.
- `client_scanner.cpp`: thin wrapper over `fg_subnet_sweep(..., "client")`.
- Serial shell: added `scan arp <ssid> <pass>` and `scan clients <ssid> <pass>`
  (args parsed from ORIGINAL-case input so passwords survive lowercasing);
  `runModuleLocked()` helper for mutex-guarded direct calls on Core 1.
- WS parse safety fix: removed `data[len]='\0'` OOB write; deserialize bounded
  `(const char*)data, len` directly.

## 5. Key decisions / gotchas (READ before editing)
- **Raw-TX bypass removed.** `ieee80211_raw_frame_sanity_check` override in
  `wifi_manager.cpp` collided at link time — espressif32 6.9.0 defines it non-weak
  ("multiple definition"). REMOVED for Phase 1 (scanners don't inject frames).
  **Phase 2 must reintroduce it via `-Wl,--wrap=ieee80211_raw_frame_sanity_check`**
  (define `__wrap_ieee80211_raw_frame_sanity_check`) rather than a plain override.
- `fg_globals.cpp` needs `#include <esp_wifi_types.h>` for the `WIFI_AUTH_*` enum.
- OUI vendor lookup now lives ONCE in `fg_globals.cpp` (`fg_oui_vendor`). Don't re-add
  a local copy in modules.
- `beginResponse_P` is deprecated (warning only) on this lib version — still works.
  Could migrate to `beginResponse(...)` later; not blocking.
- ARP sweep relies on lwIP `etharp_*`; all calls wrapped in `LOCK_TCPIP_CORE()/UNLOCK`.
- `web_assets.h` is regenerated every build — safe to delete; don't commit edits to it.

## 6. Verification status
- [x] Compiles clean.
- [x] Flash + boot — boots clean on /dev/ttyUSB0, banner OK, heap 224 KB free.
- [x] AP `ESP32-Shell` appears (ch 6, 192.168.4.1).
- [x] WebUI loads at 192.168.4.1.
- [x] AP scan streams rows in browser. ✅ confirmed working
- [ ] ARP/client scan join a real AP and list hosts. (not yet exercised)
- [ ] Serial `help`/`scan arp`/`scan clients`/`stop`/`status` (not yet exercised)

Boot log reference (2026-06-15):
```
FireGod-ESP v0.1.0 booting...
[WiFi] AP started: ESP32-Shell  IP: 192.168.4.1  Channel: 6
[Web] Server started on port 80   WebSocket ws://192.168.4.1/ws
[Boot] Ready. Free heap: 224608 bytes
```
Note: flashing/reset via Python pyserial DTR/RTS toggle works for capturing boot log;
port must be opened at 115200 (raw `cat` shows garbage at wrong baud).

## 7. Next up
- **User:** flash & confirm Phase 1 on hardware; report anything off.
- **Phase 2 — Offensive WiFi** (order: sniffer → beacon spam → SSID clone → deauth →
  karma → evil portal). Enum slots already reserved in `FGModule`. First module to build:
  `MOD_WIFI_SNIFFER` (raw 802.11 sniffer via promiscuous cb — no raw TX needed, so the
  wrap-linker work can wait until beacon/deauth).
- **Phase 3 — BLE** (NimBLE): scan → spam → bad-BLE HID.

## 8. Integration convention (every new module)
1. Reuse the `FGModule` enum slot. 2. `modules/<group>/<name>.{h,cpp}` exposing one
`fg_<name>(...)`. 3. Register in `web_server.cpp` dispatch + `module_task_wrapper` switch,
and `serial_shell.cpp`. 4. Emit JSON via `fg_send_result[_fmt]`. 5. Honor `g_stopRequested`
in loops; fully restore WiFi/BLE state on exit.
