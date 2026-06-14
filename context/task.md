# FireGod-ESP — Task Tracker (Aligned)

## Phase 1 — Boot AP + WebUI skeleton + scanners (current focus)
### Completed baseline
- [x] `platformio.ini` — Arduino ESP32 build config + dependencies
- [x] `src/config.h` — constants, pins, AP creds, task/queue sizing
- [x] `src/fg_globals.h/.cpp` — shared state, queue helpers, module enum/state
- [x] `src/core/wifi_manager.h/.cpp` — AP/STA helpers, promiscuous mode, raw TX bypass
- [x] `src/core/web_server.h/.cpp` — AsyncWebServer + WebSocket command dispatch
- [x] `src/core/serial_shell.h/.cpp` — UART shell parser
- [x] `src/modules/wifi/ap_scanner.h/.cpp` — WiFi AP scan

### Remaining blockers — DONE
- [x] `src/main.cpp` — setup/loop, queue+mutex init, task creation, AP+web boot
- [x] `web/index.html` — dashboard UI
- [x] `web/style.css` — dashboard styling
- [x] `web/app.js` — WebSocket client + live rendering logic
- [x] `scripts/embed_web.py` — gzip/embed web assets at build time
- [x] `src/data/web_assets.h` — generated PROGMEM arrays (auto-generated, gitignore-worthy)
- [x] `src/modules/wifi/client_scanner.cpp` — `fg_client_scan` (reuses subnet sweep, tag "client")
- [x] `src/modules/wifi/arp_scanner.cpp` — `fg_arp_scan` + shared `fg_subnet_sweep` (lwIP etharp)
- [x] Wire serial commands `scan clients` and `scan arp` in `core/serial_shell.cpp`
- [x] Fix WS payload parse safety (deserialize bounded `(char*)data,len`; no `data[len]` write)
- [x] `no_ota.csv` resolves during build (built-in partition table)

### Notes / changes made this pass
- OUI vendor table moved from `ap_scanner.cpp` → `fg_globals.cpp` as `fg_oui_vendor()`
  (shared by AP + ARP/client scanners).
- Removed `ieee80211_raw_frame_sanity_check` override from `wifi_manager.cpp`: on
  espressif32 6.9.0 the WiFi lib defines it non-weak → link collision. Phase 2 raw-TX
  modules will reintroduce it via `-Wl,--wrap=...`. Scanners don't need it.
- `extra_scripts = pre:scripts/embed_web.py` added to `platformio.ini`.

### Phase 1 build & verification
- [x] `pio run` compiles cleanly (RAM 13.7%, Flash 40.0%)
- [ ] `pio run -t upload` flashes successfully            (needs hardware — user)
- [ ] AP `ESP32-Shell` starts on boot (`192.168.4.1`)     (needs hardware — user)
- [ ] WebUI loads from ESP32 and WebSocket `/ws` connects (needs hardware — user)
- [ ] AP scan streams results in browser + serial          (needs hardware — user)
- [ ] `status` and `stop` work from WebUI                  (needs hardware — user)
- [ ] Serial shell `help`, `scan wifi`, `scan clients`, `scan arp` work (needs hardware — user)

## Phase 2 — Offensive WiFi modules
- [ ] `MOD_WIFI_SNIFFER` — raw 802.11 sniffer
- [ ] `MOD_WIFI_BEACON_SPAM`
- [ ] `MOD_WIFI_SSID_CLONE`
- [ ] `MOD_WIFI_DEAUTH`
- [ ] `MOD_WIFI_KARMA`
- [ ] `MOD_WIFI_EVIL_PORTAL`
- [ ] Add WebUI + serial command wiring for each module
- [ ] Validate stop handling and state cleanup per module

## Phase 3 — BLE modules
- [ ] `MOD_BLE_SCAN`
- [ ] `MOD_BLE_SPAM`
- [ ] `MOD_BLE_BAD_BLE` (HID keyboard / Ducky injection)
- [ ] Add WebUI + serial command wiring for each module
- [ ] Validate BLE/WiFi coexistence + runtime stability

## Integration checklist (apply to every new module)
- [ ] Add/confirm `FGModule` enum slot
- [ ] Add `modules/<group>/<module>.h/.cpp` with `fg_<module>(...)`
- [ ] Register in `core/web_server.cpp` command dispatch + module switch
- [ ] Register serial command path in `core/serial_shell.cpp`
- [ ] Emit JSON events via `fg_send_result` / `fg_send_result_fmt`
- [ ] Respect `g_stopRequested` and fully restore WiFi/BLE state on exit
