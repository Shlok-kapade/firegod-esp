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
- **Phase 4 — Always-up dashboard + module chaining (ESP32-only, no new HW).** See §8.
- **Phase 5 — ESP8266 coprocessor: true concurrent / channel-independent attacks.** See §9.

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

---

## 8. Phase 4 — Always-up dashboard + module chaining (ESP32-only)

### 8.0 The governing constraint (read first)
One WiFi radio = **one channel, one mode, at a time.** The admin dashboard is served by
the ESP32 SoftAP. Anything that moves the radio off the AP channel or changes the AP drops
the operator's browser association. The whole design below is about respecting that.

How each current module affects the link (single radio):
| Module | Effect on dashboard | Why |
|---|---|---|
| AP / ARP / client scan | brief blips | scan/STA-join retunes the radio momentarily |
| sniffer, karma | **drops if channel ≠ AP ch** | promiscuous + channel hop |
| beacon (hopping 1/6/11) | **drops** | radio leaves AP channel |
| beacon/clone/deauth on AP channel | **stays up** | radio never leaves the channel |
| evil portal | **dashboard SSID disappears** | tears down ESP32-Shell, brings up open AP |

### 8.1 Goal A — Dashboard resilience (keep the WebUI alive)
1. **Channel-lock policy.** Add a global "lock attacks to AP channel" mode (default ON).
   When ON, every offensive module is forced to the SoftAP channel (no hopping) so the
   radio never leaves it → browser never drops. A WS/serial toggle lets the operator opt
   into "free-roam" (hopping) attacks, with a clear warning that the dashboard will drop
   until the module stops.
2. **Heartbeat + already-present auto-reconnect.** `app.js` already reconnects on WS close;
   add a visible "link lost / reconnecting" banner and a periodic `status` ping so the UI
   reflects reality. (Cheap, do this regardless.)
3. **Evil portal carve-out.** Portal is inherently dashboard-hostile on one radio (it *is*
   the AP). Options: (a) keep it mutually exclusive with the dashboard (current behavior,
   document it), or (b) move the portal AP onto the ESP8266 in Phase 5 so the ESP32 keeps
   the admin AP. Recommend (b) long-term.

### 8.2 Goal B — Module chaining (sequential "playbook")
This is the *achievable-now* meaning of "perform multiple modules": a queue that runs
modules **one after another**, automatically, without the operator babysitting each step.
- New concept: a **chain** = ordered list of `{module, args, duration_or_until_stop}` steps.
- A `fg_chain_task` (Core 1) runs each step under the existing single-module mutex, advances
  on timeout or step-completion, and aborts the whole chain on `stop`.
- WS protocol: `{"cmd":"chain","steps":[{"mod":"deauth","bssid":"..","ch":6,"secs":10},
  {"mod":"portal","ssid":"Free WiFi"}]}`; emit `{"event":"chain_step","i":n,...}` per step.
- Serial: `chain deauth <bssid> 6 10s ; portal "Free WiFi"` (—`;`-separated steps).
- Example playbook: `scan → deauth target 10s → clone target → portal`. Classic evil-twin flow.
- Note: this is still **one module at a time** (sequential). True *parallel* needs §9.

### 8.3 Goal C — Limited same-channel parallelism (optional, ESP32-only)
If two attacks share the AP channel (e.g. deauth + beacon on ch6), a cooperative
time-slicer can interleave them in one task (round-robin bursts). Fragile and channel-bound;
treat as a stretch goal. The robust path to parallelism is the coprocessor (§9).

### 8.4 Concurrency-model change required
Today: one `g_activeModule` + `g_moduleMutex` (strictly single-module). To support chains
(and later, lanes) cleanly, generalize to **resource lanes** — at most one module per lane:
- `LANE_LOCAL_RADIO` — ESP32 WiFi (shared with dashboard AP; channel-locked by default).
- `LANE_BLE` — ESP32 BLE (coexists with WiFi via the radio's coexistence arbiter).
- `LANE_COPROC` — ESP8266 radio (Phase 5).
A chain step occupies its lane; parallel = modules in *different* lanes running at once.

---

## 9. Phase 5 — ESP8266 coprocessor (the real concurrency unlock)

### 9.1 Why
Gives a **second, fully independent 2.4 GHz radio.** The ESP32 keeps the dashboard parked
on the AP channel forever while the ESP8266 does channel-hopping RF attacks in parallel.
Solves "dashboard always up" AND "multiple modules at once" at the same time. The ESP8266
has well-proven raw deauth/beacon TX capability.

### 9.2 Division of labor
- **ESP32 (host/brains):** SoftAP + dashboard + WebSocket, all scanners, evil portal
  (needs HTTP+DNS — stays here), BLE, chain orchestration, and the link to the 8266.
- **ESP8266 (coprocessor / "RF muscle"):** stateless, fire-and-forget RF-only attacks on
  arbitrary channels — deauth, beacon spam, probe/SSID floods. No HTTP, no state.

### 9.3 Physical link
- **UART** is the simplest: ESP32 `Serial2` (GPIO17 TX → 8266 RX, GPIO16 RX ← 8266 TX),
  **common GND**, both 3.3 V logic so direct-connect is safe (no level shifter). 115200+,
  framed line protocol. (SPI is an option later if UART throughput limits.)
- Caveat: the 8266's reliable hardware UART (GPIO1/3) doubles as its USB/flash port, so the
  link occupies it — fine for a headless coprocessor; flash the 8266 separately when updating.

### 9.4 Link protocol (host ⇄ coproc)
- Tiny line/JSON protocol over UART, e.g. host→coproc:
  `{"c":"deauth","bssid":"..","tgt":"..","ch":11}` / `{"c":"beacon","ssids":[..],"ch":0}` /
  `{"c":"stop"}` / `{"c":"ping"}`; coproc→host: `{"r":"stat","sent":N,"ch":11}` / `{"r":"pong"}`.
- Host surfaces coproc status into the existing `g_resultQueue` as normal `event`s so the
  dashboard shows ESP32 and ESP8266 activity in one stream. Heartbeat ping detects an
  unplugged/crashed 8266.

### 9.5 Two firmwares
- New build target/dir for the **ESP8266 sketch** (its own `platformio.ini` env or a separate
  project under `coproc/`). Keep it minimal: UART command loop + raw TX. Document the wiring
  + flashing steps in context.

### 9.6 Suggested sequencing
1. Phase 4 first (chaining + resilience) — pure software, no hardware risk, immediate value.
2. Then 8266 bring-up: blink/echo over UART → `ping/pong` → move **deauth** to the coproc
   lane as the pilot (simplest RF-only module) → then beacon/probe floods.
3. Optionally relocate the evil-portal AP to the 8266 so the ESP32 dashboard survives a portal.
