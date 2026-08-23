# FireGod-ESP — Working Context & Progress Log

> Living document. Claude updates this as work progresses. It captures *what is
> built, what is in flight, key decisions, and gotchas* — so any session can
> resume without re-reading every file. For the formal checklist see `task.md`;
> for the design rationale see `implementation_plan.md`.

**Last updated:** 2026-06-17
**Current phase:** Phases 1–3 complete + BLE verified. NEW: `MOD_WIFI_MITM` (ARP-spoof MITM w/ L2 relay) built — compiles, NOT yet hardware-tested.
**Build status:** `pio run` ✅ SUCCESS — RAM 24.0%, Flash 55.6% (MITM module + modular WebUI rebuild).

### WebUI rebuilt — modular card-launcher (2026-06-17, NOT yet browser-tested on hw)
- Full rewrite of `web/index.html|style.css|app.js`. Home = grid of tool **cards**
  (Recon / WiFi Attacks / MITM / BLE / Logs / Status); tap a card → that tool's own
  full-screen view (back button to home). Replaces the old single cram-everything sidebar.
- Each view has its OWN controls + OWN results table; `app.js` routes WS events to the right
  table (recon: ap/host/client/sniff_dev; attacks: creds; mitm: mitm_target/dns/http; ble:
  ble_dev). Per-tool live "stat strips" (sniff/ble/mitm). Global event Log is its own view.
- Persistent header: brand/home button, live heap+uptime+active-module, a **global STOP**
  (auto-shows while a module is busy via a 5s status ping), connection dot. Status view has
  big readouts + stop. Responsive (controls stack above results on phones).
- `mitm.cpp` now emits `mitm_target` (was `host`) so discovered clients render on the MITM
  page (Proto col shows TGT/DNS/HTTP). Table factory de-dups sniff_dev/ble_dev by key.
- Verified: `node --check` clean, every JS-referenced id exists, all data-go→views and
  15 data-cmd→backend cmds resolve, gz assets small (idx 2.1K/css 2.2K/js 4.0K).
  ⏳ Live browser look/feel still needs an operator at 192.168.4.1 after flashing.
**Flash status:** ✅ bad-BLE confirmed earlier. ⏳ MITM module awaits first flash + on-hardware verification.

### MITM module (2026-06-17) — ARP-spoof + full L2 relay (NEW, NOT yet hw-verified)
- **Files:** `src/modules/wifi/mitm.{h,cpp}`, enum `MOD_WIFI_MITM` (fg_globals.h), WS cmd `mitm`
  + `module_task_wrapper` case (web_server.cpp), serial `mitm <ssid> <pass> [all|ip]`
  (serial_shell.cpp), WebUI MITM panel + unified `mitm` table schema (index.html/app.js).
- **What it does:** joins target WLAN as STA (AP stays up, AP+STA), poisons victim<->gateway
  ARP, FORWARDS traffic at L2 so victims stay online, inline-parses plain HTTP (req line +
  Host + POST body) and DNS queries → streams `mitm_http`/`mitm_dns`/`mitm_stats` events.
  Target = "all" (sweeps /24, caps 16 clients) or a single client IP. Heals ARP on stop.
- **KEY mechanism (verified vs installed IDF headers):** lwIP `CONFIG_LWIP_IP_FORWARD` is OFF
  and baked into precompiled libs → cannot route in-stack. So we bridge in SW via the private
  WiFi API: `esp_wifi_internal_reg_rxcb(WIFI_IF_STA, cb)` hijacks inbound 802.3 frames;
  our-own (dstIP==ourIP / ARP / bcast) go back up via `esp_netif_receive(staNetif,...)`;
  poisoned frames get dst-MAC rewritten (gateway for victim→net, victim for net→victim) and
  re-injected with `esp_wifi_internal_tx`. rxcb runs in WiFi-task ctx → kept cheap, drops
  records into a spinlock ring drained by the module loop. Symbols live in
  `esp_private/wifi.h` + `esp_netif.h` (confirmed present for esp32).
- **HARDWARE-VERIFY checklist (next flash):** (1) victim KEEPS internet while MITM'd (the
  relay is the risk); (2) http site visit → `mitm_http` row; (3) DNS rows stream; (4) POST to
  an http form shows body/creds; (5) `stop` heals ARP (victim recovers) + dashboard reconnects;
  (6) after MITM stop, a normal `scan arp` still re-joins OK (we set rxcb=NULL on teardown —
  watch that esp_netif re-registers its handler on the next STA connect).
- **Known limits (by design):** HTTPS stays encrypted (DNS/Host names only); single radio+no
  PSRAM → modest throughput, best-effort forwarding; dashboard drops a few s on STA-join
  (AP rides target channel) then auto-reconnects; APs w/ DAI/DHCP-snooping/client-isolation
  can block it.

### Phase 3 BLE hardening (2026-06-17) — verified against NimBLE 2.5 source + RF
- **bad_ble (HID keyboard) — FIXED, typing confirmed.** Root causes:
  (1) report map had no Report ID but `getInputReport(1)` declares ID 1 → host couldn't
      map notifications → "connects but never types". Added `0x85,0x01` to descriptor.
  (2) typed on a fixed 1.5s timer that raced encryption+CCCD write → `notify()` dropped.
      Now gated on `onSubscribe` (CCCD enable) before typing. (3) reconnect re-adv via
      `getAdvertising()->start()` guarded by `!g_stopRequested`. (4) advertises name
      "Bluetooth Keyboard" via `adv->setName()`. Verified: pairs/bonds, enumerates as
      HID (appearance 0x03C1), kernel binds `bluez-hog-device`, keystrokes land on host.
- **ble_spam — corrected, transmits, but target-OS limited.** Was connectable-undirected
  (targets ignore proximity-pair popups) → set `setConnectableMode(BLE_GAP_CONN_MODE_NON)`.
  Fast Pair used RANDOM model IDs (Google drops them) → use real registered IDs
  (Bruce list). Address churned every 40ms → added per-identity dwell (Fast Pair ~1s,
  Apple fast). Confirmed emitting over the air (laptop hci0 scan). Did NOT pop on Oppo
  Reno 11 / ColorOS 16 / Android 16 — that OS is patched (documented; not a firmware bug).
  Note: NimBLE 2.5 `addData()` appends raw (no re-framing); `setOwnAddr()`==`ble_hs_id_set_rnd`;
  static `startAdvertising()`==`getAdvertising()->start()`. Several earlier "diagnoses" were
  wrong vs the actual lib — verify against `.pio/libdeps/.../NimBLE-Arduino/src`.
- **ble_detect (NEW, defensive) — MOD_BLE_DETECT, cmd `bledetect [secs]`.** Passive scan;
  classifies adverts (Apple Continuity 0x4C00+0x07 / SwiftPair 0x0600+0x03 / Fast Pair
  svc-data FE2C) and flags the spam signature: many distinct random-static MACs per
  protocol in a sliding window (FG_THRESH=12 / FG_WIN_MS=4000). Pure logic lives in
  `ble_detect_core.h`; native test `test/test_ble_detect.cpp` (g++ -I src) = 12/12 pass.
  On hardware: 0 false positives on ambient BLE.

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

### Phase 2 hardware verification (2026-06-15) ✅
Flashed 902 KB OK, boots clean, heap 211 KB. All 6 offensive serial cmds exercised:
- `beacon 6` → module 5, TX'd 3917 frames, stop clean.  **Raw 802.11 TX CONFIRMED working**
  (gotcha #5 resolved — frames actually transmit; link is clean, no sanity-check block).
- `karma` → module 7, promiscuous ON→OFF, stop clean.
- `clone TestNet 6 wpa2` → module 8, single-SSID WPA2 beacon w/ computed BSSID, stop clean.
- `portal Free WiFi` → module 6, AP→open + DNS hijack, status shows Module6/State2,
  stop restores idle (Module0/State0). `/post` creds route wired.
- `deauth` (no args) → correct usage error. Real-target TX NOT yet exercised (needs live BSSID).
- No heap leak across all 6 launches: 211 KB → 211 KB. Min heap dipped to 194 KB (portal).

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


## Phase 2 progress (this session)
- All 6 offensive modules present: beacon_spam, deauth, ssid_clone, karma, evil_portal, sniffer.
- web_server.cpp: WS dispatch + module_task_wrapper switch handle all MOD_WIFI_* cases.
- Captive portal HTTP routes wired in web_server.cpp: `/` and onNotFound serve fg_portal_html()
  when g_portalActive; `/post` captures creds -> fg_send_result_fmt {"event":"creds",...} + serial.
- serial_shell.cpp: added `beacon [ch] [list]`, `deauth <bssid> <ch> [tgt]`, `clone <ssid> [ch] [wpa2]`,
  `karma [ch]`, `portal [ssid]` + help menu rows. Args parsed from raw (case-preserving).
- Gotcha #5 RESOLVED: raw 802.11 TX confirmed working on hardware (beacon TX'd 3917 frames).
  Frames transmit cleanly with no sanity-check block; link is clean. Done.

## NEXT
- Exercise `deauth` against a live, authorized BSSID (only path not yet TX-verified).
- Connect a phone to the `portal` AP and confirm the captive page pops + `/post` creds stream.
- Then Phase 3 — BLE (NimBLE): scan → spam → bad-BLE HID.

## WebUI update (2026-06-16)
Backend was fully wired for all modules; only the WebUI lagged (Phase 1 scans only).
Updated `web/index.html`, `web/app.js`, `web/style.css` to expose every backend cmd:
- WiFi Attacks panel: beacon_spam (CSV+ch), ssid_clone (+wpa2 chk), karma, evil_portal, deauth (bssid+target).
- BLE panel: ble_scan (secs), ble_spam (mode select), bad_ble (text).
- Sniffer gains a channel input.
- New table schemas: `ble_dev` (upsert by addr), `creds` (portal/user/pass). Handles `ble_stats`
  (status bar) and `creds` (warn log + row). app.js now builds per-command payloads via buildPayload().
- Rebuilt (embed_web.py regenerates web_assets.h), flashed, clean boot confirmed on /dev/ttyUSB0.
Browser-side functional test of each new button still pending (needs operator at 192.168.4.1).

## BLE bug fix (2026-06-16) — bad_ble crash on stop
Serial-tested all 3 BLE modules. `blescan` + `blespam` (apple/all) worked clean. `badble`
**crashed on stop** with `assert failed: heap_caps_free ... free() target pointer is outside
heap areas` → reboot. Backtrace decoded to `NimBLEServer::~NimBLEServer → FGSrvCB::~FGSrvCB`.
Root cause: `server->setCallbacks(&s_srvcb)` defaults `deleteCallbacks=true`, so NimBLE's
server dtor (run by `deinit(true)`) called `delete` on our **static** `s_srvcb` → non-heap free.
Fix in `src/modules/ble/bad_ble.cpp`:
- `setCallbacks(&s_srvcb, false)` — don't let NimBLE delete a static callback (mirrors ble_scan).
- Also `delete s_hid` before nulling (was a small leak; services are owned/freed by the server).
Reflashed + retested: badble stop is clean (no reboot, heap 137704), and blescan re-inits and
runs fine afterward → NimBLE deinit/reinit cycle healthy, no leak. All 3 BLE modules now pass.

## NEW direction (operator request 2026-06-15) — see implementation_plan.md §8–§9
Governing constraint: 1 WiFi radio = 1 channel/mode at a time → channel-hopping or AP-changing
attacks drop the admin dashboard. Three asks captured as Phase 4 + Phase 5:
- Phase 4 (ESP32-only, no HW): (a) dashboard resilience via "lock attacks to AP channel"
  toggle + reconnect banner; (b) sequential module CHAINING (`fg_chain_task`, playbook of
  steps, e.g. scan→deauth→clone→portal); (c) generalize single-mutex → resource LANES.
- Phase 5: ESP8266 as a 2nd independent radio (UART link on ESP32 Serial2 GPIO16/17, common
  GND, 3.3V direct). ESP32 = brains+dashboard+portal+BLE; ESP8266 = RF-only deauth/beacon on
  any channel → dashboard stays up + TRUE parallel attacks. Pilot: move deauth to coproc.
- Recommended order: Phase 4 (pure SW) first, then ESP8266 bring-up (echo→ping/pong→deauth).
