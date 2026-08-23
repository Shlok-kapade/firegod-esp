// ============================================================
// FireGod-ESP — Serial Shell Implementation
// ============================================================

#include "serial_shell.h"
#include "fg_globals.h"
#include "core/wifi_manager.h"
#include "core/web_server.h"
#include "modules/wifi/ap_scanner.h"
#include "modules/wifi/arp_scanner.h"
#include "modules/wifi/client_scanner.h"
#include "modules/wifi/sniffer.h"
#include "modules/wifi/beacon_spam.h"
#include "modules/wifi/deauth.h"
#include "modules/wifi/ssid_clone.h"
#include "modules/wifi/karma.h"
#include "modules/wifi/evil_portal.h"
#include "modules/wifi/mitm.h"
#include "modules/ble/ble_scan.h"
#include "modules/ble/ble_spam.h"
#include "modules/ble/bad_ble.h"
#include "modules/ble/ble_detect.h"
#include <esp_wifi.h>

static String inputBuffer = "";

static void processCommand(const String& cmd);

// Run a module body under the single-module mutex (serial path runs on Core 1,
// same core as module tasks, so we call the entry function directly).
typedef void (*FGSerialModuleFn)(void* ctx);
static bool runModuleLocked(FGModule mod, FGSerialModuleFn fn, void* ctx) {
    if (g_moduleState != STATE_IDLE) {
        Serial.println("[!] Module busy. Use 'stop' first.");
        return false;
    }
    if (xSemaphoreTake(g_moduleMutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        Serial.println("[!] Could not acquire module mutex.");
        return false;
    }
    g_moduleState = STATE_RUNNING;
    g_activeModule = mod;
    g_stopRequested = false;
    fn(ctx);
    g_moduleState = STATE_IDLE;
    g_activeModule = MOD_NONE;
    g_stopRequested = false;
    xSemaphoreGive(g_moduleMutex);
    return true;
}

// Parse `scan arp <ssid> <pass>` from the original (case-preserving) input.
// Splits on the first two spaces after the verb; pass may be empty (open net).
static bool parseJoinArgs(const String& raw, const char* verb,
                          String& ssid, String& pass) {
    String s = raw; s.trim();
    String prefix = String(verb) + " ";
    if (!s.startsWith(prefix)) return false;
    String rest = s.substring(prefix.length()); rest.trim();
    if (rest.length() == 0) return false;
    int sp = rest.indexOf(' ');
    if (sp < 0) { ssid = rest; pass = ""; }
    else { ssid = rest.substring(0, sp); pass = rest.substring(sp + 1); pass.trim(); }
    return ssid.length() > 0;
}

// Trampolines so runModuleLocked can call the join scanners with args.
struct JoinCtx { String ssid; String pass; };
static void arpTrampoline(void* ctx) {
    JoinCtx* j = (JoinCtx*)ctx;
    fg_arp_scan(j->ssid.c_str(), j->pass.c_str());
}
static void clientTrampoline(void* ctx) {
    JoinCtx* j = (JoinCtx*)ctx;
    fg_client_scan(j->ssid.c_str(), j->pass.c_str());
}
static void apTrampoline(void* ctx) { (void)ctx; fg_ap_scan(); }

void fg_serial_shell_init() {
    Serial.println("\n╔══════════════════════════════════╗");
    Serial.println("║  🔥 FireGod-ESP Serial Shell     ║");
    Serial.println("║  Type 'help' for commands        ║");
    Serial.println("╚══════════════════════════════════╝");
    Serial.print("firegod> ");
}

// Runs on Core 1 as a FreeRTOS task
void fg_serial_shell_task(void* param) {
    for (;;) {
        while (Serial.available()) {
            char c = Serial.read();
            if (c == '\n' || c == '\r') {
                if (inputBuffer.length() > 0) {
                    Serial.println();
                    processCommand(inputBuffer);
                    inputBuffer = "";
                    Serial.print("firegod> ");
                }
            } else if (c == 127 || c == 8) { // Backspace
                if (inputBuffer.length() > 0) {
                    inputBuffer.remove(inputBuffer.length() - 1);
                    Serial.print("\b \b");
                }
            } else {
                inputBuffer += c;
                Serial.print(c);
            }
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}

static void processCommand(const String& cmd) {
    String raw = cmd;
    raw.trim();
    String c = raw;          // lowercased copy for keyword matching
    c.toLowerCase();

    if (c == "help") {
        Serial.println("╔═══════════════════════════════════════════════╗");
        Serial.println("║  FireGod-ESP Commands                         ║");
        Serial.println("╠═══════════════════════════════════════════════╣");
        Serial.println("║  scan wifi              - Scan nearby APs      ║");
        Serial.println("║  scan arp <ssid> <pass> - ARP subnet sweep    ║");
        Serial.println("║  scan clients <ssid> <pass> - Client scan     ║");
        Serial.println("║  sniff [ch]             - Raw 802.11 sniffer  ║");
        Serial.println("║  beacon [ch] [list]     - Beacon spam         ║");
        Serial.println("║  deauth <bssid> <ch> [tgt] - Deauth flood     ║");
        Serial.println("║  clone <ssid> [ch] [wpa2]  - SSID clone       ║");
        Serial.println("║  karma [ch]             - Karma probe-resp    ║");
        Serial.println("║  portal [ssid]          - Evil captive portal ║");
        Serial.println("║  mitm <ssid> <pass> [all|ip] - ARP MITM       ║");
        Serial.println("║  blescan [secs]         - BLE device scan     ║");
        Serial.println("║  blespam [type]         - BLE pairing spam     ║");
        Serial.println("║  bledetect [secs]       - BLE spam detector   ║");
        Serial.println("║  badble [text]          - BLE HID keyboard    ║");
        Serial.println("║  stop                   - Stop active module  ║");
        Serial.println("║  status                 - System status       ║");
        Serial.println("║  reboot                 - Restart ESP32       ║");
        Serial.println("║  help                   - This menu           ║");
        Serial.println("╚═══════════════════════════════════════════════╝");
        Serial.println("  (open networks: omit <pass>)");
    }
    else if (c == "scan wifi") {
        Serial.println("[*] Starting WiFi AP scan...");
        runModuleLocked(MOD_WIFI_AP_SCAN, apTrampoline, nullptr);
    }
    else if (c.startsWith("scan arp")) {
        JoinCtx j;
        if (!parseJoinArgs(raw, "scan arp", j.ssid, j.pass)) {
            Serial.println("[!] Usage: scan arp <ssid> <pass>");
            return;
        }
        Serial.printf("[*] ARP sweep via '%s'...\n", j.ssid.c_str());
        runModuleLocked(MOD_WIFI_ARP_SCAN, arpTrampoline, &j);
    }
    else if (c.startsWith("scan clients")) {
        JoinCtx j;
        if (!parseJoinArgs(raw, "scan clients", j.ssid, j.pass)) {
            Serial.println("[!] Usage: scan clients <ssid> <pass>");
            return;
        }
        Serial.printf("[*] Client scan via '%s'...\n", j.ssid.c_str());
        runModuleLocked(MOD_WIFI_CLIENT_SCAN, clientTrampoline, &j);
    }
    else if (c == "sniff" || c.startsWith("sniff ")) {
        // sniff [channel]; channel 0/omitted = AP channel (WebUI stays up).
        int ch = 0;
        int sp = c.indexOf(' ');
        if (sp > 0) ch = c.substring(sp + 1).toInt();
        if (ch < 0 || ch > 14) {
            Serial.println("[!] channel must be 0-14 (0 = AP channel)");
            return;
        }
        // Runs on its own task so the shell stays responsive for 'stop'.
        if (fg_launch_module(MOD_WIFI_SNIFFER, nullptr, nullptr, (uint8_t)ch)) {
            Serial.printf("[*] Sniffer started (ch %d). Type 'stop' to end.\n", ch);
        }
    }
    else if (c == "beacon" || c.startsWith("beacon ")) {
        // beacon [ch] [ssid,ssid,...]  (ch 0 = hop 1/6/11; list optional)
        uint8_t ch = 0; String list;
        String rest = raw.substring(6); rest.trim();
        if (rest.length()) {
            int sp = rest.indexOf(' ');
            String first = sp < 0 ? rest : rest.substring(0, sp);
            if (first.toInt() > 0 || first == "0") {
                ch = (uint8_t)first.toInt();
                if (sp > 0) { list = rest.substring(sp + 1); list.trim(); }
            } else { list = rest; }      // no leading channel, whole rest is the list
        }
        if (fg_launch_module(MOD_WIFI_BEACON_SPAM, nullptr, nullptr, ch, false,
                             list.length() ? list.c_str() : nullptr))
            Serial.printf("[*] Beacon spam started (ch %d). 'stop' to end.\n", ch);
    }
    else if (c.startsWith("deauth")) {
        // deauth <bssid> <ch> [target-mac]
        String rest = raw.substring(6); rest.trim();
        String bssid, target; int ch = 0;
        int sp1 = rest.indexOf(' ');
        if (sp1 > 0) {
            bssid = rest.substring(0, sp1);
            String r2 = rest.substring(sp1 + 1); r2.trim();
            int sp2 = r2.indexOf(' ');
            if (sp2 < 0) { ch = r2.toInt(); }
            else { ch = r2.substring(0, sp2).toInt(); target = r2.substring(sp2 + 1); target.trim(); }
        }
        if (bssid.length() == 0 || ch < 1 || ch > 14) {
            Serial.println("[!] Usage: deauth <bssid> <ch 1-14> [target-mac]");
            return;
        }
        if (fg_launch_module(MOD_WIFI_DEAUTH, bssid.c_str(),
                             target.length() ? target.c_str() : nullptr, (uint8_t)ch))
            Serial.printf("[*] Deauth started on %s ch %d. 'stop' to end.\n", bssid.c_str(), ch);
    }
    else if (c.startsWith("clone")) {
        // clone <ssid> [ch] [wpa2]
        String rest = raw.substring(5); rest.trim();
        if (rest.length() == 0) { Serial.println("[!] Usage: clone <ssid> [ch] [wpa2]"); return; }
        uint8_t ch = 0; bool wpa2 = false; String ssid = rest;
        // strip optional trailing "wpa2"
        String low = rest; low.toLowerCase();
        if (low.endsWith(" wpa2")) { wpa2 = true; rest = rest.substring(0, rest.length() - 5); rest.trim(); ssid = rest; }
        // strip optional trailing channel number
        int sp = rest.lastIndexOf(' ');
        if (sp > 0 && rest.substring(sp + 1).toInt() > 0) {
            ch = (uint8_t)rest.substring(sp + 1).toInt();
            ssid = rest.substring(0, sp); ssid.trim();
        }
        if (fg_launch_module(MOD_WIFI_SSID_CLONE, ssid.c_str(), nullptr, ch, wpa2))
            Serial.printf("[*] Cloning '%s' (ch %d, %s). 'stop' to end.\n",
                          ssid.c_str(), ch, wpa2 ? "wpa2" : "open");
    }
    else if (c == "karma" || c.startsWith("karma ")) {
        int ch = 0, sp = c.indexOf(' ');
        if (sp > 0) ch = c.substring(sp + 1).toInt();
        if (ch < 0 || ch > 14) { Serial.println("[!] channel must be 0-14"); return; }
        if (fg_launch_module(MOD_WIFI_KARMA, nullptr, nullptr, (uint8_t)ch))
            Serial.printf("[*] Karma started (ch %d). 'stop' to end.\n", ch);
    }
    else if (c == "portal" || c.startsWith("portal ")) {
        // portal [ssid]  (default "Free WiFi")
        String ssid = raw.substring(6); ssid.trim();
        const char* s = ssid.length() ? ssid.c_str() : "Free WiFi";
        if (fg_launch_module(MOD_WIFI_EVIL_PORTAL, s, nullptr, 0))
            Serial.printf("[*] Evil portal '%s' up. 'stop' to end.\n", s);
    }
    else if (c == "mitm" || c.startsWith("mitm ")) {
        // mitm <ssid> <pass> [all|<client-ip>]   (parsed case-preserving)
        String rest = raw.substring(4); rest.trim();
        int sp1 = rest.indexOf(' ');
        if (sp1 < 0) { Serial.println("[!] Usage: mitm <ssid> <pass> [all|ip]"); return; }
        String ssid = rest.substring(0, sp1);
        String r2 = rest.substring(sp1 + 1); r2.trim();
        int sp2 = r2.indexOf(' ');
        String pass, target = "all";
        if (sp2 < 0) { pass = r2; }
        else { pass = r2.substring(0, sp2); target = r2.substring(sp2 + 1); target.trim(); }
        if (ssid.length() == 0 || pass.length() == 0) {
            Serial.println("[!] Usage: mitm <ssid> <pass> [all|ip]"); return;
        }
        if (fg_launch_module(MOD_WIFI_MITM, ssid.c_str(), pass.c_str(), 0, false, target.c_str()))
            Serial.printf("[*] MITM on '%s' (target %s). 'stop' to end.\n",
                          ssid.c_str(), target.c_str());
    }
    else if (c == "blescan" || c.startsWith("blescan ")) {
        // blescan [secs]  (0/omitted = until stop)
        int secs = 0, sp = c.indexOf(' ');
        if (sp > 0) secs = c.substring(sp + 1).toInt();
        if (secs < 0) secs = 0; if (secs > 255) secs = 255;
        if (fg_launch_module(MOD_BLE_SCAN, nullptr, nullptr, (uint8_t)secs))
            Serial.printf("[*] BLE scan started (%s). 'stop' to end.\n",
                          secs ? "timed" : "until stop");
    }
    else if (c == "blespam" || c.startsWith("blespam ")) {
        // blespam [all|apple|microsoft|android]
        String a = c.substring(7); a.trim();
        uint8_t mode = 0;
        if (a == "apple") mode = 1; else if (a == "microsoft" || a == "ms") mode = 2;
        else if (a == "android") mode = 3;
        if (fg_launch_module(MOD_BLE_SPAM, nullptr, nullptr, mode))
            Serial.println("[*] BLE spam started. 'stop' to end.");
    }
    else if (c == "bledetect" || c.startsWith("bledetect ")) {
        // bledetect [secs]  (0/omitted = until stop)
        int secs = 0, sp = c.indexOf(' ');
        if (sp > 0) secs = c.substring(sp + 1).toInt();
        if (secs < 0) secs = 0; if (secs > 255) secs = 255;
        if (fg_launch_module(MOD_BLE_DETECT, nullptr, nullptr, (uint8_t)secs))
            Serial.printf("[*] BLE spam detector started (%s). 'stop' to end.\n",
                          secs ? "timed" : "until stop");
    }
    else if (c == "badble" || c.startsWith("badble ")) {
        // badble [text...]  (typed on connect; default demo string)
        String txt = raw.substring(6); txt.trim();
        if (fg_launch_module(MOD_BLE_BAD_BLE, nullptr, nullptr, 0, false,
                             txt.length() ? txt.c_str() : nullptr))
            Serial.println("[*] Bad-BLE keyboard advertising. 'stop' to end.");
    }
    else if (c == "stop") {
        g_stopRequested = true;
        Serial.println("[*] Stop requested.");
    }
    else if (c == "status") {
        Serial.println("╔═══════════════════════════════════════╗");
        Serial.printf( "║  Heap Free:  %6lu bytes             ║\n", (unsigned long)ESP.getFreeHeap());
        Serial.printf( "║  Heap Min:   %6lu bytes             ║\n", (unsigned long)ESP.getMinFreeHeap());
        Serial.printf( "║  Uptime:     %6lu seconds           ║\n", (unsigned long)fg_uptime_secs());
        Serial.printf( "║  Module:     %d  State: %d              ║\n", g_activeModule, g_moduleState);
        Serial.printf( "║  WiFi Mode:  %d                        ║\n", WiFi.getMode());
        Serial.printf( "║  AP Clients: %d                        ║\n", WiFi.softAPgetStationNum());
        Serial.printf( "║  CPU Freq:   %d MHz                   ║\n", getCpuFrequencyMhz());
        Serial.println("╚═══════════════════════════════════════╝");
    }
    else if (c == "reboot") {
        Serial.println("[*] Rebooting...");
        delay(500);
        ESP.restart();
    }
    else {
        Serial.printf("[!] Unknown command: '%s'. Type 'help'.\n", cmd.c_str());
    }
}
