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
