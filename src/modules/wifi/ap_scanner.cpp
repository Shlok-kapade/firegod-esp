// ============================================================
// FireGod-ESP — WiFi AP Scanner
// Scans all 2.4GHz channels for access points
// ============================================================

#include "ap_scanner.h"
#include "fg_globals.h"
#include "core/wifi_manager.h"
#include <WiFi.h>
#include <esp_wifi.h>

void fg_ap_scan() {
    fg_send_result("{\"event\":\"log\",\"msg\":\"Starting WiFi AP scan...\"}");
    Serial.println("[APScan] Scanning...");

    // Ensure we're in a mode that allows scanning
    wifi_mode_t currentMode = WiFi.getMode();
    if (currentMode == WIFI_OFF) {
        WiFi.mode(WIFI_AP_STA);
        delay(100);
    }

    int n = WiFi.scanNetworks(false, true, false, 300);

    if (n < 0) {
        fg_send_result("{\"event\":\"error\",\"msg\":\"WiFi scan failed\"}");
        Serial.println("[APScan] Scan failed!");
        return;
    }

    fg_send_result_fmt("{\"event\":\"log\",\"msg\":\"Found %d access points\"}", n);
    Serial.printf("[APScan] Found %d networks\n", n);

    // Serial table header
    Serial.println("┌────┬──────────────────────────────┬───────────────────┬──────┬────┬────────────┬──────────┐");
    Serial.println("│ #  │ SSID                         │ BSSID             │ RSSI │ CH │ Encryption │ Vendor   │");
    Serial.println("├────┼──────────────────────────────┼───────────────────┼──────┼────┼────────────┼──────────┤");

    for (int i = 0; i < n && !g_stopRequested; i++) {
        String ssid = WiFi.SSID(i);
        String bssid = WiFi.BSSIDstr(i);
        int32_t rssi = WiFi.RSSI(i);
        int32_t ch = WiFi.channel(i);
        int authMode = WiFi.encryptionType(i);
        const char* enc = fg_auth_to_str(authMode);
        const char* vendor = fg_oui_vendor(WiFi.BSSID(i));
        bool hidden = ssid.length() == 0;

        if (hidden) ssid = "<hidden>";

        // Send to WebSocket
        fg_send_result_fmt(
            "{\"event\":\"ap\",\"ssid\":\"%s\",\"bssid\":\"%s\",\"rssi\":%d,\"ch\":%d,\"enc\":\"%s\",\"vendor\":\"%s\",\"hidden\":%s}",
            ssid.c_str(), bssid.c_str(), rssi, ch, enc, vendor,
            hidden ? "true" : "false"
        );

        // Serial table row
        Serial.printf("│ %-2d │ %-28s │ %-17s │ %-4d │ %-2d │ %-10s │ %-8s │\n",
                       i + 1, ssid.c_str(), bssid.c_str(), rssi, ch, enc, vendor);

        vTaskDelay(pdMS_TO_TICKS(10)); // Yield for WebSocket
    }

    Serial.println("└────┴──────────────────────────────┴───────────────────┴──────┴────┴────────────┴──────────┘");

    WiFi.scanDelete();

    fg_send_result_fmt("{\"event\":\"scan_complete\",\"type\":\"ap\",\"count\":%d}", n);
    Serial.printf("[APScan] Complete. %d APs found. Heap: %lu\n", n, (unsigned long)ESP.getFreeHeap());
}
