// ============================================================
// FireGod-ESP — Beacon Spam
// Broadcasts fake AP beacons (random BSSID per SSID) to populate
// nearby device scan lists. Authorized testing only.
// ============================================================

#include "beacon_spam.h"
#include "fg_globals.h"
#include "core/wifi_manager.h"
#include "wifi_frames.h"
#include <esp_wifi.h>
#include <string.h>

#define FG_BEACON_MAX_SSIDS 32

static const char* DEFAULT_SSIDS[] = {
    "FreeWiFi", "Starbucks WiFi", "Airport_Free", "Guest_Network",
    "ATT-WiFi", "xfinitywifi", "Hotel_Guest", "Public_Hotspot",
    "NETGEAR_5G", "linksys", "HomeWiFi_2.4", "CoffeeShop",
    "Library_WiFi", "Campus_Net", "OpenAccess", "ESP_Decoy",
};
static const int DEFAULT_COUNT = sizeof(DEFAULT_SSIDS) / sizeof(DEFAULT_SSIDS[0]);

// Parse a comma-separated SSID list into the fixed table; returns count.
static int parse_ssids(const char* arg, char table[][33]) {
    if (!arg || !*arg) {
        int n = DEFAULT_COUNT;
        if (n > FG_BEACON_MAX_SSIDS) n = FG_BEACON_MAX_SSIDS;
        for (int i = 0; i < n; i++) {
            strncpy(table[i], DEFAULT_SSIDS[i], 32);
            table[i][32] = '\0';
        }
        return n;
    }
    int count = 0, w = 0;
    for (const char* c = arg; ; c++) {
        if (*c == ',' || *c == '\0') {
            if (w > 0) {
                table[count][w] = '\0';
                count++;
                w = 0;
                if (count >= FG_BEACON_MAX_SSIDS) break;
            }
            if (*c == '\0') break;
        } else if (w < 32) {
            table[count][w++] = *c;
        }
    }
    return count;
}

void fg_beacon_spam(const char* ssidArg, uint8_t channel) {
    static char ssids[FG_BEACON_MAX_SSIDS][33];
    int n = parse_ssids(ssidArg, ssids);
    if (n == 0) {
        fg_send_result("{\"event\":\"error\",\"msg\":\"No SSIDs to spam\"}");
        return;
    }

    const bool hop = (channel == 0);
    uint8_t hopCh[] = {1, 6, 11};
    uint8_t ch = hop ? 1 : channel;

    fg_wifi_enter_tx_mode(ch);
    fg_send_result_fmt(
        "{\"event\":\"log\",\"msg\":\"Beacon spam: %d SSIDs, %s\"}",
        n, hop ? "hopping 1/6/11" : "fixed channel");

    uint8_t frame[160];
    uint8_t bssid[6];
    uint32_t sent = 0;
    uint32_t lastStat = millis();
    int hopIdx = 0;

    while (!g_stopRequested) {
        for (int i = 0; i < n && !g_stopRequested; i++) {
            // Stable-ish BSSID per SSID: random base XOR index.
            fg_rand_mac(bssid);
            bssid[5] = (uint8_t)i;
            int len = fg_build_beacon(frame, ssids[i], bssid, ch, false);
            fg_wifi_raw_tx(frame, len);
            sent++;
            // Small spacing so the driver TX queue keeps up.
            if ((i & 0x03) == 0) vTaskDelay(1);
        }
        if (hop) {
            hopIdx = (hopIdx + 1) % 3;
            ch = hopCh[hopIdx];
            esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        }
        uint32_t now = millis();
        if (now - lastStat >= 1000) {
            lastStat = now;
            fg_send_result_fmt(
                "{\"event\":\"spam_stats\",\"type\":\"beacon\",\"sent\":%lu,\"ch\":%u,\"ssids\":%d}",
                (unsigned long)sent, (unsigned)ch, n);
        }
        vTaskDelay(pdMS_TO_TICKS(5));
    }

    esp_wifi_set_promiscuous(false);
    fg_send_result_fmt(
        "{\"event\":\"scan_complete\",\"type\":\"beacon\",\"count\":%lu}",
        (unsigned long)sent);
}
