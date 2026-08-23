// ============================================================
// FireGod-ESP — WiFi Manager Implementation
// ============================================================

#include "wifi_manager.h"
#include "fg_globals.h"
#include <esp_wifi.h>
#include <esp_wifi_types.h>

// ----- RAW 802.11 TX BYPASS (Phase 2) -----
// Crafted-frame injection (deauth/beacon) needs the sanity check bypassed.
// On espressif32 6.9.0 the WiFi lib defines a (non-weak) symbol, so a plain
// override collides at link time. We instead intercept it with the GNU linker
// wrap (-Wl,--wrap=ieee80211_raw_frame_sanity_check in platformio.ini): every
// call to the real symbol is routed here and we always report "valid", which
// lets esp_wifi_80211_tx() inject arbitrary frames.
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3);
extern "C" int __wrap_ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
    (void)arg; (void)arg2; (void)arg3;
    return 0;  // 0 == OK; bypasses the length/format gate for raw injection.
}

void fg_wifi_init() {
    // Ensure WiFi is in a clean state
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    delay(100);
}

void fg_wifi_start_ap() {
    Serial.println("[WiFi] Starting AP mode...");

    WiFi.mode(WIFI_AP);
    delay(100);

    // Configure static IP
    WiFi.softAPConfig(FG_AP_IP, FG_AP_GATEWAY, FG_AP_SUBNET);

    // Start AP
    bool ok = WiFi.softAP(FG_AP_SSID, FG_AP_PASS, FG_AP_CHANNEL, 0, FG_AP_MAX_CONN);
    if (!ok) {
        Serial.println("[WiFi] ERROR: Failed to start AP!");
        return;
    }

    Serial.printf("[WiFi] AP started: %s\n", FG_AP_SSID);
    Serial.printf("[WiFi] IP: %s\n", WiFi.softAPIP().toString().c_str());
    Serial.printf("[WiFi] Channel: %d\n", FG_AP_CHANNEL);

    // Max TX power
    esp_wifi_set_max_tx_power(78);
}

void fg_wifi_stop() {
    Serial.println("[WiFi] Full cleanup...");
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    WiFi.disconnect(true);
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_OFF);
    delay(200);
}

void fg_wifi_set_channel(uint8_t ch) {
    if (ch < 1 || ch > 14) return;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
}

void fg_wifi_enter_promiscuous(wifi_promiscuous_cb_t cb) {
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(cb);
    esp_wifi_set_promiscuous(true);
    Serial.println("[WiFi] Promiscuous mode ON");
}

void fg_wifi_exit_promiscuous() {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    Serial.println("[WiFi] Promiscuous mode OFF");
}

bool fg_wifi_connect_sta(const char* ssid, const char* pass, uint32_t timeout_ms) {
    Serial.printf("[WiFi] Connecting STA to: %s\n", ssid);

    // Switch to AP+STA mode to keep our AP running
    WiFi.mode(WIFI_AP_STA);
    delay(100);

    // Re-establish AP in AP+STA mode
    WiFi.softAPConfig(FG_AP_IP, FG_AP_GATEWAY, FG_AP_SUBNET);
    WiFi.softAP(FG_AP_SSID, FG_AP_PASS, FG_AP_CHANNEL, 0, FG_AP_MAX_CONN);

    WiFi.begin(ssid, pass);

    uint32_t start = millis();
    while (WiFi.status() != WL_CONNECTED) {
        if (millis() - start > timeout_ms) {
            Serial.println("[WiFi] STA connection timeout!");
            return false;
        }
        if (g_stopRequested) {
            Serial.println("[WiFi] STA connection aborted.");
            return false;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    Serial.printf("[WiFi] STA connected! IP: %s\n", WiFi.localIP().toString().c_str());
    Serial.printf("[WiFi] Gateway: %s\n", WiFi.gatewayIP().toString().c_str());
    Serial.printf("[WiFi] Subnet: %s\n", WiFi.subnetMask().toString().c_str());
    return true;
}

int fg_wifi_raw_tx(const uint8_t* frame, int len) {
    // en_sys_seq=false: let the driver keep our crafted sequence/duration fields.
    return (int)esp_wifi_80211_tx(WIFI_IF_AP, frame, len, false);
}

void fg_wifi_enter_tx_mode(uint8_t ch) {
    // Injection works from AP mode with promiscuous on; this keeps our SoftAP
    // alive (so the WebUI survives) while letting us pin a channel and TX.
    if (WiFi.getMode() != WIFI_AP && WiFi.getMode() != WIFI_AP_STA) {
        WiFi.mode(WIFI_AP);
        delay(100);
        WiFi.softAPConfig(FG_AP_IP, FG_AP_GATEWAY, FG_AP_SUBNET);
        WiFi.softAP(FG_AP_SSID, FG_AP_PASS, FG_AP_CHANNEL, 0, FG_AP_MAX_CONN);
    }
    esp_wifi_set_promiscuous(true);
    if (ch >= 1 && ch <= 14) esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
}

void fg_wifi_disconnect_sta() {
    WiFi.disconnect(true);
    WiFi.mode(WIFI_AP);
    delay(100);
    // Re-establish AP
    WiFi.softAPConfig(FG_AP_IP, FG_AP_GATEWAY, FG_AP_SUBNET);
    WiFi.softAP(FG_AP_SSID, FG_AP_PASS, FG_AP_CHANNEL, 0, FG_AP_MAX_CONN);
    Serial.println("[WiFi] STA disconnected, AP restored.");
}
