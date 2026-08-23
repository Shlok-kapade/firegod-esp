#pragma once
// ============================================================
// FireGod-ESP — WiFi Manager
// AP/STA management, promiscuous mode, raw TX
// ============================================================

#include <WiFi.h>
#include <esp_wifi.h>

void fg_wifi_init();
void fg_wifi_start_ap();
void fg_wifi_stop();
void fg_wifi_set_channel(uint8_t ch);
void fg_wifi_enter_promiscuous(wifi_promiscuous_cb_t cb);
void fg_wifi_exit_promiscuous();
bool fg_wifi_connect_sta(const char* ssid, const char* pass, uint32_t timeout_ms = 10000);
void fg_wifi_disconnect_sta();

// --- Raw 802.11 TX (Phase 2 offensive modules) ---
// Puts the radio into a TX-capable AP mode if not already, then injects a raw
// 802.11 frame on the current channel. The sanity check is bypassed via the
// linker wrap (__wrap_ieee80211_raw_frame_sanity_check). Returns esp_err_t.
int  fg_wifi_raw_tx(const uint8_t* frame, int len);
// Bring the radio up in a bare AP/promisc state suitable for injection on `ch`.
void fg_wifi_enter_tx_mode(uint8_t ch);
