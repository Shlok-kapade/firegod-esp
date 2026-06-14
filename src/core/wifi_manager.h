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
