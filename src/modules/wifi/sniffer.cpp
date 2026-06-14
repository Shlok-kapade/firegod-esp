// ============================================================
// FireGod-ESP — Raw 802.11 Sniffer
//
// Promiscuous-mode capture that AGGREGATES rather than writes pcaps
// (no SD/LittleFS here). The RX callback runs in WiFi-task context,
// so it only does cheap parsing + a spinlock-guarded table update.
// The module loop periodically snapshots the table and streams
// "sniff_dev" (per-device) + "sniff_stats" events to the WebUI.
//
// Frame-decoding logic (frame-control bits, address offsets, beacon/
// deauth/EAPOL detection, SSID extraction) follows the standard
// 802.11 layout — same approach used by Bruce's sniffer (reference).
// ============================================================

#include "sniffer.h"
#include "fg_globals.h"
#include "core/wifi_manager.h"
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <ctype.h>
#include <string.h>

// --- Per-device aggregate record ---
struct SniffDev {
    uint8_t  mac[6];
    int8_t   rssi;        // last seen RSSI
    uint8_t  channel;
    uint32_t frames;      // total frames from this MAC (as transmitter)
    uint32_t lastSeen;    // millis()
    bool     isAp;        // sent a beacon/probe-resp
    char     ssid[33];    // SSID if AP (from beacon), else ""
};

// Fixed table guarded by a spinlock (touched from the RX callback).
static SniffDev      s_dev[FG_SNIFF_MAX_DEV];
static int           s_devCount = 0;
static portMUX_TYPE  s_mux = portMUX_INITIALIZER_UNLOCKED;

// Global counters (callback context).
static volatile uint32_t s_pkts = 0;
static volatile uint32_t s_mgmt = 0;
static volatile uint32_t s_data = 0;
static volatile uint32_t s_ctrl = 0;
static volatile uint32_t s_beacons = 0;
static volatile uint32_t s_deauths = 0;
static volatile uint32_t s_eapol = 0;

// ---------- helpers (callback-safe: no heap, no String) ----------
static inline bool mac_eq(const uint8_t* a, const uint8_t* b) {
    return memcmp(a, b, 6) == 0;
}

// Find or insert device by MAC. Caller holds s_mux. Returns index or -1 if full.
static int dev_find_or_add(const uint8_t* mac) {
    for (int i = 0; i < s_devCount; i++) {
        if (mac_eq(s_dev[i].mac, mac)) return i;
    }
    if (s_devCount >= FG_SNIFF_MAX_DEV) return -1;
    int i = s_devCount++;
    memcpy(s_dev[i].mac, mac, 6);
    s_dev[i].rssi = 0;
    s_dev[i].channel = 0;
    s_dev[i].frames = 0;
    s_dev[i].lastSeen = 0;
    s_dev[i].isAp = false;
    s_dev[i].ssid[0] = '\0';
    return i;
}

// Extract SSID from a beacon/probe-resp into dst (callback-safe).
static void extract_ssid(const uint8_t* payload, int len, char* dst, size_t dstLen) {
    dst[0] = '\0';
    // Fixed mgmt header (24) + timestamp(8)+interval(2)+caps(2) = 36, then tagged params.
    int offset = 36;
    while (offset + 2 <= len) {
        uint8_t tagNum = payload[offset];
        uint8_t tagLen = payload[offset + 1];
        if (offset + 2 + tagLen > len) break;
        if (tagNum == 0x00) { // SSID element
            size_t n = tagLen;
            if (n > dstLen - 1) n = dstLen - 1;
            size_t w = 0;
            for (size_t i = 0; i < n; i++) {
                uint8_t c = payload[offset + 2 + i];
                dst[w++] = isprint(c) ? (char)c : '.';
            }
            dst[w] = '\0';
            return;
        }
        offset += 2 + tagLen;
    }
}

// EAPOL detection (LLC/SNAP 88-8E), with QoS-data 2-byte shift.
static bool is_eapol(const uint8_t* p, int len) {
    if (len < 24 + 8 + 4) return false;
    if (p[24]==0xAA && p[25]==0xAA && p[26]==0x03 &&
        p[30]==0x88 && p[31]==0x8E) return true;
    if ((p[0] & 0x0F) == 0x08) { // QoS data
        if (p[26]==0xAA && p[27]==0xAA && p[28]==0x03 &&
            p[32]==0x88 && p[33]==0x8E) return true;
    }
    return false;
}

// ---------- promiscuous RX callback (WiFi-task context) ----------
static void sniff_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
    const int len = pkt->rx_ctrl.sig_len;
    const int8_t rssi = pkt->rx_ctrl.rssi;
    const uint8_t curCh = pkt->rx_ctrl.channel;
    const uint8_t* p = pkt->payload;

    s_pkts++;
    switch (type) {
        case WIFI_PKT_MGMT: s_mgmt++; break;
        case WIFI_PKT_DATA: s_data++; break;
        case WIFI_PKT_CTRL: s_ctrl++; break;
        default: break;
    }
    if (len < 16) return; // need at least through addr2 (transmitter)

    const uint16_t fc = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    const uint8_t ftype = (fc & 0x0C) >> 2;
    const uint8_t fsub  = (fc & 0xF0) >> 4;

    bool isBeacon = (ftype == 0x00 && (fsub == 0x08 || fsub == 0x05)); // beacon / probe-resp
    bool isDeauth = (ftype == 0x00 && (fsub == 0x0C || fsub == 0x0A)); // deauth / disassoc
    if (isBeacon) s_beacons++;
    if (isDeauth) s_deauths++;

    bool eapol = (type == WIFI_PKT_DATA) && is_eapol(p, len);
    if (eapol) s_eapol++;

    // Transmitter address = addr2 (bytes 10..15).
    const uint8_t* tx = p + 10;

    portENTER_CRITICAL(&s_mux);
    int i = dev_find_or_add(tx);
    if (i >= 0) {
        s_dev[i].rssi = rssi;
        s_dev[i].channel = curCh;
        s_dev[i].frames++;
        s_dev[i].lastSeen = (uint32_t)millis();
        if (isBeacon) {
            s_dev[i].isAp = true;
            if (len >= 38) extract_ssid(p, len, s_dev[i].ssid, sizeof(s_dev[i].ssid));
        }
    }
    portEXIT_CRITICAL(&s_mux);
}

// ---------- emit a snapshot of the device table to the WebUI ----------
static void emit_devices() {
    // Copy out under lock to keep the critical section short.
    static SniffDev snap[FG_SNIFF_MAX_DEV];
    int n;
    portENTER_CRITICAL(&s_mux);
    n = s_devCount;
    memcpy(snap, s_dev, sizeof(SniffDev) * n);
    portEXIT_CRITICAL(&s_mux);

    uint32_t now = millis();
    for (int i = 0; i < n; i++) {
        if (now - snap[i].lastSeen > FG_SNIFF_DEV_TTL) continue;
        String mac = fg_mac_to_str(snap[i].mac);
        const char* vendor = fg_oui_vendor(snap[i].mac);
        // Escape-free fields except SSID; SSID is sanitized to printable-or-dot already.
        fg_send_result_fmt(
            "{\"event\":\"sniff_dev\",\"mac\":\"%s\",\"rssi\":%d,\"ch\":%u,"
            "\"frames\":%lu,\"ap\":%s,\"ssid\":\"%s\",\"vendor\":\"%s\"}",
            mac.c_str(), (int)snap[i].rssi, (unsigned)snap[i].channel,
            (unsigned long)snap[i].frames, snap[i].isAp ? "true" : "false",
            snap[i].ssid, vendor);
        vTaskDelay(pdMS_TO_TICKS(3)); // let the sender drain the queue
    }
}

static void emit_stats(uint8_t channel) {
    fg_send_result_fmt(
        "{\"event\":\"sniff_stats\",\"ch\":%u,\"pkts\":%lu,\"mgmt\":%lu,"
        "\"data\":%lu,\"ctrl\":%lu,\"beacons\":%lu,\"deauth\":%lu,"
        "\"eapol\":%lu,\"devices\":%d}",
        (unsigned)channel,
        (unsigned long)s_pkts, (unsigned long)s_mgmt, (unsigned long)s_data,
        (unsigned long)s_ctrl, (unsigned long)s_beacons, (unsigned long)s_deauths,
        (unsigned long)s_eapol, s_devCount);
}

// ---------- module entry ----------
void fg_sniffer(uint8_t channel) {
    // channel 0 => stay on the AP channel so the WebUI survives.
    if (channel == 0) channel = FG_AP_CHANNEL;
    if (channel > 14) channel = FG_AP_CHANNEL;

    // Reset aggregation state.
    portENTER_CRITICAL(&s_mux);
    s_devCount = 0;
    portEXIT_CRITICAL(&s_mux);
    s_pkts = s_mgmt = s_data = s_ctrl = s_beacons = s_deauths = s_eapol = 0;

    fg_send_result_fmt(
        "{\"event\":\"log\",\"msg\":\"Sniffer starting on channel %u...\"}", channel);
    Serial.printf("[Sniffer] Promiscuous on channel %u\n", channel);

    // Enter promiscuous on the chosen channel. We keep the existing AP up;
    // setting the channel just pins the radio (AP follows on channel 0 case).
    fg_wifi_set_channel(channel);
    fg_wifi_enter_promiscuous(sniff_cb);

    uint32_t lastEmit = millis();
    while (!g_stopRequested) {
        vTaskDelay(pdMS_TO_TICKS(50));
        uint32_t now = millis();
        if (now - lastEmit >= FG_SNIFF_EMIT_MS) {
            lastEmit = now;
            emit_stats(channel);
            emit_devices();
            Serial.printf("[Sniffer] ch=%u pkts=%lu dev=%d beacons=%lu deauth=%lu eapol=%lu\n",
                          channel, (unsigned long)s_pkts, s_devCount,
                          (unsigned long)s_beacons, (unsigned long)s_deauths,
                          (unsigned long)s_eapol);
        }
    }

    fg_wifi_exit_promiscuous();
    fg_send_result_fmt(
        "{\"event\":\"scan_complete\",\"type\":\"sniff\",\"count\":%d}", s_devCount);
    Serial.printf("[Sniffer] Stopped. %lu packets, %d devices.\n",
                  (unsigned long)s_pkts, s_devCount);
}
