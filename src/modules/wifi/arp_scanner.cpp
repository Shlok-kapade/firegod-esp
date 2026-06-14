// ============================================================
// FireGod-ESP — ARP / subnet host scanner
//
// Joins a target network via STA (AP stays up via AP+STA), then
// ARP-sweeps the local /24. Live hosts are read straight out of
// the lwIP ARP cache and streamed as JSON events.
//
// The ESP32 lwIP ARP table is small (ARP_TABLE_SIZE, ~10), so we
// blast requests in small batches and drain the cache between
// batches, deduping by IP, instead of flooding all 254 at once.
// ============================================================

#include "arp_scanner.h"
#include "fg_globals.h"
#include "core/wifi_manager.h"
#include <WiFi.h>

extern "C" {
#include "lwip/netif.h"
#include "lwip/etharp.h"
#include "lwip/ip4_addr.h"
#include "lwip/tcpip.h"
}

#ifndef ARP_TABLE_SIZE
#define ARP_TABLE_SIZE 10
#endif

// Find the lwIP netif whose IPv4 address matches our STA address.
static struct netif* find_netif_for_ip(uint32_t ip_host_order) {
    for (struct netif* nif = netif_list; nif != nullptr; nif = nif->next) {
        const ip4_addr_t* a = netif_ip4_addr(nif);
        if (a && ip4_addr_get_u32(a) == lwip_htonl(ip_host_order)) return nif;
    }
    return nullptr;
}

// Drain currently-resolved ARP entries on `nif`. For each entry not already
// in seen[], emit a JSON event and record it. Returns count newly emitted.
static int drain_arp_table(struct netif* nif, const char* event,
                           uint32_t* seen, int& seenCount, uint32_t selfIp) {
    int emitted = 0;
    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
        ip4_addr_t* ip = nullptr;
        struct netif* enif = nullptr;
        struct eth_addr* eth = nullptr;

        LOCK_TCPIP_CORE();
        s8_t valid = etharp_get_entry(i, &ip, &enif, &eth);
        UNLOCK_TCPIP_CORE();

        if (!valid || !ip || !eth || enif != nif) continue;

        uint32_t hostIp = lwip_ntohl(ip4_addr_get_u32(ip));
        if (hostIp == selfIp) continue;

        // Dedup
        bool known = false;
        for (int k = 0; k < seenCount; k++) {
            if (seen[k] == hostIp) { known = true; break; }
        }
        if (known) continue;
        if (seenCount < FG_MAX_ARP_HOSTS) seen[seenCount++] = hostIp;

        uint8_t mac[6];
        memcpy(mac, eth->addr, 6);
        String macStr = fg_mac_to_str(mac);
        const char* vendor = fg_oui_vendor(mac);

        char ipStr[16];
        snprintf(ipStr, sizeof(ipStr), "%u.%u.%u.%u",
                 (unsigned)((hostIp >> 24) & 0xFF), (unsigned)((hostIp >> 16) & 0xFF),
                 (unsigned)((hostIp >> 8) & 0xFF), (unsigned)(hostIp & 0xFF));

        fg_send_result_fmt(
            "{\"event\":\"%s\",\"ip\":\"%s\",\"mac\":\"%s\",\"vendor\":\"%s\"}",
            event, ipStr, macStr.c_str(), vendor);
        Serial.printf("[ARP] %-15s  %s  %s\n", ipStr, macStr.c_str(), vendor);
        emitted++;
    }
    return emitted;
}

void fg_subnet_sweep(const char* ssid, const char* pass, const char* event) {
    fg_send_result_fmt("{\"event\":\"log\",\"msg\":\"Joining %s for sweep...\"}", ssid);

    if (!fg_wifi_connect_sta(ssid, pass)) {
        fg_send_result("{\"event\":\"error\",\"msg\":\"STA connect failed\"}");
        fg_wifi_disconnect_sta();
        return;
    }

    uint32_t self = (uint32_t)WiFi.localIP();          // network-byte-order packed
    uint32_t selfHost = lwip_ntohl(self);              // host order for math
    uint32_t mask = (uint32_t)WiFi.subnetMask();
    uint32_t maskHost = lwip_ntohl(mask);
    uint32_t base = selfHost & maskHost;               // network address (host order)

    struct netif* nif = find_netif_for_ip(selfHost);
    if (!nif) {
        fg_send_result("{\"event\":\"error\",\"msg\":\"STA netif not found\"}");
        fg_wifi_disconnect_sta();
        return;
    }

    fg_send_result_fmt(
        "{\"event\":\"log\",\"msg\":\"Sweeping subnet %u.%u.%u.0/24...\"}",
        (unsigned)((base >> 24) & 0xFF), (unsigned)((base >> 16) & 0xFF),
        (unsigned)((base >> 8) & 0xFF));

    static uint32_t seen[FG_MAX_ARP_HOSTS];
    int seenCount = 0;
    const int BATCH = 8;

    for (int start = 1; start <= 254 && !g_stopRequested; start += BATCH) {
        for (int h = start; h < start + BATCH && h <= 254; h++) {
            uint32_t targetHost = (base & 0xFFFFFF00) | (uint32_t)h;
            if (targetHost == selfHost) continue;

            ip4_addr_t target;
            ip4_addr_set_u32(&target, lwip_htonl(targetHost));

            LOCK_TCPIP_CORE();
            etharp_request(nif, &target);
            UNLOCK_TCPIP_CORE();
            vTaskDelay(pdMS_TO_TICKS(8));
        }
        // Give replies time to land, then harvest before the cache recycles.
        vTaskDelay(pdMS_TO_TICKS(220));
        drain_arp_table(nif, event, seen, seenCount, selfHost);
    }

    // Final harvest for late responders.
    if (!g_stopRequested) {
        vTaskDelay(pdMS_TO_TICKS(300));
        drain_arp_table(nif, event, seen, seenCount, selfHost);
    }

    fg_send_result_fmt(
        "{\"event\":\"scan_complete\",\"type\":\"%s\",\"count\":%d}", event, seenCount);
    Serial.printf("[ARP] Sweep complete: %d hosts.\n", seenCount);

    fg_wifi_disconnect_sta();
    fg_send_result("{\"event\":\"log\",\"msg\":\"AP restored.\"}");
}

void fg_arp_scan(const char* ssid, const char* pass) {
    fg_subnet_sweep(ssid, pass, "host");
}
