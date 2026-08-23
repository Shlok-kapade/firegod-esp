#pragma once
// ============================================================
// FireGod-ESP — ARP-spoof MITM (full L2 relay)
// ============================================================
//
// Joins `ssid`/`pass` as STA (AP stays up via AP+STA), ARP-poisons
// victim(s) <-> gateway, FORWARDS their traffic at L2 so they stay
// online, and inline-parses plain HTTP + DNS, streaming captures to
// the dashboard. On stop it heals the ARP caches and restores the AP.
//
// `target`: "all" / nullptr  -> MITM every discovered client.
//           "<a.b.c.d>"      -> MITM only that single client.
//
// NOTE: HTTPS stays encrypted (DNS/Host names only). One radio + no
// PSRAM => modest throughput, best-effort forwarding.
void fg_mitm(const char* ssid, const char* pass, const char* target);
