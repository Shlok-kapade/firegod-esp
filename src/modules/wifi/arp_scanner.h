#pragma once

void fg_arp_scan(const char* ssid, const char* pass);

// Shared subnet host-discovery sweep. Joins `ssid`/`pass` via STA (keeping the
// AP up), ARP-sweeps the local subnet, and emits one JSON event per live host
// using `event` as the event name ("host" for ARP scan, "client" for client
// scan). Restores the AP on exit and honors g_stopRequested.
void fg_subnet_sweep(const char* ssid, const char* pass, const char* event);
