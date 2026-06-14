// ============================================================
// FireGod-ESP — Client scanner
//
// Join-based station discovery: connect to the target network and
// enumerate live hosts on its subnet (IP + MAC + vendor). Shares
// the ARP subnet sweep with the ARP scanner, tagging results as
// "client" events. Restores the AP on exit; honors g_stopRequested.
// ============================================================

#include "client_scanner.h"
#include "modules/wifi/arp_scanner.h"

void fg_client_scan(const char* ssid, const char* pass) {
    fg_subnet_sweep(ssid, pass, "client");
}
