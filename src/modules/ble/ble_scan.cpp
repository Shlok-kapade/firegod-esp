// ============================================================
// FireGod-ESP — BLE Scanner (NimBLE active scan)
//
// Runs alongside the WiFi SoftAP (ESP32 software coexistence), so the
// admin dashboard stays up while scanning. Discovered advertisers are
// streamed immediately from the scan callback (NimBLE host-task context)
// as "ble_dev" events; the module loop emits periodic "ble_stats" and
// owns start/stop + NimBLE init/deinit so the radio is released on exit.
// ============================================================

#include "ble_scan.h"
#include "fg_globals.h"
#include <NimBLEDevice.h>

static volatile uint32_t s_seen = 0;          // total adverts reported
static portMUX_TYPE      s_mux  = portMUX_INITIALIZER_UNLOCKED;

// Sanitize a NimBLE string into a JSON-safe field (printable, no quotes/backslash).
static void sanitize(const std::string& in, char* dst, size_t dstLen) {
    size_t w = 0;
    for (char c : in) {
        if (w >= dstLen - 1) break;
        if (c == '"' || c == '\\') c = '.';
        dst[w++] = (c >= 0x20 && c < 0x7f) ? c : '.';
    }
    dst[w] = '\0';
}

// --- Scan callback (NimBLE host task context; not an ISR) ---
class FGScanCB : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice* dev) override {
        char name[33];
        sanitize(dev->getName(), name, sizeof(name));
        char addr[20];
        sanitize(dev->getAddress().toString(), addr, sizeof(addr));

        portENTER_CRITICAL(&s_mux);
        s_seen++;
        portEXIT_CRITICAL(&s_mux);

        fg_send_result_fmt(
            "{\"event\":\"ble_dev\",\"addr\":\"%s\",\"rssi\":%d,"
            "\"name\":\"%s\",\"appear\":%u}",
            addr, dev->getRSSI(), name, (unsigned)dev->getAppearance());
    }
};

static FGScanCB s_cb;

void fg_ble_scan(uint32_t durationSecs) {
    s_seen = 0;

    fg_send_result_fmt("{\"event\":\"log\",\"msg\":\"BLE scan starting%s...\"}",
                       durationSecs ? "" : " (until stop)");
    Serial.println("[BLE] Scan starting");

    NimBLEDevice::init("");
    NimBLEDevice::setOwnAddrType(BLE_OWN_ADDR_PUBLIC);   // in case a prior spam left RANDOM
    NimBLEScan* scan = NimBLEDevice::getScan();
    scan->setScanCallbacks(&s_cb, false);   // false = report duplicates off
    scan->setActiveScan(true);              // request scan-response (names)
    scan->setInterval(100);
    scan->setWindow(99);
    scan->setMaxResults(0);                 // callback-only, don't accumulate
    scan->start(0, false);                  // 0 = scan forever (non-blocking)

    uint32_t started = millis();
    uint32_t lastEmit = started;
    while (!g_stopRequested) {
        vTaskDelay(pdMS_TO_TICKS(50));
        uint32_t now = millis();
        if (now - lastEmit >= 1000) {
            lastEmit = now;
            uint32_t seen;
            portENTER_CRITICAL(&s_mux); seen = s_seen; portEXIT_CRITICAL(&s_mux);
            fg_send_result_fmt(
                "{\"event\":\"ble_stats\",\"seen\":%lu,\"secs\":%lu}",
                (unsigned long)seen, (unsigned long)((now - started) / 1000));
        }
        if (durationSecs && (now - started) >= durationSecs * 1000UL) break;
    }

    scan->stop();
    NimBLEDevice::deinit(true);   // free controller so WiFi/next module is clean

    fg_send_result_fmt("{\"event\":\"scan_complete\",\"type\":\"ble\",\"count\":%lu}",
                       (unsigned long)s_seen);
    Serial.printf("[BLE] Scan stopped. %lu adverts.\n", (unsigned long)s_seen);
}
